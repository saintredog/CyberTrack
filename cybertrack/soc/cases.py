"""Incident case management: open, work, report, close.

Escalating an alert as malicious opens a Case. The analyst walks it through the
NIST SP 800-61 lifecycle (detection and analysis, containment, eradication,
recovery, lessons learned), checks off response tasks seeded from the
detection's playbook, keeps a notes timeline, and writes an incident report.

The report is graded here, deterministically and transparently. Every point
comes from a rubric row the analyst can read: criterion, points earned, points
possible, and a tip. There is no randomness and no hidden model.

Rubric (100 points):
- Completeness, 30: each of the six sections is worth 5. Full marks at the
  section's minimum length, 2 points if it is started but short, 0 if empty.
- Timeline, 15: at least two distinct time-stamped (HH:MM) entries.
- IOC coverage, 20: share of the attacker's indicators (external IPs, domains,
  URLs, sender addresses, malicious files and tools, attacker-created accounts)
  mentioned anywhere in the report. Stock OS and Office binaries are not IOCs.
- Affected assets, 10: share of the victim hosts, internal IPs and accounts
  named. They belong under Scope & impact, never on an IOC or block list.
- Recommendations, 25: cover at least two of the detection's response-playbook
  actions, matched by keyword overlap.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import SEVERITY_ORDER
from ..models import CASE_STAGES, Alert, Case, CaseNote, CaseTask
from .fields import HOST, extract_fields

# ----------------------------------------------------------------- lifecycle

STAGES = CASE_STAGES
STAGE_LABELS = {
    "detection": "Detection & analysis",
    "containment": "Containment",
    "eradication": "Eradication",
    "recovery": "Recovery",
    "lessons": "Lessons learned",
}
STAGE_SHORT = {
    "detection": "Detection",
    "containment": "Containment",
    "eradication": "Eradication",
    "recovery": "Recovery",
    "lessons": "Lessons",
}
STAGE_GUIDANCE = {
    "detection": "Confirm the incident is real, work out its scope, and preserve evidence before anything changes.",
    "containment": "Stop the spread: isolate hosts, disable accounts, block indicators. Prefer containment that keeps evidence intact.",
    "eradication": "Remove the foothold: malware, persistence, rogue accounts, and the weakness the attacker used.",
    "recovery": "Return systems to normal from a known-good state, reset credentials, and watch for recurrence.",
    "lessons": "Write the incident report: root cause, what worked, and what to change in detection and preparation.",
}


@dataclass(frozen=True)
class ReportSection:
    key: str
    label: str
    min_len: int
    hint: str
    placeholder: str
    rows: int = 4


REPORT_SECTIONS = [
    ReportSection(
        "summary", "Executive summary", 100,
        "Two to four plain sentences for leadership: what happened, what was affected, current status, business risk.",
        "On 02 Oct an attacker ... The affected host was isolated within ... No evidence of ...",
    ),
    ReportSection(
        "timeline", "Timeline", 40,
        "One event per line, each starting with a time (HH:MM), from first malicious activity through containment.",
        "03:12  First failed SSH logon from 203.0.113.7\n03:17  Successful logon as ...\n03:40  Host isolated",
        rows=5,
    ),
    ReportSection(
        "scope_impact", "Scope & impact", 60,
        "Name each affected host, internal IP and account, how far it spread, and what that means for the business.",
        "Hosts: WS-0000, 10.20.x.x  Accounts: ...  Data at risk: ...  Business impact: ...",
    ),
    ReportSection(
        "iocs", "Indicators of compromise", 20,
        "Attacker-controlled indicators only: external IPs, domains, URLs, sender addresses, malicious files and tools, "
        "attacker-created accounts. Victim hosts and accounts go under Scope & impact, and stock binaries such as "
        "cmd.exe are not IOCs. Defanged forms such as 203.0.113[.]7 count.",
        "203.0.113[.]7\nhxxps://login-portal[.]example/auth\nit-support@login-portal[.]example\nInvoice_0000.docm",
        rows=5,
    ),
    ReportSection(
        "root_cause", "Root cause", 50,
        "How the attacker got in or why the activity happened, and which control failed or was missing.",
        "Initial access was ... because ... The control that would have stopped it is ...",
    ),
    ReportSection(
        "recommendations", "Recommendations", 60,
        "Concrete actions: contain, eradicate, recover, and prevent a repeat. Tie them to the response playbook.",
        "1. ...\n2. ...\n3. ...",
        rows=5,
    ),
]
SECTION_KEYS = [s.key for s in REPORT_SECTIONS]

SECTION_POINTS = 5        # x6 sections = 30
SECTION_PARTIAL = 2
TIMELINE_POINTS = 15
TIMELINE_MIN = 2
IOC_POINTS = 20
ASSET_POINTS = 10
PLAYBOOK_POINTS = 25
PLAYBOOK_MIN = 2
MAX_SCORE = SECTION_POINTS * len(REPORT_SECTIONS) + TIMELINE_POINTS + IOC_POINTS + ASSET_POINTS + PLAYBOOK_POINTS
assert MAX_SCORE == 100

NOTE_MAX = 4000
SECTION_MAX = 20000  # per report section; generous, but keeps a stray paste from bloating the DB


# -------------------------------------------------------------- case actions


def ref(case_id: int) -> str:
    return f"IR-{case_id:04d}"


def open_case(session: Session, alert: Alert, now: datetime, on: date) -> Case:
    """Open (or return the existing) case for an escalated alert.

    Response tasks are seeded from the detection's playbook. If the alert's
    ground truth is benign, the case is flagged as a false positive: it needs
    a closing note, not an incident report.
    """
    if alert.case is not None:
        return alert.case
    case = Case(
        alert=alert,
        title=alert.title,
        severity=alert.severity,
        opened_at=now,
        opened_on=on,
        stage=STAGES[0],
        status="open",
        closing_note="",
        false_positive=alert.true_disposition != "malicious",
        report_feedback=[],
        **{k: "" for k in SECTION_KEYS},
    )
    case.tasks = [CaseTask(label=label, done=False) for label in (alert.response or [])]
    session.add(case)
    session.flush()
    return case


def _require_open(case: Case) -> None:
    if case.status != "open":
        raise ValueError(f"{case.ref} is closed.")


def move_stage(case: Case, step: int) -> bool:
    """Move one stage forward (+1) or back (-1). Returns False at either end."""
    _require_open(case)
    i = STAGES.index(case.stage) + (1 if step > 0 else -1)
    if not 0 <= i < len(STAGES):
        return False
    case.stage = STAGES[i]
    return True


def toggle_task(case: Case, task: CaseTask, now: datetime) -> None:
    _require_open(case)
    task.done = not task.done
    task.done_at = now if task.done else None


def add_note(case: Case, body: str, now: datetime) -> CaseNote:
    _require_open(case)
    body = (body or "").strip()
    if not body:
        raise ValueError("Write something before adding a note.")
    note = CaseNote(created_at=now, stage=case.stage, body=body[:NOTE_MAX])
    case.notes.append(note)
    return note


def report_text(case: Case) -> dict[str, str]:
    return {k: getattr(case, k) or "" for k in SECTION_KEYS}


def submit_report(case: Case, form: Mapping[str, str], now: datetime) -> int:
    """Save the six report sections, grade them, and store the rubric. Resubmission is allowed."""
    _require_open(case)
    if case.false_positive:
        raise ValueError("False-positive cases close with a note; no incident report is needed.")
    for key in SECTION_KEYS:
        setattr(case, key, (form.get(key) or "").strip()[:SECTION_MAX])
    score, rows = grade_report(report_text(case), case.alert)
    case.report_score = score
    case.report_feedback = rows
    case.report_submitted_at = now
    return score


def close_blockers(case: Case) -> list[str]:
    """What still stands between this case and closure (empty list = closable)."""
    if case.status != "open":
        return ["the case is already closed"]
    if case.false_positive:
        return []
    out = []
    if case.report_submitted_at is None:
        out.append("submit the incident report")
    if case.stage != "lessons":
        out.append("advance the case to Lessons learned")
    return out


def close_case(case: Case, note: str, now: datetime, on: date | None = None) -> None:
    """Close the case. `on` is the app's day (db.today()), which a replayed day can set apart from `now`."""
    blockers = close_blockers(case)
    if blockers:
        raise ValueError("Can't close yet: " + "; ".join(blockers) + ".")
    note = (note or "").strip()
    if case.false_positive and not note:
        raise ValueError("Add a short closing note: why was this escalation a false positive?")
    case.status = "closed"
    case.closed_at = now
    case.closed_on = on or now.date()
    case.closing_note = note[:NOTE_MAX]


def open_cases(session: Session) -> list[Case]:
    cases = list(session.scalars(select(Case).where(Case.status == "open")))
    return sorted(cases, key=lambda c: (SEVERITY_ORDER.get(c.severity, 9), c.opened_at))


def turnover_line(case: Case) -> str:
    """One handoff line per open case, for Shift Turnover's suggested open items."""
    tasks = f"{case.tasks_done}/{len(case.tasks)} tasks done"
    if case.false_positive:
        parts = ["false positive", tasks, "close with a note"]
    elif case.report_submitted_at is None:
        parts = [STAGE_LABELS[case.stage], tasks, "report not submitted"]
    else:
        parts = [STAGE_LABELS[case.stage], tasks, f"report {case.report_score}/100"]
    return f"{case.ref} {case.title}: " + ", ".join(parts)


# ------------------------------------------------------------------- display


def age(start: datetime | None, end: datetime | None = None) -> str:
    """Compact age like 45m, 6h, 3d."""
    if start is None:
        return "--"
    secs = max(0.0, ((end or datetime.now()) - start).total_seconds())
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def score_band(score: int | None) -> dict:
    """Label + tone for a report score. Tone is a status class and always ships with the label."""
    if score is None:
        return {"label": "Not submitted", "tone": ""}
    if score >= 80:
        return {"label": "Strong", "tone": "tone-good"}
    if score >= 60:
        return {"label": "Needs work", "tone": "tone-warn"}
    return {"label": "Incomplete", "tone": "tone-bad"}


# ------------------------------------------------------------------- grading

OWN_DOMAIN = "corp.example"  # the organization's own domain is not an indicator
# Signed OS and Office binaries. They appear in process chains, but blocking or
# hunting on them is wrong, so they are never IOCs on their own.
STOCK_BINARIES = frozenset(
    "cmd.exe net.exe net1.exe powershell.exe pwsh.exe rundll32.exe regsvr32.exe mshta.exe wscript.exe cscript.exe "
    "w3wp.exe explorer.exe mmc.exe svchost.exe winword.exe excel.exe outlook.exe ccmexec.exe".split()
)
_RFC1918 = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")

Pair = tuple[str, str]  # (kind, value), e.g. ("ip", "203.0.113.7")


@dataclass(frozen=True)
class EvidenceKey:
    """What a good report on an alert cites.

    `iocs` are attacker-controlled: infrastructure, malicious files and tools,
    accounts the attacker created. `assets` are what was hit: victim hosts,
    internal IPs, compromised accounts. Keeping them apart matters because an
    IOC list feeds block lists and hunts.
    """

    iocs: list[Pair]
    assets: list[Pair]


def _grab(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text or "", re.M)
    return m.group(1) if m else None


def _stage_two(raw: str) -> str | None:
    """The script a PowerShell -enc download cradle fetches (base64, then UTF-16LE)."""
    blob = _grab(r"-enc (\S+)", raw)
    if not blob:
        return None
    try:
        decoded = base64.b64decode(blob, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return _grab(r"/([\w.-]+\.ps1)\b", decoded)


# One key per detection, read from the stored raw event (and enrichment, where the
# workstation name lives), so alerts generated before this existed grade the same way.
# Only the malicious variants are graded: a false-positive case closes with a note.
_KEYS = {
    "auth_bruteforce": lambda raw, enr: (
        [("ip", _grab(r"Accepted password for \S+ from (\S+)", raw))],
        [("host", _grab(f"({HOST})", raw)), ("account", _grab(r"Accepted password for (\S+) from", raw))],
    ),
    "beaconing": lambda raw, enr: (
        # rundll32.exe is a stock binary; the C2 domain is the indicator.
        [("domain", _grab(r"CONNECT ([\w.-]+):\d+", raw))],
        [("host", _grab(f"({HOST})", enr.get("Host", ""))), ("ip", _grab(r"^\S+ \S+ (\S+) CONNECT", raw))],
    ),
    "powershell_encoded": lambda raw, enr: (
        # The lure document, the second-stage script inside the -enc blob, and its server.
        [("ip", _grab(r"\bdst=([\d.]+)", raw)), ("file", _grab(r"([\w.-]+\.docm)\b", raw)), ("file", _stage_two(raw))],
        [("host", _grab(r"\bhost=(\S+)", raw)), ("account", _grab(r"\buser=CORP\\(\S+)", raw))],
    ),
    "internal_scan": lambda raw, enr: (
        # A sweep log holds no attacker infrastructure: the scanning host is the compromised asset.
        [],
        [("host", _grab(f"({HOST})", enr.get("Source", ""))), ("ip", _grab(r"^[\d.]+\tC\d+\t(\S+)\t", raw))],
    ),
    "phishing_click": lambda raw, enr: (
        [("domain", _grab(r"<[^<>@\s]+@([^<>\s]+)>", raw)), ("email", _grab(r"<([^<>@\s]+@[^<>\s]+)>", raw)),
         ("url", _grab(r"\bGET https?://(\S+)", raw))],
        [("host", _grab(r"^\[proxy\] \S+ (\S+) ", raw)), ("account", _grab(r"\bto=([\w.-]+)@", raw))],
    ),
    "impossible_travel": lambda raw, enr: (
        # The sign-in that skipped MFA, not the user's own MFA-satisfied session, plus the forwarding address.
        [("ip", _grab(r"\bip=(\S+)[^\n]*\bmfa=(?!satisfied)", raw)), ("email", _grab(r"\bforwardTo=(\S+)", raw))],
        [("account", _grab(r"\buser=([\w.-]+)@", raw))],
    ),
    "data_exfil": lambda raw, enr: (
        # Destination plus the tools and archive the attacker staged in ProgramData.
        [("domain", _grab(r"\bdst=([\w.-]+\.example)", raw))]
        + [("file", f) for f in re.findall(r"C:\\ProgramData\\([\w.-]+\.(?:exe|7z))\b", raw)],
        [("host", _grab(r"\bhost=(\S+)", raw)), ("ip", _grab(r"\bsrc=(\S+)", raw)),
         ("account", _grab(r"\buser=CORP\\(\S+)", raw))],
    ),
    "new_admin_account": lambda raw, enr: (
        # The backdoor account is the indicator; w3wp.exe, cmd.exe and net.exe are stock binaries.
        [("account", _grab(r"New Account: (\S+)", raw))],
        [("host", _grab(f"({HOST})", raw))],
    ),
}


def _generic_key(raw: str, enr: dict) -> tuple[list[Pair], list[Pair]]:
    """For an event from an unknown detection: sort the extracted fields by who controls them."""
    fields = extract_fields(raw)

    def values(kind: str) -> list[str]:
        common = (fields.get(kind) or Counter()).most_common()
        if len(common) > 3:  # a sweep's long list of one-off targets: keep the repeated ones
            common = [(v, c) for v, c in common if c >= 2] or common[:3]
        return [v for v, _ in common]

    iocs: list[Pair] = [("ip", ip) for ip in values("ip") if not _RFC1918.match(ip)]
    iocs += [("domain", d) for d in values("domain") if d != OWN_DOMAIN and not d.endswith("." + OWN_DOMAIN)]
    iocs += [("file", f) for f in values("file")]
    iocs += [("process", p) for p in values("process") if p.lower() not in STOCK_BINARIES]
    assets: list[Pair] = [("ip", ip) for ip in values("ip") if _RFC1918.match(ip)]
    assets += [("host", h) for h in values("host")]
    assets += [("account", u.split("@")[0]) for u in values("user")]
    return iocs, assets


def _dedupe(pairs: list[tuple[str, str | None]]) -> list[Pair]:
    out: list[Pair] = []
    seen: set[str] = set()
    for kind, value in pairs:
        if value and value.lower() not in seen:
            seen.add(value.lower())
            out.append((kind, value))
    return out


def evidence_key(alert: Alert) -> EvidenceKey:
    """The attacker IOCs and the affected assets a good report on this alert cites."""
    build = _KEYS.get(alert.scenario or "", _generic_key)
    iocs, assets = build(alert.raw_log or "", alert.enrichment or {})
    return EvidenceKey(_dedupe(iocs), _dedupe(assets))


_REFANG = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)")


def _refang(text: str) -> str:
    text = _REFANG.sub(".", text.lower())
    return text.replace("hxxp", "http").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")


def _mentioned(value: str, text: str) -> bool:
    # Whole-token match: 10.1.2.3 must not count inside 10.1.2.34, nor "admin" inside "it-admin".
    return re.search(r"(?<![\w.-])" + re.escape(value.lower()) + r"(?![\w-])", text) is not None


def ioc_coverage(text: str, iocs: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Split IOCs into (mentioned, missing). Case-insensitive; defanged forms count."""
    norm = _refang(text)
    found = [i for i in iocs if _mentioned(i[1], norm)]
    missing = [i for i in iocs if i not in found]
    return found, missing


_TIME = re.compile(r"(?<![\d:])([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?(?![\d:])")


def timeline_entries(text: str) -> int:
    """Distinct HH:MM times in the timeline (seconds ignored, 3:05 == 03:05)."""
    return len({(int(h), int(m)) for h, m in _TIME.findall(text or "")})


_STOP = set(
    """
    the and for with from that this its any all other same into then than them they their there what when where
    which who why how after before also only just more most very should would could will must can may not are was
    were has have had been being out off over under about per via each every some such new case make sure did does
    done use used using yet own now see get got let our your his her him she you one two exactly
    review check find look identify determine consider ensure need needs
    """.split()
)
_SHORT_OK = {"ip"}


def _stem(w: str) -> str:
    # A tiny suffix stripper. It only has to be consistent: both sides of the
    # comparison go through it, so "isolated", "isolating" and "isolation" all meet at "isolat".
    if w.endswith("s") and not w.endswith("ss") and (len(w) > 3 or w == "ips"):
        w = w[:-1]
    for suf, keep in (("ing", 4), ("ion", 4), ("ed", 3)):
        if w.endswith(suf) and len(w) - len(suf) >= keep:
            w = w[: -len(suf)]
            break
    if w.endswith("e") and len(w) > 3:
        w = w[:-1]
    return w


def keywords(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {_stem(w) for w in words if (len(w) >= 3 or w in _SHORT_OK) and w not in _STOP}


def playbook_coverage(recommendations: str, playbook: list[str]) -> tuple[list[str], list[str]]:
    """Split playbook actions into (covered, not covered) by the recommendations text.

    An action counts as covered when at least two of its keywords (or all of
    them, if it has fewer) appear in the recommendations.
    """
    have = keywords(recommendations)
    covered, uncovered = [], []
    for action in playbook:
        kw = keywords(action)
        need = min(2, len(kw))
        (covered if kw and len(kw & have) >= need else uncovered).append(action)
    return covered, uncovered


def _row(criterion: str, group: str, earned: int, possible: int, tip: str) -> dict:
    return {"criterion": criterion, "group": group, "earned": int(earned), "possible": possible, "tip": tip}


def _coverage_row(criterion: str, possible: int, text: str, wanted: list[Pair], noun: str, verb: str,
                  if_none: str, hint: str = "") -> dict:
    """Points in proportion to how many of `wanted` the report mentions."""
    if not wanted:
        return _row(criterion, "Evidence", possible, possible, if_none)
    found, missing = ioc_coverage(text, wanted)
    tip = f"{len(found)} of {len(wanted)} {noun}{'' if len(wanted) == 1 else 's'} {verb}."
    if missing:
        listed = ", ".join(f"{v} ({k})" for k, v in missing[:6]) + (f" +{len(missing) - 6} more" if len(missing) > 6 else "")
        tip += f" Missing: {listed}.{hint}"
    return _row(criterion, "Evidence", round(possible * len(found) / len(wanted)), possible, tip)


def _quote_list(items: list[str], limit: int = 4) -> str:
    shown = "; ".join(f'"{s}"' for s in items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def grade_report(report: Mapping[str, str], alert: Alert) -> tuple[int, list[dict]]:
    """Score a report 0-100 against the alert's evidence. Returns (score, rubric rows)."""
    rows: list[dict] = []

    for sec in REPORT_SECTIONS:
        text = (report.get(sec.key) or "").strip()
        n = len(text)
        if n >= sec.min_len:
            rows.append(_row(sec.label, "Completeness", SECTION_POINTS, SECTION_POINTS, f"Written ({n} characters)."))
        elif n:
            rows.append(_row(sec.label, "Completeness", SECTION_PARTIAL, SECTION_POINTS,
                             f"Only {n} characters; aim for at least {sec.min_len}. {sec.hint}"))
        else:
            rows.append(_row(sec.label, "Completeness", 0, SECTION_POINTS, f"Empty. {sec.hint}"))

    times = timeline_entries(report.get("timeline", ""))
    if times >= TIMELINE_MIN:
        rows.append(_row("Time-stamped timeline", "Timeline", TIMELINE_POINTS, TIMELINE_POINTS,
                         f"{times} time-stamped entries."))
    else:
        earned = TIMELINE_POINTS // 2 if times == 1 else 0
        rows.append(_row("Time-stamped timeline", "Timeline", earned, TIMELINE_POINTS,
                         f"Found {times} time-stamped entr{'y' if times == 1 else 'ies'}; need at least {TIMELINE_MIN}. "
                         "Start each line with a time like 03:14. The raw event has the timestamps."))

    full_text = "\n".join(report.get(k) or "" for k in SECTION_KEYS)
    key = evidence_key(alert)
    rows.append(_coverage_row(
        "IOC coverage", IOC_POINTS, full_text, key.iocs, "attacker indicator", "referenced",
        "No attacker infrastructure or artifacts in this event; the affected assets carry the evidence.",
    ))
    rows.append(_coverage_row(
        "Affected assets", ASSET_POINTS, full_text, key.assets, "affected asset", "named",
        "No specific hosts or accounts in this event.", " Name them under Scope & impact, not as IOCs.",
    ))

    playbook = list(alert.response or [])
    need = min(PLAYBOOK_MIN, len(playbook))
    covered, uncovered = playbook_coverage(report.get("recommendations", ""), playbook)
    if need == 0 or len(covered) >= need:
        tip = f"Covers {len(covered)} of {len(playbook)} playbook actions." if playbook else "No playbook for this detection."
        rows.append(_row("Playbook-aligned recommendations", "Response", PLAYBOOK_POINTS, PLAYBOOK_POINTS, tip))
    else:
        earned = round(PLAYBOOK_POINTS * len(covered) / need)
        rows.append(_row("Playbook-aligned recommendations", "Response", earned, PLAYBOOK_POINTS,
                         f"Covers {len(covered)} of the {need} needed. Not yet addressed: {_quote_list(uncovered)}."))

    return sum(r["earned"] for r in rows), rows
