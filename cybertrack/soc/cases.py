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
- IOC coverage, 30: share of the alert's indicators (IPs, domains, hosts,
  processes, users pulled from the raw event) mentioned anywhere in the report.
- Recommendations, 25: cover at least two of the detection's response-playbook
  actions, matched by keyword overlap.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import SEVERITY_ORDER
from ..models import CASE_STAGES, Alert, Case, CaseNote, CaseTask
from .fields import extract_fields

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
        "Which hosts, accounts and data were affected, how far it spread, and what that means for the business.",
        "Hosts: ...  Accounts: ...  Data at risk: ...  Business impact: ...",
    ),
    ReportSection(
        "iocs", "Indicators of compromise", 20,
        "Every indicator from the evidence: IPs, domains, hosts, processes and accounts. Defanged forms such as 203.0.113[.]7 count.",
        "203.0.113[.]7\nexample-bad[.]example\nWS-0000\nrundll32.exe\naccount name",
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
IOC_POINTS = 30
PLAYBOOK_POINTS = 25
PLAYBOOK_MIN = 2
MAX_SCORE = SECTION_POINTS * len(REPORT_SECTIONS) + TIMELINE_POINTS + IOC_POINTS + PLAYBOOK_POINTS
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


def close_case(case: Case, note: str, now: datetime) -> None:
    blockers = close_blockers(case)
    if blockers:
        raise ValueError("Can't close yet: " + "; ".join(blockers) + ".")
    note = (note or "").strip()
    if case.false_positive and not note:
        raise ValueError("Add a short closing note: why was this escalation a false positive?")
    case.status = "closed"
    case.closed_at = now
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

IOC_KINDS = ("ip", "domain", "host", "process", "user")
OWN_DOMAIN = "corp.example"  # the organization's own domain is not an indicator


def alert_iocs(raw_log: str) -> list[tuple[str, str]]:
    """The indicators a good report should mention, as (kind, value) pairs.

    Pulled from the raw event with extract_fields. Users are reduced to the
    account name (dchen@corp.example -> dchen), the company's own domain is
    dropped, and when one kind has more than three values (a port sweep's
    long list of targets) only the repeated ones are kept.
    """
    fields = extract_fields(raw_log)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind in IOC_KINDS:
        counter = fields.get(kind)
        if not counter:
            continue
        if kind == "user":
            merged: Counter = Counter()
            for v, c in counter.items():
                merged[v.split("@")[0]] += c
            counter = merged
        values = counter.most_common()
        if kind == "domain":
            values = [(v, c) for v, c in values if v != OWN_DOMAIN and not v.endswith("." + OWN_DOMAIN)]
        if len(values) > 3:
            values = [(v, c) for v, c in values if c >= 2] or values[:3]
        for v, _ in values:
            if v.lower() not in seen:
                seen.add(v.lower())
                out.append((kind, v))
    return out


_REFANG = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)")


def _refang(text: str) -> str:
    text = _REFANG.sub(".", text.lower())
    return text.replace("hxxp", "http").replace("[:]", ":")


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
    iocs = alert_iocs(alert.raw_log)
    found, missing = ioc_coverage(full_text, iocs)
    if not iocs:
        rows.append(_row("IOC coverage", "Evidence", IOC_POINTS, IOC_POINTS, "No extractable indicators in this event."))
    else:
        earned = round(IOC_POINTS * len(found) / len(iocs))
        if missing:
            listed = ", ".join(f"{v} ({k})" for k, v in missing[:6]) + (f" +{len(missing) - 6} more" if len(missing) > 6 else "")
            tip = f"{len(found)} of {len(iocs)} indicators referenced. Missing: {listed}."
        else:
            tip = f"All {len(iocs)} indicators referenced."
        rows.append(_row("IOC coverage", "Evidence", earned, IOC_POINTS, tip))

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
