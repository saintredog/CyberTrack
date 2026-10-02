"""SPL-flavored search over alerts.

Supports what an analyst types into a Splunk search bar, scaled down:

    index=notable urgency=high source=edr status=new beacon
    technique=T1059* "rundll32" earliest=-7d verdict=wrong

- `field=value` and `field!=value` tokens. Values may use * wildcards.
- `earliest=-Nd` limits to the last N days (by shift date).
- Anything else is free text, matched case-insensitively against the alert
  title, raw log, and enrichment. Quote phrases to keep spaces.
- `index=...` and `sourcetype=...` are accepted and ignored, so muscle memory works.

The answer key (true disposition) is never searchable; `verdict=` only
matches alerts you already triaged.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from datetime import date, timedelta

FIELD_ALIASES = {
    "urgency": "severity", "severity": "severity", "sev": "severity",
    "source": "source", "src": "source",
    "status": "status",
    "technique": "technique", "mitre": "technique", "attack": "technique",
    "rule": "scenario", "scenario": "scenario",
    "verdict": "verdict",
    "host": "text", "user": "text", "ip": "text",
}
IGNORED = {"index", "sourcetype"}
TOKEN = re.compile(r"^([A-Za-z_]+)(!=|=)(.*)$")


@dataclass
class Query:
    terms: list[tuple[str, str, bool]] = field(default_factory=list)  # (field, pattern, negate)
    text: list[str] = field(default_factory=list)
    earliest_days: int | None = None
    errors: list[str] = field(default_factory=list)


def parse(q: str) -> Query:
    out = Query()
    try:
        tokens = shlex.split(q or "")
    except ValueError:
        tokens = (q or "").replace('"', " ").split()
        out.errors.append("Unbalanced quotes; searched without them.")
    for tok in tokens:
        m = TOKEN.match(tok)
        if not m:
            if tok.upper() in ("AND", "SEARCH", "|"):
                continue
            out.text.append(tok.lower())
            continue
        key, op, value = m.group(1).lower(), m.group(2), m.group(3)
        if key in IGNORED:
            continue
        if key == "earliest":
            dm = re.fullmatch(r"-(\d+)d", value)
            if dm:
                out.earliest_days = int(dm.group(1))
            else:
                out.errors.append(f"earliest only supports -Nd (e.g. -7d), got {value!r}.")
            continue
        fname = FIELD_ALIASES.get(key)
        if fname is None:
            out.errors.append(f"Unknown field {key!r}. Try urgency, source, status, technique, rule, verdict.")
            continue
        if fname == "text":
            out.text.append(value.lower())
            continue
        out.terms.append((fname, value.lower(), op == "!="))
    return out


def _value(alert, fname: str) -> str:
    if fname == "verdict":
        if alert.triage is None:
            return ""
        return "correct" if alert.triage.correct else "wrong"
    return str(getattr(alert, fname, "") or "").lower()


def _haystack(alert) -> str:
    parts = [alert.title, alert.raw_log, alert.technique, alert.scenario]
    parts += [f"{k} {v}" for k, v in (alert.enrichment or {}).items()]
    return " ".join(parts).lower()


def matches(alert, query: Query, today: date) -> bool:
    if query.earliest_days is not None and alert.shift_date < today - timedelta(days=query.earliest_days):
        return False
    for fname, pattern, negate in query.terms:
        hit = fnmatch.fnmatchcase(_value(alert, fname), pattern)
        if hit == negate:
            return False
    if query.text:
        hay = _haystack(alert)
        for t in query.text:
            if "*" in t:
                if not fnmatch.fnmatchcase(hay, f"*{t}*"):
                    return False
            elif t not in hay:
                return False
    return True


def apply(alerts, q: str, today: date):
    query = parse(q)
    return [a for a in alerts if matches(a, query, today)], query
