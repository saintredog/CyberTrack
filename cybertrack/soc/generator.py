"""Builds a shift's alert batch and grades triage decisions."""
from __future__ import annotations

import math
import random
from datetime import date, datetime
from fractions import Fraction

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Triage
from .scenarios import SCENARIOS


def _rng_for(day: date, salt: int = 0) -> random.Random:
    # Deterministic per day so a shift is reproducible, but different day to day.
    return random.Random(day.toordinal() * 7919 + salt)


HINT_KEY = "Hint"  # enrichment entry that coaches the analyst; dropped above difficulty level 1


def _malicious_flags(count: int, share: float) -> list[bool]:
    """`count` flags, ceil(count * share) of them True, spread evenly before shuffling.

    At share 0.5 this is True, False, True, ... exactly as earlier builds made it,
    so the default shift for a given day is unchanged.
    """
    frac = Fraction(min(max(share, 0.0), 1.0)).limit_denominator(1000)
    return [math.ceil((i + 1) * frac) > math.ceil(i * frac) for i in range(count)]


def generate_shift(
    session: Session,
    day: date,
    count: int,
    salt: int = 0,
    malicious_share: float = 0.5,
    hints: bool = True,
) -> list[Alert]:
    """Create `count` alerts for `day`. About `malicious_share` malicious, never all one kind.

    Scenarios are drawn without repeats until every rule has been used, so a
    small daily batch still rotates through all eight detections over a few days.
    With `hints=False` the coaching "Hint" enrichment entry is left out, so the
    analyst has to know the technique (decoding -enc, say) unprompted.
    """
    rng = _rng_for(day, salt)
    names = list(SCENARIOS)
    rng.shuffle(names)
    # Rotate the starting point by day so consecutive shifts see different rules.
    offset = day.toordinal() % len(names)
    names = names[offset:] + names[:offset]

    malicious_flags = _malicious_flags(count, malicious_share)
    rng.shuffle(malicious_flags)
    if count >= 2 and len(set(malicious_flags)) == 1:
        malicious_flags[0] = not malicious_flags[0]

    base = datetime(day.year, day.month, day.day)
    alerts: list[Alert] = []
    for i in range(count):
        name = names[i % len(names)]
        spec = SCENARIOS[name](rng, base, malicious_flags[i])
        enrichment = spec.enrichment if hints else {k: v for k, v in spec.enrichment.items() if k != HINT_KEY}
        alert = Alert(
            shift_date=day,
            created_at=_first_timestamp(spec.raw_log, base),
            scenario=spec.scenario,
            source=spec.source,
            severity=spec.severity,
            title=spec.title,
            technique=spec.technique,
            raw_log=spec.raw_log,
            enrichment=enrichment,
            true_disposition=spec.true_disposition,
            indicators=spec.indicators,
            explanation=spec.explanation,
            response=spec.response,
            status="new",
        )
        session.add(alert)
        alerts.append(alert)
    session.flush()
    return alerts


def _first_timestamp(raw: str, fallback: datetime) -> datetime:
    """Best-effort pull of the first ISO timestamp in a log so the queue sorts by time."""
    import re

    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", raw)
    if m:
        try:
            return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
        except ValueError:
            pass
    m = re.search(r"^[A-Z][a-z]{2} \d{2} (\d{2}):(\d{2}):(\d{2})", raw, re.M)
    if m:
        return fallback.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=int(m.group(3)))
    m = re.search(r"^(\d{9,11})\.\d+\t", raw, re.M)
    if m:
        return datetime.fromtimestamp(int(m.group(1)))
    return fallback


def grade(
    session: Session,
    alert: Alert,
    disposition: str,
    reason: str,
    notes: str,
    now: datetime,
    on: date,
) -> Triage:
    if alert.triage is not None:
        raise ValueError("alert already triaged")
    if disposition not in ("benign", "malicious"):
        raise ValueError("disposition must be benign or malicious")
    if not reason.strip():
        raise ValueError("a reason is required")
    t = Triage(
        alert=alert,
        user_disposition=disposition,
        reason=reason.strip(),
        notes=notes.strip(),
        decided_at=now,
        decided_on=on,
        correct=(disposition == alert.true_disposition),
    )
    alert.status = "escalated" if disposition == "malicious" else "closed"
    session.add(t)
    session.flush()
    return t


def metrics(session: Session) -> dict:
    """Confusion matrix, accuracy, and per-rule accuracy over all triage history."""
    rows = session.execute(select(Triage, Alert).join(Alert, Triage.alert_id == Alert.id)).all()
    tp = sum(1 for t, a in rows if a.true_disposition == "malicious" and t.user_disposition == "malicious")
    tn = sum(1 for t, a in rows if a.true_disposition == "benign" and t.user_disposition == "benign")
    fp = sum(1 for t, a in rows if a.true_disposition == "benign" and t.user_disposition == "malicious")
    fn = sum(1 for t, a in rows if a.true_disposition == "malicious" and t.user_disposition == "benign")
    total = len(rows)

    per_rule: dict[str, list[int]] = {}
    for t, a in rows:
        bucket = per_rule.setdefault(a.scenario, [0, 0])
        bucket[1] += 1
        bucket[0] += int(t.correct)

    by_day: dict[date, list[int]] = {}
    for t, _ in rows:
        bucket = by_day.setdefault(t.decided_on, [0, 0])
        bucket[1] += 1
        bucket[0] += int(t.correct)

    from ..analytics import _mttt_minutes

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "mttt": _mttt_minutes(rows),
        "accuracy": (tp + tn) / total if total else None,
        "per_rule": {k: {"correct": v[0], "total": v[1]} for k, v in sorted(per_rule.items())},
        "by_day": [
            {"day": d, "correct": v[0], "total": v[1]} for d, v in sorted(by_day.items(), reverse=True)[:14]
        ],
    }
