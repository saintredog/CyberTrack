"""Aggregations behind the dashboard, analytics, and training charts."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Alert, CurriculumItem, StudyLog, Triage
from .viz import URGENCY_ORDER


def _mttt_minutes(pairs) -> float | None:
    """Mean minutes from first view to decision, ignoring alerts never opened in the UI."""
    mins = [
        (t.decided_at - a.first_viewed_at).total_seconds() / 60
        for t, a in pairs
        if a.first_viewed_at is not None and t.decided_at >= a.first_viewed_at
    ]
    return sum(mins) / len(mins) if mins else None


def daily(session: Session, end: date, days: int = 14) -> list[dict]:
    start = end - timedelta(days=days - 1)
    alerts = list(session.scalars(select(Alert).where(Alert.shift_date >= start, Alert.shift_date <= end)))
    pairs = session.execute(
        select(Triage, Alert).join(Alert, Triage.alert_id == Alert.id).where(Triage.decided_on >= start)
    ).all()
    logs = list(session.scalars(select(StudyLog).where(StudyLog.logged_on >= start)))

    by_day_alerts: dict[date, Counter] = defaultdict(Counter)
    for a in alerts:
        by_day_alerts[a.shift_date][a.severity] += 1
    by_day_triage: dict[date, list] = defaultdict(list)
    for t, a in pairs:
        by_day_triage[t.decided_on].append((t, a))
    study = Counter(l.logged_on for l in logs)
    study_min = Counter()
    for l in logs:
        study_min[l.logged_on] += l.minutes

    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        tri = by_day_triage.get(d, [])
        correct = sum(1 for t, _ in tri if t.correct)
        row = {
            "day": d,
            "alerts": sum(by_day_alerts[d].values()),
            "triaged": len(tri),
            "correct": correct,
            "accuracy": (correct / len(tri) * 100) if tri else None,
            "mttt": _mttt_minutes(tri),
            "study": study.get(d, 0),
            "study_minutes": study_min.get(d, 0),
        }
        for u in URGENCY_ORDER:
            row[u] = by_day_alerts[d][u]
        out.append(row)
    return out


def open_by_urgency(session: Session) -> dict[str, int]:
    c = Counter(session.scalars(select(Alert.severity).where(Alert.status == "new")))
    return {u: c.get(u, 0) for u in URGENCY_ORDER}


def by_source(session: Session) -> list[dict]:
    rows = session.execute(select(Alert.source, Alert.status)).all()
    total = Counter(s for s, _ in rows)
    return [{"label": s.upper(), "value": n} for s, n in total.most_common()]


def rule_accuracy(session: Session) -> list[dict]:
    from .soc.scenarios import SCENARIO_LABELS

    pairs = session.execute(select(Triage, Alert).join(Alert, Triage.alert_id == Alert.id)).all()
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for t, a in pairs:
        agg[a.scenario][0] += int(t.correct)
        agg[a.scenario][1] += 1
    rows = [
        {"key": k, "label": SCENARIO_LABELS.get(k, k), "correct": c, "total": n, "pct": round(c / n * 100)}
        for k, (c, n) in agg.items()
    ]
    rows.sort(key=lambda r: (r["pct"], -r["total"]))
    return rows


def techniques(session: Session, since: date) -> list[dict]:
    rows = session.execute(select(Alert.technique, Alert.title).where(Alert.shift_date >= since)).all()
    c = Counter(t for t, _ in rows)
    titles = {t: title for t, title in rows}
    return [{"id": t, "title": titles[t], "count": n} for t, n in c.most_common()]


def overall_mttt(session: Session) -> float | None:
    pairs = session.execute(select(Triage, Alert).join(Alert, Triage.alert_id == Alert.id)).all()
    return _mttt_minutes(pairs)


def study_activity(session: Session) -> dict[date, int]:
    return dict(Counter(session.scalars(select(StudyLog.logged_on))))


def due_items(session: Session, on: date, cwe_phase: int, limit: int = 8) -> list[CurriculumItem]:
    from .study.scheduler import is_unlocked

    items = [
        i for i in session.scalars(select(CurriculumItem))
        if i.review is not None and i.review.due_date is not None and i.review.due_date <= on
        and i.active and is_unlocked(i, cwe_phase)
    ]
    items.sort(key=lambda i: (i.review.due_date, i.review.ease))
    return items[:limit]
