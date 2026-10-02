"""Security Posture: the daily-loop home page."""
from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, render_template
from sqlalchemy import select

from .. import analytics, viz
from ..db import get_int_setting, get_session, today
from ..models import Alert, CurriculumItem, StudyLog, Triage, Turnover
from ..planner import ensure_today, previous_turnover
from ..soc.generator import metrics

bp = Blueprint("dashboard", __name__)


def _streak(session, day) -> int:
    """Consecutive days (ending today or yesterday) with any triage or study activity."""
    active_days = set(session.scalars(select(Triage.decided_on)))
    active_days |= set(session.scalars(select(StudyLog.logged_on)))
    if not active_days:
        return 0
    cursor = day if day in active_days else day - timedelta(days=1)
    streak = 0
    while cursor in active_days:
        streak += 1
        cursor -= timedelta(days=1)
    return streak


@bp.route("/")
def home():
    session = get_session()
    day = today()
    plan = ensure_today(session)
    cwe_phase = get_int_setting(session, "cwe_phase")

    alerts = list(session.scalars(select(Alert).where(Alert.id.in_(plan.alert_ids)))) if plan.alert_ids else []
    shift_open = [a for a in alerts if a.status == "new"]

    items = {i.id: i for i in session.scalars(select(CurriculumItem))}
    study_today = [items[i] for i in plan.study_item_ids if i in items]
    logged_today = set(session.scalars(select(StudyLog.item_id).where(StudyLog.logged_on == day)))

    m = metrics(session)
    days = analytics.daily(session, day, 14)
    open_urg = analytics.open_by_urgency(session)
    open_total = sum(open_urg.values())

    timeline = viz.stacked_columns(
        [
            {"label": d["day"].strftime("%d"), "tip": d["day"].strftime("%a %d %b"),
             **{u: d[u] for u in viz.URGENCY_ORDER}}
            for d in days
        ],
        viz.URGENCY_ORDER, viz.URGENCY_COLORS, height=190,
    )
    turnover_today = session.scalar(select(Turnover).where(Turnover.shift_date == day))

    # Daily-loop checklist: the three things a shift is made of.
    steps = [
        {"label": "Work the queue", "done": not shift_open and bool(alerts),
         "detail": f"{len(alerts) - len(shift_open)}/{len(alerts)} triaged", "href": "soc.queue"},
        {"label": "Study block", "done": bool(study_today) and all(i.id in logged_today for i in study_today),
         "detail": f"{len([i for i in study_today if i.id in logged_today])}/{len(study_today)} done",
         "href": "study.today_tasks"},
        {"label": "Write turnover", "done": turnover_today is not None,
         "detail": "saved" if turnover_today else "not yet", "href": "soc.turnover"},
    ]

    return render_template(
        "dashboard/home.html",
        day=day,
        steps=steps,
        loop_done=sum(1 for s in steps if s["done"]),
        open_total=open_total,
        open_urg=open_urg,
        shift_open=shift_open,
        alerts_total=len(alerts),
        study_today=study_today,
        logged_today=logged_today,
        prev_turnover=previous_turnover(session),
        streak=_streak(session, day),
        m=m,
        spark_acc=viz.sparkline([d["accuracy"] for d in days]),
        spark_mttt=viz.sparkline([d["mttt"] for d in days]),
        spark_study=viz.sparkline([d["study_minutes"] for d in days]),
        due_count=len(analytics.due_items(session, day, cwe_phase, limit=999)),
        timeline=timeline,
        days=days,
        techniques=analytics.techniques(session, day - timedelta(days=6)),
        cwe_phase=cwe_phase,
    )
