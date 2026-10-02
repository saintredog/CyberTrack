"""Home blueprint: the daily loop surface you land on."""
from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, render_template
from sqlalchemy import select

from ..db import get_int_setting, get_session, today
from ..models import Alert, CurriculumItem, StudyLog, Triage
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

    alerts = list(session.scalars(select(Alert).where(Alert.id.in_(plan.alert_ids)))) if plan.alert_ids else []
    open_alerts = [a for a in alerts if a.status == "new"]

    items = {i.id: i for i in session.scalars(select(CurriculumItem))}
    study_today = [items[i] for i in plan.study_item_ids if i in items]
    logged_today = set(session.scalars(select(StudyLog.item_id).where(StudyLog.logged_on == day)))
    study_remaining = [i for i in study_today if i.id not in logged_today]

    m = metrics(session)
    return render_template(
        "dashboard/home.html",
        day=day,
        open_alerts=open_alerts,
        alerts_total=len(alerts),
        study_today=study_today,
        study_remaining=study_remaining,
        prev_turnover=previous_turnover(session),
        streak=_streak(session, day),
        accuracy=m["accuracy"],
        triaged_total=m["total"],
        fn=m["fn"],
        cwe_phase=get_int_setting(session, "cwe_phase"),
    )
