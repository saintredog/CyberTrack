"""The daily plan: ties a day's generated alerts to its scheduled study items.

A DailyPlan row is created the first time the app is used on a given day, so
the daily loop (alerts + study + turnover) is stable and reviewable.
"""
from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_int_setting, today
from .models import CurriculumItem, DailyPlan, Turnover
from .progression import shift_params
from .soc.generator import generate_shift
from .study.scheduler import pick_daily


def _all_items(session: Session) -> list[CurriculumItem]:
    return list(session.scalars(select(CurriculumItem)))


def ensure_today(session: Session, day: date | None = None) -> DailyPlan:
    day = day or today()
    plan = session.scalar(select(DailyPlan).where(DailyPlan.plan_date == day))
    if plan:
        return plan

    # Difficulty (pinned, or following the analyst's tier) sets the shift's size,
    # its benign/malicious mix, and whether hints ship with the enrichment.
    shift = shift_params(session)
    minutes_per_alert = get_int_setting(session, "minutes_per_alert")
    daily_minutes = get_int_setting(session, "daily_minutes")
    cwe_phase = get_int_setting(session, "cwe_phase")

    alerts = generate_shift(
        session, day, shift.alerts, malicious_share=shift.malicious_share, hints=shift.hints
    )

    study_budget = max(10, daily_minutes - shift.alerts * minutes_per_alert)
    picks = pick_daily(_all_items(session), day, study_budget, cwe_phase)

    plan = DailyPlan(
        plan_date=day,
        alert_ids=[a.id for a in alerts],
        study_item_ids=[p.item.id for p in picks],
        completed=False,
        difficulty=shift.level.number,
    )
    session.add(plan)
    session.commit()
    return plan


def previous_turnover(session: Session, day: date | None = None) -> Turnover | None:
    day = day or today()
    return session.scalar(
        select(Turnover).where(Turnover.shift_date < day).order_by(Turnover.shift_date.desc())
    )
