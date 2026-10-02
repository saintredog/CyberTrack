"""Flask CLI commands: seed the curriculum, build a demo week, reset the DB."""
from __future__ import annotations

from datetime import timedelta

import click
from flask import current_app
from flask.cli import with_appcontext
from sqlalchemy import delete, select

from .db import get_int_setting, get_session, set_setting, today
from .models import (
    Alert,
    CurriculumItem,
    DailyPlan,
    ReviewState,
    StudyLog,
    Triage,
    Turnover,
)


def register(app) -> None:
    app.cli.add_command(seed)
    app.cli.add_command(demo)
    app.cli.add_command(reset)


@click.command("seed")
@with_appcontext
def seed():
    """Load curriculum YAML into the database (no-op if already present)."""
    from .study.curriculum import load_curriculum_if_empty

    session = get_session()
    loaded = load_curriculum_if_empty(session, current_app.config["CURRICULUM_DIR"])
    total = len(session.execute(select(CurriculumItem.id)).all())
    click.echo(f"Curriculum {'loaded' if loaded else 'already present'}: {total} items.")


@click.command("demo")
@click.option("--days", default=5, help="How many past days of activity to fabricate.")
@with_appcontext
def demo(days: int):
    """Generate a few past shifts with sample triage + study so the UI isn't empty."""
    import random

    from .planner import ensure_today
    from .soc.generator import grade
    from .study.scheduler import apply_review

    session = get_session()
    from .study.curriculum import load_curriculum_if_empty

    load_curriculum_if_empty(session, current_app.config["CURRICULUM_DIR"])

    base = today()
    rng = random.Random(42)
    for offset in range(days, 0, -1):
        day = base - timedelta(days=offset)
        plan = ensure_today(session, day)
        alerts = list(session.scalars(select(Alert).where(Alert.id.in_(plan.alert_ids))))
        from datetime import datetime

        for a in alerts:
            if a.triage is not None:
                continue
            # 80% correct, so metrics look like a learner improving.
            correct = rng.random() < 0.8
            disp = a.true_disposition if correct else ("benign" if a.true_disposition == "malicious" else "malicious")
            grade(session, a, disp, "demo triage decision", "", datetime.now(), day)
        # Log a couple of study items per day.
        items = list(session.scalars(select(CurriculumItem).where(CurriculumItem.id.in_(plan.study_item_ids))))
        for item in items[:2]:
            rev = item.review or ReviewState(item_id=item.id)
            if item.review is None:
                session.add(rev)
            apply_review(rev, rng.randint(3, 5), day)
            session.add(StudyLog(item_id=item.id, logged_on=day, action="studied", minutes=item.minutes, confidence=rng.randint(3, 5)))
        if offset > 1:
            session.add(
                Turnover(
                    shift_date=day,
                    summary=f"Quiet shift. Worked {len(alerts)} alerts, escalated the real ones.",
                    open_items=["Follow up on the escalated host in the morning"] if rng.random() < 0.5 else [],
                    written_at=datetime.now(),
                )
            )
    session.commit()
    ensure_today(session, base)
    click.echo(f"Demo data created for the last {days} days. Run the app and open /.")


@click.command("reset")
@click.confirmation_option(prompt="Delete all alerts, triage, turnover, study logs, and plans?")
@with_appcontext
def reset():
    """Wipe activity but keep the curriculum. Use before a fresh start."""
    session = get_session()
    for model in (Triage, Alert, Turnover, StudyLog, ReviewState, DailyPlan):
        session.execute(delete(model))
    session.commit()
    click.echo("Activity cleared. Curriculum kept.")
