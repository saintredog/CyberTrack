"""Study blueprint: track dashboard, mark complete, phase + budget settings."""
from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import select

from .. import analytics, viz
from ..db import get_int_setting, get_session, get_setting, set_setting, today
from ..models import CurriculumItem, ReviewState, StudyLog
from ..planner import ensure_today
from .curriculum import TRACK_LABELS
from .scheduler import apply_review, is_unlocked, pick_daily

bp = Blueprint("study", __name__, url_prefix="/study")

CWE_SKILL_HINT = (
    "Drill this with the cwe-interview-prep skill: tell Claude \"quiz me on "
    "this\" for a Socratic session, then log your confidence here."
)


def _items(session):
    return list(session.scalars(select(CurriculumItem).order_by(CurriculumItem.position)))


@bp.route("/")
def dashboard():
    session = get_session()
    ensure_today(session)
    cwe_phase = get_int_setting(session, "cwe_phase")
    day = today()

    items = _items(session)
    plan_ids = set(ensure_today(session).study_item_ids)

    tracks: dict[str, dict] = {}
    for item in items:
        t = tracks.setdefault(item.track, {"label": TRACK_LABELS.get(item.track, item.track), "sections": {}})
        sec = t["sections"].setdefault(item.section, [])
        rev = item.review
        done = rev is not None and rev.repetitions > 0
        total_secs = t.setdefault("_counts", [0, 0])
        total_secs[1] += 1
        total_secs[0] += int(done)
        sec.append(
            {
                "item": item,
                "done": done,
                "due": rev is not None and rev.due_date is not None and rev.due_date <= day,
                "locked": not is_unlocked(item, cwe_phase),
                "confidence": rev.last_confidence if rev else None,
                "today": item.id in plan_ids,
            }
        )
    for key, t in tracks.items():
        c = t.pop("_counts", [0, 0])
        t["done"] = c[0]
        t["total"] = c[1]
        t["ring"] = viz.ring(c[0], c[1])
        t["color"] = viz.TRACK_COLORS.get(key, viz.SERIES[0])
        t["due"] = sum(1 for rows in t["sections"].values() for r in rows if r["due"] and not r["locked"])
        t["locked"] = sum(1 for rows in t["sections"].values() for r in rows if r["locked"])

    order = ["cwe", "cysa", "pentest", "wgu"]
    ordered = [(k, tracks[k]) for k in order if k in tracks] + [
        (k, v) for k, v in tracks.items() if k not in order
    ]
    activity = analytics.study_activity(session)
    week_start = day - timedelta(days=6)
    return render_template(
        "study/dashboard.html",
        tracks=ordered,
        cwe_phase=cwe_phase,
        daily_minutes=get_int_setting(session, "daily_minutes"),
        analyst=get_setting(session, "analyst_name"),
        cwe_hint=CWE_SKILL_HINT,
        heat=viz.heatmap(activity, day, weeks=26),
        sessions_week=sum(v for d, v in activity.items() if d >= week_start),
        due=analytics.due_items(session, day, cwe_phase),
    )


@bp.route("/today")
def today_tasks():
    session = get_session()
    cwe_phase = get_int_setting(session, "cwe_phase")
    plan = ensure_today(session)
    items = {i.id: i for i in _items(session)}
    picks = [items[i] for i in plan.study_item_ids if i in items]
    logged = {
        l.item_id: l for l in session.scalars(select(StudyLog).where(StudyLog.logged_on == today()))
    }
    return render_template(
        "study/today.html",
        picks=picks,
        logged=logged,
        planned_minutes=sum(i.minutes for i in picks),
        cwe_phase=cwe_phase,
        cwe_hint=CWE_SKILL_HINT,
    )


@bp.post("/item/<int:item_id>/log")
def log_item(item_id: int):
    session = get_session()
    item = session.get(CurriculumItem, item_id)
    if item is None:
        abort(404)
    try:
        confidence = int(request.form.get("confidence", "3"))
    except ValueError:
        confidence = 3
    minutes = request.form.get("minutes", "")
    minutes = int(minutes) if minutes.isdigit() else item.minutes
    action = request.form.get("action", "studied")
    notes = request.form.get("notes", "").strip()

    rev = item.review or ReviewState(item_id=item.id)
    if item.review is None:
        session.add(rev)
    apply_review(rev, confidence, today())
    session.add(
        StudyLog(
            item_id=item.id,
            logged_on=today(),
            action=action,
            minutes=minutes,
            confidence=max(1, min(5, confidence)),
            notes=notes,
        )
    )
    session.commit()
    flash(f"Logged: {item.topic}. Next review in {rev.interval_days} day(s).", "ok")
    return redirect(request.form.get("next") or url_for("study.dashboard"))


@bp.post("/settings")
def settings():
    session = get_session()
    phase = request.form.get("cwe_phase")
    minutes = request.form.get("daily_minutes")
    if phase and phase.isdigit() and 1 <= int(phase) <= 4:
        set_setting(session, "cwe_phase", phase)
    if minutes and minutes.isdigit() and int(minutes) >= 10:
        set_setting(session, "daily_minutes", minutes)
    name = (request.form.get("analyst_name") or "").strip()
    if name:
        set_setting(session, "analyst_name", name[:40])
    session.commit()
    flash("Settings updated. Tomorrow's plan uses the new values.", "ok")
    return redirect(request.form.get("next") or url_for("study.dashboard"))
