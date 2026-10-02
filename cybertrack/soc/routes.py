"""SOC blueprint: alert queue, alert detail + triage, and shift turnover."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import select

from .. import SEVERITY_ORDER
from ..db import get_session, today
from ..models import Alert, Turnover
from ..planner import ensure_today, previous_turnover
from .generator import grade, metrics

bp = Blueprint("soc", __name__, url_prefix="/soc")


@bp.route("/")
def queue():
    session = get_session()
    ensure_today(session)
    show = request.args.get("show", "open")
    sort = request.args.get("sort", "severity")

    stmt = select(Alert)
    if show == "open":
        stmt = stmt.where(Alert.status == "new")
    alerts = list(session.scalars(stmt))

    if sort == "time":
        alerts.sort(key=lambda a: a.created_at, reverse=True)
    else:
        alerts.sort(key=lambda a: (a.status != "new", SEVERITY_ORDER.get(a.severity, 9), a.created_at))

    open_total = len(session.execute(select(Alert.id).where(Alert.status == "new")).all())
    return render_template(
        "soc/queue.html",
        alerts=alerts,
        show=show,
        sort=sort,
        open_total=open_total,
        prev_turnover=previous_turnover(session),
    )


@bp.route("/alert/<int:alert_id>")
def alert_detail(alert_id: int):
    session = get_session()
    alert = session.get(Alert, alert_id)
    if alert is None:
        abort(404)
    return render_template("soc/alert.html", alert=alert)


@bp.post("/alert/<int:alert_id>/triage")
def triage(alert_id: int):
    session = get_session()
    alert = session.get(Alert, alert_id)
    if alert is None:
        abort(404)
    if alert.triage is not None:
        flash("That alert was already triaged.", "warn")
        return redirect(url_for("soc.alert_detail", alert_id=alert_id))

    disposition = request.form.get("disposition", "")
    reason = request.form.get("reason", "")
    notes = request.form.get("notes", "")
    try:
        grade(session, alert, disposition, reason, notes, datetime.now(), today())
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("soc.alert_detail", alert_id=alert_id))
    session.commit()
    return redirect(url_for("soc.alert_detail", alert_id=alert_id))


@bp.route("/turnover", methods=["GET", "POST"])
def turnover():
    session = get_session()
    day = today()
    ensure_today(session)
    existing = session.scalar(select(Turnover).where(Turnover.shift_date == day))

    if request.method == "POST":
        summary = request.form.get("summary", "").strip()
        open_items = [line.strip() for line in request.form.get("open_items", "").splitlines() if line.strip()]
        if not summary:
            flash("Write a shift summary before saving turnover.", "error")
        else:
            if existing:
                existing.summary = summary
                existing.open_items = open_items
                existing.written_at = datetime.now()
            else:
                session.add(
                    Turnover(
                        shift_date=day,
                        summary=summary,
                        open_items=open_items,
                        written_at=datetime.now(),
                    )
                )
            session.commit()
            flash("Turnover saved.", "ok")
            return redirect(url_for("soc.turnover"))

    # Suggest open items from alerts escalated today that still need follow-up.
    escalated = list(
        session.scalars(select(Alert).where(Alert.status == "escalated", Alert.shift_date == day))
    )
    return render_template(
        "soc/turnover.html",
        existing=existing,
        prev_turnover=previous_turnover(session),
        escalated=escalated,
    )


@bp.route("/metrics")
def metrics_view():
    session = get_session()
    return render_template("soc/metrics.html", m=metrics(session))
