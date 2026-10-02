"""SOC blueprint: Incident Review, Investigation, Shift Turnover, Analytics."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import select

from .. import SEVERITY_ORDER
from .. import analytics, viz
from ..db import get_session, today
from ..models import Alert, Turnover
from ..planner import ensure_today, previous_turnover
from .fields import extract_fields
from .generator import grade, metrics
from .scenarios import SCENARIO_LABELS
from .search import apply as apply_search

bp = Blueprint("soc", __name__, url_prefix="/soc")

RANGES = {"today": 0, "7d": 6, "30d": 29, "all": None}
RANGE_LABELS = {"today": "Today", "7d": "Last 7 days", "30d": "Last 30 days", "all": "All time"}
STATUSES = ["new", "escalated", "closed"]


def _sorted(alerts, sort):
    if sort == "time":
        return sorted(alerts, key=lambda a: a.created_at, reverse=True)
    return sorted(alerts, key=lambda a: (a.status != "new", SEVERITY_ORDER.get(a.severity, 9), a.created_at))


@bp.route("/")
def queue():
    session = get_session()
    ensure_today(session)
    day = today()
    q = request.args.get("q", "").strip()
    rng = request.args.get("range", "all")
    if rng not in RANGES:
        rng = "all"
    status = request.args.get("status", "new" if not q else "any")
    sort = request.args.get("sort", "urgency")

    alerts = list(session.scalars(select(Alert)))
    if RANGES[rng] is not None:
        start = day - timedelta(days=RANGES[rng])
        alerts = [a for a in alerts if a.shift_date >= start]
    alerts, query = apply_search(alerts, q, day)

    # Facets are counted on the searched set, before the status chip narrows it.
    facet_status = Counter(a.status for a in alerts)
    facet_urgency = Counter(a.severity for a in alerts)
    facet_source = Counter(a.source for a in alerts)

    shown = alerts if status == "any" else [a for a in alerts if a.status == status]
    shown = _sorted(shown, sort)

    return render_template(
        "soc/queue.html",
        alerts=shown,
        matched=len(alerts),
        q=q, rng=rng, status=status, sort=sort,
        ranges=RANGE_LABELS,
        query_errors=query.errors,
        facet_status=facet_status,
        facet_urgency=[(u, facet_urgency.get(u, 0)) for u in viz.URGENCY_ORDER],
        facet_source=facet_source.most_common(),
        prev_turnover=previous_turnover(session),
        labels=SCENARIO_LABELS,
    )


@bp.route("/alert/<int:alert_id>")
def alert_detail(alert_id: int):
    session = get_session()
    alert = session.get(Alert, alert_id)
    if alert is None:
        abort(404)
    if alert.first_viewed_at is None:
        alert.first_viewed_at = datetime.now()
        session.commit()

    open_ids = [a.id for a in _sorted(list(session.scalars(select(Alert).where(Alert.status == "new"))), "urgency")]
    next_id = next((i for i in open_ids if i != alert.id), None)
    related = list(
        session.scalars(
            select(Alert).where(Alert.scenario == alert.scenario, Alert.id != alert.id, Alert.status != "new")
            .order_by(Alert.created_at.desc()).limit(4)
        )
    )
    mttt = None
    if alert.triage and alert.first_viewed_at:
        mttt = max(0.0, (alert.triage.decided_at - alert.first_viewed_at).total_seconds() / 60)
    return render_template(
        "soc/alert.html",
        alert=alert,
        fields=extract_fields(alert.raw_log),
        next_id=next_id,
        open_left=len([i for i in open_ids if i != alert.id]),
        related=related,
        rule_label=SCENARIO_LABELS.get(alert.scenario, alert.scenario),
        mttt=mttt,
    )


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


def _shift_stats(session, day):
    from ..models import Triage

    pairs = session.execute(
        select(Triage, Alert).join(Alert, Triage.alert_id == Alert.id).where(Triage.decided_on == day)
    ).all()
    worked = len(pairs)
    correct = sum(1 for t, _ in pairs if t.correct)
    return {
        "worked": worked,
        "escalated": sum(1 for t, _ in pairs if t.user_disposition == "malicious"),
        "closed": sum(1 for t, _ in pairs if t.user_disposition == "benign"),
        "accuracy": (correct / worked * 100) if worked else None,
        "missed": sum(1 for t, a in pairs if a.true_disposition == "malicious" and t.user_disposition == "benign"),
        "backlog": len(session.execute(select(Alert.id).where(Alert.status == "new")).all()),
        "mttt": analytics._mttt_minutes(pairs),
    }


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
                session.add(Turnover(shift_date=day, summary=summary, open_items=open_items, written_at=datetime.now()))
            session.commit()
            flash("Turnover saved.", "ok")
            return redirect(url_for("soc.turnover"))

    escalated = list(session.scalars(select(Alert).where(Alert.status == "escalated", Alert.shift_date == day)))
    history = list(
        session.scalars(select(Turnover).where(Turnover.shift_date < day).order_by(Turnover.shift_date.desc()).limit(10))
    )
    return render_template(
        "soc/turnover.html",
        existing=existing,
        prev_turnover=previous_turnover(session),
        escalated=escalated,
        stats=_shift_stats(session, day),
        history=history,
    )


@bp.route("/metrics")
def metrics_view():
    session = get_session()
    day = today()
    m = metrics(session)
    days = analytics.daily(session, day, 14)
    acc_chart = viz.line_chart(
        [{"label": d["day"].strftime("%d %b"), "value": d["accuracy"],
          "tip": f"{d['correct']}/{d['triaged']} correct" if d["triaged"] else "no triage"} for d in days],
        reference=80,
    )
    mttt_chart = viz.line_chart(
        [{"label": d["day"].strftime("%d %b"), "value": d["mttt"],
          "tip": f"{d['triaged']} triaged" if d["mttt"] is not None else "no data"} for d in days],
        vmax=None, suffix="m", width=540, height=180,
    )
    rules = analytics.rule_accuracy(session)
    sources = analytics.by_source(session)
    return render_template(
        "soc/metrics.html",
        m=m, days=days, acc_chart=acc_chart, mttt_chart=mttt_chart,
        rules=rules, sources=sources, source_max=max([s["value"] for s in sources] or [1]),
    )
