"""SOC blueprint: Incident Review, Investigation, Cases, Shift Turnover, Analytics."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import select

from .. import SEVERITY_ORDER
from .. import analytics, viz
from ..db import get_session, today
from ..models import Alert, Case, CaseTask, Turnover
from ..planner import ensure_today, previous_turnover
from . import cases as ir
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
        # One query instead of a lazy load per row.
        case_refs={aid: (cid, ir.ref(cid)) for aid, cid in session.execute(select(Case.alert_id, Case.id))},
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
    now = datetime.now()
    try:
        grade(session, alert, disposition, reason, notes, now, today())
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("soc.alert_detail", alert_id=alert_id))
    if disposition == "malicious":
        case = ir.open_case(session, alert, now, today())
        flash(f"Escalated. {case.ref} opened for incident response.", "ok")
    session.commit()
    return redirect(url_for("soc.alert_detail", alert_id=alert_id))


@bp.post("/alert/<int:alert_id>/case")
def open_alert_case(alert_id: int):
    """Open a case for an alert escalated before case management existed (or by the demo seeder)."""
    session = get_session()
    alert = session.get(Alert, alert_id)
    if alert is None:
        abort(404)
    if alert.status != "escalated":
        flash("Only escalated alerts open an incident case.", "warn")
        return redirect(url_for("soc.alert_detail", alert_id=alert_id))
    case = ir.open_case(session, alert, datetime.now(), today())
    session.commit()
    return redirect(url_for("soc.case_detail", case_id=case.id))


# --------------------------------------------------------------------- cases

CASE_FILTERS = {"open": "Open", "closed": "Closed", "all": "All"}


@bp.route("/cases")
def cases():
    session = get_session()
    show = request.args.get("show", "open")
    if show not in CASE_FILTERS:
        show = "open"
    every = list(session.scalars(select(Case)))
    open_ = sorted((c for c in every if c.status == "open"), key=lambda c: (SEVERITY_ORDER.get(c.severity, 9), c.opened_at))
    closed = sorted((c for c in every if c.status == "closed"), key=lambda c: c.closed_at or c.opened_at, reverse=True)
    shown = {"open": open_, "closed": closed, "all": open_ + closed}[show]
    scores = [c.report_score for c in every if c.report_score is not None]
    return render_template(
        "soc/cases.html",
        cases=shown,
        show=show,
        filters=CASE_FILTERS,
        counts={"open": len(open_), "closed": len(closed), "all": len(every)},
        kpi={
            "open": len(open_),
            "critical": sum(1 for c in open_ if c.severity in ("critical", "high")),
            "awaiting": sum(1 for c in open_ if not c.false_positive and c.report_submitted_at is None),
            "avg_score": round(sum(scores) / len(scores)) if scores else None,
            "graded": len(scores),
            "closed": len(closed),
            "fp": sum(1 for c in every if c.false_positive),
        },
        now=datetime.now(),
    )


def _case_or_404(case_id: int) -> Case:
    case = get_session().get(Case, case_id)
    if case is None:
        abort(404)
    return case


def _back(case: Case, anchor: str | None = None):
    return redirect(url_for("soc.case_detail", case_id=case.id, _anchor=anchor))


@bp.route("/case/<int:case_id>")
def case_detail(case_id: int):
    case = _case_or_404(case_id)
    return render_template(
        "soc/case.html",
        case=case,
        alert=case.alert,
        stage_i=case.stage_index,
        guidance=ir.STAGE_GUIDANCE,
        sections=ir.REPORT_SECTIONS,
        band=ir.score_band(case.report_score),
        score_ring=viz.ring(case.report_score or 0, 100, r=34, stroke=8),
        blockers=ir.close_blockers(case),
        rule_label=SCENARIO_LABELS.get(case.alert.scenario, case.alert.scenario),
        now=datetime.now(),
    )


@bp.post("/case/<int:case_id>/stage")
def case_stage(case_id: int):
    session = get_session()
    case = _case_or_404(case_id)
    forward = request.form.get("dir") == "next"
    try:
        moved = ir.move_stage(case, 1 if forward else -1)
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(case)
    if moved:
        session.commit()
    else:
        flash("Already at the last stage." if forward else "Already at the first stage.", "warn")
    return _back(case)


@bp.post("/case/<int:case_id>/task/<int:task_id>")
def case_task(case_id: int, task_id: int):
    session = get_session()
    case = _case_or_404(case_id)
    task = session.get(CaseTask, task_id)
    if task is None or task.case_id != case.id:
        abort(404)
    try:
        ir.toggle_task(case, task, datetime.now())
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(case, "tasks")
    session.commit()
    return _back(case, "tasks")


@bp.post("/case/<int:case_id>/note")
def case_note(case_id: int):
    session = get_session()
    case = _case_or_404(case_id)
    try:
        ir.add_note(case, request.form.get("body", ""), datetime.now())
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(case, "notes")
    session.commit()
    return _back(case, "notes")


@bp.post("/case/<int:case_id>/report")
def case_report(case_id: int):
    session = get_session()
    case = _case_or_404(case_id)
    try:
        score = ir.submit_report(case, request.form, datetime.now())
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(case)
    session.commit()
    flash(f"Report graded: {score}/100. The rubric shows where every point came from.", "ok")
    return _back(case, "grade")


@bp.post("/case/<int:case_id>/close")
def case_close(case_id: int):
    session = get_session()
    case = _case_or_404(case_id)
    try:
        ir.close_case(case, request.form.get("note", ""), datetime.now())
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(case)
    session.commit()
    flash(f"{case.ref} closed.", "ok")
    return _back(case)


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
        case_items=[(c, ir.turnover_line(c)) for c in ir.open_cases(session)],
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
