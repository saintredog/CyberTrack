"""Analyst progression: XP, tiers, and the difficulty level they drive.

XP is computed from history every time it is needed, so there is no XP table
to drift out of sync with the work it rewards:

- triage: +10 for a correct call, +2 for an incorrect one (you still worked it)
- study: +5 per study log
- turnover: +5 per shift turnover written
- cases: a closed true-positive case earns round(report_score / 5), so 0-20 for
  the incident report; a closed false-positive case earns +5 for the closing note

Tiers are XP thresholds. The tier also sets the default difficulty ("auto"),
which shapes each new daily shift: how many alerts, how much benign noise, and
whether the enrichment still carries decoding hints.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time
from heapq import nlargest

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_int_setting, get_setting, is_explicit
from .models import Alert, Case, CurriculumItem, StudyLog, Triage, Turnover

# ---------------------------------------------------------------------- XP

XP_TRIAGE_CORRECT = 10
XP_TRIAGE_INCORRECT = 2
XP_STUDY = 5
XP_TURNOVER = 5
XP_CASE_FALSE_POSITIVE = 5

SOURCES = ("triage", "study", "turnover", "case")
SOURCE_LABELS = {"triage": "Triage", "study": "Study", "turnover": "Turnover", "case": "Cases"}
SOURCE_RULES = {
    "triage": f"+{XP_TRIAGE_CORRECT} correct, +{XP_TRIAGE_INCORRECT} incorrect",
    "study": f"+{XP_STUDY} per study log",
    "turnover": f"+{XP_TURNOVER} per turnover",
    "case": f"report score / 5 per closed incident, +{XP_CASE_FALSE_POSITIVE} per closed false positive",
}


def triage_xp(correct: bool) -> int:
    return XP_TRIAGE_CORRECT if correct else XP_TRIAGE_INCORRECT


def case_xp(case: Case) -> int:
    """XP for a closed case. True positives are paid by report quality (0-20)."""
    if case.false_positive:
        return XP_CASE_FALSE_POSITIVE
    return round((case.report_score or 0) / 5)


@dataclass(frozen=True)
class XPEvent:
    source: str        # triage | study | turnover | case
    points: int
    on: date
    label: str         # "Correct triage", "Study log", ...
    detail: str = ""   # alert title, topic, case ref
    at: datetime | None = None
    ref: int = 0       # row id, a stable tie-breaker

    @property
    def sort_key(self) -> tuple:
        return (self.on, self.at or datetime.combine(self.on, time.min), SOURCES.index(self.source), self.ref)


def xp_breakdown(session: Session) -> dict[str, int]:
    """XP per source over all history, computed with aggregates (cheap enough for every page)."""
    correct = session.scalar(select(func.count()).select_from(Triage).where(Triage.correct.is_(True))) or 0
    incorrect = session.scalar(select(func.count()).select_from(Triage).where(Triage.correct.is_(False))) or 0
    studies = session.scalar(select(func.count()).select_from(StudyLog)) or 0
    turnovers = session.scalar(select(func.count()).select_from(Turnover)) or 0
    closed = session.execute(
        select(Case.false_positive, Case.report_score).where(Case.status == "closed")
    ).all()
    case_points = sum(
        XP_CASE_FALSE_POSITIVE if fp else round((score or 0) / 5) for fp, score in closed
    )
    return {
        "triage": correct * XP_TRIAGE_CORRECT + incorrect * XP_TRIAGE_INCORRECT,
        "study": studies * XP_STUDY,
        "turnover": turnovers * XP_TURNOVER,
        "case": case_points,
    }


def total_xp(session: Session) -> int:
    return sum(xp_breakdown(session).values())


def xp_events(session: Session, limit: int | None = None) -> list[XPEvent]:
    """Every XP-earning event, newest first. With `limit`, only the newest `limit`."""

    def take(stmt):
        return stmt.limit(limit) if limit is not None else stmt

    events: list[XPEvent] = []

    rows = session.execute(take(
        select(Triage, Alert.title).join(Alert, Triage.alert_id == Alert.id)
        .order_by(Triage.decided_on.desc(), Triage.decided_at.desc(), Triage.id.desc())
    )).all()
    for t, title in rows:
        events.append(XPEvent(
            "triage", triage_xp(t.correct), t.decided_on,
            "Correct triage" if t.correct else "Incorrect triage", title, t.decided_at, t.id,
        ))

    rows = session.execute(take(
        select(StudyLog, CurriculumItem.topic).join(CurriculumItem, StudyLog.item_id == CurriculumItem.id)
        .order_by(StudyLog.logged_on.desc(), StudyLog.id.desc())
    )).all()
    for log, topic in rows:
        events.append(XPEvent("study", XP_STUDY, log.logged_on, "Study log", topic, None, log.id))

    for tv in session.scalars(take(select(Turnover).order_by(Turnover.shift_date.desc(), Turnover.id.desc()))):
        events.append(XPEvent(
            "turnover", XP_TURNOVER, tv.shift_date, "Shift turnover",
            f"Handoff for {tv.shift_date.strftime('%a %d %b')}", tv.written_at, tv.id,
        ))

    for c in session.scalars(take(
        select(Case).where(Case.status == "closed", Case.closed_at.is_not(None))
        .order_by(Case.closed_at.desc(), Case.id.desc())
    )):
        if c.false_positive:
            label, detail = "Closed false positive", f"{c.ref} {c.title}"
        else:
            label, detail = "Closed incident", f"{c.ref} {c.title} · report {c.report_score or 0}/100"
        events.append(XPEvent("case", case_xp(c), c.closed_at.date(), label, detail, c.closed_at, c.id))

    if limit is None:
        return sorted(events, key=lambda e: e.sort_key, reverse=True)
    return nlargest(limit, events, key=lambda e: e.sort_key)


# -------------------------------------------------------------------- tiers


@dataclass(frozen=True)
class Tier:
    number: int
    name: str
    min_xp: int


TIERS = (
    Tier(1, "Tier 1 Analyst", 0),
    Tier(2, "Tier 2 Analyst", 600),
    Tier(3, "Tier 3 Analyst", 1600),
    Tier(4, "SOC Lead", 3500),
)


def tier_for(xp: int) -> Tier:
    current = TIERS[0]
    for t in TIERS:
        if xp >= t.min_xp:
            current = t
    return current


def next_tier(tier: Tier) -> Tier | None:
    return TIERS[tier.number] if tier.number < len(TIERS) else None


# --------------------------------------------------------------- difficulty


@dataclass(frozen=True)
class Level:
    number: int
    name: str
    alerts: int             # alerts per shift
    malicious_share: float  # share of the shift that is truly malicious
    hints: bool             # keep the "Hint" enrichment entry

    @property
    def effects(self) -> list[str]:
        return [
            f"{self.alerts} alerts per shift",
            f"About {round(self.malicious_share * 100)}% malicious"
            + (", more benign noise" if self.malicious_share < 0.5 else ""),
            "Decoding hints shown" if self.hints else "No decoding hints",
        ]

    @property
    def summary(self) -> str:
        """One sentence, e.g. "9 alerts per shift, about 40% malicious, more benign noise, no decoding hints."."""
        first, *rest = self.effects
        return ", ".join([first] + [e[0].lower() + e[1:] for e in rest]) + "."


LEVELS = {
    1: Level(1, "Guided", 5, 0.5, True),
    2: Level(2, "Standard", 7, 0.5, False),
    3: Level(3, "Realistic", 9, 0.4, False),
}
DIFFICULTY_CHOICES = ("auto", "1", "2", "3")


def level_for_tier(tier: Tier) -> int:
    """Auto difficulty follows the tier. SOC Lead counts as 3, the top level."""
    return min(tier.number, max(LEVELS))


def difficulty_setting(session: Session) -> str:
    raw = (get_setting(session, "difficulty") or "auto").strip().lower()
    return raw if raw in DIFFICULTY_CHOICES else "auto"


def difficulty_level(session: Session, xp: int | None = None) -> int:
    """The level a new shift is built at: the explicit setting, or the tier's level on auto."""
    setting = difficulty_setting(session)
    if setting != "auto":
        return int(setting)
    return level_for_tier(tier_for(total_xp(session) if xp is None else xp))


@dataclass(frozen=True)
class ShiftParams:
    level: Level
    alerts: int
    malicious_share: float
    hints: bool
    alerts_explicit: bool  # alerts_per_day was saved by the user and overrides the level


def shift_params(session: Session) -> ShiftParams:
    """What generate_shift should build today. An explicitly saved alerts_per_day wins on count."""
    level = LEVELS[difficulty_level(session)]
    explicit = is_explicit(session, "alerts_per_day")
    alerts = max(1, get_int_setting(session, "alerts_per_day")) if explicit else level.alerts
    return ShiftParams(level, alerts, level.malicious_share, level.hints, explicit)


def tier_changes(current: Level, upcoming: Level, alerts_explicit: bool = False) -> list[str]:
    """Plain-language list of what moving from one level to another changes."""
    out: list[str] = []
    if upcoming.alerts != current.alerts and not alerts_explicit:
        out.append(f"Shifts grow from {current.alerts} to {upcoming.alerts} alerts")
    if upcoming.malicious_share != current.malicious_share:
        out.append(
            f"Malicious share drops from about {round(current.malicious_share * 100)}% "
            f"to {round(upcoming.malicious_share * 100)}%: more benign noise to clear"
        )
    if current.hints and not upcoming.hints:
        out.append("Decoding hints are removed from alert enrichment")
    return out


# --------------------------------------------------------------- standing


@dataclass
class Progression:
    xp: int
    tier: Tier
    next_tier: Tier | None
    xp_into_tier: int
    xp_to_next: int          # 0 at the top tier
    progress: float          # 0.0-1.0 through the current tier (1.0 at the top)
    breakdown: dict[str, int] = field(default_factory=dict)
    events: list[XPEvent] = field(default_factory=list)

    @property
    def pct(self) -> int:
        return int(self.progress * 100)

    @property
    def tier_span(self) -> int:
        return self.next_tier.min_xp - self.tier.min_xp if self.next_tier else 0


def standing(xp: int) -> Progression:
    """Tier math for an XP total (pure; no database)."""
    tier = tier_for(xp)
    nxt = next_tier(tier)
    into = xp - tier.min_xp
    if nxt is None:
        return Progression(xp, tier, None, into, 0, 1.0)
    span = nxt.min_xp - tier.min_xp
    return Progression(xp, tier, nxt, into, nxt.min_xp - xp, min(1.0, into / span))


def progression(session: Session, recent: int = 10) -> Progression:
    """Current tier, XP, and progress, plus the last `recent` XP events (0 skips them)."""
    breakdown = xp_breakdown(session)
    p = standing(sum(breakdown.values()))
    p.breakdown = breakdown
    if recent:
        p.events = xp_events(session, limit=recent)
    return p
