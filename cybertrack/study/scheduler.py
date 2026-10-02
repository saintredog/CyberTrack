"""Spaced repetition and daily study selection.

SM-2-lite: after each study session the user rates confidence 1-5.
  - Below 3 resets the item to review tomorrow.
  - 3 and up grows the interval: 1 day, then 3 days, then interval * ease.
Ease drifts with confidence so shaky topics come back sooner.

Daily selection fills a minute budget in this order:
  1. Items already due (most overdue first, then lowest ease).
  2. New items, interleaved across tracks so no single track hogs the day.
CWE items above the current CWE phase stay locked.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ..models import CurriculumItem, ReviewState

TRACK_ORDER = ["cwe", "cysa", "pentest", "wgu"]


def apply_review(state: ReviewState, confidence: int, on: date) -> ReviewState:
    q = max(1, min(5, int(confidence)))
    ease = state.ease if state.ease is not None else 2.5
    reps = state.repetitions or 0
    interval = state.interval_days or 0
    if q < 3:
        reps = 0
        interval = 1
    else:
        reps += 1
        if reps == 1:
            interval = 1
        elif reps == 2:
            interval = 3
        else:
            interval = max(1, round(interval * ease))
    ease = max(1.3, ease + 0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
    state.ease = round(ease, 3)
    state.repetitions = reps
    state.interval_days = interval
    state.last_reviewed = on
    state.last_confidence = q
    state.due_date = on + timedelta(days=interval)
    return state


def is_unlocked(item: CurriculumItem, cwe_phase: int) -> bool:
    return item.track != "cwe" or item.phase is None or item.phase <= cwe_phase


@dataclass
class Pick:
    item: CurriculumItem
    reason: str  # "due" | "new"


def pick_daily(
    items: list[CurriculumItem],
    today: date,
    budget_minutes: int,
    cwe_phase: int,
) -> list[Pick]:
    pool = [i for i in items if i.active and is_unlocked(i, cwe_phase)]

    due = [i for i in pool if i.review is not None and i.review.due_date is not None and i.review.due_date <= today]
    due.sort(key=lambda i: (i.review.due_date, i.review.ease))

    # New items: per-track queues in curriculum order. The current CWE phase
    # comes first in the CWE queue so the commission path always moves.
    queues: dict[str, list[CurriculumItem]] = {}
    for i in sorted(pool, key=lambda i: (i.position, i.id)):
        if i.review is None:
            queues.setdefault(i.track, []).append(i)
    if "cwe" in queues:
        queues["cwe"].sort(key=lambda i: (0 if i.phase == cwe_phase else 1, i.position))

    tracks = [t for t in TRACK_ORDER if t in queues] + sorted(t for t in queues if t not in TRACK_ORDER)
    if tracks:
        start = today.toordinal() % len(tracks)
        tracks = tracks[start:] + tracks[:start]
    interleaved: list[CurriculumItem] = []
    while any(queues.get(t) for t in tracks):
        for t in tracks:
            if queues.get(t):
                interleaved.append(queues[t].pop(0))

    picks: list[Pick] = []
    used = 0
    for reason, candidates in (("due", due), ("new", interleaved)):
        for item in candidates:
            if picks and used + item.minutes > budget_minutes:
                continue
            picks.append(Pick(item, reason))
            used += item.minutes
            if used >= budget_minutes:
                return picks
    return picks
