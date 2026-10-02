from datetime import date, timedelta

from cybertrack.models import CurriculumItem, ReviewState
from cybertrack.study.scheduler import apply_review, is_unlocked, pick_daily


def _item(id, track, minutes=20, phase=None, pos=0, review=None):
    it = CurriculumItem(
        id=id, key=f"{track}.{id}", track=track, section="s", topic=f"t{id}",
        minutes=minutes, phase=phase, position=pos, active=True,
    )
    it.review = review
    return it


def test_apply_review_grows_and_resets():
    rev = ReviewState(item_id=1)
    apply_review(rev, 5, date(2026, 10, 2))
    assert rev.interval_days == 1 and rev.repetitions == 1
    apply_review(rev, 5, date(2026, 10, 3))
    assert rev.interval_days == 3 and rev.repetitions == 2
    apply_review(rev, 4, date(2026, 10, 6))
    assert rev.interval_days > 3 and rev.repetitions == 3
    # A low score resets the ladder.
    apply_review(rev, 1, date(2026, 10, 20))
    assert rev.interval_days == 1 and rev.repetitions == 0
    assert rev.due_date == date(2026, 10, 21)


def test_cwe_phase_gating():
    locked = _item(1, "cwe", phase=3)
    unlocked = _item(2, "cwe", phase=1)
    assert is_unlocked(unlocked, 1)
    assert not is_unlocked(locked, 1)
    assert is_unlocked(locked, 3)


def test_pick_respects_budget_and_due_first():
    today = date(2026, 10, 2)
    overdue_rev = ReviewState(item_id=10, due_date=today - timedelta(days=2), interval_days=1, repetitions=1)
    due = _item(10, "cysa", minutes=15, review=overdue_rev, pos=5)
    news = [_item(i, "pentest", minutes=20, pos=i) for i in range(1, 6)]
    picks = pick_daily([due] + news, today, budget_minutes=40, cwe_phase=1)

    assert picks[0].item.id == 10 and picks[0].reason == "due"
    total = sum(p.item.minutes for p in picks)
    # First pick always allowed; subsequent picks must fit the budget.
    assert total <= 40 + news[0].minutes


def test_pick_interleaves_tracks():
    today = date(2026, 10, 2)
    items = []
    for t in ("cwe", "cysa", "pentest"):
        for i in range(3):
            items.append(_item(hash((t, i)) % 100000, t, minutes=10, phase=1 if t == "cwe" else None, pos=i))
    picks = pick_daily(items, today, budget_minutes=1000, cwe_phase=1)
    tracks = [p.item.track for p in picks[:3]]
    assert len(set(tracks)) > 1, "early picks should span multiple tracks"


def test_locked_cwe_items_not_scheduled():
    today = date(2026, 10, 2)
    items = [_item(1, "cwe", phase=4, pos=0)]
    picks = pick_daily(items, today, budget_minutes=100, cwe_phase=1)
    assert picks == []
