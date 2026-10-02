from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import select

from cybertrack.db import set_setting
from cybertrack.models import Alert, Case, CurriculumItem, DailyPlan, StudyLog, Turnover
from cybertrack.planner import ensure_today
from cybertrack.progression import (
    LEVELS,
    TIERS,
    case_xp,
    difficulty_level,
    level_for_tier,
    progression,
    shift_params,
    standing,
    tier_changes,
    tier_for,
    total_xp,
    xp_breakdown,
    xp_events,
)
from cybertrack.soc import cases as ir
from cybertrack.soc.generator import HINT_KEY, _malicious_flags, generate_shift, grade

DAY = date(2026, 10, 2)
NOW = datetime(2026, 10, 2, 9, 0)


# ------------------------------------------------------------------ helpers


def _item_id(session) -> int:
    return session.scalar(select(CurriculumItem.id).order_by(CurriculumItem.id))


def _study_logs(session, n: int, start: date = DAY) -> None:
    """n study logs (5 XP each), one per day going back from `start`."""
    item = _item_id(session)
    session.add_all(
        StudyLog(item_id=item, logged_on=start - timedelta(days=i), action="studied", minutes=20, confidence=4)
        for i in range(n)
    )
    session.commit()


def _alerts(session, count: int = 6) -> tuple[list[Alert], list[Alert]]:
    alerts = generate_shift(session, DAY, count)
    session.commit()
    mal = [a for a in alerts if a.true_disposition == "malicious"]
    ben = [a for a in alerts if a.true_disposition == "benign"]
    return mal, ben


def _close_true_positive(session, alert: Alert, score: int) -> Case:
    grade(session, alert, "malicious", "confirmed", "", NOW, DAY)
    case = ir.open_case(session, alert, NOW, DAY)
    case.report_score = score
    case.report_submitted_at = NOW
    case.stage = "lessons"
    ir.close_case(case, "", NOW + timedelta(hours=2))
    session.commit()
    return case


# ------------------------------------------------------------------ XP math


def test_fresh_database_has_zero_xp(session):
    p = progression(session)
    assert p.xp == 0 and p.events == []
    assert p.tier.name == "Tier 1 Analyst"
    assert xp_breakdown(session) == {"triage": 0, "study": 0, "turnover": 0, "case": 0}


def test_triage_xp_correct_and_incorrect(session):
    mal, ben = _alerts(session, 4)
    grade(session, mal[0], "malicious", "c2 beacon", "", NOW, DAY)       # correct
    grade(session, ben[0], "benign", "approved change", "", NOW, DAY)    # correct
    grade(session, mal[1], "benign", "looked fine", "", NOW, DAY)        # incorrect (missed)
    session.commit()
    assert xp_breakdown(session)["triage"] == 10 + 10 + 2
    labels = sorted(e.label for e in xp_events(session))
    assert labels == ["Correct triage", "Correct triage", "Incorrect triage"]
    assert {e.points for e in xp_events(session) if e.label == "Incorrect triage"} == {2}


def test_study_and_turnover_xp(session):
    _study_logs(session, 3)
    session.add(Turnover(shift_date=DAY, summary="quiet", open_items=[], written_at=NOW))
    session.commit()
    b = xp_breakdown(session)
    assert b["study"] == 15 and b["turnover"] == 5
    assert total_xp(session) == 20
    sources = [e.source for e in xp_events(session)]
    assert sources.count("study") == 3 and sources.count("turnover") == 1


def test_case_xp_true_positive_paid_by_report_score(session):
    mal, _ = _alerts(session)
    case = _close_true_positive(session, mal[0], 87)
    assert case_xp(case) == round(87 / 5) == 17
    # +10 for the correct escalation, +17 for the report.
    assert xp_breakdown(session) == {"triage": 10, "study": 0, "turnover": 0, "case": 17}
    ev = next(e for e in xp_events(session) if e.source == "case")
    assert ev.points == 17 and ev.label == "Closed incident" and "87/100" in ev.detail
    assert ev.on == (NOW + timedelta(hours=2)).date()


@pytest.mark.parametrize("score,xp", [(0, 0), (4, 1), (52, 10), (88, 18), (100, 20)])
def test_case_xp_rounding(score, xp):
    assert case_xp(Case(false_positive=False, report_score=score)) == xp


def test_false_positive_case_earns_five_and_open_cases_earn_nothing(session):
    mal, ben = _alerts(session)
    grade(session, ben[0], "malicious", "looked odd", "", NOW, DAY)  # incorrect, +2
    fp = ir.open_case(session, ben[0], NOW, DAY)
    ir.close_case(fp, "approved admin activity", NOW)
    grade(session, mal[0], "malicious", "confirmed", "", NOW, DAY)   # correct, +10
    ir.open_case(session, mal[0], NOW, DAY)                           # left open: 0
    session.commit()
    assert fp.false_positive and case_xp(fp) == 5
    assert xp_breakdown(session) == {"triage": 12, "study": 0, "turnover": 0, "case": 5}


def test_total_matches_events_and_recent_is_newest_ten(session):
    mal, ben = _alerts(session)
    _close_true_positive(session, mal[0], 72)
    grade(session, ben[0], "benign", "fine", "", NOW, DAY)
    _study_logs(session, 15, start=DAY - timedelta(days=1))
    session.add(Turnover(shift_date=DAY - timedelta(days=3), summary="s", open_items=[], written_at=NOW))
    session.commit()

    everything = xp_events(session)
    assert sum(e.points for e in everything) == total_xp(session) == 10 + 14 + 10 + 75 + 5
    keys = [e.sort_key for e in everything]
    assert keys == sorted(keys, reverse=True), "events come newest first"

    p = progression(session)
    assert len(p.events) == 10
    assert [(e.source, e.points, e.on) for e in p.events] == [(e.source, e.points, e.on) for e in everything[:10]]
    assert p.events[0].on == DAY
    assert all(isinstance(e.on, date) and e.points > 0 for e in p.events)
    assert progression(session, recent=0).events == []


# ------------------------------------------------------------------ tiers


@pytest.mark.parametrize(
    "xp,tier",
    [
        (0, "Tier 1 Analyst"), (599, "Tier 1 Analyst"),
        (600, "Tier 2 Analyst"), (1599, "Tier 2 Analyst"),
        (1600, "Tier 3 Analyst"), (3499, "Tier 3 Analyst"),
        (3500, "SOC Lead"), (50000, "SOC Lead"),
    ],
)
def test_tier_boundaries(xp, tier):
    assert tier_for(xp).name == tier
    assert standing(xp).tier.name == tier


def test_tier_thresholds():
    assert [(t.name, t.min_xp) for t in TIERS] == [
        ("Tier 1 Analyst", 0), ("Tier 2 Analyst", 600), ("Tier 3 Analyst", 1600), ("SOC Lead", 3500),
    ]


def test_standing_progress_fields():
    p = standing(1100)
    assert p.tier.number == 2 and p.next_tier.name == "Tier 3 Analyst"
    assert p.xp_into_tier == 500 and p.xp_to_next == 500
    assert p.progress == pytest.approx(0.5) and p.pct == 50

    start = standing(600)
    assert start.xp_into_tier == 0 and start.xp_to_next == 1000 and start.progress == 0

    almost = standing(599)
    assert almost.xp_to_next == 1 and almost.progress < 1

    top = standing(4000)
    assert top.next_tier is None and top.xp_to_next == 0
    assert top.xp_into_tier == 500 and top.progress == 1.0


# ------------------------------------------------------------------ difficulty


def test_auto_difficulty_follows_tier():
    assert [level_for_tier(t) for t in TIERS] == [1, 2, 3, 3], "SOC Lead counts as level 3"


def test_difficulty_level_auto_and_explicit(session):
    assert difficulty_level(session) == 1  # default is auto, and a fresh analyst is Tier 1
    assert [difficulty_level(session, xp=x) for x in (0, 600, 1600, 3500)] == [1, 2, 3, 3]
    set_setting(session, "difficulty", "3")
    assert difficulty_level(session, xp=0) == 3
    set_setting(session, "difficulty", "1")
    assert difficulty_level(session, xp=5000) == 1
    set_setting(session, "difficulty", "bogus")
    assert difficulty_level(session, xp=700) == 2, "an unknown value falls back to auto"


def test_level_definitions():
    assert (LEVELS[1].alerts, LEVELS[1].malicious_share, LEVELS[1].hints) == (5, 0.5, True)
    assert (LEVELS[2].alerts, LEVELS[2].malicious_share, LEVELS[2].hints) == (7, 0.5, False)
    assert (LEVELS[3].alerts, LEVELS[3].malicious_share, LEVELS[3].hints) == (9, 0.4, False)


def test_tier_changes_describe_the_next_level():
    one_two = tier_changes(LEVELS[1], LEVELS[2])
    assert any("5 to 7" in c for c in one_two) and any("hints" in c.lower() for c in one_two)
    two_three = tier_changes(LEVELS[2], LEVELS[3])
    assert any("7 to 9" in c for c in two_three) and any("40%" in c for c in two_three)
    assert tier_changes(LEVELS[3], LEVELS[3]) == []
    assert not any("alerts" in c for c in tier_changes(LEVELS[1], LEVELS[2], alerts_explicit=True))


# ------------------------------------------------------------------ generate_shift


def test_default_shift_mix_is_unchanged():
    for n in range(1, 20):
        assert _malicious_flags(n, 0.5) == [i % 2 == 0 for i in range(n)]


def test_level_three_shift_is_mixed_noisier_and_hintless(session):
    hinted_somewhere = False
    for offset in range(24):
        day = DAY + timedelta(days=offset)
        alerts = generate_shift(session, day, 9, malicious_share=0.4, hints=False)
        dispositions = [a.true_disposition for a in alerts]
        scenarios = [a.scenario for a in alerts]
        assert len(alerts) == 9
        assert set(dispositions) == {"benign", "malicious"}, "never all one disposition"
        assert dispositions.count("malicious") == 4, "about 40% malicious"
        assert all(HINT_KEY not in a.enrichment for a in alerts)
        session.rollback()

        # Same day with hints on: the coaching entry is there whenever its scenario fires malicious.
        hinted = generate_shift(session, day, 9, malicious_share=0.4, hints=True)
        hinted_somewhere |= any(HINT_KEY in a.enrichment for a in hinted)
        assert [a.scenario for a in hinted] == scenarios, "hints change nothing else"
        assert [a.true_disposition for a in hinted] == dispositions
        session.rollback()
    assert hinted_somewhere, "the test should cover a shift where a hint would have appeared"


def test_small_noisy_shift_still_mixed(session):
    for count in (2, 3):
        alerts = generate_shift(session, DAY, count, malicious_share=0.0)
        assert {a.true_disposition for a in alerts} == {"benign", "malicious"}
        session.rollback()


# ------------------------------------------------------------------ ensure_today


def _plan_alerts(session, day: date = DAY) -> list[Alert]:
    plan = ensure_today(session, day)
    return list(session.scalars(select(Alert).where(Alert.id.in_(plan.alert_ids))))


def test_fresh_plan_is_level_one(session):
    alerts = _plan_alerts(session)
    assert len(alerts) == 5
    plan = session.scalar(select(DailyPlan).where(DailyPlan.plan_date == DAY))
    assert plan.difficulty == 1


@pytest.mark.parametrize("level,count", [("1", 5), ("2", 7), ("3", 9)])
def test_explicit_level_sets_alert_count(session, level, count):
    set_setting(session, "difficulty", level)
    session.commit()
    alerts = _plan_alerts(session)
    assert len(alerts) == count
    assert {a.true_disposition for a in alerts} == {"benign", "malicious"}
    if level != "1":
        assert all(HINT_KEY not in a.enrichment for a in alerts)
    assert session.scalar(select(DailyPlan.difficulty).where(DailyPlan.plan_date == DAY)) == int(level)


def test_auto_level_rises_with_tier(session):
    _study_logs(session, 120, start=DAY - timedelta(days=1))  # 600 XP: Tier 2
    assert progression(session, recent=0).tier.number == 2
    assert len(_plan_alerts(session)) == 7
    _study_logs(session, 200, start=DAY - timedelta(days=200))  # +1000 XP: Tier 3
    assert len(_plan_alerts(session, DAY + timedelta(days=1))) == 9


def test_pinned_level_beats_tier(session):
    _study_logs(session, 320, start=DAY - timedelta(days=1))  # 1600 XP: Tier 3
    set_setting(session, "difficulty", "1")
    session.commit()
    assert len(_plan_alerts(session)) == 5


def test_saved_alerts_per_day_wins_over_level_count(session):
    set_setting(session, "difficulty", "3")
    set_setting(session, "alerts_per_day", "4")
    session.commit()
    params = shift_params(session)
    assert params.alerts == 4 and params.alerts_explicit and params.level.number == 3
    alerts = _plan_alerts(session)
    assert len(alerts) == 4
    assert {a.true_disposition for a in alerts} == {"benign", "malicious"}
    assert all(HINT_KEY not in a.enrichment for a in alerts), "the level still removes hints"


def test_saved_default_value_still_counts_as_explicit(session):
    set_setting(session, "difficulty", "2")
    set_setting(session, "alerts_per_day", "5")
    session.commit()
    assert len(_plan_alerts(session)) == 5


# ------------------------------------------------------------------ UI


def test_settings_form_saves_difficulty(client, app):
    r = client.get("/study/")
    assert b'name="difficulty"' in r.data and b"Auto &middot; follows your tier" in r.data
    client.post("/study/settings", data={"difficulty": "3"})
    with app.app_context():
        from cybertrack.db import get_session

        assert difficulty_level(get_session()) == 3
    client.post("/study/settings", data={"difficulty": "9"})  # ignored
    with app.app_context():
        from cybertrack.db import get_session

        assert difficulty_level(get_session()) == 3
    client.post("/study/settings", data={"difficulty": "auto"})
    with app.app_context():
        from cybertrack.db import get_session

        assert difficulty_level(get_session()) == 1


def test_posture_and_sidebar_show_progression(client, app):
    r = client.get("/")
    assert r.status_code == 200
    html = r.data.decode()
    assert "Analyst progression" in html and 'id="progression"' in html
    assert "Tier 1 analyst" not in html, "the static tier text is gone"
    assert 'class="tier-line"><span>Tier 1 Analyst</span><span class="xp">0 XP</span>' in html
    assert "<b>600</b> to Tier 2 Analyst" in html
    assert "No XP yet" in html

    with app.app_context():
        from cybertrack.db import get_session

        s = get_session()
        _study_logs(s, 130, start=DAY - timedelta(days=1))  # 650 XP
    html = client.get("/").data.decode()
    assert '<span>Tier 2 Analyst</span><span class="xp">650 XP</span>' in html
    assert "Study log" in html and "+5" in html
    # Tier 2 -> 3 on auto: shifts grow and get noisier.
    assert "Shifts grow from 7 to 9 alerts" in html
