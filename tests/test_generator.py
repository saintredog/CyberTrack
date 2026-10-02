from datetime import date, datetime

from cybertrack.soc.generator import generate_shift, grade, metrics
from cybertrack.soc.scenarios import SCENARIOS


def test_every_scenario_produces_gradeable_alert(session):
    import random

    day = date(2026, 10, 2)
    base = datetime(2026, 10, 2)
    for name, fn in SCENARIOS.items():
        for malicious in (True, False):
            spec = fn(random.Random(1), base, malicious)
            assert spec.true_disposition in ("benign", "malicious")
            assert spec.true_disposition == ("malicious" if malicious else "benign")
            assert spec.raw_log.strip()
            assert spec.indicators, f"{name} has no indicators"
            assert spec.explanation.strip()


def test_shift_is_mixed_and_sized(session):
    alerts = generate_shift(session, date(2026, 10, 2), count=6)
    session.commit()
    assert len(alerts) == 6
    dispositions = {a.true_disposition for a in alerts}
    assert dispositions == {"benign", "malicious"}, "a shift should never be all one disposition"


def test_shift_is_deterministic_per_day(session):
    a = generate_shift(session, date(2026, 10, 3), count=5)
    sigs_a = [(x.scenario, x.true_disposition) for x in a]
    session.rollback()
    b = generate_shift(session, date(2026, 10, 3), count=5)
    sigs_b = [(x.scenario, x.true_disposition) for x in b]
    assert sigs_a == sigs_b


def test_grade_marks_correct_and_updates_status(session):
    alerts = generate_shift(session, date(2026, 10, 2), count=4)
    session.commit()
    mal = next(a for a in alerts if a.true_disposition == "malicious")
    ben = next(a for a in alerts if a.true_disposition == "benign")

    t1 = grade(session, mal, "malicious", "clear C2 pattern", "", datetime.now(), date(2026, 10, 2))
    assert t1.correct is True
    assert mal.status == "escalated"

    t2 = grade(session, ben, "malicious", "looked odd", "", datetime.now(), date(2026, 10, 2))
    assert t2.correct is False
    assert ben.status == "escalated"
    session.commit()

    m = metrics(session)
    assert m["total"] == 2
    assert m["tp"] == 1
    assert m["fp"] == 1


def test_grade_requires_reason(session):
    alerts = generate_shift(session, date(2026, 10, 2), count=2)
    session.commit()
    try:
        grade(session, alerts[0], "benign", "   ", "", datetime.now(), date(2026, 10, 2))
        assert False, "expected ValueError"
    except ValueError:
        pass
