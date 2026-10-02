from datetime import date, datetime

from cybertrack.models import Alert, Triage
from cybertrack.soc.search import apply, parse

TODAY = date(2026, 10, 2)


def _alert(id, sev="high", source="edr", status="new", scenario="beaconing", technique="T1071.001",
           title="Periodic outbound connections", raw="proc=rundll32.exe dst=cdn.example", day=TODAY, triage=None):
    a = Alert(id=id, shift_date=day, created_at=datetime(2026, 10, 2, 9), scenario=scenario, source=source,
              severity=sev, title=title, technique=technique, raw_log=raw, enrichment={"Host": "WS-0142"},
              true_disposition="malicious", indicators=[], explanation="", response=[], status=status)
    a.triage = triage
    return a


def test_parse_fields_text_and_ignored():
    q = parse('index=notable urgency=high source!=proxy "rundll32" beacon earliest=-7d')
    assert ("severity", "high", False) in q.terms
    assert ("source", "proxy", True) in q.terms
    assert q.text == ["rundll32", "beacon"]
    assert q.earliest_days == 7
    assert q.errors == []


def test_unknown_field_reports_error():
    q = parse("colour=red")
    assert q.errors and "colour" in q.errors[0]


def test_filters_and_wildcards():
    alerts = [
        _alert(1, sev="high", source="edr", technique="T1059.001"),
        _alert(2, sev="low", source="proxy", technique="T1071.001"),
        _alert(3, sev="critical", source="firewall", technique="T1567.002", raw="rclone.exe"),
    ]
    assert [a.id for a in apply(alerts, "urgency=high", TODAY)[0]] == [1]
    assert [a.id for a in apply(alerts, "technique=T10*", TODAY)[0]] == [1, 2]
    assert [a.id for a in apply(alerts, "source!=proxy rclone", TODAY)[0]] == [3]
    assert [a.id for a in apply(alerts, "ws-0142", TODAY)[0]] == [1, 2, 3]  # enrichment is searchable


def test_earliest_and_verdict():
    old = _alert(1, day=date(2026, 9, 1))
    t = Triage(user_disposition="malicious", reason="x", decided_at=datetime.now(), decided_on=TODAY, correct=False)
    new = _alert(2, triage=t, status="escalated")
    assert [a.id for a in apply([old, new], "earliest=-7d", TODAY)[0]] == [2]
    assert [a.id for a in apply([old, new], "verdict=wrong", TODAY)[0]] == [2]
    assert apply([old, new], "verdict=correct", TODAY)[0] == []


def test_answer_key_is_not_searchable():
    # 'disposition' is not a known field, so it can't be used to peek at ground truth.
    q = parse("disposition=malicious")
    assert q.terms == [] and q.errors
