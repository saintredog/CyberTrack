from datetime import date

from sqlalchemy import select

from cybertrack.db import get_session
from cybertrack.models import Alert, CurriculumItem, Turnover
from cybertrack.planner import ensure_today


def test_curriculum_autoloaded(session):
    count = len(session.execute(select(CurriculumItem.id)).all())
    assert count > 40, "all four tracks should load"
    tracks = {t for (t,) in session.execute(select(CurriculumItem.track).distinct())}
    assert tracks == {"cysa", "pentest", "wgu", "cwe"}


def test_home_renders_on_fresh_db(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Start of shift" in r.data


def test_queue_and_plan_created(client, app):
    r = client.get("/soc/")
    assert r.status_code == 200
    with app.app_context():
        s = get_session()
        plan = ensure_today(s)
        assert len(plan.alert_ids) == 5
        assert plan.study_item_ids


def test_triage_flow_end_to_end(client, app):
    client.get("/soc/")
    with app.app_context():
        s = get_session()
        mal = s.scalar(select(Alert).where(Alert.true_disposition == "malicious"))
        mal_id = mal.id
    r = client.post(f"/soc/alert/{mal_id}/triage", data={"disposition": "malicious", "reason": "test"}, follow_redirects=True)
    assert r.status_code == 200
    assert b"Correct" in r.data
    with app.app_context():
        s = get_session()
        a = s.get(Alert, mal_id)
        assert a.triage is not None and a.triage.correct is True
        assert a.status == "escalated"


def test_triage_requires_reason(client, app):
    client.get("/soc/")
    with app.app_context():
        s = get_session()
        aid = s.scalar(select(Alert.id))
    r = client.post(f"/soc/alert/{aid}/triage", data={"disposition": "benign", "reason": ""}, follow_redirects=True)
    assert b"reason is required" in r.data


def test_study_log_advances_review(client, app):
    client.get("/study/")
    with app.app_context():
        s = get_session()
        item_id = s.scalar(select(CurriculumItem.id).where(CurriculumItem.track == "cysa"))
    client.post(f"/study/item/{item_id}/log", data={"confidence": "5", "action": "studied"}, follow_redirects=True)
    with app.app_context():
        s = get_session()
        item = s.get(CurriculumItem, item_id)
        assert item.review is not None
        assert item.review.interval_days >= 1
        assert item.review.due_date is not None


def test_turnover_saves_and_shows_next_day(client, app):
    client.get("/soc/turnover")
    r = client.post("/soc/turnover", data={"summary": "Quiet shift", "open_items": "Check host WS-1"}, follow_redirects=True)
    assert b"Turnover saved" in r.data
    with app.app_context():
        s = get_session()
        t = s.scalar(select(Turnover))
        assert t.summary == "Quiet shift"
        assert t.open_items == ["Check host WS-1"]


def test_cwe_phase_setting_locks_higher_phases(client, app):
    client.post("/study/settings", data={"cwe_phase": "1", "daily_minutes": "40"}, follow_redirects=True)
    r = client.get("/study/")
    assert b"locked" in r.data.lower()


def test_migration_adds_new_columns_to_old_database(tmp_path):
    import sqlite3

    from cybertrack import create_app

    path = tmp_path / "old.db"
    create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True})
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE alerts DROP COLUMN first_viewed_at")  # simulate the pre-UI schema
    con.commit()
    assert "first_viewed_at" not in [r[1] for r in con.execute("PRAGMA table_info(alerts)")]
    con.close()

    app = create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True, "TODAY": "2026-10-02"})
    con = sqlite3.connect(path)
    assert "first_viewed_at" in [r[1] for r in con.execute("PRAGMA table_info(alerts)")]
    con.close()
    assert app.test_client().get("/").status_code == 200


def test_every_page_renders_and_alert_view_sets_first_viewed(client, app):
    for path in ["/", "/soc/", "/soc/?q=urgency%3Dhigh+earliest%3D-7d&status=any", "/soc/?q=bogus%3Dx",
                 "/soc/turnover", "/soc/metrics", "/study/", "/study/today"]:
        assert client.get(path).status_code == 200, path
    with app.app_context():
        aid = get_session().scalar(select(Alert.id))
    r = client.get(f"/soc/alert/{aid}")
    assert r.status_code == 200 and b"Interesting fields" in r.data
    with app.app_context():
        assert get_session().get(Alert, aid).first_viewed_at is not None
