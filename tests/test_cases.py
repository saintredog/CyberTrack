import random
import re
import sqlite3
from datetime import datetime

import pytest
from sqlalchemy import select

from cybertrack import create_app
from cybertrack.db import get_session
from cybertrack.models import Alert, Case
from cybertrack.soc import cases as ir
from cybertrack.soc.generator import grade
from cybertrack.soc.scenarios import SCENARIOS

NOW = datetime(2026, 10, 2, 9, 0)


# ------------------------------------------------------------------ helpers


def _escalate(client, app, truth: str) -> tuple[int, int]:
    """Triage the first new alert with the given ground truth as malicious. Returns (alert_id, case_id)."""
    client.get("/soc/")
    with app.app_context():
        aid = get_session().scalar(
            select(Alert.id).where(Alert.true_disposition == truth, Alert.status == "new").order_by(Alert.id)
        )
    client.post(f"/soc/alert/{aid}/triage", data={"disposition": "malicious", "reason": "looks bad"})
    with app.app_context():
        case_id = get_session().scalar(select(Case.id).where(Case.alert_id == aid))
    return aid, case_id


def _alert(name: str, malicious: bool = True, seed: int = 1) -> Alert:
    """A transient (unsaved) alert built straight from a scenario."""
    spec = SCENARIOS[name](random.Random(seed), datetime(2026, 10, 2), malicious)
    return Alert(
        scenario=spec.scenario, raw_log=spec.raw_log, enrichment=spec.enrichment, response=spec.response,
        true_disposition=spec.true_disposition, title=spec.title, severity=spec.severity,
    )


def _strong_report(alert: Alert) -> dict:
    key = ir.evidence_key(alert)
    return {
        "summary": "An external actor gained access and acted on a corporate system. The affected host and "
                   "account were contained the same morning and no further spread was found.",
        "timeline": "02:10 first malicious event in the logs\n02:15 follow-on activity\n02:40 host contained",
        "scope_impact": "One host and one account affected; data on the host may have been exposed to the actor. "
                        "Affected: " + ", ".join(v for _, v in key.assets),
        # Defanged on purpose: 203.0.113[.]7 must count as 203.0.113.7.
        "iocs": "\n".join(v.replace(".", "[.]").replace("@", "[@]") for _, v in key.iocs) or "No external indicators in this event.",
        "root_cause": "A missing preventive control let the actor in, and nothing alerted until this detection fired.",
        "recommendations": "\n".join(alert.response),
    }


# -------------------------------------------------------------- opening


def test_malicious_escalation_opens_case_with_playbook_tasks(client, app):
    aid, case_id = _escalate(client, app, "malicious")
    assert case_id is not None
    with app.app_context():
        s = get_session()
        case = s.get(Case, case_id)
        alert = s.get(Alert, aid)
        assert case.alert_id == aid and alert.case is case
        assert case.status == "open" and case.stage == "detection"
        assert case.false_positive is False
        assert case.title == alert.title and case.severity == alert.severity
        assert case.opened_on.isoformat() == "2026-10-02"
        assert [t.label for t in case.tasks] == alert.response
        assert all(not t.done for t in case.tasks)
        assert case.report_score is None and case.report_feedback == []
    # The nav badge counts it.
    assert b'title="open cases">1<' in client.get("/").data


def test_closing_as_benign_opens_no_case(client, app):
    client.get("/soc/")
    with app.app_context():
        aid = get_session().scalar(select(Alert.id).where(Alert.status == "new"))
    client.post(f"/soc/alert/{aid}/triage", data={"disposition": "benign", "reason": "fine"})
    with app.app_context():
        assert get_session().scalar(select(Case.id)) is None


def test_benign_escalation_is_a_false_positive_case(client, app):
    aid, case_id = _escalate(client, app, "benign")
    with app.app_context():
        case = get_session().get(Case, case_id)
        assert case.false_positive is True
        assert len(case.tasks) == len(case.alert.response)
    page = client.get(f"/soc/case/{case_id}").data
    assert b"False positive" in page and b"Close as false positive" in page
    assert b"Submit for grading" not in page  # no report for a false positive


def test_open_case_is_idempotent_and_backfills_old_escalations(client, app):
    client.get("/soc/")
    with app.app_context():
        s = get_session()
        alert = s.scalar(select(Alert).where(Alert.true_disposition == "malicious"))
        aid = alert.id
        grade(s, alert, "malicious", "escalated before cases existed", "", NOW, NOW.date())  # no case
        s.commit()
        assert alert.case is None
    r = client.post(f"/soc/alert/{aid}/case")
    assert r.status_code == 302 and "/soc/case/" in r.headers["Location"]
    client.post(f"/soc/alert/{aid}/case")
    with app.app_context():
        assert len(get_session().scalars(select(Case)).all()) == 1


# -------------------------------------------------------------- grading


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_strong_report_scores_high_for_every_detection(scenario):
    alert = _alert(scenario)
    score, rows = ir.grade_report(_strong_report(alert), alert)
    assert score >= 90, rows
    assert score == sum(r["earned"] for r in rows)
    assert sum(r["possible"] for r in rows) == 100


def test_empty_and_thin_reports_score_low_with_actionable_tips():
    alert = _alert("auth_bruteforce")
    score, rows = ir.grade_report({}, alert)
    assert score == 0
    assert {"criterion", "earned", "possible", "tip"} <= set(rows[0])
    assert all(r["earned"] == 0 and r["tip"] for r in rows)
    ioc_row = next(r for r in rows if r["criterion"] == "IOC coverage")
    assert "Missing:" in ioc_row["tip"]

    thin, _ = ir.grade_report({"summary": "bad login", "recommendations": "reset password"}, alert)
    assert 0 < thin < 20


def test_rubric_rows_cover_each_criterion():
    alert = _alert("beaconing")
    _, rows = ir.grade_report(_strong_report(alert), alert)
    names = [r["criterion"] for r in rows]
    assert names[:6] == [s.label for s in ir.REPORT_SECTIONS]
    assert names[6:] == ["Time-stamped timeline", "IOC coverage", "Affected assets", "Playbook-aligned recommendations"]


def test_short_section_gets_partial_credit():
    alert = _alert("beaconing")
    report = _strong_report(alert)
    report["root_cause"] = "phish"
    _, rows = ir.grade_report(report, alert)
    row = next(r for r in rows if r["criterion"] == "Root cause")
    assert row["earned"] == ir.SECTION_PARTIAL and "aim for at least" in row["tip"]


def test_generic_key_splits_attacker_iocs_from_affected_assets():
    """An event from an unknown detection: external values are IOCs, internal ones are assets."""
    raw = (
        "2026-10-02T03:10:00Z EDR ProcessCreate host=WS-0142 user=CORP\\dchen image=rundll32.exe\n"
        "2026-10-02T03:10:05Z proxy 10.20.3.4 CONNECT bad-cdn.example:443 to=dchen@corp.example\n"
        "2026-10-02T03:10:09Z FW allow src=10.20.3.4 dst=203.0.113.7 cmdline=C:\\ProgramData\\drop.ps1"
    )
    key = ir.evidence_key(Alert(raw_log=raw, response=[]))
    assert key.iocs == [("ip", "203.0.113.7"), ("domain", "bad-cdn.example"), ("file", "drop.ps1")]
    # Our own domain is not an indicator, and rundll32.exe is a stock binary, not an IOC.
    assert key.assets == [("ip", "10.20.3.4"), ("host", "WS-0142"), ("account", "dchen")]

    # Case-insensitive, defanged forms count, and tokens must match whole.
    found, missing = ir.ioc_coverage("Seen: 203.0.113[.]7, BAD-CDN[.]example and 10.20.3.45", key.assets + key.iocs)
    assert {v for _, v in found} == {"203.0.113.7", "bad-cdn.example"}
    assert {v for _, v in missing} == {"10.20.3.4", "WS-0142", "dchen", "drop.ps1"}

    alert = Alert(raw_log=raw, response=[])
    _, rows = ir.grade_report({"iocs": "203.0.113[.]7 bad-cdn[.]example", "scope_impact": "WS-0142 (10.20.3.4)"}, alert)
    ioc_row = next(r for r in rows if r["criterion"] == "IOC coverage")
    assert ioc_row["earned"] == round(ir.IOC_POINTS * 2 / 3) == 13
    assert "2 of 3" in ioc_row["tip"] and "drop.ps1 (file)" in ioc_row["tip"]
    asset_row = next(r for r in rows if r["criterion"] == "Affected assets")
    assert asset_row["earned"] == round(ir.ASSET_POINTS * 2 / 3) == 7
    assert "dchen (account)" in asset_row["tip"] and "Scope & impact" in asset_row["tip"]


STOCK = {"cmd.exe", "net.exe", "w3wp.exe", "powershell.exe", "winword.exe", "rundll32.exe"}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_every_detection_has_a_grounded_evidence_key(scenario):
    for seed in range(12):
        alert = _alert(scenario, seed=seed)
        key = ir.evidence_key(alert)
        assert key.iocs or key.assets, seed
        assert key.assets, f"{scenario}: a report always names what was hit"
        haystack = (alert.raw_log + str(alert.enrichment)).lower()
        for kind, value in key.iocs + key.assets:
            if (kind, value) != ("file", "a.ps1"):  # a.ps1 is only inside the -enc blob
                assert value.lower() in haystack, (scenario, seed, kind, value)
        assert not {v.lower() for _, v in key.iocs} & STOCK, "stock OS and Office binaries are not IOCs"
        assert not {v for _, v in key.iocs} & {v for _, v in key.assets}


def test_backdoor_account_is_the_admin_account_ioc():
    alert = _alert("new_admin_account")
    name = re.search(r"New Account: (\S+)", alert.raw_log).group(1)
    host = re.search(r"Z (\S+) Security", alert.raw_log).group(1)
    key = ir.evidence_key(alert)
    assert key.iocs == [("account", name)] and key.assets == [("host", host)]

    report = _strong_report(alert)
    report["iocs"] = f"Backdoor local admin account {name} created and added to Administrators"
    score, rows = ir.grade_report(report, alert)
    assert score == 100, rows
    # Naming only the stock process chain is not IOC coverage.
    report["iocs"] = f"cmd.exe net.exe w3wp.exe {host}"
    _, rows = ir.grade_report(report, alert)
    row = next(r for r in rows if r["criterion"] == "IOC coverage")
    assert row["earned"] == 0 and f"{name} (account)" in row["tip"]


def test_powershell_key_has_lure_and_decoded_stage_two_not_binaries():
    alert = _alert("powershell_encoded")
    key = ir.evidence_key(alert)
    kinds = dict((v, k) for k, v in key.iocs)
    docm = re.search(r"Invoice_\d+\.docm", alert.raw_log).group(0)
    assert kinds[docm] == "file" and kinds["a.ps1"] == "file"
    assert sum(k == "ip" for k in kinds.values()) == 1
    assert {k for k, _ in key.assets} == {"host", "account"}


def test_impossible_travel_does_not_flag_the_users_own_sign_in():
    alert = _alert("impossible_travel")
    legit = re.search(r"ip=(\S+) loc=\"Norfolk", alert.raw_log).group(1)
    attacker = re.search(r"ip=(\S+) loc=\"Lagos", alert.raw_log).group(1)
    forward = re.search(r"forwardTo=(\S+)", alert.raw_log).group(1)
    key = ir.evidence_key(alert)
    assert key.iocs == [("ip", attacker), ("email", forward)]
    assert legit not in {v for _, v in key.iocs + key.assets}

    _, rows = ir.grade_report({"iocs": f"{attacker}\n{forward}"}, alert)
    row = next(r for r in rows if r["criterion"] == "IOC coverage")
    assert row["earned"] == ir.IOC_POINTS


def test_internal_hosts_are_assets_not_iocs():
    for name in ("beaconing", "data_exfil", "internal_scan"):
        key = ir.evidence_key(_alert(name))
        internal = [v for k, v in key.assets if k == "ip"]
        assert len(internal) == 1 and internal[0].startswith("10."), name
        assert not [v for k, v in key.iocs if k == "ip"], name
    # The sweep's one-off targets are neither.
    assert ir.evidence_key(_alert("internal_scan")).iocs == []


def test_phishing_key_is_url_sender_and_domain_not_a_url_path():
    alert = _alert("phishing_click")
    domain = re.search(r"<it-support@([\w.-]+)>", alert.raw_log).group(1)
    key = ir.evidence_key(alert)
    assert key.iocs == [("domain", domain), ("email", f"it-support@{domain}"), ("url", f"{domain}/owa/auth/logon.aspx")]
    assert "owaauth.dll" not in {v for _, v in key.iocs + key.assets}
    # The defanged full URL and sender count.
    found, _ = ir.ioc_coverage(f"hxxps://{domain.replace('.', '[.]')}/owa/auth/logon[.]aspx it-support[@]{domain}", key.iocs)
    assert len(found) == 3


def test_timeline_needs_two_time_stamped_entries():
    assert ir.timeline_entries("") == 0
    assert ir.timeline_entries("03:12 failed logons\n03:17 success") == 2
    assert ir.timeline_entries("2026-10-02T03:12:44Z first, then 3:12 again") == 1  # same minute
    assert ir.timeline_entries("ports 445:3389 and version 10.20") == 0
    alert = _alert("auth_bruteforce")
    _, rows = ir.grade_report({"timeline": "03:12 only one entry here"}, alert)
    row = next(r for r in rows if r["criterion"] == "Time-stamped timeline")
    assert row["earned"] == ir.TIMELINE_POINTS // 2


def test_recommendations_match_playbook_by_keywords():
    playbook = ["Isolate the host with EDR", "Block the domain and resolve it", "Hunt for the same DLL hash"]
    covered, uncovered = ir.playbook_coverage("We isolated the host and blocked the domain at the proxy.", playbook)
    assert covered == playbook[:2] and uncovered == playbook[2:]
    covered, _ = ir.playbook_coverage("Look into it.", playbook)
    assert covered == []

    alert = _alert("beaconing")
    _, rows = ir.grade_report({"recommendations": "Isolate the host with EDR right away."}, alert)
    row = next(r for r in rows if r["criterion"] == "Playbook-aligned recommendations")
    assert 0 < row["earned"] < ir.PLAYBOOK_POINTS and "Not yet addressed" in row["tip"]


def test_submit_report_stores_score_and_allows_resubmission(client, app):
    _, case_id = _escalate(client, app, "malicious")
    r = client.post(f"/soc/case/{case_id}/report", data={"summary": "too short"}, follow_redirects=True)
    assert b"Report grade" in r.data and b"Resubmit for grading" in r.data
    with app.app_context():
        case = get_session().get(Case, case_id)
        first = case.report_score
        assert case.report_submitted_at is not None and case.report_feedback
        strong = _strong_report(case.alert)
    client.post(f"/soc/case/{case_id}/report", data=strong)
    with app.app_context():
        case = get_session().get(Case, case_id)
        assert case.report_score >= 90 > first
        assert case.summary == strong["summary"]


# -------------------------------------------------------------- lifecycle


def test_stage_advance_and_back_respect_bounds(client, app):
    _, case_id = _escalate(client, app, "malicious")
    with app.app_context():
        s = get_session()
        case = s.get(Case, case_id)
        assert ir.move_stage(case, -1) is False and case.stage == "detection"
        for expected in ir.STAGES[1:]:
            assert ir.move_stage(case, +1) is True
            assert case.stage == expected
        assert ir.move_stage(case, +1) is False and case.stage == "lessons"
        assert ir.move_stage(case, -1) is True and case.stage == "recovery"
        s.commit()

    for _ in range(3):
        r = client.post(f"/soc/case/{case_id}/stage", data={"dir": "next"}, follow_redirects=True)
    assert b"Already at the last stage" in r.data
    for _ in range(6):
        r = client.post(f"/soc/case/{case_id}/stage", data={"dir": "prev"}, follow_redirects=True)
    assert b"Already at the first stage" in r.data
    with app.app_context():
        assert get_session().get(Case, case_id).stage == "detection"


def test_tasks_toggle_and_notes_are_stamped_with_stage(client, app):
    _, case_id = _escalate(client, app, "malicious")
    with app.app_context():
        task_id = get_session().get(Case, case_id).tasks[0].id
    client.post(f"/soc/case/{case_id}/task/{task_id}")
    client.post(f"/soc/case/{case_id}/stage", data={"dir": "next"})
    client.post(f"/soc/case/{case_id}/note", data={"body": "Host isolated via EDR"})
    r = client.post(f"/soc/case/{case_id}/note", data={"body": "   "}, follow_redirects=True)
    assert b"Write something" in r.data
    with app.app_context():
        case = get_session().get(Case, case_id)
        assert case.tasks[0].done and case.tasks[0].done_at is not None
        assert [(n.stage, n.body) for n in case.notes] == [("containment", "Host isolated via EDR")]
    client.post(f"/soc/case/{case_id}/task/{task_id}")
    with app.app_context():
        task = get_session().get(Case, case_id).tasks[0]
        assert not task.done and task.done_at is None
    assert client.post(f"/soc/case/{case_id}/task/99999").status_code == 404


def test_redirects_keep_flash_messages_in_view(client, app):
    """Flashes render at the top of the page, so a redirect that flashes must not jump to a panel anchor."""
    _, case_id = _escalate(client, app, "malicious")
    _, fp_id = _escalate(client, app, "benign")
    with app.app_context():
        s = get_session()
        task_id, fp_task_id = s.get(Case, case_id).tasks[0].id, s.get(Case, fp_id).tasks[0].id

    def lands(r):
        assert r.status_code == 302
        return r.headers["Location"].split("/soc/case/")[1]

    # Silent successes return to the panel that changed.
    assert lands(client.post(f"/soc/case/{case_id}/note", data={"body": "Host isolated"})) == f"{case_id}#notes"
    assert lands(client.post(f"/soc/case/{case_id}/task/{task_id}")) == f"{case_id}#tasks"
    # Errors and the grading flash land at the top.
    assert lands(client.post(f"/soc/case/{case_id}/note", data={"body": "    "})) == str(case_id)
    assert lands(client.post(f"/soc/case/{case_id}/report", data={"summary": "short"})) == str(case_id)
    client.post(f"/soc/case/{fp_id}/close", data={"note": "Vendor AV beacon"})
    r = client.post(f"/soc/case/{fp_id}/task/{fp_task_id}")
    assert lands(r) == str(fp_id)
    assert b"is closed." in client.get(f"/soc/case/{fp_id}").data


def test_out_of_range_ids_are_404_not_500(client, app):
    _, case_id = _escalate(client, app, "malicious")
    big = 2**63  # one past SQLite's signed 64-bit INTEGER
    for method, path in [
        ("get", f"/soc/case/{big}"), ("post", f"/soc/case/{big}/stage"), ("post", f"/soc/case/{big}/note"),
        ("post", f"/soc/case/{big}/report"), ("post", f"/soc/case/{big}/close"),
        ("post", f"/soc/case/{case_id}/task/{big}"), ("post", f"/soc/alert/{big}/case"),
        ("get", f"/soc/alert/{big}"), ("post", f"/soc/alert/{big}/triage"), ("post", f"/study/item/{big}/log"),
        ("get", "/soc/case/99999999999999999999"), ("get", f"/soc/case/{big - 1}"),
    ]:
        assert getattr(client, method)(path).status_code == 404, path


def test_true_positive_closing_needs_report_and_lessons_stage(client, app):
    _, case_id = _escalate(client, app, "malicious")
    with app.app_context():
        s = get_session()
        case = s.get(Case, case_id)
        assert ir.close_blockers(case) == ["submit the incident report", "advance the case to Lessons learned"]
        with pytest.raises(ValueError, match="submit the incident report"):
            ir.close_case(case, "", NOW)

        ir.submit_report(case, _strong_report(case.alert), NOW)
        with pytest.raises(ValueError, match="Lessons learned"):
            ir.close_case(case, "", NOW)

        while ir.move_stage(case, +1):
            pass
        ir.close_case(case, "Contained and eradicated.", NOW)
        assert case.status == "closed" and case.closed_at == NOW
        assert case.closing_note == "Contained and eradicated."

        # A closed case is read-only.
        for action in (lambda: ir.move_stage(case, -1), lambda: ir.add_note(case, "late", NOW),
                       lambda: ir.toggle_task(case, case.tasks[0], NOW),
                       lambda: ir.submit_report(case, {}, NOW), lambda: ir.close_case(case, "", NOW)):
            with pytest.raises(ValueError):
                action()


def test_closing_route_reports_why_it_cannot_close(client, app):
    _, case_id = _escalate(client, app, "malicious")
    r = client.post(f"/soc/case/{case_id}/close", data={"note": ""}, follow_redirects=True)
    assert b"Can&#39;t close yet" in r.data
    with app.app_context():
        assert get_session().get(Case, case_id).status == "open"


def test_false_positive_closes_with_a_note_and_no_report(client, app):
    _, case_id = _escalate(client, app, "benign")
    r = client.post(f"/soc/case/{case_id}/report", data={"summary": "x" * 200}, follow_redirects=True)
    assert b"no incident report is needed" in r.data
    r = client.post(f"/soc/case/{case_id}/close", data={"note": "  "}, follow_redirects=True)
    assert b"closing note" in r.data
    r = client.post(f"/soc/case/{case_id}/close", data={"note": "Vendor AV beacon; tune the rule."}, follow_redirects=True)
    assert b"closed." in r.data
    with app.app_context():
        case = get_session().get(Case, case_id)
        assert case.status == "closed" and case.report_submitted_at is None
        assert case.stage == "detection"  # FP closure does not walk the lifecycle


# -------------------------------------------------------------- pages


def test_all_case_pages_render(client, app):
    aid, tp_id = _escalate(client, app, "malicious")
    _, fp_id = _escalate(client, app, "benign")
    _, open_id = _escalate(client, app, "malicious")

    for path in ["/soc/cases", "/soc/cases?show=closed", "/soc/cases?show=all", "/soc/cases?show=bogus",
                 f"/soc/case/{tp_id}", f"/soc/case/{fp_id}"]:
        assert client.get(path).status_code == 200, path

    # Graded, then closed true positive; closed false positive.
    with app.app_context():
        strong = _strong_report(get_session().get(Case, tp_id).alert)
    client.post(f"/soc/case/{tp_id}/report", data=strong)
    page = client.get(f"/soc/case/{tp_id}").data
    assert b"Report grade" in page and b"IOC coverage" in page and b"Affected assets" in page and b"Strong" in page
    assert b"Resubmit as often as you like" in page
    assert b"then close the case" in client.get(f"/soc/case/{fp_id}").data
    for _ in range(4):
        client.post(f"/soc/case/{tp_id}/stage", data={"dir": "next"})
    client.post(f"/soc/case/{tp_id}/close", data={"note": "done"})
    client.post(f"/soc/case/{fp_id}/close", data={"note": "benign"})
    for path in [f"/soc/case/{tp_id}", f"/soc/case/{fp_id}", "/soc/cases?show=closed", "/soc/cases?show=all"]:
        r = client.get(path)
        assert r.status_code == 200, path
    # A closed case no longer asks for actions it can't take.
    tp_page = client.get(f"/soc/case/{tp_id}").data
    assert b"Closed" in tp_page and b"Resubmit as often" not in tp_page and b"Final grade" in tp_page
    fp_page = client.get(f"/soc/case/{fp_id}").data
    assert b"then close the case" not in fp_page and b"No incident report was needed" in fp_page
    assert client.get("/soc/case/99999").status_code == 404

    # Integrations: alert disposition, incident review row, posture, turnover, nav badge.
    case_ref = f"IR-{open_id:04d}".encode()
    assert f"/soc/case/{tp_id}".encode() in client.get(f"/soc/alert/{aid}").data
    assert case_ref in client.get("/soc/?status=any").data
    home = client.get("/").data
    assert b"Open cases" in home and case_ref in home
    turnover = client.get("/soc/turnover").data
    assert b"suggested open items" in turnover and case_ref + b" " in turnover and b"data-add-item" in turnover
    # The KPI strip is a responsive class, not an inline 5-column grid that phones can't override.
    assert b'class="kpis k5"' in turnover and b"grid-template-columns" not in turnover
    assert b'title="open cases">1<' in home


def test_user_text_is_escaped_on_case_pages(client, app):
    _, case_id = _escalate(client, app, "malicious")
    payload = "<script>alert(1)</script>"
    client.post(f"/soc/case/{case_id}/note", data={"body": payload})
    client.post(f"/soc/case/{case_id}/report", data={"summary": payload})
    page = client.get(f"/soc/case/{case_id}").data
    assert payload.encode() not in page
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_case_tables_are_added_to_an_older_database(tmp_path):
    path = tmp_path / "old.db"
    create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True})
    con = sqlite3.connect(path)
    for table in ("case_notes", "case_tasks", "cases"):
        con.execute(f"DROP TABLE {table}")  # simulate the pre-cases schema
    con.commit()
    con.close()

    app = create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True, "TODAY": "2026-10-02"})
    con = sqlite3.connect(path)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert {"cases", "case_tasks", "case_notes"} <= tables
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/soc/cases").status_code == 200


def test_closed_on_is_added_to_an_older_cases_table(tmp_path):
    path = tmp_path / "old.db"
    create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True})
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE cases DROP COLUMN closed_on")  # simulate the schema before closed_on
    con.commit()
    con.close()

    create_app({"DATABASE_URL": f"sqlite:///{path}", "TESTING": True})
    con = sqlite3.connect(path)
    cols = {r[1] for r in con.execute("PRAGMA table_info(cases)")}
    con.close()
    assert "closed_on" in cols
