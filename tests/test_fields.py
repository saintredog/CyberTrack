import random
from datetime import datetime

from cybertrack.soc.fields import extract_fields, highlight
from cybertrack.soc.scenarios import SCENARIOS


def test_extracts_core_fields():
    raw = (
        "2026-10-02T09:01:02Z EDR ProcessCreate host=WS-0142 user=CORP\\jsmith\n"
        "  cmdline: powershell.exe -nop -w hidden -enc AAAA\n"
        "2026-10-02T09:01:04Z EDR NetworkConnect host=WS-0142 image=powershell.exe dst=203.0.113.9:80"
    )
    f = extract_fields(raw)
    assert "203.0.113.9" in f["ip"]
    assert f["host"]["WS-0142"] == 2
    assert "jsmith" in f["user"]
    assert "powershell.exe" in f["process"]
    assert "80" in f["port"]


def test_url_path_is_not_a_process():
    raw = (
        "[proxy] 2026-10-02T09:04:00Z WS-0523 POST https://login-portal.example/owa/auth/owaauth.dll 302\n"
        "2026-10-02T09:05:00Z EDR ProcessCreate image=C:\\Windows\\System32\\rundll32.exe proc=AVAgent.exe"
    )
    assert set(extract_fields(raw)["process"]) == {"rundll32.exe", "AVAgent.exe"}


def test_every_scenario_extracts_something():
    base = datetime(2026, 10, 2)
    for name, fn in SCENARIOS.items():
        for mal in (True, False):
            spec = fn(random.Random(3), base, mal)
            assert extract_fields(spec.raw_log), f"{name} produced no fields"


def test_highlight_escapes_markup():
    out = str(highlight('<script>alert(1)</script> user="x" src=10.0.0.1 "quoted"'))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert '<span class="t-ip">10.0.0.1</span>' in out
    assert '<span class="t-key">user</span>' in out


def test_highlight_preserves_text():
    import re

    raw = "Oct 02 02:13:44 srv-jump-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2"
    html = str(highlight(raw))
    stripped = re.sub(r"<[^>]+>", "", html)
    assert stripped == raw


def test_ports_ignore_timestamp_seconds():
    raw = (
        "2026-10-02 02:28:01 10.20.2.152 CONNECT cdn.example:443 200\n"
        "Oct 02 02:13:44 srv-jump-01 sshd[1]: Failed password for root from 203.0.113.4 port 51234 ssh2\n"
        "dst=198.51.100.7:80"
    )
    ports = set(extract_fields(raw)["port"])
    assert ports == {"443", "51234", "80"}
