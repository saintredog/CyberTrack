"""Field extraction and syntax highlighting for raw events.

`extract_fields` is the "Interesting fields" sidebar from Splunk's event view:
it pulls IPs, hosts, users, processes, domains, ports, event codes, and
generic key=value pairs out of a raw log so the analyst can pivot on them.

`highlight` returns safe HTML. It escapes the raw text FIRST, then wraps
recognized tokens in spans in a single regex pass, so nothing in a log can
inject markup.
"""
from __future__ import annotations

import re
from collections import Counter, OrderedDict

from markupsafe import Markup, escape

IP = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
HOST = r"\b(?:WS-\d{3,4}|srv-[a-z]+-\d{2}|vulnscan-\d{2})\b"
DOMAIN = r"\b[a-z0-9][a-z0-9.-]*\.example\b"
PROC = r"\b[\w.-]+\.(?:exe|dll|ps1|docm|7z)\b"  # highlight both processes and files
EXE = r"\b[\w.-]+\.(?:exe|dll)\b"
FILE = r"\b[\w.-]+\.(?:ps1|docm|7z)\b"
ISO_TS = r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z?\b"
SYSLOG_TS = r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}"
EPOCH_TS = r"^\d{9,11}\.\d+"
TECH = r"\bT\d{4}(?:\.\d{3})?\b"

_USER_PATTERNS = [
    re.compile(r"\buser=(?:CORP\\)?([\w.@-]+)", re.I),
    re.compile(r"\bCORP\\([\w.-]+)"),
    re.compile(r"\bfor (?:invalid user )?([\w.-]+) from\b"),
    re.compile(r"\bto=([\w.-]+)@"),
]
_KV = re.compile(r"\b([a-z_][\w.]*)=(\"[^\"]*\"|[^\s]+)")
# A port follows "port ", or a colon right after an IP or domain. Never a timestamp's ":SS".
_PORT = re.compile(r"\bport (\d{2,5})\b|\b(?:\d{1,3}\.){3}\d{1,3}:(\d{2,5})\b|\.example:(\d{2,5})\b")
_EVENT = re.compile(r"\bSecurity (\d{4})\b")

# Keys already covered by a dedicated field, or too noisy to be interesting.
_KV_SKIP = {"user", "to", "from", "host", "image", "cmdline", "parent", "proc"}


def extract_fields(raw: str) -> "OrderedDict[str, Counter]":
    fields: "OrderedDict[str, Counter]" = OrderedDict()

    def add(name: str, values):
        vals = [v for v in values if v]
        if vals:
            fields.setdefault(name, Counter()).update(vals)

    add("ip", re.findall(IP, raw))
    add("host", re.findall(HOST, raw))
    users = []
    for pat in _USER_PATTERNS:
        users += pat.findall(raw)
    add("user", users)
    add("process", re.findall(EXE, raw, re.I))
    add("file", re.findall(FILE, raw, re.I))
    add("domain", re.findall(DOMAIN, raw))
    add("port", ["".join(groups) for groups in _PORT.findall(raw)])
    add("event_code", _EVENT.findall(raw))
    for key, val in _KV.findall(raw):
        if key.lower() in _KV_SKIP or key.startswith("id."):
            continue
        add(key.lower(), [val.strip('"')])
    return fields


_TOKEN = re.compile(
    "|".join(
        [
            rf"(?P<ts>{ISO_TS})",
            rf"(?P<sts>{SYSLOG_TS})",
            rf"(?P<ets>{EPOCH_TS})",
            rf"(?P<ip>{IP})",
            rf"(?P<domain>{DOMAIN})",
            rf"(?P<host>{HOST})",
            rf"(?P<proc>{PROC})",
            rf"(?P<tech>{TECH})",
            r"(?P<key>\b[a-z_][\w.]*)(?==)",
            r"(?P<bad>\b(?:Failed|fail|REJ|deny|invalid|not_required\(legacy_auth\))\b)",
            r"(?P<good>\b(?:Accepted|success|pass|allow|satisfied)\b)",
            r"(?P<flag>(?<=\s)-(?:enc|nop|w hidden|ExecutionPolicy|EncodedCommand)\b)",
        ]
    ),
    re.M | re.I,
)

_CLASS = {
    "ts": "t-ts", "sts": "t-ts", "ets": "t-ts",
    "ip": "t-ip", "domain": "t-dom", "host": "t-host", "proc": "t-proc",
    "tech": "t-tech", "key": "t-key", "bad": "t-bad", "good": "t-good", "flag": "t-flag",
}


def highlight(raw: str) -> Markup:
    escaped = str(escape(raw))

    def repl(m: re.Match) -> str:
        kind = m.lastgroup
        return f'<span class="{_CLASS[kind]}">{m.group(0)}</span>'

    # Entities like &#34; contain no characters our token patterns can latch
    # onto in a way that would split them (no dotted quads, no '=').
    return Markup(_TOKEN.sub(repl, escaped))
