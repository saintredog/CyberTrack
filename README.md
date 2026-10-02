# CyberTrack

A local, single-user cybersecurity practice portal. You log in each day and work it
like a real cybersecurity job: pull up alerts, triage them, write shift turnover, and
keep a long-running study plan moving across CySA+, pen testing, your WGU coursework,
and the Cyber Warfare Engineer path.

Everything is synthetic and runs offline. No real networks, no live threat feeds, no
third-party accounts. The alerts are generated on your machine and graded against a
built-in answer key so you get immediate feedback on every call.

## What's in the MVP

- **SOC daily-driver.** Each day generates a fresh shift of alerts drawn from eight
  detections CySA+ cares about (brute force, C2 beaconing, encoded PowerShell, internal
  port sweeps, phishing clicks, impossible travel, data exfiltration, rogue admin
  accounts). Every detection has a malicious variant and a benign look-alike, so triage
  is a real decision, not pattern-matching the title. You decide **escalate** or
  **close**, give a reason, and get graded with the indicators that gave it away and the
  response actions a real analyst would take.
- **Shift turnover.** End-of-shift handoff. Your open items show up at the top of the
  next day's queue.
- **Study tracker.** One tracker for four tracks (CySA+, Pen Test, WGU, CWE path) with
  spaced repetition. It hands you a daily study block sized to your time budget,
  weighted toward what's due and your current CWE phase.
- **Metrics.** Triage accuracy, a confusion matrix (watch the false negatives: those are
  missed threats), per-detection accuracy, and a daily streak.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Option A: start empty (curriculum auto-loads on first run)
python run.py

# Option B: fill it with a week of sample activity first, so the UI isn't blank
flask --app cybertrack demo --days 6
python run.py
```

Then open http://127.0.0.1:5000.

A typical day: open the **Dashboard**, work the **SOC Queue** (a few alerts, ~3 min
each), do **Today's** study task, then write **Turnover**. Budget is about 30-45 minutes.

## Commands

```bash
flask --app cybertrack seed        # load the curriculum (idempotent)
flask --app cybertrack demo --days 6   # fabricate past shifts + study for a populated UI
flask --app cybertrack reset       # wipe activity, keep the curriculum
pytest                             # run the test suite
```

## Set it up for yourself

- **CWE phase and daily minutes** are set on the **Study** page. Only CWE topics at or
  below your current phase get scheduled, so you're not handed exploit-dev before C.
- **Curriculum** lives in `data/curriculum/*.yaml`. Edit freely. In particular,
  `wgu.yaml` is seeded with the standard course list; mark courses you've passed with
  `active: false` (or delete them) so only remaining work gets scheduled.
- **Shift size** (alerts per day, minutes per alert) is stored in settings with sensible
  defaults in `cybertrack/db.py` (`DEFAULTS`).

## How it fits with the CWE interview-prep skill

Your existing `cwe-interview-prep` skill runs the actual Socratic quizzing (trace it,
break it, write it, explain it) and keeps its own roadmap and miss log. CyberTrack does
**not** duplicate that. It schedules the CWE topics beside everything else and tracks your
progress; when a CWE topic comes up, tell Claude "quiz me on this" to run a session with
the skill, then log your confidence back in CyberTrack. The two stay loosely coupled:
there's no automatic two-way sync in this build.

## Project layout

```
cybertrack/
  __init__.py        app factory, config
  models.py          SQLAlchemy models
  db.py              engine, sessions, the app clock, settings
  planner.py         builds each day's plan (alerts + study)
  cli.py             seed / demo / reset commands
  soc/
    scenarios.py     the eight detections, each malicious + benign
    generator.py     builds a shift, grades triage, computes metrics
    routes.py        queue, alert detail, turnover, metrics
  study/
    curriculum.py    loads the YAML tracks
    scheduler.py     SM-2-lite spaced repetition + daily selection
    routes.py        tracker, today's tasks, settings
  dashboard/routes.py  the daily-loop home page
data/curriculum/     cysa.yaml, pentest.yaml, wgu.yaml, cwe.yaml
tests/               generator, scheduler, and end-to-end app tests
```

## Replaying a specific day

Set `CYBERTRACK_TODAY=YYYY-MM-DD` to make the app treat that as today. Useful for testing
the turnover carry-over or generating a particular day's shift.

## Roadmap (next, not in this build)

Self-contained Docker labs under `labs/`: a vulnerable-by-design web app for the pen-test
track, reverse-engineering and binary challenge targets that ladder with the CWE phases,
and a log-replay lab that feeds a real attack capture into the SOC queue. CyberTrack will
get a `/labs` launcher that starts a container, tracks completion, and links the lab to its
curriculum item. All targets are locally built and locally attacked.

## Note

CyberTrack is a personal training tool. The scenarios teach you to recognize and respond
to attacker behavior from the defender's seat. Use the skills you build here only on
systems you're authorized to test.
