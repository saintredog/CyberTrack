"""Engine, per-request sessions, the app clock, and small settings helpers."""
from __future__ import annotations

from datetime import date

from flask import current_app, g, has_app_context
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base, Setting

DEFAULTS = {
    "cwe_phase": "1",          # current phase of the CWE roadmap (1-4)
    "daily_minutes": "40",     # total daily budget, alerts + study
    "alerts_per_day": "5",     # new alerts generated per shift
    "minutes_per_alert": "3",  # time estimate used to size the study block
    "analyst_name": "Analyst", # shown in the top bar and as alert owner
}


def _add_missing_columns(engine) -> None:
    """Tiny additive migration: add new nullable columns to existing tables.

    create_all() makes missing tables but never alters existing ones, so a
    database created by an older version would lack newer columns.
    """
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have or not col.nullable:
                    continue
                ddl_type = col.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl_type}'))


def init_app(app) -> None:
    engine = create_engine(app.config["DATABASE_URL"])
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    app.extensions["cybertrack.engine"] = engine
    app.extensions["cybertrack.sessionmaker"] = sessionmaker(bind=engine, expire_on_commit=False)
    app.teardown_appcontext(close_session)


def get_session() -> Session:
    if "db" not in g:
        g.db = current_app.extensions["cybertrack.sessionmaker"]()
    return g.db


def close_session(exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def today() -> date:
    """The app's notion of today. Override with CYBERTRACK_TODAY to replay a day."""
    if has_app_context():
        override = current_app.config.get("TODAY")
        if override:
            return override if isinstance(override, date) else date.fromisoformat(str(override))
    return date.today()


def get_setting(session: Session, key: str) -> str:
    row = session.get(Setting, key)
    return row.value if row else DEFAULTS[key]


def get_int_setting(session: Session, key: str) -> int:
    try:
        return int(get_setting(session, key))
    except ValueError:
        return int(DEFAULTS[key])


def set_setting(session: Session, key: str, value) -> None:
    row = session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=str(value)))
    else:
        row.value = str(value)
