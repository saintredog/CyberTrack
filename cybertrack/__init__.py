"""CyberTrack: a local daily cybersecurity practice portal.

Run it with `python run.py`, then open http://127.0.0.1:5000.
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask
from werkzeug.routing import IntegerConverter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "data" / "cybertrack.db"
CURRICULUM_DIR = PROJECT_ROOT / "data" / "curriculum"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SQLITE_INT_MAX = 2**63 - 1


class SQLiteIntConverter(IntegerConverter):
    """`<int:...>` capped at SQLite's signed 64-bit INTEGER.

    Werkzeug's int converter takes any number of digits, and SQLite raises
    OverflowError binding anything bigger, so /soc/case/99999999999999999999
    was a 500. With the cap the URL doesn't match and the app answers 404.
    """

    def __init__(self, map, fixed_digits=0, min=None, max=SQLITE_INT_MAX, signed=False):
        super().__init__(map, fixed_digits=fixed_digits, min=min, max=max, signed=signed)


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.url_map.converters["int"] = SQLiteIntConverter  # before any blueprint adds a rule
    app.config.update(
        SECRET_KEY=os.environ.get("CYBERTRACK_SECRET", "local-dev-only"),
        DATABASE_URL=os.environ.get("CYBERTRACK_DB_URL", f"sqlite:///{DEFAULT_DB}"),
        TODAY=os.environ.get("CYBERTRACK_TODAY"),
        CURRICULUM_DIR=str(CURRICULUM_DIR),
        AUTO_SEED=True,
    )
    if config:
        app.config.update(config)

    if app.config["DATABASE_URL"].startswith("sqlite:///"):
        Path(app.config["DATABASE_URL"].removeprefix("sqlite:///")).parent.mkdir(
            parents=True, exist_ok=True
        )

    from . import cli, db
    from .dashboard.routes import bp as dashboard_bp
    from .soc.routes import bp as soc_bp
    from .study.routes import bp as study_bp

    db.init_app(app)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(study_bp)
    cli.register(app)

    @app.template_filter("dt")
    def _fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
        return value.strftime(fmt) if value else ""

    @app.template_filter("mins")
    def _fmt_mins(value):
        if value is None:
            return "--"
        if value < 1:
            return f"{round(value * 60)}s"
        if value < 60:
            return f"{value:.1f}m"
        return f"{value / 60:.1f}h"

    @app.template_filter("num")
    def _fmt_num(value):
        return f"{int(value or 0):,}"

    from .progression import progression, standing
    from .soc.cases import STAGE_LABELS, STAGE_SHORT, STAGES, age, score_band
    from .soc.fields import highlight
    from .viz import TRACK_COLORS, URGENCY_COLORS

    app.add_template_filter(highlight, "highlight")
    app.add_template_filter(age, "age")
    app.add_template_filter(score_band, "band")

    @app.context_processor
    def _inject_shell():
        from sqlalchemy import func, select

        from .models import Alert, Case

        ctx = {
            "today": db.today(), "URGENCY_COLORS": URGENCY_COLORS, "TRACK_COLORS": TRACK_COLORS,
            "CASE_STAGES": STAGES, "STAGE_LABELS": STAGE_LABELS, "STAGE_SHORT": STAGE_SHORT,
        }
        try:
            s = db.get_session()
            ctx["nav_open"] = s.scalar(select(func.count()).select_from(Alert).where(Alert.status == "new"))
            ctx["nav_cases"] = s.scalar(select(func.count()).select_from(Case).where(Case.status == "open"))
            name = db.get_setting(s, "analyst_name")
            ctx["analyst_name"] = name
            ctx["analyst_initials"] = "".join(p[0] for p in name.split()[:2]).upper() or "A"
            ctx["nav_cwe_phase"] = db.get_int_setting(s, "cwe_phase")
            ctx["nav_prog"] = progression(s, recent=0)
        except Exception:  # never let the chrome break a page
            ctx.setdefault("nav_open", 0)
            ctx.setdefault("nav_cases", 0)
            ctx.setdefault("analyst_name", "Analyst")
            ctx.setdefault("analyst_initials", "A")
            ctx.setdefault("nav_cwe_phase", 1)
            ctx.setdefault("nav_prog", standing(0))
        return ctx

    if app.config["AUTO_SEED"]:
        from .study.curriculum import load_curriculum_if_empty

        with app.app_context():
            load_curriculum_if_empty(db.get_session(), app.config["CURRICULUM_DIR"])

    return app
