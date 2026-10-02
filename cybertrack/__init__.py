"""CyberTrack: a local daily cybersecurity practice portal.

Run it with `python run.py`, then open http://127.0.0.1:5000.
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "data" / "cybertrack.db"
CURRICULUM_DIR = PROJECT_ROOT / "data" / "curriculum"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
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

    @app.context_processor
    def _inject_today():
        return {"today": db.today()}

    if app.config["AUTO_SEED"]:
        from .study.curriculum import load_curriculum_if_empty

        with app.app_context():
            load_curriculum_if_empty(db.get_session(), app.config["CURRICULUM_DIR"])

    return app
