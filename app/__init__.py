from pathlib import Path

from flask import Flask
from sqlalchemy import inspect

from app.config import Config
from app.extensions import db, login_manager, migrate
from app.scanners.real_scanner import initialize_auto_scan


def _ensure_sqlite_tables(app) -> None:
    """Create ORM tables on SQLite if missing (avoids OperationalError when DB file exists but is empty)."""
    uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if not uri.startswith("sqlite"):
        return
    raw = uri.replace("sqlite:///", "", 1)
    db_path = Path(raw)
    if not db_path.is_absolute():
        db_path = Path.cwd() / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with app.app_context():
        if not inspect(db.engine).has_table("user"):
            db.create_all()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    from app.models import (  # noqa: F401 — register all tables with SQLAlchemy metadata
        user,
        device,
        vulnerability,
        scan_result,
        patch,
        alert,
        incident,
        endpoint_agent,
        mitre,
        security_event,
    )
    from app.routes.api import api_bp
    from app.routes.alerts import alerts_bp
    from app.routes.auth import auth_bp
    from app.routes.compliance import compliance_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.devices import devices_bp
    from app.routes.patches import patches_bp
    from app.routes.reports import reports_bp
    from app.routes.vulnerabilities import vulnerabilities_bp
    from app.routes.security_tools import security_tools_bp
    from app.routes.ai_chat import ai_chat_bp
    from app.routes.control_center import control_center_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(patches_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(security_tools_bp)
    app.register_blueprint(control_center_bp)
    app.register_blueprint(ai_chat_bp)
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    _ensure_sqlite_tables(app)

    initialize_auto_scan(app)

    return app
