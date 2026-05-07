from flask import Flask

from app.config import Config
from app.extensions import db, login_manager, migrate
from app.scanners.real_scanner import initialize_auto_scan


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    from app.models import user, device, vulnerability, scan_result, patch, alert, incident, endpoint_agent  # noqa: F401
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

    initialize_auto_scan(app)

    return app
