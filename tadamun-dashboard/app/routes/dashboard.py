from flask import Blueprint, render_template
from flask_login import login_required

from app.models.alert import Alert
from app.models.device import Device
from app.models.vulnerability import Vulnerability
from app.scanners.real_scanner import get_scan_state

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    devices_count = Device.query.count()
    vulns_count = Vulnerability.query.count()
    critical_count = Vulnerability.query.filter_by(severity="critical").count()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
    scan_state = get_scan_state()
    return render_template(
        "dashboard/index.html",
        devices_count=devices_count,
        vulns_count=vulns_count,
        critical_count=critical_count,
        recent_alerts=recent_alerts,
        scan_state=scan_state,
    )
