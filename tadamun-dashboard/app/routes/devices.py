from flask import Blueprint, render_template
from flask_login import login_required

from app.models.device import Device
from app.routes.rbac import roles_required

devices_bp = Blueprint("devices", __name__, url_prefix="/devices")


@devices_bp.route("/")
@login_required
@roles_required("admin", "network_admin", "viewer")
def list_devices():
    devices = Device.query.order_by(Device.department, Device.hostname).all()
    return render_template("devices/list.html", devices=devices)


@devices_bp.route("/<int:device_id>")
@login_required
@roles_required("admin", "network_admin", "viewer")
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    vulnerabilities = list(device.vulnerabilities)
    if vulnerabilities:
        avg_cvss = round(sum(v.cvss_base_score for v in vulnerabilities) / len(vulnerabilities), 2)
        avg_ai_risk = round(sum(v.ai_risk_score for v in vulnerabilities) / len(vulnerabilities), 2)
        exploit_ratio = round((sum(1 for v in vulnerabilities if v.exploit_availability) / len(vulnerabilities)) * 100, 1)
        exposure = round(sum(v.network_exposure_factor for v in vulnerabilities) / len(vulnerabilities), 2)
        impact = round(sum(v.impact_score for v in vulnerabilities) / len(vulnerabilities), 2)
    else:
        avg_cvss = 0
        avg_ai_risk = 0
        exploit_ratio = 0
        exposure = 0
        impact = 0
    ai_factors = {
        "labels": ["CVSS", "AI Risk", "Exploit Availability", "Exposure", "Impact"],
        "values": [avg_cvss, avg_ai_risk, exploit_ratio / 10, exposure * 10, impact],
    }
    analysis = {
        "linked_vulns": len(vulnerabilities),
        "critical_vulns": sum(1 for v in vulnerabilities if v.severity == "critical"),
        "highest_risk_cve": max(vulnerabilities, key=lambda v: v.ai_risk_score).cve_id if vulnerabilities else "N/A",
    }
    return render_template("devices/detail.html", device=device, ai_factors=ai_factors, analysis=analysis)
