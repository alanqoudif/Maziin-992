from flask import Blueprint, render_template
from flask_login import login_required

from app.models.vulnerability import Vulnerability
from app.routes.rbac import roles_required

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vulnerabilities_bp.route("/")
@login_required
@roles_required("admin", "security_analyst", "viewer")
def list_vulnerabilities():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.ai_priority_rank.asc()).all()
    return render_template("vulnerabilities/list.html", vulnerabilities=vulnerabilities)


@vulnerabilities_bp.route("/<int:vuln_id>")
@login_required
@roles_required("admin", "security_analyst", "viewer")
def vulnerability_detail(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    ai_factors = {
        "labels": ["CVSS", "Exploitability", "Impact", "Exposure", "Asset Criticality"],
        "values": [
            vulnerability.cvss_base_score,
            vulnerability.exploitability_score,
            vulnerability.impact_score,
            round(vulnerability.network_exposure_factor * 10, 2),
            round(vulnerability.asset_criticality_factor * 2.5, 2),
        ],
    }
    analysis = {
        "affected_device_count": len(vulnerability.affected_devices),
        "status": vulnerability.status,
        "exploitability": "High" if vulnerability.exploit_availability else "Moderate",
    }
    return render_template("vulnerabilities/detail.html", vulnerability=vulnerability, ai_factors=ai_factors, analysis=analysis)
