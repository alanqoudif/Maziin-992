from flask import Blueprint, render_template
from flask_login import login_required

from app.models.vulnerability import Vulnerability
from app.models.scan_result import ScanResult
from app.routes.rbac import roles_required

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vulnerabilities_bp.route("/")
@login_required
@roles_required("admin", "security_analyst", "viewer")
def list_vulnerabilities():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.ai_priority_rank.asc()).all()
    
    # Simple confirmed exploit mapping for the list view
    confirmed_cves = set()
    msf_scans = ScanResult.query.filter_by(scan_type="metasploit").all()
    for s in msf_scans:
        res = s.parsed_results or {}
        if isinstance(res, str):
            try: res = json.loads(res)
            except: res = {}
        if res.get("result") == "vulnerable":
            confirmed_cves.add(res.get("cve"))

    return render_template("vulnerabilities/list.html", vulnerabilities=vulnerabilities, confirmed_cves=confirmed_cves)


@vulnerabilities_bp.route("/<int:vuln_id>")
@login_required
@roles_required("admin", "security_analyst", "viewer")
def vulnerability_detail(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    
    # Check if confirmed exploitable by Metasploit
    is_confirmed = ScanResult.query.filter(
        ScanResult.scan_type == "metasploit",
        ScanResult.parsed_results.contains(vulnerability.cve_id),
        ScanResult.parsed_results.contains("vulnerable")
    ).first() is not None

    ai_factors = {
        "labels": ["CVSS", "Exploitability", "Impact", "Exposure", "Asset Criticality", "MITRE Scope"],
        "values": [
            vulnerability.cvss_base_score,
            vulnerability.exploitability_score,
            vulnerability.impact_score,
            round(vulnerability.network_exposure_factor * 10, 2),
            round(vulnerability.asset_criticality_factor * 2.5, 2),
            min(len(vulnerability.mitre_techniques) * 2.5, 10),
        ],
    }
    analysis = {
        "affected_device_count": len(vulnerability.affected_devices),
        "status": vulnerability.status,
        "exploitability": "High" if vulnerability.exploit_availability else "Moderate",
    }
    return render_template("vulnerabilities/detail.html", vulnerability=vulnerability, ai_factors=ai_factors, analysis=analysis, is_confirmed=is_confirmed)
