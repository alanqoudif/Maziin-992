import json
from flask import Blueprint, render_template
from flask_login import login_required

from app.models.alert import Alert
from app.models.device import Device
from app.models.vulnerability import Vulnerability
from app.models.mitre import MitreAttack
from app.models.scan_result import ScanResult
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
    
    # Simple confirmed exploit mapping
    confirmed_cves = set()
    msf_scans = ScanResult.query.filter_by(scan_type="metasploit").all()
    for s in msf_scans:
        res = s.parsed_results or {}
        if isinstance(res, str):
            try: res = json.loads(res)
            except: res = {}
        
        if isinstance(res, dict):
            if res.get("result") == "vulnerable":
                confirmed_cves.add(res.get("cve"))
            elif "exploit_results" in res:
                 for item in res["exploit_results"]:
                     if item.get("result") == "vulnerable":
                         confirmed_cves.add(item.get("cve"))
        elif isinstance(res, list):
             for item in res:
                 if item.get("result") == "vulnerable":
                     confirmed_cves.add(item.get("cve"))

    # Calculate MITRE Coverage
    total_tactics = 14
    mapped_vulns = Vulnerability.query.filter(Vulnerability.mitre_techniques.any()).all()
    covered_tactics = set()
    for v in mapped_vulns:
        for t in v.mitre_techniques:
            covered_tactics.add(t.tactic)
    
    mitre_coverage = round((len(covered_tactics) / total_tactics) * 100, 1) if total_tactics > 0 else 0
    
    # Overall Network Health
    if critical_count > 10:
        health_status = "red"
    elif critical_count > 0 or vulns_count > 50:
        health_status = "yellow"
    else:
        health_status = "green"

    return render_template(
        "dashboard/index.html",
        devices_count=devices_count,
        vulns_count=vulns_count,
        critical_count=critical_count,
        recent_alerts=recent_alerts,
        scan_state=scan_state,
        mitre_coverage=mitre_coverage,
        health_status=health_status,
        confirmed_cves=confirmed_cves
    )
