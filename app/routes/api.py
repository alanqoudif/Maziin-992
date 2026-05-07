from collections import Counter
from datetime import datetime, timedelta

import joblib
import numpy as np
import pandas as pd
from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required

from app.ai.feature_engineering import build_features
from app.models.alert import Alert
from app.models.device import Device
from app.models.patch import Patch
from app.models.security_event import SecurityEvent
from app.models.vulnerability import Vulnerability
from app.routes.rbac import roles_required
from app.scanners.real_scanner import get_scan_state
from app.scanners.simulator import generate_devices

api_bp = Blueprint("api", __name__)

SEVERITY_WEIGHTS = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}


def _compliance_score(done, total):
    return round((done / total) * 100) if total else 0


@api_bp.get("/dashboard/stats")
@login_required
def dashboard_stats():
    total_devices = Device.query.count()
    total_vulns = Vulnerability.query.count()
    critical = Vulnerability.query.filter_by(severity="critical").count()
    total_patches = Patch.query.count()
    applied_patches = Patch.query.filter_by(status="applied").count()
    patch_compliance = round((applied_patches / total_patches) * 100, 1) if total_patches else 0
    avg_ai = np.mean([v.ai_risk_score for v in Vulnerability.query.all()] or [0])
    return jsonify(
        {
            "total_devices": total_devices,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical,
            "patch_compliance_percent": patch_compliance,
            "ai_risk_score_average": round(float(avg_ai), 2),
        }
    )


@api_bp.get("/vulnerabilities")
@login_required
def vulnerabilities_api():
    severity = request.args.get("severity")
    status = request.args.get("status")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    query = Vulnerability.query
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    p = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(
        {
            "items": [
                {"id": v.id, "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "ai_risk_score": v.ai_risk_score}
                for v in p.items
            ],
            "page": p.page,
            "pages": p.pages,
            "total": p.total,
        }
    )


@api_bp.get("/vulnerabilities/<int:vuln_id>")
@login_required
def vulnerability_detail_api(vuln_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    return jsonify(
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "description": v.description,
            "cvss_base_score": v.cvss_base_score,
            "ai_risk_score": v.ai_risk_score,
            "affected_devices": [d.hostname for d in v.affected_devices],
        }
    )


@api_bp.get("/devices")
@login_required
def devices_api():
    dept = request.args.get("department")
    device_type = request.args.get("type")
    query = Device.query
    if dept:
        query = query.filter_by(department=dept)
    if device_type:
        query = query.filter_by(device_type=device_type)
    devices = query.limit(500).all()
    return jsonify([{"id": d.id, "hostname": d.hostname, "ip": d.ip_address, "department": d.department} for d in devices])


@api_bp.get("/alerts")
@login_required
def alerts_api():
    unread = request.args.get("unread") == "true"
    query = Alert.query
    if unread:
        query = query.filter_by(is_read=False)
    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify(
        {
            "total": len(alerts),
            "items": [
                {
                    "id": a.id,
                    "type": a.alert_type,
                    "message": a.message,
                    "severity": a.severity,
                    "device": a.device.hostname if a.device else None,
                    "cve_id": a.vulnerability.cve_id if a.vulnerability else None,
                    "created_at": a.created_at.isoformat(),
                }
                for a in alerts
            ],
        }
    )


@api_bp.route("/scan/network-info", methods=["GET"])
@login_required
def get_network_info_api():
    """Get current network information"""
    from app.scanners.network_utils import get_network_info, check_nmap_installed
    info = get_network_info()
    nmap = check_nmap_installed()
    return jsonify({
        "network": info,
        "nmap": nmap
    })

@api_bp.route("/scan/start", methods=["POST"])
@login_required
@roles_required("admin", "network_admin", "security_analyst")
def start_real_scan():
    """Start a real Nmap scan on the connected network"""
    from app.scanners.real_scanner import start_scan_async, get_scan_state
    from app.scanners.network_utils import get_network_cidr, check_nmap_installed
    
    # Check nmap is installed
    nmap_check = check_nmap_installed()
    if not nmap_check["installed"]:
        return jsonify({"error": "Nmap is not installed. Install it with: brew install nmap (macOS) or sudo apt install nmap (Linux)"}), 400
    
    # Check not already running
    state = get_scan_state()
    if state["status"] == "running":
        return jsonify({"error": "A scan is already running", "state": state}), 409
    
    # Get target — from request body or auto-detect
    data = request.get_json(silent=True) or {}
    target = data.get("target") or get_network_cidr()
    scan_type = data.get("scan_type", "normal")  # quick, normal, deep
    
    if not target:
        return jsonify({"error": "Could not detect network. Please provide target CIDR."}), 400
    
    # Validate CIDR format
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target):
        return jsonify({"error": "Invalid CIDR format. Use format: 192.168.1.0/24"}), 400
    
    # Start scan in background
    start_scan_async(current_app._get_current_object(), target, scan_type)
    
    return jsonify({
        "message": f"Scan started on {target} ({scan_type} mode)",
        "target": target,
        "scan_type": scan_type
    })

@api_bp.route("/scan/status", methods=["GET"])
@login_required
def scan_status_api():
    """Get current scan status and progress"""
    from app.scanners.real_scanner import get_scan_state
    return jsonify(get_scan_state())

@api_bp.route("/scan/results", methods=["GET"])
@login_required
def scan_results_api():
    """Get the latest scan results"""
    from app.scanners.real_scanner import get_scan_state
    state = get_scan_state()
    if state["results"]:
        return jsonify(state["results"])
    return jsonify({"hosts": [], "message": "No scan results available. Run a scan first."})


@api_bp.get("/compliance/score")
@login_required
def compliance_score():
    iso_done, iso_total = 66, 79
    nist_done, nist_total = 69, 96
    cis_done, cis_total = 54, 78
    iso_score = _compliance_score(iso_done, iso_total)
    nist_score = _compliance_score(nist_done, nist_total)
    cis_score = _compliance_score(cis_done, cis_total)
    overall = round((iso_score * 0.4) + (nist_score * 0.35) + (cis_score * 0.25))
    return jsonify({"iso27001": iso_score, "nist_csf": nist_score, "cis_controls_v8": cis_score, "overall": overall})


@api_bp.get("/ai/predict")
@login_required
def ai_predict():
    model = joblib.load("ml_models/vulnerability_model.pkl")
    row = {
        "cvss_base_score": float(request.args.get("cvss_base_score", 8.7)),
        "exploitability_score": float(request.args.get("exploitability_score", 8.2)),
        "impact_score": float(request.args.get("impact_score", 7.8)),
        "asset_criticality": request.args.get("asset_criticality", "high"),
        "network_exposure": float(request.args.get("network_exposure", 0.8)),
        "exploit_available": request.args.get("exploit_available", "1") in {"1", "true", "True"},
        "days_since_published": int(request.args.get("days_since_published", 120)),
        "device_type": request.args.get("device_type", "server"),
        "mitre_attack_technique_count": int(request.args.get("mitre_attack_technique_count", 6)),
    }
    X = build_features(pd.DataFrame([row]))
    pred = int(model.predict(X)[0])
    return jsonify({"prediction": pred})


@api_bp.get("/charts/<string:chart_type>")
@login_required
def chart_data(chart_type):
    vulns = Vulnerability.query.all()
    if chart_type == "severity_distribution":
        counts = Counter(v.severity for v in vulns)
        return jsonify({"labels": list(counts.keys()), "values": list(counts.values())})
    if chart_type == "department_vulns":
        counts = Counter()
        for v in vulns:
            for d in v.affected_devices:
                counts[d.department] += 1
        return jsonify({"labels": list(counts.keys()), "values": list(counts.values())})
    if chart_type == "trend":
        window_start = datetime.utcnow() - timedelta(days=29)
        daily_counts = {}
        for day_index in range(30):
            day = (window_start + timedelta(days=day_index)).date()
            daily_counts[day] = 0
        for vuln in vulns:
            if vuln.discovered_at and vuln.discovered_at.date() in daily_counts:
                daily_counts[vuln.discovered_at.date()] += 1
        labels = [day.strftime("%b %d") for day in daily_counts.keys()]
        values = list(daily_counts.values())
        return jsonify({"labels": labels, "values": values})
    return jsonify({"error": "unknown chart type"}), 404


@api_bp.get("/dashboard/top-critical-devices")
@login_required
def top_critical_devices():
    device_scores = []
    for device in Device.query.all():
        vulns = device.vulnerabilities
        if not vulns:
            continue
        weighted_score = sum(v.ai_risk_score * SEVERITY_WEIGHTS.get(v.severity, 1.0) for v in vulns)
        critical_count = sum(1 for v in vulns if v.severity == "critical")
        top_cve = max(vulns, key=lambda v: v.ai_risk_score)
        device_scores.append(
            {
                "id": device.id,
                "hostname": device.hostname,
                "department": device.department,
                "criticality": device.criticality,
                "critical_vuln_count": critical_count,
                "weighted_risk": round(weighted_score, 2),
                "top_cve": top_cve.cve_id,
            }
        )
    top = sorted(device_scores, key=lambda d: (d["weighted_risk"], d["critical_vuln_count"]), reverse=True)[:5]
    return jsonify({"items": top})


@api_bp.get("/attacks/geo")
@login_required
def attacks_geo():
    """Aggregate security events by source-IP country for the geo map."""
    from app.data.geoip_lookup import lookup, COUNTRY_META

    now = datetime.utcnow()
    events = (
        SecurityEvent.query
        .filter(SecurityEvent.timestamp >= now - timedelta(days=30))
        .with_entities(SecurityEvent.source_ip, SecurityEvent.event_type)
        .all()
    )

    country_counts: dict = {}
    country_top_event: dict = {}
    for src_ip, event_type in events:
        geo = lookup(src_ip or "")
        code = geo["country_code"]
        if code == "INT":
            continue
        country_counts[code] = country_counts.get(code, 0) + 1
        if code not in country_top_event:
            country_top_event[code] = Counter()
        country_top_event[code][event_type] += 1

    result = []
    for code, count in sorted(country_counts.items(), key=lambda x: -x[1]):
        meta = COUNTRY_META.get(code, (code, 0.0, 0.0))
        top_type = country_top_event[code].most_common(1)[0][0] if country_top_event.get(code) else "Unknown"
        result.append({
            "country_code": code,
            "country_name": meta[0],
            "lat": meta[1],
            "lng": meta[2],
            "count": count,
            "top_event_type": top_type,
        })
    return jsonify(result)


@api_bp.get("/attacks/killchain")
@login_required
def attacks_killchain():
    """Map security events to MITRE ATT&CK tactics via device → vulnerability → technique."""
    from app.models.mitre import MitreAttack

    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    now = datetime.utcnow()
    events = (
        SecurityEvent.query
        .filter(SecurityEvent.timestamp >= now - timedelta(days=30))
        .all()
    )

    # Build device_id → set of tactics via vulnerabilities
    device_tactic_cache: dict = {}

    def get_tactics_for_device(device_id):
        if device_id in device_tactic_cache:
            return device_tactic_cache[device_id]
        device = Device.query.get(device_id) if device_id else None
        tactics = set()
        if device:
            for vuln in device.vulnerabilities:
                for technique in vuln.mitre_techniques:
                    tactics.add(technique.tactic)
        device_tactic_cache[device_id] = tactics
        return tactics

    # Count events per tactic; fallback: map event_type to tactic heuristically
    FALLBACK_MAP = {
        "Intrusion Attempt": "Initial Access",
        "Login Failure": "Credential Access",
        "Policy Violation": "Defense Evasion",
        "Unauthorized Process": "Execution",
    }

    sev_order = ["critical", "high", "medium", "low", "info"]
    tactic_counts: dict = {t: 0 for t in TACTIC_ORDER}
    tactic_severity: dict = {t: {s: 0 for s in sev_order} for t in TACTIC_ORDER}

    for e in events:
        tactics = get_tactics_for_device(e.device_id)
        if not tactics:
            fallback = FALLBACK_MAP.get(e.event_type)
            if fallback:
                tactics = {fallback}
        for tactic in tactics:
            if tactic in tactic_counts:
                tactic_counts[tactic] += 1
                tactic_severity[tactic][e.severity] = tactic_severity[tactic].get(e.severity, 0) + 1

    result = []
    for tactic in TACTIC_ORDER:
        result.append({
            "tactic": tactic,
            "count": tactic_counts[tactic],
            "severity_breakdown": tactic_severity[tactic],
        })
    return jsonify(result)


@api_bp.get("/attacks/timeline")
@login_required
def attacks_timeline():
    """30 daily buckets × severity for a stacked bar chart."""
    now = datetime.utcnow()
    sev_order = ["critical", "high", "medium", "low", "info"]
    days = 30

    # Build empty buckets (day labels)
    labels = [(now - timedelta(days=d)).strftime("%b %d") for d in range(days - 1, -1, -1)]
    matrix = {label: {s: 0 for s in sev_order} for label in labels}

    events = (
        SecurityEvent.query
        .filter(SecurityEvent.timestamp >= now - timedelta(days=days))
        .with_entities(SecurityEvent.timestamp, SecurityEvent.severity)
        .all()
    )
    for ts, sev in events:
        label = ts.strftime("%b %d")
        if label in matrix and sev in sev_order:
            matrix[label][sev] += 1

    return jsonify({
        "labels": labels,
        "datasets": {s: [matrix[lbl][s] for lbl in labels] for s in sev_order},
    })


@api_bp.get("/attacks/recent")
@login_required
def attacks_recent():
    """Last 10 security events with geo lookup."""
    from app.data.geoip_lookup import lookup

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    result = []
    for e in events:
        geo = lookup(e.source_ip or "")
        result.append({
            "id": e.id,
            "ts": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source": e.source,
            "event_type": e.event_type,
            "severity": e.severity,
            "src_ip": e.source_ip or "—",
            "src_country": geo["country_name"],
            "src_country_code": geo["country_code"],
            "dst_ip": e.dest_ip or "—",
            "dst_host": e.device.hostname if e.device else "—",
            "message": e.message,
        })
    return jsonify(result)


@api_bp.get("/dashboard/recent-alerts")
@login_required
def dashboard_recent_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(8).all()
    return jsonify(
        {
            "items": [
                {
                    "id": a.id,
                    "type": a.alert_type,
                    "severity": a.severity,
                    "message": a.message,
                    "device": a.device.hostname if a.device else "N/A",
                    "created_at": a.created_at.isoformat(),
                }
                for a in alerts
            ]
        }
    )
