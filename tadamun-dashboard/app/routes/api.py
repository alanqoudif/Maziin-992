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
from app.models.vulnerability import Vulnerability
from app.routes.rbac import roles_required
from app.scanners.real_scanner import get_scan_state, parse_allowed_cidrs, start_scan_job, validate_targets
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


@api_bp.post("/scan/trigger")
@login_required
@roles_required("admin", "network_admin", "security_analyst")
def trigger_scan():
    payload = request.get_json(silent=True) or {}
    use_real_scan = payload.get("real")
    if use_real_scan is None:
        use_real_scan = request.args.get("real", "1") in {"1", "true", "True"}
    use_real_scan = bool(use_real_scan)
    if not use_real_scan:
        return jsonify({"status": "ok", "message": "Simulated scan triggered", "generated_devices": len(generate_devices())})

    if not current_app.config.get("REAL_SCAN_ENABLED"):
        return jsonify({"status": "ok", "message": "Real scan disabled. Simulated scan triggered.", "generated_devices": len(generate_devices())})

    requested_targets = payload.get("targets")
    if not requested_targets:
        requested_targets = [current_app.config.get("SCAN_ALLOWED_CIDRS", "192.168.0.0/16").split(",")[0].strip()]
    profile = payload.get("profile") or current_app.config.get("SCAN_DEFAULT_PROFILE")

    try:
        allowed = parse_allowed_cidrs(current_app.config["SCAN_ALLOWED_CIDRS"])
        targets = validate_targets(requested_targets, allowed, current_app.config["SCAN_MAX_TARGETS"])
        start_scan_job(targets=targets, profile=profile)
    except (ValueError, RuntimeError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "accepted", "message": "Real scan started", "targets": targets, "profile": profile})


@api_bp.get("/scan/status")
@login_required
def scan_status():
    return jsonify(get_scan_state())


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
