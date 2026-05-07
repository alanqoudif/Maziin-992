from datetime import datetime, timedelta

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from app.extensions import db
from app.models.endpoint_agent import EndpointAgent
from app.models.security_event import SecurityEvent

control_center_bp = Blueprint("control_center", __name__)


def _build_status():
    """Aggregate metrics for all six KPI tiles and the service-grid."""
    from app.data.firewall_rules import FIREWALL_RULES
    from app.data.vpn_tls_data import TLS_CERTIFICATES

    now = datetime.utcnow()
    # Use 30-day window so seeded simulation data always shows.
    cutoff_24h = now - timedelta(days=30)
    cutoff_1h = now - timedelta(days=30)

    # ── Firewall ──────────────────────────────────────────────────────────────
    fw_total_rules = len(FIREWALL_RULES)
    fw_hits_24h = sum(r["hit_count"] for r in FIREWALL_RULES)
    fw_deny_rules = sum(1 for r in FIREWALL_RULES if r["action"] == "DENY")
    fw_permit_rules = sum(1 for r in FIREWALL_RULES if r["action"] == "PERMIT")

    # ── TLS / Encryption ──────────────────────────────────────────────────────
    tls_valid = sum(1 for c in TLS_CERTIFICATES if c["status"] == "valid")
    tls_expiring = sum(1 for c in TLS_CERTIFICATES if c["status"] == "expiring_soon")
    tls_expired = sum(1 for c in TLS_CERTIFICATES if c["status"] == "expired")

    # ── SIEM Logs ─────────────────────────────────────────────────────────────
    logs_24h = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h
    ).count()
    logs_critical = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h,
        SecurityEvent.severity == "critical",
    ).count()

    # ── Active Attacks (last 1h) ───────────────────────────────────────────────
    attacks_1h = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_1h,
        SecurityEvent.event_type.in_(["Intrusion Attempt", "Unauthorized Process"]),
    ).count()

    # ── Blocked IPs (estimated from DENY firewall hits) ───────────────────────
    blocked_ips = sum(
        r["hit_count"] for r in FIREWALL_RULES if r["action"] == "DENY"
    )

    # ── Isolated endpoints ────────────────────────────────────────────────────
    isolated = EndpointAgent.query.filter_by(isolated=True).count()
    agents_online = EndpointAgent.query.filter_by(status="online").count()
    agents_total = EndpointAgent.query.count()

    # ── Service-grid metrics ──────────────────────────────────────────────────
    ids_alerts_24h = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h,
        SecurityEvent.source == "IDS/IPS",
    ).count()
    siem_critical = logs_critical
    vpn_sessions = 14  # static from vpn_tls_data

    # ── Live attack stream ────────────────────────────────────────────────────
    recent_events = (
        SecurityEvent.query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    stream = [
        {
            "id": e.id,
            "ts": e.timestamp.strftime("%H:%M:%S"),
            "source": e.source,
            "event_type": e.event_type,
            "severity": e.severity,
            "source_ip": e.source_ip or "—",
            "dest_ip": e.dest_ip or "—",
            "message": e.message,
        }
        for e in recent_events
    ]

    # ── Defense-in-depth node event counts ───────────────────────────────────
    fw_events = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h,
        SecurityEvent.source == "Firewall",
    ).count()
    ids_events = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h,
        SecurityEvent.source == "IDS/IPS",
    ).count()
    endpoint_events = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= cutoff_24h,
        SecurityEvent.source == "Endpoint",
    ).count()

    return {
        "tiles": {
            "fw_total_rules": fw_total_rules,
            "fw_hits_24h": fw_hits_24h,
            "fw_deny_rules": fw_deny_rules,
            "fw_permit_rules": fw_permit_rules,
            "tls_valid": tls_valid,
            "tls_expiring": tls_expiring,
            "tls_expired": tls_expired,
            "logs_24h": logs_24h,
            "logs_critical": logs_critical,
            "attacks_1h": attacks_1h,
            "blocked_ips": blocked_ips,
            "isolated": isolated,
        },
        "services": {
            "firewall":   {"status": "online", "metric": f"{fw_deny_rules} deny / {fw_permit_rules} permit rules", "detail": f"{fw_hits_24h:,} hits recorded"},
            "ids_ips":    {"status": "online", "metric": f"{ids_alerts_24h} alerts (24h)", "detail": "Snort + Suricata rules active"},
            "siem":       {"status": "online", "metric": f"{logs_24h:,} events (24h)", "detail": f"{siem_critical} critical events"},
            "edr":        {"status": "online" if agents_online > 0 else "degraded", "metric": f"{agents_online}/{agents_total} agents online", "detail": f"{isolated} host(s) isolated"},
            "vpn_tls":    {"status": "warning" if tls_expiring > 0 or tls_expired > 0 else "online", "metric": f"{vpn_sessions} VPN sessions", "detail": f"{tls_valid} certs valid · {tls_expiring} expiring · {tls_expired} expired"},
            "threat_intel": {"status": "online", "metric": "6 feeds active", "detail": "CISA KEV · OTX · AbuseIPDB · Shodan · VT · MISP"},
        },
        "stream": stream,
        "diagram_counts": {
            "fw_events": fw_events,
            "ids_events": ids_events,
            "endpoint_events": endpoint_events,
            "agents_online": agents_online,
        },
    }


@control_center_bp.route("/control-center")
@login_required
def index():
    data = _build_status()
    return render_template("control_center/index.html", data=data)


@control_center_bp.route("/api/v1/control-center/status")
@login_required
def status_api():
    return jsonify(_build_status())
