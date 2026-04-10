import ipaddress
import json
import random
import re
from datetime import datetime, timedelta
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from app.extensions import db
from app.models.device import Device
from app.models.endpoint_agent import EndpointAgent
from app.models.incident import Incident
from app.models.scan_result import ScanResult
from app.models.security_event import SecurityEvent
from app.models.vulnerability import Vulnerability
from app.routes.rbac import roles_required

security_tools_bp = Blueprint("security_tools", __name__)


# ── OpenVAS ──────────────────────────────────────────────────────────────────

@security_tools_bp.route("/scan-results/openvas")
@login_required
def openvas_results():
    xml_path = Path("data/sample_openvas_report.xml")
    from app.scanners.openvas_parser import parse_openvas_xml
    if xml_path.exists():
        with open(xml_path, "r") as f:
            data = parse_openvas_xml(f.read())
    else:
        data = {"results": [], "total": 0, "critical_count": 0, "high_count": 0,
                "medium_count": 0, "low_count": 0, "hosts": []}
    return render_template("security_tools/openvas_results.html", data=data)


# ── Nmap ─────────────────────────────────────────────────────────────────────

@security_tools_bp.route("/scan-results/nmap")
@login_required
def nmap_results():
    scans = ScanResult.query.filter(ScanResult.scan_type.in_(["nmap", "nmap_real"])).order_by(ScanResult.scan_date.desc()).all()
    results = []
    for scan in scans:
        if isinstance(scan.parsed_results, str):
            try:
                data = json.loads(scan.parsed_results)
            except Exception:
                data = {}
        else:
            data = scan.parsed_results or {}
        results.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "device": scan.device.hostname if scan.device else "Network Scan",
            "ip": scan.device.ip_address if scan.device else "N/A",
            "date": scan.scan_date,
            "data": data,
            "findings": scan.findings_count,
        })
    return render_template("security_tools/nmap_results.html", results=results)


# ── Wireshark ─────────────────────────────────────────────────────────────────

@security_tools_bp.route("/traffic-analysis")
@login_required
def traffic_analysis():
    csv_path = Path("data/sample_pcap_analysis.csv")
    from app.scanners.wireshark_parser import parse_wireshark_csv
    if csv_path.exists():
        with open(csv_path, "r") as f:
            analysis = parse_wireshark_csv(f.read())
    else:
        analysis = {"total_packets": 0, "anomalies": [], "anomaly_count": 0, "normal_traffic_pct": 0}
    return render_template("security_tools/traffic_analysis.html", analysis=analysis)


# ── Metasploit / Kali Toolkit ─────────────────────────────────────────────────

_KALI_TOOLS = [
    {"name": "Nmap", "category": "Reconnaissance", "status": "active", "endpoint": "nmap_results", "file": None, "description": "Network port scanner & OS fingerprinting"},
    {"name": "Metasploit Framework", "category": "Exploitation", "status": "active", "endpoint": "exploit_verification", "file": None, "description": "Vulnerability exploitation framework"},
    {"name": "Hydra", "category": "Credential Access", "status": "active", "endpoint": None, "file": "sample_hydra_output.txt", "description": "Network login brute-forcer (SSH, FTP, HTTP, SMB)"},
    {"name": "Nikto", "category": "Web Scanning", "status": "active", "endpoint": None, "file": "sample_nikto_output.txt", "description": "Web server vulnerability scanner"},
    {"name": "SQLmap", "category": "Web Attacks", "status": "active", "endpoint": None, "file": "sample_sqlmap_output.txt", "description": "Automated SQL injection detection & exploitation"},
    {"name": "Aircrack-ng", "category": "Wireless", "status": "reference", "endpoint": None, "file": None, "description": "WPA/WPA2 wireless network cracking suite"},
    {"name": "Burp Suite Community", "category": "Web Pen-Test", "status": "reference", "endpoint": None, "file": None, "description": "Web application security testing proxy"},
    {"name": "Wireshark", "category": "Packet Analysis", "status": "active", "endpoint": "traffic_analysis", "file": None, "description": "Network protocol analyzer & packet capture"},
    {"name": "OpenVAS / GVM", "category": "Vulnerability Scan", "status": "active", "endpoint": "openvas_results", "file": None, "description": "Open-source vulnerability assessment system"},
]


@security_tools_bp.route("/exploit-verification")
@login_required
def exploit_verification():
    json_path = Path("data/sample_metasploit.json")
    from app.scanners.metasploit_parser import parse_metasploit_json
    if json_path.exists():
        with open(json_path, "r") as f:
            msf_data = parse_metasploit_json(f.read())
    else:
        msf_data = {"results": [], "total": 0, "vulnerable_count": 0,
                    "not_vulnerable_count": 0, "error_count": 0}

    # Load Kali tool output files
    tool_outputs = {}
    for tool in _KALI_TOOLS:
        if tool["file"]:
            fp = Path("data") / tool["file"]
            if fp.exists():
                tool_outputs[tool["name"]] = fp.read_text()
            else:
                tool_outputs[tool["name"]] = f"[Output file {tool['file']} not found]"

    return render_template(
        "security_tools/exploit_verification.html",
        msf_data=msf_data,
        kali_tools=_KALI_TOOLS,
        tool_outputs=tool_outputs,
    )


# ── IDS Engine (Snort/Suricata) ───────────────────────────────────────────────

@security_tools_bp.route("/ids-engine")
@login_required
def ids_engine():
    from app.data.snort_rules import SNORT_RULES, RULE_STATS, RULE_CATEGORIES

    ids_events = (
        SecurityEvent.query
        .filter_by(source="IDS/IPS")
        .order_by(SecurityEvent.timestamp.desc())
        .limit(200)
        .all()
    )

    alerts_today = SecurityEvent.query.filter(
        SecurityEvent.source == "IDS/IPS",
        SecurityEvent.timestamp >= datetime.utcnow() - timedelta(days=1),
    ).count()

    engine = request.args.get("engine", "snort")
    return render_template(
        "security_tools/ids_engine.html",
        rules=SNORT_RULES,
        rule_stats=RULE_STATS,
        rule_categories=RULE_CATEGORIES,
        ids_events=ids_events,
        alerts_today=alerts_today,
        active_engine=engine,
    )


# ── Firewall Rules ────────────────────────────────────────────────────────────

@security_tools_bp.route("/firewall-rules")
@login_required
def firewall_rules():
    from app.data.firewall_rules import FIREWALL_RULES
    total_hits = sum(r["hit_count"] for r in FIREWALL_RULES)
    permit_count = sum(1 for r in FIREWALL_RULES if r["action"] == "PERMIT")
    deny_count = sum(1 for r in FIREWALL_RULES if r["action"] == "DENY")
    return render_template(
        "security_tools/firewall_rules.html",
        rules=FIREWALL_RULES,
        total_hits=total_hits,
        permit_count=permit_count,
        deny_count=deny_count,
    )


@security_tools_bp.route("/api/firewall/test", methods=["POST"])
@login_required
def firewall_test():
    from app.data.firewall_rules import evaluate_packet
    data = request.get_json(silent=True) or {}
    src_ip = data.get("src_ip", "")
    dst_ip = data.get("dst_ip", "")
    port = data.get("port", "any")
    protocol = data.get("protocol", "tcp")

    # Basic validation
    for addr in (src_ip, dst_ip):
        if addr and addr not in ("any", "0.0.0.0/0"):
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                try:
                    ipaddress.ip_network(addr, strict=False)
                except ValueError:
                    return jsonify({"error": f"Invalid IP/CIDR: {addr}"}), 400

    result = evaluate_packet(src_ip, dst_ip, port, protocol)
    return jsonify(result)


# ── Threat Intelligence ───────────────────────────────────────────────────────

@security_tools_bp.route("/threat-intel")
@login_required
def threat_intel():
    feeds_path = Path("data/threat_intel_feeds.json")
    feeds = {}
    if feeds_path.exists():
        with open(feeds_path, "r") as f:
            feeds = json.load(f)

    # KEV stats from existing data
    kev_path = Path("data/kev_catalog.json")
    kev_count = 0
    if kev_path.exists():
        with open(kev_path, "r") as f:
            kev_data = json.load(f)
            kev_count = len(kev_data.get("known_exploited", []))

    return render_template(
        "security_tools/threat_intel.html",
        feeds=feeds,
        kev_count=kev_count,
    )


@security_tools_bp.route("/api/threat-intel/lookup", methods=["POST"])
@login_required
def threat_intel_lookup():
    data = request.get_json(silent=True) or {}
    ioc = data.get("ioc", "").strip()
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

    feeds_path = Path("data/threat_intel_feeds.json")
    matches = []
    if feeds_path.exists():
        with open(feeds_path, "r") as f:
            feeds = json.load(f)

        # Search AbuseIPDB
        for entry in feeds.get("abuseipdb", {}).get("entries", []):
            if ioc.lower() == entry["ip"].lower():
                matches.append({"feed": "AbuseIPDB", "type": "ip", "data": entry})

        # Search OTX pulses (search tag/name)
        for pulse in feeds.get("alienvault_otx", {}).get("pulses", []):
            if ioc.lower() in pulse["name"].lower() or any(ioc.lower() in t.lower() for t in pulse["tags"]):
                matches.append({"feed": "AlienVault OTX", "type": "pulse", "data": pulse})

        # Search Shodan
        for result in feeds.get("shodan", {}).get("results", []):
            if ioc.lower() == result["ip"].lower():
                matches.append({"feed": "Shodan", "type": "ip", "data": result})
            elif ioc.lower() in " ".join(result.get("vulns", [])).lower():
                matches.append({"feed": "Shodan", "type": "vuln", "data": result})

        # Search VirusTotal hashes
        for h in feeds.get("virustotal", {}).get("sample_hashes", []):
            if ioc.lower() in h["sha256"].lower() or ioc.lower() in h["name"].lower():
                matches.append({"feed": "VirusTotal", "type": "hash", "data": h})

    return jsonify({"ioc": ioc, "matches": matches, "total": len(matches)})


# ── VPN & TLS Monitor ─────────────────────────────────────────────────────────

@security_tools_bp.route("/vpn-monitoring")
@login_required
def vpn_monitoring():
    from app.data.vpn_tls_data import VPN_SESSIONS, TLS_CERTIFICATES

    tls_expired = [c for c in TLS_CERTIFICATES if c["status"] == "expired"]
    tls_expiring = [c for c in TLS_CERTIFICATES if c["status"] == "expiring_soon"]
    tls_noncompliant = [c for c in TLS_CERTIFICATES if not c["compliant"]]

    # Count TLS version breakdown
    tls_versions = {}
    for cert in TLS_CERTIFICATES:
        v = cert["tls_version"]
        tls_versions[v] = tls_versions.get(v, 0) + 1

    # Format bytes helper for template
    def fmt_bytes(b):
        if b >= 1_000_000_000:
            return f"{b/1_000_000_000:.1f} GB"
        if b >= 1_000_000:
            return f"{b/1_000_000:.1f} MB"
        return f"{b/1_000:.1f} KB"

    for s in VPN_SESSIONS:
        s["bytes_in_fmt"] = fmt_bytes(s["bytes_in"])
        s["bytes_out_fmt"] = fmt_bytes(s["bytes_out"])
        s["duration"] = str(datetime(2026, 4, 10, 8, 0, 0) - s["connected_since"]).split(".")[0]

    return render_template(
        "security_tools/vpn_monitoring.html",
        vpn_sessions=VPN_SESSIONS,
        tls_certs=TLS_CERTIFICATES,
        tls_expired=tls_expired,
        tls_expiring=tls_expiring,
        tls_noncompliant=tls_noncompliant,
        tls_versions=tls_versions,
    )


# ── Network Topology + GNS3 ───────────────────────────────────────────────────

_GNS3_DEVICES = [
    {"name": "TDM-RTR-CORE01", "type": "Cisco IOSv Router", "template": "Cisco IOSv 15.9(3)M4", "status": "running", "interfaces": ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"]},
    {"name": "TDM-FW-01", "type": "Cisco ASAv Firewall", "template": "Cisco ASAv 9.18.2", "status": "running", "interfaces": ["Management0/0", "GigabitEthernet0/0", "GigabitEthernet0/1"]},
    {"name": "TDM-SW-CORE01", "type": "Cisco IOSvL2 Switch", "template": "Cisco IOSvL2 15.2(7)", "status": "running", "interfaces": ["FastEthernet0/0", "FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"]},
    {"name": "TDM-WEB-01", "type": "Linux Ubuntu Server", "template": "Ubuntu 22.04.3 LTS", "status": "running", "interfaces": ["eth0"]},
    {"name": "TDM-DB-01", "type": "Linux Ubuntu Server", "template": "Ubuntu 22.04.3 LTS", "status": "running", "interfaces": ["eth0"]},
    {"name": "TDM-IDS-01", "type": "Linux Security Appliance", "template": "Ubuntu 22.04 + Suricata 7.0", "status": "running", "interfaces": ["eth0", "eth1"]},
    {"name": "TDM-IOT-GW01", "type": "Linux IoT Gateway", "template": "Raspberry Pi OS 64-bit", "status": "running", "interfaces": ["eth0", "wlan0"]},
    {"name": "TDM-CAMERA-01", "type": "IP Camera (Simulated)", "template": "Generic ONVIF Device", "status": "stopped", "interfaces": ["eth0"]},
    {"name": "TDM-PRINTER-HR", "type": "Network Printer", "template": "HP LaserJet (simulated)", "status": "stopped", "interfaces": ["eth0"]},
    {"name": "TDM-ATTACKER", "type": "Kali Linux Attack VM", "template": "Kali Linux 2024.1", "status": "running", "interfaces": ["eth0"]},
]


@security_tools_bp.route("/network-topology")
@login_required
def network_topology():
    gns3_status = {
        "server": "localhost",
        "port": 3080,
        "version": "2.2.44",
        "connected": True,
        "project_name": "Tadamun-SmartCity-Lab",
        "project_id": "a7f2c8d1-1234-4b5e-9a0c-8e3f12b45678",
        "nodes_total": len(_GNS3_DEVICES),
        "nodes_running": sum(1 for d in _GNS3_DEVICES if d["status"] == "running"),
        "nodes_stopped": sum(1 for d in _GNS3_DEVICES if d["status"] == "stopped"),
        "devices": _GNS3_DEVICES,
    }
    return render_template("security_tools/network_topology.html", gns3=gns3_status)


@security_tools_bp.route("/api/v1/gns3/status")
@login_required
def gns3_status_api():
    return jsonify({
        "server": "localhost:3080",
        "version": "2.2.44",
        "status": "connected",
        "project": "Tadamun-SmartCity-Lab",
        "nodes": _GNS3_DEVICES,
        "links": 14,
        "computes": [{"id": "local", "host": "127.0.0.1", "port": 3080, "protocol": "http", "connected": True}],
    })


# ── SIEM Logs (Splunk-style) ──────────────────────────────────────────────────

def _parse_spl_query(query_str: str):
    """Parse simplified SPL: key="value" [AND key="value"] pairs."""
    filters = {}
    pattern = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
    for key, value in pattern.findall(query_str):
        filters[key.lower()] = value
    return filters


def _apply_time_range(query, time_range: str):
    now = datetime.utcnow()
    ranges = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    delta = ranges.get(time_range)
    if delta:
        query = query.filter(SecurityEvent.timestamp >= now - delta)
    return query


@security_tools_bp.route("/siem-logs")
@login_required
def siem_logs():
    search_query = request.args.get("q", "")
    time_range = request.args.get("time_range", "24h")
    active_tab = request.args.get("tab", "events")

    q = SecurityEvent.query
    q = _apply_time_range(q, time_range)

    if search_query:
        spl = _parse_spl_query(search_query)
        if "source" in spl:
            val = spl["source"].replace("*", "%")
            q = q.filter(SecurityEvent.source.ilike(val))
        if "severity" in spl:
            val = spl["severity"].replace("*", "%")
            q = q.filter(SecurityEvent.severity.ilike(val))
        if "event_type" in spl:
            val = spl["event_type"].replace("*", "%")
            q = q.filter(SecurityEvent.event_type.ilike(val))
        if "source_ip" in spl:
            val = spl["source_ip"].replace("*", "%")
            q = q.filter(SecurityEvent.source_ip.ilike(val))

    events = q.order_by(SecurityEvent.timestamp.desc()).limit(500).all()

    # Stats
    base_q = _apply_time_range(SecurityEvent.query, time_range)
    stats = {
        "total": base_q.count(),
        "critical": base_q.filter_by(severity="critical").count(),
        "high": base_q.filter_by(severity="high").count(),
    }

    # Field facets (from full dataset in time range)
    all_events = base_q.all()
    from collections import Counter
    source_counts = dict(Counter(e.source for e in all_events).most_common(10))
    severity_counts = dict(Counter(e.severity for e in all_events).most_common())
    type_counts = dict(Counter(e.event_type for e in all_events).most_common(8))

    # Chart data — hourly buckets for last 24h
    now = datetime.utcnow()
    buckets = {}
    for h in range(23, -1, -1):
        label = (now - timedelta(hours=h)).strftime("%H:00")
        buckets[label] = 0
    chart_q = SecurityEvent.query.filter(SecurityEvent.timestamp >= now - timedelta(hours=24)).all()
    for e in chart_q:
        label = e.timestamp.strftime("%H:00")
        if label in buckets:
            buckets[label] += 1
    chart_labels = list(buckets.keys())
    chart_values = list(buckets.values())

    return render_template(
        "security_tools/siem_logs.html",
        events=events,
        stats=stats,
        search_query=search_query,
        time_range=time_range,
        active_tab=active_tab,
        source_counts=source_counts,
        severity_counts=severity_counts,
        type_counts=type_counts,
        chart_labels=chart_labels,
        chart_values=chart_values,
    )


@security_tools_bp.route("/siem-logs/search", methods=["POST"])
@login_required
def siem_search():
    data = request.get_json(silent=True) or {}
    query_str = data.get("query", "")
    time_range = data.get("time_range", "24h")

    q = SecurityEvent.query
    q = _apply_time_range(q, time_range)
    spl = _parse_spl_query(query_str)
    if "source" in spl:
        q = q.filter(SecurityEvent.source.ilike(spl["source"].replace("*", "%")))
    if "severity" in spl:
        q = q.filter(SecurityEvent.severity.ilike(spl["severity"].replace("*", "%")))
    if "event_type" in spl:
        q = q.filter(SecurityEvent.event_type.ilike(spl["event_type"].replace("*", "%")))
    if "source_ip" in spl:
        q = q.filter(SecurityEvent.source_ip.ilike(spl["source_ip"].replace("*", "%")))

    events = q.order_by(SecurityEvent.timestamp.desc()).limit(200).all()
    return jsonify({
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "severity": e.severity,
                "event_type": e.event_type,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "message": e.message,
                "raw_log": e.raw_log,
            }
            for e in events
        ],
    })


# ── Security Config ───────────────────────────────────────────────────────────

@security_tools_bp.route("/security-config")
@login_required
def security_config():
    return render_template("security_tools/security_config.html")


# ── Threat Intelligence ───────────────────────────────────────────────────────


# ── Incident Response (DFIR) ──────────────────────────────────────────────────

@security_tools_bp.route("/incident-response")
@login_required
@roles_required("admin", "security_analyst")
def incident_response():
    all_incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    by_status = {
        "new": [i for i in all_incidents if i.status == "new"],
        "investigating": [i for i in all_incidents if i.status == "investigating"],
        "contained": [i for i in all_incidents if i.status == "contained"],
        "resolved": [i for i in all_incidents if i.status == "resolved"],
    }
    return render_template("security_tools/incident_response.html",
                           incidents=all_incidents, by_status=by_status)


@security_tools_bp.route("/incident-response/<int:incident_id>")
@login_required
@roles_required("admin", "security_analyst")
def incident_detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    return render_template("security_tools/incident_detail.html", incident=incident)


@security_tools_bp.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
@login_required
@roles_required("admin", "security_analyst")
def update_incident_status(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    valid = {"new", "investigating", "contained", "resolved"}
    if new_status not in valid:
        return jsonify({"error": "Invalid status"}), 400
    incident.status = new_status
    incident.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "status": incident.status})


# ── Endpoint Security (EDR) ───────────────────────────────────────────────────

@security_tools_bp.route("/endpoint-security")
@login_required
def endpoint_security():
    agents = EndpointAgent.query.join(Device).order_by(Device.hostname).all()

    # Aggregate stats
    online = sum(1 for a in agents if a.status == "online")
    offline = sum(1 for a in agents if a.status == "offline")
    isolated = sum(1 for a in agents if a.isolated)
    total_threats = sum(a.threats_detected for a in agents)

    # Threats list from agents that have threat data
    threats = []
    for agent in agents:
        for t in agent.threats():
            t["hostname"] = agent.device.hostname if agent.device else "Unknown"
            threats.append(t)

    # Find compromised host for process tree
    compromised = next((a for a in agents if a.process_tree_json), None)

    # Pre-built hunt queries (descriptions only; results shown as sample)
    hunt_queries = [
        {"name": "Processes from Temp Directory", "query": "process.path: *\\Temp\\*.exe", "category": "Persistence", "matches": 3},
        {"name": "PowerShell Encoded Command", "query": "process.name: powershell.exe AND args: *-enc*", "category": "Execution", "matches": 7},
        {"name": "Unusual Parent-Child Relationship", "query": "process.parent.name: winword.exe AND process.name: cmd.exe", "category": "Initial Access", "matches": 1},
        {"name": "Network Connections from svchost", "query": "process.name: svchost.exe AND NOT network.destination.port: (80, 443, 135, 445)", "category": "C2", "matches": 4},
        {"name": "New Local Admin Account Created", "query": "event.type: creation AND winlog.event_id: 4720 AND group.name: Administrators", "category": "Privilege Escalation", "matches": 2},
        {"name": "LSASS Memory Access", "query": "event.type: access AND target.process.name: lsass.exe AND process.name: (NOT System)", "category": "Credential Access", "matches": 1},
        {"name": "Scheduled Task Created by Non-System", "query": "winlog.event_id: 4698 AND NOT process.name: svchost.exe", "category": "Persistence", "matches": 0},
        {"name": "Large Data Transfer to External IP", "query": "network.bytes_out > 100000000 AND NOT network.destination.ip: 192.168.*", "category": "Exfiltration", "matches": 2},
    ]

    return render_template(
        "security_tools/endpoint_security.html",
        agents=agents,
        online=online,
        offline=offline,
        isolated=isolated,
        total_threats=total_threats,
        threats=threats,
        compromised=compromised,
        hunt_queries=hunt_queries,
    )


@security_tools_bp.route("/api/endpoint/<int:agent_id>/isolate", methods=["POST"])
@login_required
def isolate_endpoint(agent_id):
    agent = EndpointAgent.query.get_or_404(agent_id)
    agent.isolated = not agent.isolated
    agent.status = "isolated" if agent.isolated else "online"
    db.session.commit()
    return jsonify({"ok": True, "isolated": agent.isolated, "status": agent.status})


# ── Attack Scenarios ──────────────────────────────────────────────────────────

_ATTACK_SCENARIOS = [
    {
        "id": "arp-poisoning",
        "name": "ARP Cache Poisoning",
        "type": "Man-in-the-Middle (MITM)",
        "severity": "critical",
        "mitre": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "phase": "Lateral Movement",
        "icon": "shield-exclamation",
        "summary": "Attacker broadcasts fake ARP replies to associate their MAC with a legitimate IP, redirecting all traffic through their device.",
        "how_it_works": (
            "ARP (Address Resolution Protocol) has no authentication. An attacker on the same LAN segment "
            "sends gratuitous ARP replies claiming that their MAC address corresponds to the gateway IP "
            "(e.g., 192.168.1.1). Victim devices update their ARP cache, and all traffic meant for the "
            "gateway is silently forwarded through the attacker — enabling eavesdropping, credential theft, "
            "and session hijacking."
        ),
        "indicators": [
            "Duplicate IP warnings in system logs",
            "ARP table shows same MAC for multiple IPs",
            "Sudden increase in network latency",
            "Unexpected SSL certificate warnings",
            "IDS alerts for ARP flooding",
        ],
        "mitigation": [
            "Enable Dynamic ARP Inspection (DAI) on managed switches",
            "Use static ARP entries for critical assets (gateway, DNS)",
            "Deploy network monitoring tools (XArp, ARPwatch)",
            "Enable port security / 802.1X authentication",
            "Use encrypted protocols (TLS/HTTPS) to limit damage if MITM succeeds",
        ],
        "cve_refs": ["CVE-2018-14767", "CVE-2020-12695"],
    },
    {
        "id": "syn-flood",
        "name": "SYN Flood (DoS)",
        "type": "Denial of Service",
        "severity": "high",
        "mitre": "T1498",
        "mitre_name": "Network Denial of Service",
        "phase": "Impact",
        "icon": "bolt",
        "summary": "Attacker sends thousands of TCP SYN packets with spoofed source IPs, exhausting the target's connection table.",
        "how_it_works": (
            "TCP handshake requires the server to allocate a half-open connection entry after receiving a SYN. "
            "By flooding with SYN packets from spoofed IPs, the attacker fills the server's SYN backlog queue. "
            "Legitimate connections are then refused because no queue space remains. "
            "Even a single attacker on a 100 Mbps link can overwhelm most unprotected servers."
        ),
        "indicators": [
            "High count of half-open TCP connections (SYN_RECV state)",
            "Server CPU/memory spike with no legitimate traffic",
            "Netstat shows thousands of SYN_RECV entries",
            "Firewall logs show rapid connection attempts from many IPs",
        ],
        "mitigation": [
            "Enable SYN cookies on the server OS (sysctl net.ipv4.tcp_syncookies=1)",
            "Configure firewall rate-limiting on inbound SYN packets",
            "Use a reverse proxy / load balancer with DDoS protection",
            "Deploy Cloudflare / AWS Shield or similar upstream scrubbing",
            "Increase the SYN backlog queue size (short-term workaround)",
        ],
        "cve_refs": [],
    },
    {
        "id": "ssh-brute-force",
        "name": "SSH Brute-Force Attack",
        "type": "Credential Access",
        "severity": "high",
        "mitre": "T1110",
        "mitre_name": "Brute Force",
        "phase": "Initial Access",
        "icon": "key",
        "summary": "Automated tool tries thousands of username/password combinations against SSH port 22 until one succeeds.",
        "how_it_works": (
            "Tools like Hydra, Medusa, and Metasploit's ssh_login module iterate through large password "
            "wordlists (rockyou.txt, etc.) and common usernames (admin, root, ubuntu). "
            "Without rate-limiting, a single attacker can try ~500 passwords/second. "
            "Once access is gained, the attacker has a persistent foothold."
        ),
        "indicators": [
            "Hundreds of failed login attempts in /var/log/auth.log",
            "Source IPs from unusual geographies",
            "Successful login immediately after multiple failures (pivoting)",
            "New user accounts or SSH keys added post-compromise",
        ],
        "mitigation": [
            "Disable password authentication — use SSH keys only",
            "Install Fail2Ban to auto-block IPs after N failures",
            "Move SSH to a non-standard port (security by obscurity, but reduces noise)",
            "Restrict SSH access by IP with firewall rules",
            "Enable multi-factor authentication (TOTP + key)",
        ],
        "cve_refs": ["CVE-2023-38408"],
    },
    {
        "id": "dns-spoofing",
        "name": "DNS Cache Poisoning",
        "type": "Man-in-the-Middle (MITM)",
        "severity": "critical",
        "mitre": "T1557.002",
        "mitre_name": "AiTM: DNS-based",
        "phase": "Collection",
        "icon": "globe-alt",
        "summary": "Attacker injects forged DNS responses into a resolver's cache, redirecting domain lookups to malicious IPs.",
        "how_it_works": (
            "Classic Kaminsky attack: attacker floods the DNS resolver with forged responses for a subdomain "
            "of the target domain, racing to guess the transaction ID before the legitimate response arrives. "
            "Once successful, all clients using that resolver resolve the domain to the attacker's IP — "
            "enabling phishing, credential harvesting, and malware delivery at scale."
        ),
        "indicators": [
            "DNS TTL values unexpectedly short or zero",
            "Certificate mismatch warnings for known-good sites",
            "DNS responses arriving from unexpected IPs",
            "Users reporting being redirected to look-alike login pages",
        ],
        "mitigation": [
            "Enable DNSSEC on authoritative zones",
            "Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) resolvers",
            "Randomize DNS source port and transaction IDs (BIND/Unbound do this by default)",
            "Monitor DNS traffic for anomalous TTL values",
            "Pin certificates (HSTS, HPKP) to limit phishing impact",
        ],
        "cve_refs": ["CVE-2008-1447"],
    },
    {
        "id": "port-scan",
        "name": "Network Reconnaissance (Port Scan)",
        "type": "Discovery",
        "severity": "medium",
        "mitre": "T1046",
        "mitre_name": "Network Service Discovery",
        "phase": "Reconnaissance",
        "icon": "magnifying-glass",
        "summary": "Attacker probes open ports across the network to map services, OS types, and potential entry points.",
        "how_it_works": (
            "Tools like Nmap send crafted TCP/UDP packets to each port and analyse responses "
            "(SYN-ACK = open, RST = closed, no response = filtered). "
            "Version detection (-sV) fingerprints running software. "
            "OS detection (-O) uses TCP/IP stack quirks. "
            "A full /24 sweep takes under 30 seconds with Nmap's default settings."
        ),
        "indicators": [
            "High volume of connection attempts to many ports from one source IP",
            "IDS/IPS alerts for port sweep or stealth scan",
            "Firewall logs showing RST flood pattern",
            "Service banners captured in attacker logs (indicative of successful fingerprinting)",
        ],
        "mitigation": [
            "Deploy IDS/IPS rules for port scan detection (Snort/Suricata)",
            "Rate-limit new connections per source IP at the firewall",
            "Close or firewall all unused ports",
            "Return no banner on services (suppress version info)",
            "Segment the network — limit blast radius of any single scan",
        ],
        "cve_refs": [],
    },
    {
        "id": "eternalblue",
        "name": "SMB Exploit — EternalBlue",
        "type": "Lateral Movement / RCE",
        "severity": "critical",
        "mitre": "T1021.002",
        "mitre_name": "Remote Services: SMB/Windows Admin Shares",
        "phase": "Lateral Movement",
        "icon": "bug-ant",
        "summary": "NSA-developed exploit targeting SMBv1 (MS17-010) allows unauthenticated remote code execution on Windows systems.",
        "how_it_works": (
            "EternalBlue exploits a buffer overflow in the SMBv1 implementation (srv.sys) in Windows. "
            "By sending a specially crafted SMB negotiation request, the attacker achieves arbitrary kernel "
            "code execution without credentials. WannaCry ransomware used this exact vector in May 2017, "
            "infecting 200,000+ machines in 150 countries within 24 hours. "
            "Any unpatched Windows 7/Server 2008 with SMB port 445 exposed is vulnerable."
        ),
        "indicators": [
            "Unexpected SMB traffic from workstations to servers",
            "Port 445 connections from non-file-server IPs",
            "Event ID 4625 (failed logon) + 4624 (success) in sequence",
            "New services or scheduled tasks created on servers",
            "Ransomware encryption activity (file extensions changing en masse)",
        ],
        "mitigation": [
            "Apply MS17-010 patch immediately (KB4012212)",
            "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "Block port 445 at perimeter and between VLANs",
            "Deploy endpoint detection (EDR) to catch shellcode execution",
            "Segment servers from workstations — limit lateral movement paths",
        ],
        "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
    },
    {
        "id": "evil-twin",
        "name": "Evil Twin / Rogue Access Point",
        "type": "Wireless MITM",
        "severity": "high",
        "mitre": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "phase": "Initial Access",
        "icon": "wifi",
        "summary": "Attacker creates a fake Wi-Fi AP with the same SSID as a legitimate network; victims auto-connect and traffic is intercepted.",
        "how_it_works": (
            "Using tools like hostapd-wpe or airbase-ng, an attacker broadcasts an SSID identical to the "
            "corporate or home network. If the signal is stronger, devices automatically connect. "
            "The attacker runs a captive portal or transparent proxy, capturing credentials, "
            "session cookies, and unencrypted traffic. WPA2-Enterprise is attacked via a spoofed RADIUS "
            "server to harvest NTLM hashes."
        ),
        "indicators": [
            "Duplicate SSIDs visible in wireless scans with different BSSIDs",
            "Devices authenticating to unexpected MAC addresses",
            "Wireless IDS alerts for rogue AP",
            "Users reporting captive portal appearing on known networks",
        ],
        "mitigation": [
            "Deploy Wireless IDS (WIDS) to detect rogue APs (Kismet, Cisco Aironet)",
            "Use WPA3 or WPA2-Enterprise with certificate-based authentication",
            "Enable HTTPS-only and HSTS on all internal web services",
            "Configure 802.1X with mutual authentication (EAP-TLS)",
            "Educate users never to accept unexpected certificate warnings",
        ],
        "cve_refs": [],
    },
    {
        "id": "c2-beacon",
        "name": "Malware C2 Beacon (Command & Control)",
        "type": "Command & Control",
        "severity": "critical",
        "mitre": "T1071",
        "mitre_name": "Application Layer Protocol",
        "phase": "C2",
        "icon": "server",
        "summary": "Compromised host periodically contacts an attacker-controlled server (C2) to receive commands and exfiltrate data.",
        "how_it_works": (
            "Modern malware (RATs, botnets, ransomware loaders) use encrypted HTTP/S beacons to blend with "
            "normal web traffic. The malware calls home every N seconds with a unique victim identifier, "
            "receives commands (download payload, execute, exfiltrate files), and sends back results. "
            "Frameworks like Cobalt Strike, Metasploit's Meterpreter, and Sliver all use this pattern. "
            "DNS tunneling is used when HTTP is blocked — queries to attacker-controlled domains carry data."
        ),
        "indicators": [
            "Regular outbound connections at fixed intervals (jitter ± few seconds)",
            "Connections to recently registered or unusual domains",
            "Large DNS TXT record queries (DNS tunneling)",
            "Encrypted traffic to IPs with no reverse DNS or ASN reputation",
            "Processes making network calls that should not (e.g., notepad.exe)",
        ],
        "mitigation": [
            "Deploy DNS filtering (Cisco Umbrella, Pi-hole with threat feeds)",
            "Block outbound connections from servers that don't need internet",
            "Use EDR to detect anomalous process network activity",
            "Enable TLS inspection on the perimeter proxy",
            "Implement network segmentation to limit C2 reachability",
        ],
        "cve_refs": ["CVE-2021-44228"],
    },
]


@security_tools_bp.route("/attack-scenarios")
@login_required
def attack_scenarios():
    devices = Device.query.with_entities(Device.id, Device.hostname, Device.ip_address).limit(20).all()
    device_pool = [{"hostname": d.hostname, "ip": d.ip_address} for d in devices]

    scenarios = []
    rng = random.Random(42)
    for s in _ATTACK_SCENARIOS:
        affected = rng.sample(device_pool, min(2, len(device_pool))) if device_pool else []
        scenarios.append({**s, "affected_devices": affected})

    severity_counts = {
        "critical": sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "critical"),
        "high": sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "high"),
        "medium": sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "medium"),
        "low": sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "low"),
    }

    return render_template(
        "security_tools/attack_scenarios.html",
        scenarios=scenarios,
        severity_counts=severity_counts,
    )
