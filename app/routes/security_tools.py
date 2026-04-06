from flask import Blueprint, render_template, current_app, jsonify
from flask_login import login_required
from app.models.scan_result import ScanResult
from app.models.security_event import SecurityEvent
from app.models.device import Device
from app.models.vulnerability import Vulnerability
from app.extensions import db
import json
import random
from pathlib import Path

security_tools_bp = Blueprint("security_tools", __name__)

@security_tools_bp.route("/scan-results/nmap")
@login_required
def nmap_results():
    scans = ScanResult.query.filter(ScanResult.scan_type.in_(["nmap", "nmap_real"])).order_by(ScanResult.scan_date.desc()).all()
    results = []
    for scan in scans:
        if isinstance(scan.parsed_results, str):
            try:
                data = json.loads(scan.parsed_results)
            except:
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
            "findings": scan.findings_count
        })
    return render_template("security_tools/nmap_results.html", results=results)

@security_tools_bp.route("/traffic-analysis")
@login_required
def traffic_analysis():
    # In a real app, this would parse a file or read from DB
    # For now, we'll read the sample CSV file
    csv_path = Path("data/sample_pcap_analysis.csv")
    from app.scanners.wireshark_parser import parse_wireshark_csv
    if csv_path.exists():
        with open(csv_path, "r") as f:
            analysis = parse_wireshark_csv(f.read())
    else:
        analysis = {"total_packets": 0, "anomalies": [], "anomaly_count": 0, "normal_traffic_pct": 0}
    
    return render_template("security_tools/traffic_analysis.html", analysis=analysis)

@security_tools_bp.route("/exploit-verification")
@login_required
def exploit_verification():
    json_path = Path("data/sample_metasploit.json")
    from app.scanners.metasploit_parser import parse_metasploit_json
    if json_path.exists():
        with open(json_path, "r") as f:
            msf_data = parse_metasploit_json(f.read())
    else:
        msf_data = {"results": [], "total": 0, "vulnerable_count": 0, "not_vulnerable_count": 0, "error_count": 0}
    
    return render_template("security_tools/exploit_verification.html", msf_data=msf_data)

@security_tools_bp.route("/network-topology")
@login_required
def network_topology():
    return render_template("security_tools/network_topology.html")

@security_tools_bp.route("/siem-logs")
@login_required
def siem_logs():
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    
    # Summary stats
    stats = {
        "total": SecurityEvent.query.count(),
        "critical": SecurityEvent.query.filter_by(severity="critical").count(),
        "high": SecurityEvent.query.filter_by(severity="high").count(),
    }
    
    return render_template("security_tools/siem_logs.html", events=events, stats=stats)

@security_tools_bp.route("/security-config")
@login_required
def security_config():
    # All static/simulated data as requested
    return render_template("security_tools/security_config.html")


# ── Attack Scenario definitions ──────────────────────────────────────────────
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
    # Attach 1-2 real device names to each scenario for context
    devices = Device.query.with_entities(Device.id, Device.hostname, Device.ip_address).limit(20).all()
    device_pool = [{"hostname": d.hostname, "ip": d.ip_address} for d in devices]

    scenarios = []
    rng = random.Random(42)  # deterministic seed so the page doesn't change on refresh
    for s in _ATTACK_SCENARIOS:
        affected = rng.sample(device_pool, min(2, len(device_pool))) if device_pool else []
        scenarios.append({**s, "affected_devices": affected})

    severity_counts = {
        "critical": sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "critical"),
        "high":     sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "high"),
        "medium":   sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "medium"),
        "low":      sum(1 for s in _ATTACK_SCENARIOS if s["severity"] == "low"),
    }

    return render_template(
        "security_tools/attack_scenarios.html",
        scenarios=scenarios,
        severity_counts=severity_counts,
    )
