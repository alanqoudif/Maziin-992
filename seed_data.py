import csv
import random
import json
from datetime import datetime, timedelta
from pathlib import Path

from app import create_app
from app.ai.model import train_and_compare
from app.ai.scoring import weighted_risk_score
from app.extensions import db
from app.models.alert import Alert
from app.models.device import Device
from app.models.patch import Patch
from app.models.scan_result import ScanResult
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.mitre import MitreAttack
from app.models.security_event import SecurityEvent
from app.models.incident import Incident
from app.models.endpoint_agent import EndpointAgent
from app.scanners.simulator import generate_devices, save_topology
from app.scanners.nmap_parser import parse_nmap_xml
from app.scanners.wireshark_parser import parse_wireshark_csv
from app.scanners.metasploit_parser import parse_metasploit_json

REALISTIC_VULN_TEMPLATES = [
    ("Apache Log4j Remote Code Execution", "A vulnerable Log4j dependency allows unauthenticated remote code execution via crafted JNDI payloads."),
    ("OpenSSH Authentication Bypass", "An authentication logic weakness can allow remote users to bypass intended access checks on exposed SSH services."),
    ("Microsoft Exchange Privilege Escalation", "A chain of Exchange flaws may allow authenticated attackers to escalate privileges and access mailbox data."),
    ("Fortinet SSL-VPN Out-of-Bounds Write", "A memory handling flaw in SSL-VPN can be exploited to execute arbitrary code on perimeter gateways."),
    ("Cisco IOS XE Web UI Privilege Abuse", "Improper access controls in management endpoints can permit privilege escalation and unauthorized configuration changes."),
    ("VMware vCenter Server Remote Code Execution", "Unsafe input handling in vCenter management services may allow remote code execution under privileged context."),
    ("Kubernetes API Server Authorization Bypass", "Authorization checks can be bypassed in specific API paths, exposing cluster resources."),
    ("Nginx HTTP Request Smuggling", "Malformed request parsing can desynchronize upstream and downstream proxies, enabling cache poisoning and session hijack."),
    ("PostgreSQL Extension Privilege Escalation", "A vulnerable extension allows local database users to execute commands with elevated permissions."),
    ("Windows SMB Remote Code Execution", "Crafted SMB packets can trigger memory corruption and remote code execution on unpatched hosts."),
    ("Apache Tomcat Session Fixation", "Session token handling allows attackers to force known session identifiers and hijack authenticated sessions."),
    ("Oracle WebLogic Deserialization RCE", "Unsafe deserialization in admin services enables unauthenticated remote code execution."),
]

MITRE_TECHNIQUES = [
    {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    {"technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access"},
    {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
    {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic": "Execution"},
    {"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement"},
    {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
    {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
    {"technique_id": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access"},
    {"technique_id": "T1562", "technique_name": "Impair Defenses", "tactic": "Defense Evasion"},
    {"technique_id": "T1070", "technique_name": "Indicator Removal", "tactic": "Defense Evasion"},
    {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
    {"technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery"},
    {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"technique_id": "T1499", "technique_name": "Endpoint Denial of Service", "tactic": "Impact"},
    {"technique_id": "T1557", "technique_name": "Adversary-in-the-Middle", "tactic": "Collection"},
    {"technique_id": "T1595", "technique_name": "Active Scanning", "tactic": "Reconnaissance"},
    {"technique_id": "T1592", "technique_name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
]

ALERT_MESSAGE_TEMPLATES = {
    "critical_vuln": [
        "Critical CVE {cve_id} detected on {hostname}; immediate containment is required.",
        "High-risk vulnerability {cve_id} is exploitable on {hostname} and impacts core services.",
    ],
    "exploit_detected": [
        "Exploit activity pattern matched against {cve_id} on {hostname}; IDS correlation score exceeded threshold.",
        "Metasploit-like behavior observed on {hostname}; possible active exploitation targeting {cve_id}.",
    ],
    "compliance_violation": [
        "Control gap detected: {hostname} is missing required hardening baseline for quarterly audit.",
        "{hostname} failed policy validation for privileged access and logging retention requirements.",
    ],
    "anomaly": [
        "Network anomaly detected from {hostname}; east-west traffic deviates from learned baseline.",
        "Behavioral anomaly flagged on {hostname}; process telemetry indicates unusual execution chain.",
    ],
}

PATCH_RECOMMENDATIONS = {
    "critical": "Apply emergency patch within 24 hours and isolate exposed services until validation is complete.",
    "high": "Patch in the next 72 hours and enforce temporary compensating controls at the network edge.",
    "medium": "Schedule patch in the next maintenance window and monitor exploit telemetry daily.",
    "low": "Apply patch in the standard monthly cycle and track remediation in backlog governance.",
}

def synthetic_dataset(path="data/cve_dataset.csv", rows=2000):
    Path("data").mkdir(exist_ok=True)
    fields = [
        "cvss_base_score",
        "exploitability_score",
        "impact_score",
        "asset_criticality",
        "network_exposure",
        "exploit_available",
        "days_since_published",
        "device_type",
        "mitre_attack_technique_count",
        "risk_priority",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for _ in range(rows):
            cvss = round(random.uniform(2.0, 10.0), 1)
            expl = round(random.uniform(1.0, 10.0), 1)
            impact = round(random.uniform(1.0, 10.0), 1)
            crit = random.choice(["low", "medium", "high", "critical"])
            exposure = round(random.uniform(0.1, 1.0), 2)
            exploit_available = random.choice([0, 1])
            days = random.randint(1, 2000)
            device_type = random.choice(["server", "firewall", "ids", "workstation", "printer"])
            mitre_count = random.randint(0, 12)
            composite = cvss * 0.4 + expl * 0.2 + impact * 0.2 + exposure * 2 + exploit_available
            risk = 4 if composite >= 8 else 3 if composite >= 6 else 2 if composite >= 4 else 1
            writer.writerow(
                {
                    "cvss_base_score": cvss,
                    "exploitability_score": expl,
                    "impact_score": impact,
                    "asset_criticality": crit,
                    "network_exposure": exposure,
                    "exploit_available": exploit_available,
                    "days_since_published": days,
                    "device_type": device_type,
                    "mitre_attack_technique_count": mitre_count,
                    "risk_priority": risk,
                }
            )

def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        Path("ml_models").mkdir(exist_ok=True)
        synthetic_dataset()
        train_and_compare("data/cve_dataset.csv", "ml_models/vulnerability_model.pkl")
        save_topology("data/tadamun_network.json")

        # Seed Users
        users = [
            ("admin", "admin@tadamun.om", "admin", "admin"),
            ("analyst", "analyst@tadamun.om", "analyst123", "security_analyst"),
            ("netadmin", "netadmin@tadamun.om", "netadmin123", "network_admin"),
            ("viewer", "viewer@tadamun.om", "viewer123", "viewer"),
        ]
        for username, email, password, role in users:
            u = User(username=username, email=email, role=role)
            u.set_password(password)
            db.session.add(u)

        # Seed MITRE Techniques
        mitre_objs = []
        for t in MITRE_TECHNIQUES:
            obj = MitreAttack(
                technique_id=t["technique_id"],
                technique_name=t["technique_name"],
                tactic=t["tactic"],
                description=f"Description for {t['technique_name']}",
                url=f"https://attack.mitre.org/techniques/{t['technique_id']}/"
            )
            db.session.add(obj)
            mitre_objs.append(obj)
        db.session.flush()

        # Seed Devices
        devices = []
        for d in generate_devices(200):
            device = Device(**d)
            db.session.add(device)
            devices.append(device)
        db.session.flush()

        # Seed Vulnerabilities
        severities = ["critical", "high", "medium", "low"]
        vuln_list = []
        for i in range(500):
            severity = random.choices(severities, weights=[0.15, 0.35, 0.35, 0.15], k=1)[0]
            cvss = {"critical": random.uniform(9, 10), "high": random.uniform(7, 8.9), "medium": random.uniform(4, 6.9), "low": random.uniform(0.1, 3.9)}[severity]
            title, description = random.choice(REALISTIC_VULN_TEMPLATES)
            vuln = Vulnerability(
                cve_id=f"CVE-{2020 + i % 6}-{1000 + i}",
                title=title,
                description=description,
                cvss_base_score=round(cvss, 1),
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity=severity,
                exploitability_score=round(random.uniform(1, 10), 1),
                impact_score=round(random.uniform(1, 10), 1),
                status=random.choice(["open", "patched", "accepted_risk", "false_positive"]),
                discovered_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                exploit_availability=random.choice([True, False]),
                network_exposure_factor=round(random.uniform(0.1, 1), 2),
            )
            vuln.affected_devices = random.sample(devices, k=random.randint(1, 6))
            
            # Logical MITRE Mapping
            if "RCE" in title or "Code Execution" in title:
                vuln.mitre_techniques.append(next(t for t in mitre_objs if t.technique_id == "T1190"))
            if "SSH" in title:
                vuln.mitre_techniques.extend([t for t in mitre_objs if t.technique_id in ["T1021", "T1110"]])
            if not vuln.mitre_techniques:
                vuln.mitre_techniques = random.sample(mitre_objs, k=random.randint(1, 3))

            row = {
                "cvss_base_score": vuln.cvss_base_score,
                "exploitability_score": vuln.exploitability_score,
                "impact_score": vuln.impact_score,
                "asset_criticality": {"critical": 4, "high": 3, "medium": 2, "low": 1}[random.choice(["critical", "high", "medium", "low"])],
                "network_exposure": vuln.network_exposure_factor,
                "exploit_available": 1 if vuln.exploit_availability else 0,
            }
            vuln.asset_criticality_factor = float(row["asset_criticality"])
            vuln.ai_risk_score = weighted_risk_score(row)
            vuln_list.append(vuln)
            db.session.add(vuln)
        db.session.flush()

        sorted_v = sorted(vuln_list, key=lambda v: v.ai_risk_score, reverse=True)
        for idx, v in enumerate(sorted_v, 1):
            v.ai_priority_rank = idx

        # Seed Patches
        for v in vuln_list[:350]:
            urgency = random.choice(["critical", "high", "medium", "low"])
            db.session.add(
                Patch(
                    vulnerability=v,
                    patch_name=f"Patch for {v.cve_id}",
                    vendor=random.choice(["Microsoft", "Cisco", "Canonical", "RedHat"]),
                    release_date=datetime.utcnow() - timedelta(days=random.randint(1, 90)),
                    urgency=urgency,
                    recommendation=PATCH_RECOMMENDATIONS[urgency],
                    status=random.choice(["pending", "scheduled", "applied", "failed"]),
                )
            )

        # Seed Scan Results using generated sample data
        nmap_xml_path = Path("data/sample_nmap_scan.xml")
        if nmap_xml_path.exists():
             with open(nmap_xml_path, "r") as f:
                 nmap_hosts = parse_nmap_xml(f.read())
                 for h in nmap_hosts[:20]: # Only a few scan results in DB for demo
                     dev = next((d for d in devices if d.ip_address == h["ip"]), random.choice(devices))
                     db.session.add(ScanResult(
                         scan_type="nmap",
                         device=dev,
                         raw_output="SIMULATED NMAP XML DATA",
                         parsed_results=h,
                         findings_count=h["findings_count"]
                     ))

        wireshark_csv_path = Path("data/sample_pcap_analysis.csv")
        if wireshark_csv_path.exists():
             with open(wireshark_csv_path, "r") as f:
                 traffic_data = parse_wireshark_csv(f.read())
                 for i in range(5):
                      db.session.add(ScanResult(
                          scan_type="wireshark",
                          device=random.choice(devices),
                          parsed_results=traffic_data,
                          findings_count=traffic_data["anomaly_count"]
                      ))

        msf_json_path = Path("data/sample_metasploit.json")
        if msf_json_path.exists():
             with open(msf_json_path, "r") as f:
                 msf_data = parse_metasploit_json(f.read())
                 for r in msf_data["vulnerable"]:
                      dev = next((d for d in devices if d.ip_address == r["target_host"]), random.choice(devices))
                      db.session.add(ScanResult(
                          scan_type="metasploit",
                          device=dev,
                          parsed_results=r,
                          findings_count=1
                      ))

        # Seed Security Events (SIEM Logs)
        sources = ["Firewall", "IDS/IPS", "SIEM", "Endpoint"]
        event_types = ["Intrusion Attempt", "Login Failure", "Policy Violation", "Unauthorized Process"]
        severities = ["critical", "high", "medium", "low", "info"]
        
        for i in range(500):
            source = random.choice(sources)
            severity = random.choice(severities)
            event_type = random.choice(event_types)
            device = random.choice(devices)
            
            message = f"[{source}] {event_type} detected on {device.hostname}"
            if "Log4j" in message:
                 severity = "critical"
            
            db.session.add(SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(minutes=random.randint(1, 10000)),
                source=source,
                event_type=event_type,
                severity=severity,
                source_ip=f"203.0.{random.randint(100, 200)}.{random.randint(1, 254)}",
                dest_ip=device.ip_address,
                message=message,
                raw_log=f"CEF:0|Tadamun|SOC|1.0|{i}|{event_type}|{severity.upper()}|src={device.ip_address}",
                device=device
            ))

        # Seed Alerts (using original templates but updated with more context)
        for _ in range(120):
            alert_type = random.choice(["critical_vuln", "exploit_detected", "compliance_violation", "anomaly"])
            device = random.choice(devices)
            vulnerability = random.choice(vuln_list)
            message_template = random.choice(ALERT_MESSAGE_TEMPLATES[alert_type])
            message = message_template.format(cve_id=vulnerability.cve_id, hostname=device.hostname)
            db.session.add(
                Alert(
                    alert_type=alert_type,
                    severity=random.choice(["critical", "high", "medium", "low"]),
                    message=message,
                    device=device,
                    vulnerability=vulnerability,
                    is_read=random.choice([True, False]),
                )
            )
            
        # ── OpenVAS scan results ──────────────────────────────────────────────
        openvas_xml_path = Path("data/sample_openvas_report.xml")
        if openvas_xml_path.exists():
            from app.scanners.openvas_parser import parse_openvas_xml
            with open(openvas_xml_path, "r") as f:
                ov_data = parse_openvas_xml(f.read())
                for r in ov_data["results"][:15]:
                    dev = next(
                        (d for d in devices if d.ip_address == r["host"]),
                        random.choice(devices)
                    )
                    db.session.add(ScanResult(
                        scan_type="openvas",
                        device=dev,
                        raw_output=f"OpenVAS NVT {r['nvt_oid']}",
                        parsed_results=r,
                        findings_count=1,
                    ))

        # ── Incidents (DFIR) ─────────────────────────────────────────────────
        _NOW = datetime.utcnow()
        _INCIDENTS = [
            {
                "incident_id": "INC-2026-0001",
                "title": "Log4Shell RCE Exploitation — Tadamun App Server",
                "severity": "critical",
                "status": "investigating",
                "assigned_to": "analyst",
                "description": "Active exploitation of CVE-2021-44228 (Log4Shell) detected on TDM-APP-01 (192.168.20.50:8080). JNDI callback observed to external attacker-controlled LDAP server (45.142.212.18:1389). Possible initial access achieved.",
                "timeline": [
                    {"time": "2026-04-10 04:12:33", "actor": "Suricata IDS", "action": "Alert: Log4Shell JNDI injection detected in HTTP User-Agent header"},
                    {"time": "2026-04-10 04:13:01", "actor": "SIEM", "action": "Correlated with outbound LDAP connection to 45.142.212.18:1389"},
                    {"time": "2026-04-10 04:20:00", "actor": "analyst", "action": "Incident created and investigation initiated"},
                    {"time": "2026-04-10 04:35:00", "actor": "analyst", "action": "Network isolation applied to 192.168.20.50 pending forensic review"},
                ],
                "iocs": [
                    {"type": "IP", "value": "45.142.212.18", "description": "LDAP C2 server"},
                    {"type": "URL", "value": "ldap://45.142.212.18:1389/exploit", "description": "JNDI payload URL"},
                    {"type": "Pattern", "value": "${jndi:ldap://45.142.212.18:1389/}", "description": "Log4Shell payload in User-Agent"},
                ],
                "evidence": [
                    {"type": "Network Capture", "name": "tdm-app01-pcap-2026-04-10.pcap", "size": "42.3 MB", "hash": "a3f3e7f44f17c61e2d4d5b2c10e9f872bd45f0e1c7d2a9b3e8c5d7e1f0a2b4c6", "collected": "2026-04-10 04:40:00"},
                    {"type": "Log File", "name": "catalina.out.2026-04-10.gz", "size": "8.1 MB", "hash": "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef", "collected": "2026-04-10 04:42:00"},
                ],
                "recommended_actions": "1. Immediately isolate 192.168.20.50 from network\n2. Update Log4j to 2.17.1+ across all Java applications\n3. Block outbound connections to 45.142.212.18 at firewall\n4. Search all application logs for JNDI patterns\n5. Reset all credentials on affected host\n6. Deploy WAF rule blocking ${jndi: in all input fields",
            },
            {
                "incident_id": "INC-2026-0002",
                "title": "SMB Lateral Movement — Finance to Data Center",
                "severity": "high",
                "status": "contained",
                "assigned_to": "analyst",
                "description": "Suspicious SMB traffic detected from Finance VLAN (192.168.20.x) to Data Center servers (192.168.40.x). PsExec artifacts identified. Source host: TDM-FIN-WS-14. Possible insider threat or compromised Finance workstation.",
                "timeline": [
                    {"time": "2026-04-09 22:30:00", "actor": "Snort IDS", "action": "Alert: PsExec lateral movement signature detected on VLAN 20→40"},
                    {"time": "2026-04-09 22:45:00", "actor": "SIEM", "action": "Correlation: TDM-FIN-WS-14 attempted connections to 12 servers in DC VLAN"},
                    {"time": "2026-04-09 23:00:00", "actor": "analyst", "action": "Firewall rule applied blocking TDM-FIN-WS-14 from VLAN 40"},
                    {"time": "2026-04-10 00:15:00", "actor": "analyst", "action": "Memory dump acquired from TDM-FIN-WS-14"},
                ],
                "iocs": [
                    {"type": "Hostname", "value": "TDM-FIN-WS-14", "description": "Source workstation"},
                    {"type": "Tool", "value": "PSEXESVC", "description": "PsExec service binary found in C:\\Windows\\"},
                    {"type": "IP", "value": "192.168.20.114", "description": "Source IP of lateral movement"},
                ],
                "evidence": [
                    {"type": "Memory Dump", "name": "TDM-FIN-WS-14-memory.dmp", "size": "16.0 GB", "hash": "84c82835a5d21bbcf75a61706d8ab549c41b8fd", "collected": "2026-04-10 00:30:00"},
                    {"type": "Registry Hive", "name": "TDM-FIN-WS-14-SYSTEM.hiv", "size": "22.1 MB", "hash": "d7e2f0b4c8a1e3d5f7b9a2c4e6d8f0b2a4c6e8d0f2b4a6c8e0d2f4b6a8c0e2", "collected": "2026-04-10 00:35:00"},
                ],
                "recommended_actions": "1. Forensic analysis of TDM-FIN-WS-14 memory dump\n2. Check for additional PsExec artifacts on DC servers\n3. Review Active Directory logs for privilege escalation\n4. Implement VLAN ACL blocking Finance→DC SMB (port 445)\n5. Enable Windows Defender Credential Guard on all workstations",
            },
            {
                "incident_id": "INC-2026-0003",
                "title": "SSH Brute-Force — External to HR Server",
                "severity": "high",
                "status": "new",
                "assigned_to": "netadmin",
                "description": "Hydra SSH brute-force attack detected from 91.196.8.79 (Ukraine) against TDM-HR-SRV-01 (192.168.30.15:22). 3 credentials successfully cracked. Attacker may have gained access.",
                "timeline": [
                    {"time": "2026-04-10 06:30:00", "actor": "Fail2Ban", "action": "Rate limiting triggered after 200 failed SSH attempts"},
                    {"time": "2026-04-10 06:31:00", "actor": "Suricata", "action": "Alert: Hydra SSH brute-force signature matched (libssh agent string)"},
                    {"time": "2026-04-10 06:58:00", "actor": "Auth Log", "action": "Successful SSH login from 91.196.8.79 with user 'backup'"},
                    {"time": "2026-04-10 07:05:00", "actor": "SIEM", "action": "Correlated alert: new incident created automatically"},
                ],
                "iocs": [
                    {"type": "IP", "value": "91.196.8.79", "description": "Attack source (AS56694, Ukraine)"},
                    {"type": "User", "value": "backup", "description": "Compromised credential"},
                    {"type": "Tool", "value": "Hydra 9.5", "description": "Brute-force tool (identified from libssh agent string)"},
                ],
                "evidence": [
                    {"type": "Log File", "name": "auth.log.2026-04-10", "size": "1.2 MB", "hash": "2eb14920c75d5e73264f77cfa273ad2c2a1b8f7de9be6d4ffa9b7a5c1f0e4d8a", "collected": "2026-04-10 07:10:00"},
                ],
                "recommended_actions": "1. Block 91.196.8.79 at firewall immediately\n2. Disable 'backup' account and rotate SSH keys\n3. Disable SSH password authentication — keys only\n4. Install Fail2Ban with aggressive thresholds (3 attempts → 1h ban)\n5. Consider moving SSH to non-standard port\n6. Audit all files accessed in the backup user's session",
            },
            {
                "incident_id": "INC-2026-0004",
                "title": "Ransomware Beaconing — Possible Infection Stage",
                "severity": "critical",
                "status": "new",
                "assigned_to": "analyst",
                "description": "Endpoint TDM-IT-WS-07 (192.168.10.107) showing periodic HTTP beaconing to known LockBit 3.0 infrastructure (104.236.178.134). Beacon interval: ~300s with ±10s jitter. No encryption observed yet — possible pre-encryption staging phase.",
                "timeline": [
                    {"time": "2026-04-10 03:00:00", "actor": "EDR", "action": "Behavioral alert: periodic outbound connection at fixed interval detected"},
                    {"time": "2026-04-10 03:05:00", "actor": "Threat Intel", "action": "IP 104.236.178.134 matched LockBit 3.0 C2 IOC feed"},
                    {"time": "2026-04-10 03:10:00", "actor": "SIEM", "action": "Critical priority incident auto-created — ransomware precursor activity"},
                ],
                "iocs": [
                    {"type": "IP", "value": "104.236.178.134", "description": "LockBit C2 server (DigitalOcean)"},
                    {"type": "SHA256", "value": "a3f3e7f44f17c61e2d4d5b2c10e9f872bd45f0e1c7d2a9b3e8c5d7e1f0a2b4c6", "description": "Beacon DLL loaded by explorer.exe"},
                    {"type": "Domain", "value": "update-service.cloud", "description": "C2 domain used for beacon"},
                ],
                "evidence": [
                    {"type": "Process Memory", "name": "explorer.exe-3421-2026-04-10.dmp", "size": "128 MB", "hash": "a3f3e7f44f17c61e2d4d5b2c10e9f872bd45f0e1c7d2a9b3e8c5d7e1f0a2b4c6", "collected": "2026-04-10 03:15:00"},
                ],
                "recommended_actions": "1. IMMEDIATELY isolate TDM-IT-WS-07 from network\n2. Block 104.236.178.134 and update-service.cloud at DNS and firewall\n3. Take full disk image of TDM-IT-WS-07 before any remediation\n4. Search all endpoints for the beacon DLL SHA256 hash\n5. Scan all shared drives for partial encryption (.locked, .lockbit extensions)\n6. Alert management — activate Ransomware Response Plan",
            },
            {
                "incident_id": "INC-2026-0005",
                "title": "Insider Data Exfiltration — HR Records",
                "severity": "high",
                "status": "resolved",
                "assigned_to": "analyst",
                "description": "DLP alert: HR manager account (maryam.alhashmi) uploaded 2.4 GB archive to personal Google Drive at 02:14 AM. Archive appears to contain employee records (HRMS export). Access at unusual hours suggests malicious intent.",
                "timeline": [
                    {"time": "2026-04-08 02:14:22", "actor": "DLP System", "action": "Alert: Large HTTPS upload to drive.google.com from hr.tadamun.local"},
                    {"time": "2026-04-08 02:15:00", "actor": "SIEM", "action": "Correlated with after-hours user activity (outside policy window 08:00-18:00)"},
                    {"time": "2026-04-08 08:00:00", "actor": "analyst", "action": "Incident reviewed — HR manager account suspended pending investigation"},
                    {"time": "2026-04-09 14:00:00", "actor": "Legal", "action": "Confirmed malicious intent — employee terminated, police report filed"},
                    {"time": "2026-04-09 16:00:00", "actor": "analyst", "action": "Incident resolved — Google reported, data takedown request submitted"},
                ],
                "iocs": [
                    {"type": "User", "value": "maryam.alhashmi", "description": "Insider threat — HR Manager"},
                    {"type": "Domain", "value": "drive.google.com", "description": "Exfiltration destination"},
                    {"type": "File", "value": "hr_export_all_2026.zip", "description": "Exfiltrated archive (2.4 GB)"},
                ],
                "evidence": [
                    {"type": "Network Log", "name": "proxy-logs-2026-04-08.csv", "size": "44 MB", "hash": "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef", "collected": "2026-04-08 09:00:00"},
                    {"type": "HRMS Export Log", "name": "hrms-audit-trail.pdf", "size": "1.1 MB", "hash": "84c82835a5d21bbcf75a61706d8ab549c41b8fd", "collected": "2026-04-08 09:30:00"},
                ],
                "recommended_actions": "1. Implement DLP policy blocking uploads >500MB to personal cloud storage\n2. Enable after-hours activity alerts for all privileged accounts\n3. Apply principle of least privilege — HR bulk export should require manager approval\n4. Conduct security awareness training for HR department\n5. Review all HRMS bulk export logs for past 90 days",
            },
            {
                "incident_id": "INC-2026-0006",
                "title": "OpenVAS Critical Finding — Unauthenticated Redis",
                "severity": "high",
                "status": "investigating",
                "assigned_to": "netadmin",
                "description": "OpenVAS scan identified Redis server (192.168.40.25:6379) accessible without authentication. Full database readable by any network host. Contains session tokens and application cache data.",
                "timeline": [
                    {"time": "2026-04-10 01:00:00", "actor": "OpenVAS GVM", "action": "Scheduled vulnerability scan completed — critical finding: Redis no auth"},
                    {"time": "2026-04-10 07:30:00", "actor": "analyst", "action": "Finding reviewed — incident created for immediate remediation"},
                ],
                "iocs": [
                    {"type": "IP", "value": "192.168.40.25", "description": "Exposed Redis server"},
                    {"type": "Port", "value": "6379/tcp", "description": "Redis service port"},
                ],
                "evidence": [
                    {"type": "Scan Report", "name": "openvas-report-2026-04-10.xml", "size": "2.3 MB", "hash": "d7e2f0b4c8a1e3d5f7b9a2c4e6d8f0b2a4c6e8d0f2b4a6c8e0d2f4b6a8c0e2", "collected": "2026-04-10 01:00:00"},
                ],
                "recommended_actions": "1. Immediately set requirepass in /etc/redis/redis.conf\n2. Bind Redis to 127.0.0.1 only\n3. Flush all current session data (could be compromised)\n4. Enable firewall rule blocking 6379 from all hosts except app server\n5. Enable Redis ACL for granular access control",
            },
            {
                "incident_id": "INC-2026-0007",
                "title": "Cobalt Strike Beacon — IT Workstation",
                "severity": "critical",
                "status": "investigating",
                "assigned_to": "analyst",
                "description": "Suricata detected Cobalt Strike Beacon C2 traffic from TDM-IT-WS-12. HTTP GET to /jquery-3.3.1.min.js using CS malleable profile. Staging potentially complete — full implant likely active.",
                "timeline": [
                    {"time": "2026-04-10 05:45:00", "actor": "Suricata", "action": "Alert: Cobalt Strike default malleable C2 profile detected (sid:2016924)"},
                    {"time": "2026-04-10 05:47:00", "actor": "EDR", "action": "Suspicious process: powershell.exe spawned by winword.exe with encoded command"},
                    {"time": "2026-04-10 05:55:00", "actor": "analyst", "action": "Host isolated from network — forensic collection initiated"},
                ],
                "iocs": [
                    {"type": "IP", "value": "195.178.110.55", "description": "Cobalt Strike Team Server (AS35598)"},
                    {"type": "URL", "value": "/jquery-3.3.1.min.js", "description": "C2 beacon URI (malleable profile)"},
                    {"type": "Process", "value": "winword.exe → powershell.exe -enc ...", "description": "Initial access via macro-enabled document"},
                ],
                "evidence": [
                    {"type": "Memory Dump", "name": "TDM-IT-WS-12-memory-2026-04-10.dmp", "size": "16 GB", "hash": "2eb14920c75d5e73264f77cfa273ad2c2a1b8f7de9be6d4ffa9b7a5c1f0e4d8a", "collected": "2026-04-10 06:00:00"},
                ],
                "recommended_actions": "1. Immediately isolate TDM-IT-WS-12\n2. Block 195.178.110.55 at all firewall layers\n3. Search all endpoints for beacon SHA256 and CS artifacts\n4. Analyze macro-enabled document source (phishing email?)\n5. Hunt for additional CS implants using JA3 fingerprinting\n6. Activate IR playbook — assume full network compromise",
            },
            {
                "incident_id": "INC-2026-0008",
                "title": "DNS Zone Transfer Disclosure",
                "severity": "medium",
                "status": "resolved",
                "assigned_to": "netadmin",
                "description": "DNS server (192.168.10.5) allowing AXFR zone transfers to any host. Complete internal DNS zone retrieved by external scanner including all 200+ hostnames and internal IP mappings.",
                "timeline": [
                    {"time": "2026-04-09 03:00:00", "actor": "OpenVAS GVM", "action": "Detected: AXFR zone transfer allowed for tadamun.local zone"},
                    {"time": "2026-04-09 08:00:00", "actor": "netadmin", "action": "BIND9 ACL configured: allow-transfer { none; }"},
                    {"time": "2026-04-09 08:30:00", "actor": "netadmin", "action": "Verified fix — zone transfer now blocked. Incident resolved."},
                ],
                "iocs": [
                    {"type": "IP", "value": "192.168.10.5", "description": "DNS server (TDM-DNS-01)"},
                    {"type": "Data", "value": "tadamun.local zone (214 records)", "description": "Disclosed internal DNS records"},
                ],
                "evidence": [
                    {"type": "DNS Dump", "name": "tadamun.local-axfr-dump.txt", "size": "48 KB", "hash": "a3f3e7f44f17c61e2d4d5b2c10e9f872bd45f0e1c7d2a9b3e8c5d7e1f0a2b4c6", "collected": "2026-04-09 03:05:00"},
                ],
                "recommended_actions": "RESOLVED: Applied BIND9 ACL. Monitor for unauthorized zone transfer attempts going forward.",
            },
            {
                "incident_id": "INC-2026-0009",
                "title": "IoT Camera Botnet Recruitment Attempt",
                "severity": "medium",
                "status": "contained",
                "assigned_to": "netadmin",
                "description": "Multiple IoT IP cameras in VLAN 50 (192.168.50.x) detected scanning external networks on port 23 (Telnet) and 2323. Behavior consistent with Mirai botnet propagation. Default Telnet credentials confirmed on 3 cameras.",
                "timeline": [
                    {"time": "2026-04-09 18:00:00", "actor": "Snort IDS", "action": "Alert: Internal scan from 192.168.50.x to external Telnet ports"},
                    {"time": "2026-04-09 18:05:00", "actor": "Firewall", "action": "Blocked outbound Telnet from VLAN 50 (FW-003 implicitly)"},
                    {"time": "2026-04-09 19:00:00", "actor": "netadmin", "action": "Affected cameras identified — factory reset initiated on 3 devices"},
                    {"time": "2026-04-10 06:00:00", "actor": "netadmin", "action": "Cameras restored with unique passwords and firmware updated"},
                ],
                "iocs": [
                    {"type": "IP Range", "value": "192.168.50.22, 50.31, 50.44", "description": "Compromised IP cameras"},
                    {"type": "Port", "value": "23/tcp, 2323/tcp", "description": "Telnet ports used for botnet propagation"},
                ],
                "evidence": [
                    {"type": "Network Flow", "name": "iot-vlan-netflow-2026-04-09.csv", "size": "1.8 MB", "hash": "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef", "collected": "2026-04-09 18:10:00"},
                ],
                "recommended_actions": "1. Change all default IoT credentials immediately\n2. Enable automatic firmware updates on all cameras\n3. Implement additional VLAN 50 egress filtering\n4. Consider deploying dedicated IoT security gateway\n5. Implement network behavioral analysis for VLAN 50",
            },
            {
                "incident_id": "INC-2026-0010",
                "title": "Phishing Campaign — Finance Department Targeted",
                "severity": "high",
                "status": "resolved",
                "assigned_to": "analyst",
                "description": "Targeted spear-phishing campaign against Finance department. 12 emails received claiming to be from CFO requesting wire transfer. 2 employees clicked malicious link. No credential theft confirmed — MFA prevented unauthorized access.",
                "timeline": [
                    {"time": "2026-04-07 09:00:00", "actor": "Email Gateway", "action": "12 phishing emails blocked — 2 delivered before rule update"},
                    {"time": "2026-04-07 09:15:00", "actor": "User", "action": "Employee reported suspicious email — phishing confirmed"},
                    {"time": "2026-04-07 09:20:00", "actor": "analyst", "action": "IOCs extracted — email gateway updated, malicious domain blocked"},
                    {"time": "2026-04-07 10:00:00", "actor": "analyst", "action": "All Finance users notified — mandatory password reset initiated"},
                    {"time": "2026-04-08 09:00:00", "actor": "analyst", "action": "No breach confirmed (MFA held) — incident resolved"},
                ],
                "iocs": [
                    {"type": "Domain", "value": "tadamun-cfo.com", "description": "Phishing domain (lookalike)"},
                    {"type": "Email", "value": "cfo@tadamun-cfo.com", "description": "Sender address (spoofed CFO)"},
                    {"type": "URL", "value": "https://tadamun-cfo.com/login", "description": "Credential harvest page"},
                ],
                "evidence": [
                    {"type": "Email Headers", "name": "phishing-email-sample.eml", "size": "28 KB", "hash": "84c82835a5d21bbcf75a61706d8ab549c41b8fd", "collected": "2026-04-07 09:25:00"},
                ],
                "recommended_actions": "RESOLVED. Ongoing: Implement DMARC strict policy, deploy email security training, enable anti-phishing MFA prompts.",
            },
        ]

        for inc_data in _INCIDENTS:
            dev = random.choice(devices)
            vuln = random.choice(vuln_list[:50]) if vuln_list else None
            inc = Incident(
                incident_id=inc_data["incident_id"],
                title=inc_data["title"],
                severity=inc_data["severity"],
                status=inc_data["status"],
                assigned_to=inc_data["assigned_to"],
                device=dev,
                vulnerability=vuln,
                description=inc_data["description"],
                timeline_json=json.dumps(inc_data["timeline"]),
                iocs_json=json.dumps(inc_data["iocs"]),
                evidence_json=json.dumps(inc_data["evidence"]),
                recommended_actions=inc_data["recommended_actions"],
                created_at=_NOW - timedelta(days=random.randint(0, 5), hours=random.randint(0, 10)),
                updated_at=_NOW - timedelta(hours=random.randint(0, 3)),
            )
            db.session.add(inc)

        # ── Endpoint Agents (EDR) ─────────────────────────────────────────────
        AGENT_VERSIONS = ["5.3.1", "5.2.8", "5.1.4", "4.9.2"]
        STATUSES = ["online"] * 70 + ["offline"] * 20 + ["error"] * 10

        # Threat templates for compromised hosts
        THREATS = [
            {"name": "WannaCry.Ransom", "type": "Ransomware", "severity": "critical", "process": "wannacry.exe", "path": "C:\\Windows\\Temp\\wannacry.exe", "detected": "2026-04-10 03:15:00", "status": "Quarantined"},
            {"name": "CobaltStrike.Beacon", "type": "RAT", "severity": "critical", "process": "rundll32.exe", "path": "C:\\Users\\admin\\AppData\\Roaming\\bc.dll", "detected": "2026-04-10 05:47:00", "status": "Active"},
            {"name": "Emotet.Loader", "type": "Trojan", "severity": "high", "process": "outlook.exe→cmd.exe", "path": "C:\\Windows\\Temp\\emo.dll", "detected": "2026-04-09 22:30:00", "status": "Quarantined"},
            {"name": "MimikatzDump", "type": "Credential Theft", "severity": "critical", "process": "lsass.exe (accessed)", "path": "C:\\Windows\\Temp\\mimi.exe", "detected": "2026-04-10 04:00:00", "status": "Blocked"},
            {"name": "Suspicious.PSEncode", "type": "Malicious Script", "severity": "high", "process": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "detected": "2026-04-10 05:48:00", "status": "Active"},
        ]

        # Process tree for compromised host
        PROCESS_TREE = {
            "name": "winlogon.exe", "pid": 524, "args": "",
            "children": [{
                "name": "cmd.exe", "pid": 3821, "args": "/C powershell.exe",
                "anomalous": True,
                "children": [{
                    "name": "powershell.exe", "pid": 3844, "args": "-NoP -NonI -W Hidden -Enc SQBFAF...",
                    "suspicious": True,
                    "children": [{
                        "name": "rundll32.exe", "pid": 4012, "args": "C:\\Users\\admin\\AppData\\Roaming\\bc.dll,DllMain",
                        "suspicious": True,
                        "children": [{
                            "name": "conhost.exe", "pid": 4100, "args": "0xffffffff -ForceV1",
                            "suspicious": True, "children": []
                        }]
                    }]
                }]
            }]
        }

        compromised_device = None
        for i, device in enumerate(devices[:min(len(devices), 100)]):
            status = random.choice(STATUSES)
            has_threats = (i < 5)  # first 5 devices have threats
            threat_data = []
            if has_threats:
                threat_data = [random.choice(THREATS)]
            
            agent = EndpointAgent(
                device=device,
                agent_version=random.choice(AGENT_VERSIONS),
                status=status,
                last_seen=_NOW - timedelta(minutes=random.randint(1, 180)),
                threats_detected=len(threat_data),
                isolated=(i == 3),  # 4th device is isolated
                threats_json=json.dumps(threat_data),
                process_tree_json=json.dumps(PROCESS_TREE) if i == 1 else None,
            )
            db.session.add(agent)
            if i == 1:
                compromised_device = device

        db.session.commit()
        print("Seed completed.")

if __name__ == "__main__":
    seed()
