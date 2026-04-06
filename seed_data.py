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
            
        db.session.commit()
        print("Seed completed.")

if __name__ == "__main__":
    seed()
