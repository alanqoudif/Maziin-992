import csv
import random
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
from app.scanners.simulator import generate_devices, save_topology

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

        devices = []
        for d in generate_devices(200):
            device = Device(**d)
            db.session.add(device)
            devices.append(device)
        db.session.flush()

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

        for d in devices:
            for scan_type in ["nmap", "wireshark", "metasploit"]:
                db.session.add(
                    ScanResult(
                        scan_type=scan_type,
                        scan_date=datetime.utcnow() - timedelta(days=random.randint(0, 30)),
                        device=d,
                        raw_output=f"{scan_type} simulated output for {d.hostname}",
                        parsed_results={"hostname": d.hostname, "status": "ok"},
                        findings_count=random.randint(0, 8),
                    )
                )

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
