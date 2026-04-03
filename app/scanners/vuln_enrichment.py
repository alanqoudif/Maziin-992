import json
from pathlib import Path

from app.extensions import db
from app.models.alert import Alert
from app.models.patch import Patch
from app.models.vulnerability import Vulnerability

DATA_DIR = Path("data")
SERVICE_MAP_FILE = DATA_DIR / "cve_service_map.json"
KEV_FILE = DATA_DIR / "kev_catalog.json"


def _read_json(path, fallback):
    if not path.exists():
        return fallback
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _severity_from_cvss(cvss):
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def load_feed_catalogs():
    default_map = {
        "ssh": [{"cve_id": "CVE-2018-15473", "title": "OpenSSH user enumeration", "cvss": 5.3}],
        "http": [{"cve_id": "CVE-2021-41773", "title": "Apache path traversal", "cvss": 7.5}],
        "https": [{"cve_id": "CVE-2021-41773", "title": "Apache path traversal", "cvss": 7.5}],
        "smb": [{"cve_id": "CVE-2017-0144", "title": "SMB remote code execution", "cvss": 8.1}],
        "rdp": [{"cve_id": "CVE-2019-0708", "title": "BlueKeep remote code execution", "cvss": 9.8}],
        "ftp": [{"cve_id": "CVE-2011-2523", "title": "Backdoor command execution", "cvss": 10.0}],
        "telnet": [{"cve_id": "CVE-1999-0619", "title": "Cleartext remote administration", "cvss": 9.0}],
    }
    service_map = _read_json(SERVICE_MAP_FILE, default_map)
    kev = _read_json(KEV_FILE, {"known_exploited": ["CVE-2017-0144", "CVE-2019-0708", "CVE-2021-41773"]})
    return service_map, set(kev.get("known_exploited", []))


def _upsert_patch(vulnerability):
    if vulnerability.id is None:
        return Patch(
            vulnerability=vulnerability,
            patch_name=f"Mitigation for {vulnerability.cve_id}",
            vendor="Security Advisory Feed",
            urgency=vulnerability.severity,
            recommendation="Prioritize remediation on externally exposed assets.",
            status="pending",
        )
    existing = Patch.query.filter_by(vulnerability_id=vulnerability.id).first()
    if existing:
        return existing
    patch = Patch(
        vulnerability=vulnerability,
        patch_name=f"Mitigation for {vulnerability.cve_id}",
        vendor="Security Advisory Feed",
        urgency=vulnerability.severity,
        recommendation="Prioritize remediation on externally exposed assets.",
        status="pending",
    )
    return patch


def enrich_device_vulnerabilities(device, open_ports):
    service_map, kev_set = load_feed_catalogs()
    created = 0
    for port in open_ports:
        service = (port.get("service") or "").lower()
        for candidate in service_map.get(service, []):
            cve_id = candidate["cve_id"]
            cvss = float(candidate.get("cvss", 5.0))
            vulnerability = Vulnerability.query.filter_by(cve_id=cve_id, status="open").first()
            if vulnerability is None:
                vulnerability = Vulnerability(
                    cve_id=cve_id,
                    title=candidate.get("title", f"Potential issue on {service}"),
                    description=f"Service fingerprint indicates a potential vulnerability for {service}.",
                    cvss_base_score=cvss,
                    severity=_severity_from_cvss(cvss),
                    exploitability_score=max(1.0, min(10.0, cvss - 0.8)),
                    impact_score=max(1.0, min(10.0, cvss - 0.5)),
                    status="open",
                    ai_risk_score=round(min(10.0, cvss), 2),
                    ai_priority_rank=1,
                    network_exposure_factor=0.9,
                    exploit_availability=cve_id in kev_set,
                )
                db.session.add(vulnerability)
                vulnerability.affected_devices.append(device)
                created += 1
            elif device not in vulnerability.affected_devices:
                vulnerability.affected_devices.append(device)

            if cve_id in kev_set:
                alert = Alert(
                    alert_type="known_exploited_vulnerability",
                    severity="critical",
                    message=f"{device.hostname} appears exposed to known exploited vulnerability {cve_id}.",
                    device=device,
                    vulnerability=vulnerability,
                    is_read=False,
                )
                created += 1
                yield ("alert", alert)

            patch = _upsert_patch(vulnerability)
            yield ("vulnerability", vulnerability)
            yield ("patch", patch)

    return created
