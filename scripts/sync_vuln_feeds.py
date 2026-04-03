import json
from pathlib import Path
from urllib.request import urlopen

DATA_DIR = Path("data")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev():
    with urlopen(KEV_URL, timeout=30) as resp:  # noqa: S310
        payload = json.loads(resp.read().decode("utf-8"))
    cves = [v.get("cveID") for v in payload.get("vulnerabilities", []) if v.get("cveID")]
    return {"known_exploited": sorted(set(cves))}


def write_defaults():
    DATA_DIR.mkdir(exist_ok=True)
    service_map = {
        "ssh": [{"cve_id": "CVE-2018-15473", "title": "OpenSSH user enumeration", "cvss": 5.3}],
        "http": [{"cve_id": "CVE-2021-41773", "title": "Apache path traversal", "cvss": 7.5}],
        "https": [{"cve_id": "CVE-2021-41773", "title": "Apache path traversal", "cvss": 7.5}],
        "smb": [{"cve_id": "CVE-2017-0144", "title": "SMB remote code execution", "cvss": 8.1}],
        "rdp": [{"cve_id": "CVE-2019-0708", "title": "BlueKeep remote code execution", "cvss": 9.8}],
        "ftp": [{"cve_id": "CVE-2011-2523", "title": "Backdoor command execution", "cvss": 10.0}],
        "telnet": [{"cve_id": "CVE-1999-0619", "title": "Cleartext remote administration", "cvss": 9.0}],
    }
    with open(DATA_DIR / "cve_service_map.json", "w", encoding="utf-8") as fh:
        json.dump(service_map, fh, indent=2)
    try:
        kev_data = fetch_kev()
    except Exception:  # noqa: BLE001
        kev_data = {"known_exploited": ["CVE-2017-0144", "CVE-2019-0708", "CVE-2021-41773"]}
    with open(DATA_DIR / "kev_catalog.json", "w", encoding="utf-8") as fh:
        json.dump(kev_data, fh, indent=2)


if __name__ == "__main__":
    write_defaults()
    print("Vulnerability feed cache synchronized.")
