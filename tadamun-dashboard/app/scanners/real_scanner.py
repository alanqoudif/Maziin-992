import ipaddress
import os
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import current_app

from app.extensions import db
from app.models.device import Device
from app.models.scan_result import ScanResult
from app.scanners.nmap_parser import parse_nmap_xml
from app.scanners.vuln_enrichment import enrich_device_vulnerabilities

_SCAN_STATE = {
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "error": None,
    "targets": [],
    "duration_sec": 0.0,
    "discovered_hosts": 0,
    "open_ports_count": 0,
    "enrichment_hits": 0,
}
_STATE_LOCK = threading.Lock()
_EXECUTOR = ThreadPoolExecutor(max_workers=1)
_AUTO_SCAN_STARTED = False


def parse_allowed_cidrs(raw):
    entries = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        entries.append(ipaddress.ip_network(part, strict=False))
    return entries


def validate_targets(targets, allowed_cidrs, max_targets):
    if not targets:
        raise ValueError("No scan targets provided.")
    if len(targets) > max_targets:
        raise ValueError(f"Too many targets requested. Max allowed is {max_targets}.")
    resolved = []
    for target in targets:
        network = ipaddress.ip_network(target, strict=False)
        if not any(network.subnet_of(allowed) for allowed in allowed_cidrs):
            raise ValueError(f"Target {target} is outside allowed CIDRs.")
        resolved.append(str(network))
    return resolved


def _detect_device_type(open_ports):
    ports = {int(p["port"]) for p in open_ports}
    if 3389 in ports:
        return "workstation"
    if 22 in ports and 80 in ports:
        return "server"
    if 161 in ports:
        return "switch"
    return "endpoint"


def _run_nmap(targets, profile, binary_path, timeout_sec):
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    cmd = [binary_path, "-oX", xml_path] + profile.split() + targets
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "nmap execution failed")
    with open(xml_path, "r", encoding="utf-8") as fh:
        return fh.read()


def _upsert_device_from_host(host):
    ip = host["ip"]
    if ip == "unknown":
        return None, []
    device = Device.query.filter_by(ip_address=ip).first()
    open_ports = [p for p in host["ports"] if p["state"] == "open"]
    if device is None:
        host_tail = ip.replace(".", "-")
        device = Device(
            hostname=f"DISC-{host_tail}",
            ip_address=ip,
            mac_address="00:00:00:00:00:00",
            device_type=_detect_device_type(open_ports),
            os="Unknown",
            os_version=None,
            department="Discovered Network",
            vlan="Unknown",
            subnet=f"{ip.rsplit('.', 1)[0]}.0/24",
            role="discovered endpoint",
            criticality="medium",
            status="active",
        )
        db.session.add(device)
    device.last_scan = datetime.utcnow()
    return device, open_ports


def get_scan_state():
    with _STATE_LOCK:
        return dict(_SCAN_STATE)


def _set_scan_state(**kwargs):
    with _STATE_LOCK:
        _SCAN_STATE.update(kwargs)


def run_real_scan(app, targets, profile):
    started = datetime.utcnow()
    _set_scan_state(
        status="running",
        started_at=started.isoformat(),
        finished_at=None,
        error=None,
        targets=targets,
        duration_sec=0.0,
        discovered_hosts=0,
        open_ports_count=0,
        enrichment_hits=0,
    )
    with app.app_context():
        cfg = current_app.config
        fallback_used = False
        warning_message = None
        try:
            xml_content = _run_nmap(
                targets=targets,
                profile=profile,
                binary_path=cfg["NMAP_BINARY_PATH"],
                timeout_sec=cfg["SCAN_TIMEOUT_SEC"],
            )
        except RuntimeError as exc:
            if "timed out" not in str(exc):
                raise
            fallback_used = True
            warning_message = f"Primary profile timed out, fallback profile used: {cfg.get('SCAN_FALLBACK_PROFILE', '-sn')}"
            xml_content = _run_nmap(
                targets=targets,
                profile=cfg.get("SCAN_FALLBACK_PROFILE", "-sn"),
                binary_path=cfg["NMAP_BINARY_PATH"],
                timeout_sec=cfg["SCAN_TIMEOUT_SEC"],
            )
        hosts = parse_nmap_xml(xml_content)
        open_ports_total = 0
        enrichment_hits = 0
        for host in hosts:
            device, open_ports = _upsert_device_from_host(host)
            if device is None:
                continue
            open_ports_total += len(open_ports)
            scan_row = ScanResult(
                scan_type="nmap_real",
                scan_date=datetime.utcnow(),
                device=device,
                raw_output=xml_content[:10000],
                parsed_results=host,
                findings_count=len(open_ports),
            )
            db.session.add(scan_row)
            for entity_type, entity in enrich_device_vulnerabilities(device, open_ports):
                db.session.add(entity)
                if entity_type == "vulnerability":
                    enrichment_hits += 1
        db.session.commit()
        ended = datetime.utcnow()
        _set_scan_state(
            status="completed",
            finished_at=ended.isoformat(),
            duration_sec=round((ended - started).total_seconds(), 2),
            discovered_hosts=len(hosts),
            open_ports_count=open_ports_total,
            enrichment_hits=enrichment_hits,
            error=warning_message if fallback_used else None,
        )


def start_scan_job(targets, profile):
    if get_scan_state()["status"] == "running":
        raise RuntimeError("Scan already running.")

    app_obj = current_app._get_current_object()

    def _wrapped():
        try:
            run_real_scan(app_obj, targets, profile)
        except Exception as exc:  # noqa: BLE001
            ended = datetime.utcnow()
            started_at = get_scan_state().get("started_at")
            duration = 0.0
            if started_at:
                try:
                    duration = round((ended - datetime.fromisoformat(started_at)).total_seconds(), 2)
                except ValueError:
                    duration = 0.0
            _set_scan_state(status="failed", finished_at=ended.isoformat(), duration_sec=duration, error=str(exc))

    _EXECUTOR.submit(_wrapped)


def start_scan_job_for_app(app, targets, profile):
    if get_scan_state()["status"] == "running":
        return False

    def _wrapped():
        try:
            run_real_scan(app, targets, profile)
        except Exception as exc:  # noqa: BLE001
            ended = datetime.utcnow()
            started_at = get_scan_state().get("started_at")
            duration = 0.0
            if started_at:
                try:
                    duration = round((ended - datetime.fromisoformat(started_at)).total_seconds(), 2)
                except ValueError:
                    duration = 0.0
            _set_scan_state(status="failed", finished_at=ended.isoformat(), duration_sec=duration, error=str(exc))

    _EXECUTOR.submit(_wrapped)
    return True


def _default_targets_for_app(app):
    raw = app.config.get("SCAN_ALLOWED_CIDRS", "192.168.0.0/16")
    allowed = parse_allowed_cidrs(raw)
    first = str(allowed[0]) if allowed else "192.168.0.0/24"
    return [first]


def initialize_auto_scan(app):
    global _AUTO_SCAN_STARTED  # noqa: PLW0603
    if _AUTO_SCAN_STARTED:
        return
    if not app.config.get("REAL_SCAN_ENABLED"):
        return
    if not app.config.get("AUTO_SCAN_ON_START", True):
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    _AUTO_SCAN_STARTED = True

    def _loop():
        while True:
            with app.app_context():
                targets = _default_targets_for_app(app)
                profile = app.config.get("SCAN_DEFAULT_PROFILE", "-sV -Pn --open")
                if get_scan_state()["status"] in {"idle", "failed", "completed"}:
                    start_scan_job_for_app(app, targets, profile)
            time.sleep(int(app.config.get("AUTO_SCAN_INTERVAL_SEC", 300)))

    threading.Thread(target=_loop, daemon=True).start()
