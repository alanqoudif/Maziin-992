import subprocess
import xml.etree.ElementTree as ET
import json
import os
import threading
from datetime import datetime
from app.models import db
from app.scanners.light_scanner import run_light_scan

# Global scan state
scan_state = {
    "status": "idle",        # idle, running, completed, failed
    "progress": 0,           # 0-100
    "message": "",
    "started_at": None,
    "completed_at": None,
    "results": None,
    "error": None,
    "target": None
}

def run_nmap_scan(target_cidr, scan_type="normal"):
    """
    Run an actual Nmap scan on the target network.
    
    scan_type options:
    - "quick": Fast ping scan + top 100 ports (-F)
    - "normal": Service version detection on top 1000 ports (-sV)
    - "deep": Full scan with OS detection + scripts (-sV -O -sC)
    """
    global scan_state
    
    scan_state["status"] = "running"
    scan_state["progress"] = 0
    scan_state["message"] = f"Starting {scan_type} scan on {target_cidr}..."
    scan_state["started_at"] = datetime.utcnow().isoformat()
    scan_state["target"] = target_cidr
    scan_state["error"] = None
    
    # Build nmap command based on scan type
    output_file = f"/tmp/nmap_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xml"
    
    if scan_type == "quick":
        cmd = ["nmap", "-sn", "-F", "-T4", "--open", "-oX", output_file, target_cidr]
    elif scan_type == "normal":
        cmd = ["nmap", "-sV", "-T4", "--open", "-oX", output_file, target_cidr]
    elif scan_type == "deep":
        cmd = ["nmap", "-sV", "-O", "-sC", "-T3", "--open", "-oX", output_file, target_cidr]
    else:
        cmd = ["nmap", "-sV", "-T4", "--open", "-oX", output_file, target_cidr]
    
    try:
        scan_state["progress"] = 10
        scan_state["message"] = "Nmap scan in progress..."

        # Run nmap (this can take 1-5 minutes depending on network size)
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        scan_state["progress"] = 70
        scan_state["message"] = "Parsing scan results..."

        if process.returncode != 0 and not os.path.exists(output_file):
            scan_state["status"] = "failed"
            scan_state["error"] = process.stderr or "Nmap scan failed"
            return None

        # Parse XML results
        results = parse_nmap_xml(output_file)

        scan_state["progress"] = 90
        scan_state["message"] = "Saving to database..."

        scan_state["progress"] = 100
        scan_state["status"] = "completed"
        scan_state["completed_at"] = datetime.utcnow().isoformat()
        scan_state["results"] = results
        scan_state["message"] = f"Scan complete. Found {len(results['hosts'])} hosts."

        # Clean up XML file
        try:
            if os.path.exists(output_file):
                os.remove(output_file)
        except:
            pass

        return results

    except FileNotFoundError:
        # nmap not installed — fall back to pure-Python light scanner
        return _run_light_scan_fallback(target_cidr)
    except subprocess.TimeoutExpired:
        scan_state["status"] = "failed"
        scan_state["error"] = "Scan timed out after 10 minutes"
        return None
    except Exception as e:
        scan_state["status"] = "failed"
        scan_state["error"] = str(e)
        return None


def _run_light_scan_fallback(target_cidr: str) -> dict | None:
    """Fall back to pure-Python scanner when nmap is not available."""
    global scan_state
    scan_state["progress"] = 10
    scan_state["message"] = "nmap not found — using built-in scanner (ping + TCP probe)..."

    try:
        results = run_light_scan(target_cidr)

        scan_state["progress"] = 100
        scan_state["status"] = "completed"
        scan_state["completed_at"] = datetime.utcnow().isoformat()
        scan_state["results"] = results
        scan_state["message"] = (
            f"Light scan complete. Found {results['total_hosts']} hosts "
            f"({results['total_open_ports']} open ports)."
        )
        return results
    except Exception as e:
        scan_state["status"] = "failed"
        scan_state["error"] = f"Light scan failed: {e}"
        return None


def parse_nmap_xml(xml_file):
    """Parse Nmap XML output into structured data"""
    results = {
        "scan_info": {},
        "hosts": [],
        "total_hosts": 0,
        "total_open_ports": 0
    }
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Scan info
        results["scan_info"] = {
            "scanner": root.get("scanner", "nmap"),
            "args": root.get("args", ""),
            "start_time": root.get("startstr", ""),
            "version": root.get("version", "")
        }
        
        # Parse each host
        for host_elem in root.findall("host"):
            host = parse_host(host_elem)
            if host and host["state"] == "up":
                results["hosts"].append(host)
        
        results["total_hosts"] = len(results["hosts"])
        results["total_open_ports"] = sum(len(h.get("ports", [])) for h in results["hosts"])
        
    except ET.ParseError as e:
        results["error"] = f"XML parse error: {str(e)}"
    
    return results


def parse_host(host_elem):
    """Parse a single host element from Nmap XML"""
    host = {
        "state": "down",
        "ip": None,
        "hostname": None,
        "mac": None,
        "vendor": None,
        "os": None,
        "ports": [],
        "scripts": []
    }
    
    # State
    status = host_elem.find("status")
    if status is not None:
        host["state"] = status.get("state", "down")
    
    # IP Address
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr")
        elif addr.get("addrtype") == "mac":
            host["mac"] = addr.get("addr")
            host["vendor"] = addr.get("vendor", "Unknown")
    
    # Hostname
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        hostname = hostnames.find("hostname")
        if hostname is not None:
            host["hostname"] = hostname.get("name")
    
    if not host["hostname"]:
        host["hostname"] = host["ip"]
    
    # OS Detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            host["os"] = osmatch.get("name", "Unknown")
            host["os_accuracy"] = osmatch.get("accuracy", "0")
    
    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port = parse_port(port_elem)
            if port:
                host["ports"].append(port)
    
    # Host scripts
    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host["scripts"].append({
                "id": script.get("id"),
                "output": script.get("output", "")
            })
    
    return host


def parse_port(port_elem):
    """Parse a single port element"""
    state_elem = port_elem.find("state")
    if state_elem is None or state_elem.get("state") != "open":
        return None
    
    port = {
        "port": int(port_elem.get("portid", 0)),
        "protocol": port_elem.get("protocol", "tcp"),
        "state": "open",
        "service": None,
        "version": None,
        "product": None,
        "scripts": []
    }
    
    # Service info
    service = port_elem.find("service")
    if service is not None:
        port["service"] = service.get("name", "unknown")
        port["product"] = service.get("product", "")
        port["version"] = service.get("version", "")
        
        # Build version string
        parts = [port["product"], port["version"], service.get("extrainfo", "")]
        port["version_full"] = " ".join(p for p in parts if p).strip()
    
    # Port scripts (NSE)
    for script in port_elem.findall("script"):
        port["scripts"].append({
            "id": script.get("id"),
            "output": script.get("output", "")
        })
    
    return port


def start_scan_async(app, target_cidr, scan_type="normal"):
    """Start scan in a background thread"""
    def scan_thread():
        with app.app_context():
            results = run_nmap_scan(target_cidr, scan_type)
            if results:
                save_scan_to_db(results, target_cidr)
    
    thread = threading.Thread(target=scan_thread, daemon=True)
    thread.start()
    return True


def save_scan_to_db(results, target_cidr):
    """Save scan results to database — update existing devices or create new ones"""
    from app.models.device import Device
    from app.models.scan_result import ScanResult
    
    # Save scan result record
    scan_record = ScanResult(
        scan_type="nmap_real",
        scan_date=datetime.utcnow(),
        raw_output=json.dumps(results, default=str),
        parsed_results=results["hosts"], # json.dumps not needed if using JSON column
        findings_count=results["total_hosts"]
    )
    db.session.add(scan_record)
    
    # For each discovered host, create or update device
    for host in results["hosts"]:
        if not host["ip"]:
            continue
        
        # Check if device already exists
        existing = Device.query.filter_by(ip_address=host["ip"]).first()
        
        if existing:
            # Update existing device
            if host.get("hostname") and host["hostname"] != host["ip"]:
                existing.hostname = host["hostname"]
            if host.get("os"):
                existing.os = host["os"]
            if host.get("mac"):
                existing.mac_address = host["mac"]
            existing.status = "active"
            existing.last_scan = datetime.utcnow()
            
            # Store port info as JSON in a field or update scan result
            existing.open_ports_json = json.dumps(host.get("ports", []))
        else:
            # Create new device
            device_type = guess_device_type(host)
            new_device = Device(
                hostname=host.get("hostname") or host["ip"],
                ip_address=host["ip"],
                mac_address=host.get("mac") or "00:00:00:00:00:00",
                device_type=device_type,
                os=host.get("os", "Unknown"),
                department="Discovered",
                vlan="N/A",
                subnet=target_cidr,
                role=device_type,
                criticality=guess_criticality(host),
                status="active",
                last_scan=datetime.utcnow()
            )
            # Store open ports
            new_device.open_ports_json = json.dumps(host.get("ports", []))
            db.session.add(new_device)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error saving scan results: {e}")


def guess_device_type(host):
    """Guess device type based on open ports and OS"""
    ports = [p["port"] for p in host.get("ports", [])]
    os_name = (host.get("os") or "").lower()
    
    if any(p in ports for p in [80, 443, 8080, 8443]) and any(p in ports for p in [22, 3306, 5432]):
        return "server"
    elif any(p in ports for p in [23, 161, 162]) or "cisco" in os_name or "router" in os_name:
        return "router"
    elif any(p in ports for p in [3389, 445, 139, 135]):
        return "workstation"
    elif any(p in ports for p in [631, 9100, 515]):
        return "printer"
    elif any(p in ports for p in [502, 1883, 8883]):
        return "iot_device"
    elif any(p in ports for p in [80, 443]):
        return "server"
    else:
        return "unknown"


def guess_criticality(host):
    """Guess criticality based on services"""
    ports = [p["port"] for p in host.get("ports", [])]
    
    if any(p in ports for p in [3306, 5432, 1433, 53]):  # DB or DNS
        return "critical"
    elif any(p in ports for p in [22, 80, 443, 8080]):
        return "high"
    elif any(p in ports for p in [3389, 445]):
        return "medium"
    else:
        return "low"


def get_scan_state():
    """Return current scan state"""
    return scan_state.copy()

_AUTO_SCAN_STARTED = False

def initialize_auto_scan(app):
    """Initialize automatic scanning on startup if enabled"""
    global _AUTO_SCAN_STARTED
    if _AUTO_SCAN_STARTED:
        return
    if not app.config.get("REAL_SCAN_ENABLED"):
        return
    if not app.config.get("AUTO_SCAN_ON_START", True):
        return
    # Avoid double initialization in Flask debug mode
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    _AUTO_SCAN_STARTED = True

    def auto_scan_loop():
        import time
        from app.scanners.network_utils import get_network_cidr
        
        # Initial delay to let the app start
        time.sleep(10)
        
        while True:
            with app.app_context():
                state = get_scan_state()
                if state["status"] != "running":
                    target = app.config.get("SCAN_ALLOWED_CIDRS", "").split(",")[0].strip() or get_network_cidr()
                    if target:
                        print(f"[*] Starting auto-scan on {target}")
                        start_scan_async(app, target, "normal")
            
            # Wait for the next interval
            interval = int(app.config.get("AUTO_SCAN_INTERVAL_SEC", 3600))
            time.sleep(interval)

    thread = threading.Thread(target=auto_scan_loop, daemon=True)
    thread.start()
