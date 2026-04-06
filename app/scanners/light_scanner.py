"""
Light Scanner — pure-Python network discovery.
No root, no nmap required. Works on macOS and Linux.
Uses ping + TCP connect + ARP cache + reverse DNS.
"""
import socket
import subprocess
import platform
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common ports to probe (service name → port)
COMMON_PORTS = [
    (21,  "ftp"),
    (22,  "ssh"),
    (23,  "telnet"),
    (25,  "smtp"),
    (53,  "dns"),
    (80,  "http"),
    (110, "pop3"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (554, "rtsp"),
    (587, "smtp"),
    (631, "ipp"),
    (1883,"mqtt"),
    (3306,"mysql"),
    (3389,"rdp"),
    (5432,"postgresql"),
    (5900,"vnc"),
    (8080,"http-alt"),
    (8443,"https-alt"),
    (9100,"jetdirect"),
]


def _ping(ip: str, timeout: float = 1.0) -> bool:
    """ICMP ping a single host. Works without root via OS ping."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
        return False


def _probe_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """TCP connect probe — returns True if port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _resolve_hostname(ip: str) -> str | None:
    """Reverse DNS lookup."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def _get_arp_table() -> dict[str, dict]:
    """
    Read ARP cache from OS (no root needed).
    Returns {ip: {"mac": str, "vendor": str}}
    """
    arp_map: dict[str, dict] = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return arp_map

        # macOS: ? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
        # Linux: Address  HWtype  HWaddress  Flags Mask  Iface
        mac_pattern = re.compile(
            r"[\(\s](\d{1,3}(?:\.\d{1,3}){3})[\)\s].*?([\da-fA-F]{1,2}[:\-][\da-fA-F]{1,2}[:\-][\da-fA-F]{1,2}[:\-][\da-fA-F]{1,2}[:\-][\da-fA-F]{1,2}[:\-][\da-fA-F]{1,2})"
        )
        for line in result.stdout.splitlines():
            m = mac_pattern.search(line)
            if m:
                ip_addr = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                arp_map[ip_addr] = {"mac": mac, "vendor": _guess_vendor(mac)}
    except Exception:
        pass
    return arp_map


_OUI_MAP = {
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "AC:DE:48": "Apple",
    "F4:F1:5A": "Apple",
    "A4:83:E7": "Apple",
    "3C:22:FB": "Apple",
    "00:1A:2B": "Cisco",
    "00:0C:29": "VMware",
    "FC:EC:DA": "Ubiquiti",
    "18:FE:34": "Espressif (IoT)",
    "2C:F4:32": "Espressif (IoT)",
    "24:0A:C4": "Espressif (IoT)",
}


def _guess_vendor(mac: str) -> str:
    oui = mac[:8].upper()
    return _OUI_MAP.get(oui, "Unknown")


def _scan_host(ip: str, arp_table: dict) -> dict | None:
    """Ping + port scan a single host. Returns host dict or None if down."""
    alive = _ping(ip)
    if not alive:
        # Try a quick TCP probe on port 80/443 as fallback
        alive = _probe_port(ip, 80) or _probe_port(ip, 443) or _probe_port(ip, 22)
    if not alive:
        return None

    # Port scan
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_port, ip, port, 0.5): (port, svc) for port, svc in COMMON_PORTS}
        for fut in as_completed(futures):
            port, svc = futures[fut]
            if fut.result():
                open_ports.append({"port": port, "protocol": "tcp", "service": svc, "state": "open"})
    open_ports.sort(key=lambda p: p["port"])

    # Hostname
    hostname = _resolve_hostname(ip) or ip

    # MAC from ARP
    arp_info = arp_table.get(ip, {})
    mac = arp_info.get("mac", "00:00:00:00:00:00")
    vendor = arp_info.get("vendor", "Unknown")

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "os": None,
        "state": "up",
        "ports": open_ports,
        "scripts": [],
    }


def _guess_device_type(host: dict) -> str:
    ports = [p["port"] for p in host.get("ports", [])]
    hostname = (host.get("hostname") or "").lower()
    vendor = (host.get("vendor") or "").lower()

    if "raspberry" in vendor or "espressif" in vendor or "mqtt" in hostname:
        return "iot_device"
    if any(p in ports for p in [80, 443, 8080, 8443]) and any(p in ports for p in [22, 3306, 5432]):
        return "server"
    if any(p in ports for p in [23, 161, 162]) or "cisco" in vendor or "router" in hostname:
        return "router"
    if any(p in ports for p in [3389, 445, 139, 135]):
        return "workstation"
    if any(p in ports for p in [631, 9100, 515]):
        return "printer"
    if any(p in ports for p in [80, 443]):
        return "server"
    return "unknown"


def _guess_criticality(host: dict) -> str:
    ports = [p["port"] for p in host.get("ports", [])]
    if any(p in ports for p in [3306, 5432, 1433, 53]):
        return "critical"
    if any(p in ports for p in [22, 80, 443, 8080]):
        return "high"
    if any(p in ports for p in [3389, 445]):
        return "medium"
    return "low"


def run_light_scan(target_cidr: str, max_workers: int = 50) -> dict:
    """
    Discover live hosts in a /24 subnet without nmap or root.
    Returns the same structure as real_scanner.parse_nmap_xml().
    """
    # Parse the base network (only /24 supported for speed)
    try:
        base = ".".join(target_cidr.split("/")[0].split(".")[:3])
    except Exception:
        base = "192.168.1"

    ips = [f"{base}.{i}" for i in range(1, 255)]
    arp_table = _get_arp_table()

    hosts = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_host, ip, arp_table): ip for ip in ips}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                # Enrich with device type
                result["device_type"] = _guess_device_type(result)
                result["criticality"] = _guess_criticality(result)
                hosts.append(result)

    hosts.sort(key=lambda h: list(map(int, h["ip"].split("."))))

    return {
        "scan_info": {
            "scanner": "light_scanner",
            "args": f"ping+socket {target_cidr}",
            "start_time": datetime.utcnow().isoformat(),
            "version": "1.0",
        },
        "hosts": hosts,
        "total_hosts": len(hosts),
        "total_open_ports": sum(len(h.get("ports", [])) for h in hosts),
    }
