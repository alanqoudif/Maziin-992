import subprocess
import re
import socket
import platform

def get_local_ip():
    """Get the machine's local IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_network_cidr():
    """Auto-detect the network CIDR (e.g., 192.168.1.0/24)"""
    local_ip = get_local_ip()
    # Extract first 3 octets and append .0/24
    parts = local_ip.split(".")
    if len(parts) == 4:
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network
    return None

def get_network_info():
    """Get comprehensive network info"""
    local_ip = get_local_ip()
    network = get_network_cidr()
    hostname = socket.gethostname()
    
    # Try to get gateway
    gateway = None
    try:
        if platform.system() == "Darwin":  # macOS
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        gateway = parts[1]
                        break
        elif platform.system() == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                gateway = match.group(1)
    except:
        pass
    
    return {
        "local_ip": local_ip,
        "network_cidr": network,
        "hostname": hostname,
        "gateway": gateway
    }

def check_nmap_installed():
    """Check if nmap is installed and accessible"""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.split("\n")[0] if result.stdout else "Unknown"
            return {"installed": True, "version": version}
    except FileNotFoundError:
        pass
    return {"installed": False, "version": None}
