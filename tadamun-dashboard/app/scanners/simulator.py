import ipaddress
import json
import random
from datetime import datetime, timedelta


DEPARTMENTS = [
    ("IT Department", "VLAN 10", "192.168.10.0/24", 45),
    ("Finance Department", "VLAN 20", "192.168.20.0/24", 42),
    ("HR Department", "VLAN 30", "192.168.30.0/24", 36),
    ("Administration", "VLAN 40", "192.168.40.0/24", 30),
    ("Smart Infrastructure", "VLAN 50", "192.168.50.0/24", 47),
]

DEPARTMENT_TYPE_WEIGHTS = {
    "IT Department": {
        "server": 0.24,
        "router": 0.16,
        "switch": 0.18,
        "firewall": 0.16,
        "ids": 0.12,
        "workstation": 0.14,
    },
    "Finance Department": {
        "server": 0.18,
        "router": 0.14,
        "switch": 0.18,
        "firewall": 0.14,
        "ids": 0.08,
        "workstation": 0.22,
        "printer": 0.06,
    },
    "HR Department": {
        "server": 0.16,
        "router": 0.12,
        "switch": 0.16,
        "firewall": 0.12,
        "ids": 0.08,
        "workstation": 0.30,
        "printer": 0.06,
    },
    "Administration": {
        "server": 0.17,
        "router": 0.13,
        "switch": 0.17,
        "firewall": 0.13,
        "ids": 0.08,
        "workstation": 0.26,
        "printer": 0.06,
    },
    "Smart Infrastructure": {
        "server": 0.20,
        "router": 0.15,
        "switch": 0.19,
        "firewall": 0.14,
        "ids": 0.10,
        "workstation": 0.14,
        "controller": 0.05,
        "iot_sensor": 0.03,
    },
}

CRITICALITY_BY_TYPE = {
    "server": ["critical", "high", "high", "medium"],
    "router": ["critical", "high", "high", "medium"],
    "switch": ["high", "high", "medium", "medium"],
    "firewall": ["critical", "high", "high", "medium"],
    "ids": ["high", "high", "medium", "medium"],
    "workstation": ["high", "medium", "medium", "low"],
    "printer": ["medium", "low", "low", "low"],
    "controller": ["high", "medium", "medium", "low"],
    "iot_sensor": ["medium", "medium", "low", "low"],
}


def _mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def _weighted_type(dept_name):
    weighted = DEPARTMENT_TYPE_WEIGHTS[dept_name]
    types = list(weighted.keys())
    weights = list(weighted.values())
    return random.choices(types, weights=weights, k=1)[0]


def generate_devices(total_target=200):
    devices = []
    for dept_name, vlan, subnet, count in DEPARTMENTS:
        hosts = list(ipaddress.ip_network(subnet).hosts())
        for i in range(count):
            ip = str(hosts[i + 10])
            device_type = _weighted_type(dept_name)
            criticality = random.choice(CRITICALITY_BY_TYPE.get(device_type, ["medium", "low"]))
            hostname = f"TDM-{dept_name.split()[0][:3].upper()}-{device_type[:3].upper()}-{i+1:02d}"
            devices.append(
                {
                    "hostname": hostname,
                    "ip_address": ip,
                    "mac_address": _mac(),
                    "device_type": device_type,
                    "os": random.choice(["Windows 11", "Ubuntu 22.04", "Windows Server 2022", "Cisco IOS"]),
                    "os_version": "sim-v1",
                    "department": dept_name,
                    "vlan": vlan,
                    "subnet": subnet,
                    "role": f"{device_type} endpoint",
                    "criticality": criticality,
                    "status": "active",
                    "last_scan": datetime.utcnow() - timedelta(days=random.randint(0, 30)),
                }
            )
    return devices[:total_target]


def topology_json():
    return {
        "city": "Tadamun Smart City (تضامن)",
        "location": "Muscat, Oman",
        "departments": [
            {
                "name": name,
                "vlan": vlan,
                "subnet": subnet,
                "device_count": count,
            }
            for name, vlan, subnet, count in DEPARTMENTS
        ],
        "core_network": {
            "routers": ["TDM-RTR-CORE01", "TDM-RTR-EDGE01"],
            "switches": ["TDM-SW-CORE01", "TDM-SW-ACC01", "TDM-SW-ACC02", "TDM-SW-ACC03"],
            "total_devices": "~200",
        },
    }


def save_topology(path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(topology_json(), fh, indent=2, ensure_ascii=False)
