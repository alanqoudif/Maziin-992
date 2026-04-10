"""Cisco ASA-style firewall rules for the Tadamun network (simulated).

VLANs:
  10 — IT Department      192.168.10.0/24
  20 — Finance Dept       192.168.20.0/24
  30 — HR Department      192.168.30.0/24
  40 — Data Center / Srv  192.168.40.0/24
  50 — IoT / Smart Infra  192.168.50.0/24
"""

FIREWALL_RULES = [
    {
        "id": "FW-001",
        "priority": 1,
        "action": "DENY",
        "protocol": "any",
        "src_ip": "any",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "22",
        "description": "Block all SSH to Data Center except from IT VLAN (hardened admin access)",
        "interface": "outside",
        "enabled": True,
        "hit_count": 4821,
        "log": True,
    },
    {
        "id": "FW-002",
        "priority": 2,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "192.168.10.0/24",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "22",
        "description": "Allow IT Department SSH access to Data Center servers",
        "interface": "inside",
        "enabled": True,
        "hit_count": 1203,
        "log": True,
    },
    {
        "id": "FW-003",
        "priority": 3,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "any",
        "dst_ip": "any",
        "dst_port": "23",
        "description": "Block Telnet — cleartext protocol prohibited by security policy",
        "interface": "any",
        "enabled": True,
        "hit_count": 87,
        "log": True,
    },
    {
        "id": "FW-004",
        "priority": 4,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "192.168.10.0/24",
        "dst_ip": "any",
        "dst_port": "80,443",
        "description": "Allow IT staff HTTP/HTTPS access to internet via web proxy",
        "interface": "inside",
        "enabled": True,
        "hit_count": 98714,
        "log": False,
    },
    {
        "id": "FW-005",
        "priority": 5,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "192.168.50.0/24",
        "dst_ip": "192.168.20.0/24",
        "dst_port": "any",
        "description": "Block IoT VLAN from accessing Finance VLAN (critical isolation)",
        "interface": "inside",
        "enabled": True,
        "hit_count": 512,
        "log": True,
    },
    {
        "id": "FW-006",
        "priority": 6,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "192.168.50.0/24",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "any",
        "description": "Block IoT VLAN from accessing Data Center (strict micro-segmentation)",
        "interface": "inside",
        "enabled": True,
        "hit_count": 341,
        "log": True,
    },
    {
        "id": "FW-007",
        "priority": 7,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "192.168.50.0/24",
        "dst_ip": "192.168.40.10",
        "dst_port": "1883",
        "description": "Allow IoT devices to MQTT broker on VLAN 40 (TDM-IOT-SRV)",
        "interface": "inside",
        "enabled": True,
        "hit_count": 52840,
        "log": False,
    },
    {
        "id": "FW-008",
        "priority": 8,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "0.0.0.0/0",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "3306,5432,6379,27017",
        "description": "Block all external access to database ports (MySQL, PostgreSQL, Redis, MongoDB)",
        "interface": "outside",
        "enabled": True,
        "hit_count": 2904,
        "log": True,
    },
    {
        "id": "FW-009",
        "priority": 9,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "0.0.0.0/0",
        "dst_ip": "192.168.10.20",
        "dst_port": "443",
        "description": "Allow inbound HTTPS to Tadamun public web portal (DMZ server)",
        "interface": "outside",
        "enabled": True,
        "hit_count": 284930,
        "log": False,
    },
    {
        "id": "FW-010",
        "priority": 10,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "0.0.0.0/0",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "445",
        "description": "Block SMB from external network — prevents EternalBlue exploitation",
        "interface": "outside",
        "enabled": True,
        "hit_count": 7821,
        "log": True,
    },
    {
        "id": "FW-011",
        "priority": 11,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "0.0.0.0/0",
        "dst_ip": "any",
        "dst_port": "3389",
        "description": "Block RDP from internet — remote desktop must use VPN first",
        "interface": "outside",
        "enabled": True,
        "hit_count": 12044,
        "log": True,
    },
    {
        "id": "FW-012",
        "priority": 12,
        "action": "PERMIT",
        "protocol": "udp",
        "src_ip": "192.168.10.5",
        "dst_ip": "any",
        "dst_port": "53",
        "description": "Allow DNS resolver (TDM-DNS-01) to external DNS for recursive queries",
        "interface": "inside",
        "enabled": True,
        "hit_count": 431829,
        "log": False,
    },
    {
        "id": "FW-013",
        "priority": 13,
        "action": "DENY",
        "protocol": "udp",
        "src_ip": "any",
        "dst_ip": "any",
        "dst_port": "53",
        "description": "Block all other DNS queries — force use of authoritative DNS servers",
        "interface": "any",
        "enabled": True,
        "hit_count": 1287,
        "log": True,
    },
    {
        "id": "FW-014",
        "priority": 14,
        "action": "PERMIT",
        "protocol": "icmp",
        "src_ip": "192.168.10.0/24",
        "dst_ip": "any",
        "dst_port": "any",
        "description": "Allow ICMP ping from IT Department for network diagnostics",
        "interface": "inside",
        "enabled": True,
        "hit_count": 9040,
        "log": False,
    },
    {
        "id": "FW-015",
        "priority": 15,
        "action": "DENY",
        "protocol": "icmp",
        "src_ip": "0.0.0.0/0",
        "dst_ip": "any",
        "dst_port": "any",
        "description": "Block ICMP from external — prevent ICMP-based reconnaissance",
        "interface": "outside",
        "enabled": True,
        "hit_count": 3291,
        "log": True,
    },
    {
        "id": "FW-016",
        "priority": 16,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "10.8.0.0/24",
        "dst_ip": "192.168.40.0/24",
        "dst_port": "any",
        "description": "Allow VPN clients (10.8.0.0/24) full access to Data Center segment",
        "interface": "vpn",
        "enabled": True,
        "hit_count": 24581,
        "log": False,
    },
    {
        "id": "FW-017",
        "priority": 17,
        "action": "DENY",
        "protocol": "tcp",
        "src_ip": "192.168.20.0/24",
        "dst_ip": "192.168.30.0/24",
        "dst_port": "any",
        "description": "Block Finance VLAN from HR VLAN — department data isolation",
        "interface": "inside",
        "enabled": True,
        "hit_count": 210,
        "log": True,
    },
    {
        "id": "FW-018",
        "priority": 18,
        "action": "PERMIT",
        "protocol": "tcp",
        "src_ip": "192.168.20.0/24",
        "dst_ip": "192.168.40.25",
        "dst_port": "3306",
        "description": "Allow Finance VLAN MySQL access to dedicated Finance DB server only",
        "interface": "inside",
        "enabled": True,
        "hit_count": 78340,
        "log": False,
    },
    {
        "id": "FW-019",
        "priority": 19,
        "action": "PERMIT",
        "protocol": "udp",
        "src_ip": "192.168.10.0/24",
        "dst_ip": "192.168.30.5",
        "dst_port": "161",
        "description": "Allow IT Department SNMP monitoring of HR infrastructure devices",
        "interface": "inside",
        "enabled": True,
        "hit_count": 18920,
        "log": False,
    },
    {
        "id": "FW-020",
        "priority": 9999,
        "action": "DENY",
        "protocol": "any",
        "src_ip": "any",
        "dst_ip": "any",
        "dst_port": "any",
        "description": "Implicit deny all — default deny policy (catch-all last rule)",
        "interface": "any",
        "enabled": True,
        "hit_count": 54321,
        "log": True,
    },
]


def evaluate_packet(src_ip: str, dst_ip: str, port: str, protocol: str) -> dict:
    """Walk the rule list in priority order and return the first match."""
    import ipaddress

    def ip_in_net(ip_str: str, net_str: str) -> bool:
        if net_str in ("any", "0.0.0.0/0"):
            return True
        try:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(net_str, strict=False)
        except ValueError:
            return ip_str == net_str

    def port_matches(pkt_port: str, rule_port: str) -> bool:
        if rule_port == "any":
            return True
        for rp in rule_port.split(","):
            rp = rp.strip()
            if rp == pkt_port:
                return True
        return False

    def proto_matches(pkt_proto: str, rule_proto: str) -> bool:
        return rule_proto in ("any", pkt_proto.lower())

    for rule in sorted(FIREWALL_RULES, key=lambda r: r["priority"]):
        if not rule["enabled"]:
            continue
        if (
            ip_in_net(src_ip, rule["src_ip"])
            and ip_in_net(dst_ip, rule["dst_ip"])
            and port_matches(port, rule["dst_port"])
            and proto_matches(protocol, rule["protocol"])
        ):
            return {
                "action": rule["action"],
                "matched_rule": rule["id"],
                "priority": rule["priority"],
                "description": rule["description"],
            }

    return {
        "action": "DENY",
        "matched_rule": "IMPLICIT-DENY",
        "priority": 9999,
        "description": "Implicit deny all — no rule matched",
    }
