import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_content: str):
    root = ET.fromstring(xml_content)
    hosts = []
    for host in root.findall("host"):
        ip = "unknown"
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr", "unknown")
                break
        ports = []
        for port in host.findall(".//port"):
            state = port.find("state").attrib.get("state", "unknown")
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.attrib.get("portid", 0)),
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "state": state,
                    "service": service.attrib.get("name", "unknown") if service is not None else "unknown",
                }
            )
        hosts.append({"ip": ip, "ports": ports, "findings_count": len([p for p in ports if p["state"] == "open"])})
    return hosts
