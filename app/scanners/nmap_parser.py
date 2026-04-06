import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_content: str):
    root = ET.fromstring(xml_content)
    hosts = []
    for host in root.findall("host"):
        ip = "unknown"
        hostname = "unknown"
        state = "unknown"
        
        status = host.find("status")
        if status is not None:
            state = status.attrib.get("state", "unknown")

        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr", "unknown")
        
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name", "unknown")

        os_match = "unknown"
        os = host.find("os")
        if os is not None:
            os_class = os.find("osmatch")
            if os_class is not None:
                os_match = os_class.attrib.get("name", "unknown")

        ports = []
        for port_node in host.findall(".//port"):
            port_id = port_node.attrib.get("portid", "0")
            protocol = port_node.attrib.get("protocol", "tcp")
            port_state = port_node.find("state").attrib.get("state", "unknown")
            service_node = port_node.find("service")
            
            service_name = "unknown"
            service_version = "unknown"
            if service_node is not None:
                service_name = service_node.attrib.get("name", "unknown")
                service_version = service_node.attrib.get("version", "unknown")
                service_product = service_node.attrib.get("product", "")
                if service_product:
                    service_version = f"{service_product} {service_version}"

            # NSE Script results
            scripts = []
            for script in port_node.findall("script"):
                scripts.append({
                    "id": script.attrib.get("id"),
                    "output": script.attrib.get("output")
                })

            ports.append({
                "port": int(port_id),
                "protocol": protocol,
                "state": port_state,
                "service": service_name,
                "version": service_version,
                "scripts": scripts
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "os": os_match,
            "ports": ports,
            "findings_count": len([p for p in ports if p["state"] == "open"])
        })
    return hosts
