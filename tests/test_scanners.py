from app.scanners.metasploit_parser import parse_metasploit_json
from app.scanners.nmap_parser import parse_nmap_xml
from app.scanners.wireshark_parser import parse_wireshark_csv


def test_nmap_parser():
    xml = """<nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>"""
    result = parse_nmap_xml(xml)
    assert result[0]["ip"] == "192.168.1.10"
    assert result[0]["findings_count"] == 1


def test_wireshark_parser():
    csv_content = "No.,Time,Source,Destination,Protocol,Length,Info\n1,0.1,1.1.1.1,2.2.2.2,TELNET,100,a\n"
    result = parse_wireshark_csv(csv_content)
    assert result["anomaly_count"] == 1


def test_metasploit_parser():
    raw = '{"results":[{"cve_id":"CVE-1","exploitable":true},{"cve_id":"CVE-2","exploitable":false}]}'
    result = parse_metasploit_json(raw)
    assert result["exploitable_count"] == 1
