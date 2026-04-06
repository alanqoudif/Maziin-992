import csv
from io import StringIO

def parse_wireshark_csv(csv_content: str):
    rows = list(csv.DictReader(StringIO(csv_content)))
    anomalies = []
    
    # Simple anomaly detection logic
    # 1. Port scanning: Many different destination ports from same source
    src_ports = {}
    
    # 2. ARP Spoofing: Same IP, different MACs (if MACs were in CSV, but we only have IPs here)
    # We can simulate by looking for repeated ARP replies.
    
    for row in rows:
        proto = row.get("Protocol", "").upper()
        length = row.get("Length", "0")
        try:
            length = int(float(length))
        except ValueError:
            length = 0
            
        info = row.get("Info", "")
        src = row.get("Source")
        dst = row.get("Destination")

        is_anomaly = False
        reason = ""

        # Flag anomalies
        if proto in {"TELNET"} :
            is_anomaly = True
            reason = "unauthorized_protocol_usage"
        elif "SYN" in info and "ACK" not in info: # Simplified port scan detection
            src_ports[src] = src_ports.get(src, 0) + 1
            if src_ports[src] > 50:
                is_anomaly = True
                reason = "port_scanning_detected"
        elif "ARP" in proto and "duplicate" in info.lower():
            is_anomaly = True
            reason = "arp_spoofing_indicator"
        elif "DNS" in proto and len(info) > 100:
            is_anomaly = True
            reason = "dns_tunneling_indicator"
        elif length > 1500: # Large packet
             is_anomaly = True
             reason = "potential_data_exfiltration"
        
        if is_anomaly:
            anomalies.append({
                "no": row.get("No"),
                "time": row.get("Time"),
                "source": src,
                "destination": dst,
                "protocol": proto,
                "length": length,
                "info": info,
                "reason": reason
            })
            
    return {
        "total_packets": len(rows),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "normal_traffic_pct": round(((len(rows) - len(anomalies)) / len(rows)) * 100, 1) if rows else 0
    }
