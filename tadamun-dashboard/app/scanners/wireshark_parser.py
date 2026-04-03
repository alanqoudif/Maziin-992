import csv
from io import StringIO


def parse_wireshark_csv(csv_content: str):
    rows = list(csv.DictReader(StringIO(csv_content)))
    anomalies = []
    for row in rows:
        proto = row.get("Protocol", "").upper()
        length = int(float(row.get("Length", "0")))
        if proto in {"TELNET", "FTP"} or length > 1400:
            anomalies.append(
                {
                    "source": row.get("Source"),
                    "destination": row.get("Destination"),
                    "protocol": proto,
                    "length": length,
                    "reason": "legacy_protocol_or_large_packet",
                }
            )
    return {"packets": len(rows), "anomalies": anomalies, "anomaly_count": len(anomalies)}
