import xml.etree.ElementTree as ET


def parse_openvas_xml(xml_content: str) -> dict:
    """Parse an OpenVAS/GVM XML report and return a structured summary."""
    root = ET.fromstring(xml_content)

    results = []
    for result in root.findall(".//result"):
        name = _text(result, "name")
        host = _text(result, "host")
        port = _text(result, "port")
        threat = _text(result, "threat")
        severity_str = _text(result, "severity")
        description = _text(result, "description")
        solution = _text(result, "solution")

        try:
            severity_score = float(severity_str)
        except (ValueError, TypeError):
            severity_score = 0.0

        nvt = result.find("nvt")
        nvt_oid = ""
        nvt_name = name
        nvt_family = ""
        cvss_base = severity_str
        solution_type = "VendorFix"
        cve_ids = []

        if nvt is not None:
            nvt_oid = nvt.attrib.get("oid", "")
            nvt_name = _text(nvt, "name") or name
            nvt_family = _text(nvt, "family")
            cvss_base = _text(nvt, "cvss_base") or severity_str

            tags_raw = _text(nvt, "tags") or ""
            tag_map = {}
            for pair in tags_raw.split("|"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    tag_map[k.strip()] = v.strip()
            solution_type = tag_map.get("solution_type", "VendorFix")
            if not solution:
                solution = tag_map.get("solution", "")

            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.attrib.get("type", "").upper() == "CVE":
                        cve_ids.append(ref.attrib.get("id", ""))

        results.append({
            "id": result.attrib.get("id", ""),
            "name": nvt_name,
            "host": host,
            "port": port,
            "threat": threat,
            "severity": severity_score,
            "cvss_base": cvss_base,
            "nvt_oid": nvt_oid,
            "nvt_family": nvt_family,
            "solution_type": solution_type,
            "cve_ids": cve_ids,
            "description": description,
            "solution": solution,
        })

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Log": 0}
    for r in results:
        t = r["threat"]
        if t in severity_counts:
            severity_counts[t] += 1

    return {
        "results": results,
        "total": len(results),
        "severity_counts": severity_counts,
        "critical_count": severity_counts["Critical"],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"],
        "hosts": list({r["host"] for r in results}),
    }


def _text(element, tag: str) -> str:
    """Safely get text from a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""
