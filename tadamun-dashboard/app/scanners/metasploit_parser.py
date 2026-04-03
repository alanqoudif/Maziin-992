import json


def parse_metasploit_json(raw_json: str):
    data = json.loads(raw_json)
    exploitable = [i for i in data.get("results", []) if i.get("exploitable") is True]
    return {"total": len(data.get("results", [])), "exploitable": exploitable, "exploitable_count": len(exploitable)}
