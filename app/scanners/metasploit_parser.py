import json

def parse_metasploit_json(raw_json: str):
    data = json.loads(raw_json)
    results = data.get("exploit_results", [])
    
    vulnerable = [r for r in results if r.get("result") == "vulnerable"]
    not_vulnerable = [r for r in results if r.get("result") == "not_vulnerable"]
    error = [r for r in results if r.get("result") == "error"]
    
    return {
        "scan_info": data.get("scan_info", {}),
        "results": results,
        "total": len(results),
        "vulnerable_count": len(vulnerable),
        "not_vulnerable_count": len(not_vulnerable),
        "error_count": len(error),
        "vulnerable": vulnerable
    }
