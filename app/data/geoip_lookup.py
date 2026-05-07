"""
Lightweight IP-to-country resolver that works entirely offline.

Priority:
1. Exact-match against the AbuseIPDB entries in threat_intel_feeds.json
2. CIDR prefix match for synthetic 203.0.x.x attacker IPs seeded by seed_data.py
3. RFC-5737 / RFC-1918 ranges → "Internal"
"""
import json
import ipaddress
from pathlib import Path
from functools import lru_cache

# ---------------------------------------------------------------------------
# Country metadata: iso2 → (name, lat, lng)
# ---------------------------------------------------------------------------
COUNTRY_META = {
    "CN": ("China",           35.86, 104.19),
    "RU": ("Russia",          61.52,  105.32),
    "DE": ("Germany",         51.17,   10.45),
    "UA": ("Ukraine",         48.38,   31.17),
    "NL": ("Netherlands",     52.13,    5.29),
    "CH": ("Switzerland",     46.82,    8.23),
    "HK": ("Hong Kong",       22.32,  114.17),
    "US": ("United States",   37.09,  -95.71),
    "FR": ("France",          46.23,    2.21),
    "BR": ("Brazil",         -14.24,  -51.93),
    "KR": ("South Korea",     35.91,  127.77),
    "IN": ("India",           20.59,   78.96),
    "TR": ("Turkey",          38.96,   35.24),
    "IR": ("Iran",            32.43,   53.69),
    "PK": ("Pakistan",        30.38,   69.35),
    "NG": ("Nigeria",          9.08,    8.68),
    "GB": ("United Kingdom",  55.38,   -3.44),
    "CA": ("Canada",          56.13,  -106.35),
    "AU": ("Australia",      -25.27,  133.78),
    "JP": ("Japan",           36.20,  138.25),
}

# Synthetic second-octet → country iso2 mapping
# seed_data.py generates 203.0.{100-200}.x  (randint(100,200))
_SECOND_OCTET_MAP = {
    range(100, 110): "CN",
    range(110, 120): "RU",
    range(120, 130): "DE",
    range(130, 140): "UA",
    range(140, 150): "NL",
    range(150, 160): "US",
    range(160, 170): "FR",
    range(170, 180): "BR",
    range(180, 190): "KR",
    range(190, 201): "IN",
}


def _build_second_octet_lookup() -> dict:
    result = {}
    for rng, iso2 in _SECOND_OCTET_MAP.items():
        for val in rng:
            result[val] = iso2
    return result


_SECOND_OCTET_LOOKUP: dict = _build_second_octet_lookup()


@lru_cache(maxsize=1)
def _load_threat_intel() -> dict:
    """Load AbuseIPDB entries from threat_intel_feeds.json, cached."""
    path = Path("data/threat_intel_feeds.json")
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            feeds = json.load(f)
        result = {}
        for entry in feeds.get("abuseipdb", {}).get("entries", []):
            ip = entry.get("ip", "")
            country = entry.get("country", "")
            if ip and country:
                result[ip] = country
        return result
    except Exception:
        return {}


_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in _RFC1918)


def lookup(ip: str) -> dict:
    """
    Return dict:
      {ip, country_code, country_name, lat, lng}
    country_code is "INT" for internal/unknown.
    """
    default = {"ip": ip, "country_code": "INT", "country_name": "Internal/Unknown",
                "lat": 0.0, "lng": 0.0}
    if not ip:
        return default

    # 1. Exact-match threat intel
    ti = _load_threat_intel()
    if ip in ti:
        iso2 = ti[ip]
        meta = COUNTRY_META.get(iso2, (iso2, 0.0, 0.0))
        return {"ip": ip, "country_code": iso2, "country_name": meta[0],
                "lat": meta[1], "lng": meta[2]}

    # 2. Try parsing
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return default

    if _is_private(addr):
        return {**default, "country_name": "Internal Network"}

    # 3. Synthetic 203.0.x.x range
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "203" and parts[1] == "0":
        try:
            second = int(parts[2])
            iso2 = _SECOND_OCTET_LOOKUP.get(second)
            if iso2:
                meta = COUNTRY_META.get(iso2, (iso2, 0.0, 0.0))
                return {"ip": ip, "country_code": iso2, "country_name": meta[0],
                        "lat": meta[1], "lng": meta[2]}
        except (ValueError, IndexError):
            pass

    return default
