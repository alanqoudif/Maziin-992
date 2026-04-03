import pandas as pd

CRITICALITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEVICE_TYPE_MAP = {"printer": 0, "workstation": 1, "ids": 2, "server": 3, "firewall": 3}


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    work = df.copy()
    work["asset_criticality"] = work["asset_criticality"].map(CRITICALITY_MAP).fillna(2)
    work["device_type_encoded"] = work["device_type"].map(DEVICE_TYPE_MAP).fillna(1)
    work["exploit_available"] = work["exploit_available"].astype(int)
    return work[
        [
            "cvss_base_score",
            "exploitability_score",
            "impact_score",
            "asset_criticality",
            "network_exposure",
            "exploit_available",
            "days_since_published",
            "device_type_encoded",
            "mitre_attack_technique_count",
        ]
    ]
