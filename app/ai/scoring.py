def weighted_risk_score(row):
    score = (
        row["cvss_base_score"] * 0.30
        + row["exploitability_score"] * 0.20
        + row["impact_score"] * 0.20
        + (row["asset_criticality"] / 4) * 10 * 0.15
        + row["network_exposure"] * 10 * 0.10
        + row["exploit_available"] * 10 * 0.05
    )
    return round(min(max(score * 10 / 10, 0), 100), 2)
