import csv
from pathlib import Path

from app.ai.model import train_and_compare


def test_train_and_compare(tmp_path):
    dataset = tmp_path / "dataset.csv"
    model_path = tmp_path / "model.pkl"
    with open(dataset, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "cvss_base_score",
                "exploitability_score",
                "impact_score",
                "asset_criticality",
                "network_exposure",
                "exploit_available",
                "days_since_published",
                "device_type",
                "mitre_attack_technique_count",
                "risk_priority",
            ]
        )
        for i in range(80):
            writer.writerow([8, 7, 7, "high", 0.7, 1, i + 1, "server", 3, 4 if i % 2 == 0 else 3])
    output = train_and_compare(str(dataset), str(model_path))
    assert output["best_model"] in {"random_forest", "svm", "decision_tree"}
    assert Path(model_path).exists()
