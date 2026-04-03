import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from app.ai.feature_engineering import build_features


def train_and_compare(dataset_path: str, output_model_path: str):
    df = pd.read_csv(dataset_path)
    X = build_features(df)
    y = df["risk_priority"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    models = {
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=42),
        "svm": SVC(kernel="rbf", gamma="scale"),
        "decision_tree": DecisionTreeClassifier(max_depth=8, random_state=42),
    }
    metrics = {}
    best_name, best_acc = None, 0.0
    for name, model in models.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        metrics[name] = {
            "accuracy": float(acc),
            "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
        }
        if acc > best_acc:
            best_acc = acc
            best_name = name
    best_model = models[best_name]
    Path(output_model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, output_model_path)

    if best_name == "random_forest":
        metrics["feature_importance"] = dict(zip(X.columns, best_model.feature_importances_.tolist()))
    else:
        metrics["feature_importance"] = {}

    metrics_path = Path(output_model_path).with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return {"best_model": best_name, "metrics": metrics}
