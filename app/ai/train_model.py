from app.ai.model import train_and_compare


if __name__ == "__main__":
    result = train_and_compare("data/cve_dataset.csv", "ml_models/vulnerability_model.pkl")
    print(result["best_model"])
