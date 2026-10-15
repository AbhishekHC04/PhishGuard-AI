
from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "artifacts"
    / "phishing_model.joblib"
)


def load_model():
    """Load the trained phishing classifier."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}. "
            "Run python train_model.py first."
        )

    return joblib.load(MODEL_PATH)


def predict_features(features: dict) -> dict:
    """
    Predict benign/phishing from precomputed URL features.

    This function expects the same engineered features used during training,
    not a raw URL string.
    """
    bundle = load_model()
    model = bundle["model"]
    feature_columns = bundle["feature_columns"]

    row = pd.DataFrame([features])

    # Ensure training feature order and reject missing feature names.
    missing = [column for column in feature_columns if column not in row.columns]
    if missing:
        raise ValueError(
            f"Missing {len(missing)} required features: {missing}"
        )

    row = row[feature_columns]

    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]

    return {
        "prediction": "phishing" if prediction == 1 else "benign",
        "phishing_probability": round(float(probabilities[1]), 4),
        "benign_probability": round(float(probabilities[0]), 4),
        "model": "RandomForestClassifier",
        "feature_count": len(feature_columns),
    }
