
from pathlib import Path

import joblib


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "artifacts"
    / "raw_url_model.joblib"
)

_bundle = None


def load_model():
    """Load the trained raw-URL model once per process."""
    global _bundle

    if _bundle is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Run python train_url_model.py first."
            )
        _bundle = joblib.load(MODEL_PATH)

    return _bundle["model"]


def predict_url(url: str) -> dict:
    """Predict phishing risk from URL text without visiting the URL."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")

    url = url.strip()

    model = load_model()
    probabilities = model.predict_proba([url])[0]
    classes = list(model.classes_)

    phishing_index = classes.index("phishing")
    phishing_probability = float(probabilities[phishing_index])

    prediction = (
        "phishing"
        if model.predict([url])[0] == "phishing"
        else "legitimate"
    )

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": round(phishing_probability, 4),
        "model": "TF-IDF + Logistic Regression",
        "note": (
            "This is a model estimate based on URL text. "
            "It does not prove whether a website is safe or malicious."
        ),
    }
