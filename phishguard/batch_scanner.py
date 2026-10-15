
import pandas as pd

from phishguard.url_analyzer import analyze_url
from phishguard.raw_url_predictor import predict_url


def scan_urls(urls: list[str]) -> pd.DataFrame:
    """Analyze URL text using heuristic rules and the ML model."""
    results = []

    for url in urls:
        try:
            result = analyze_url(url)
            ml_result = predict_url(url)

            results.append({
                "url": result["url"],
                "hostname": result["hostname"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "ml_prediction": ml_result["prediction"],
                "phishing_probability": ml_result["phishing_probability"],
                "indicators": "; ".join(result["indicators"]),
                "error": "",
            })

        except ValueError as exc:
            results.append({
                "url": str(url),
                "hostname": "",
                "risk_score": None,
                "risk_level": "Invalid",
                "ml_prediction": "Unavailable",
                "phishing_probability": None,
                "indicators": "",
                "error": str(exc),
            })

    return pd.DataFrame(results)
