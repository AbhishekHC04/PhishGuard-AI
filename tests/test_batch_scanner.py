
from phishguard.batch_scanner import scan_urls


def test_batch_scanner_returns_ml_and_heuristic_columns():
    urls = [
        "https://www.example.com/",
        "http://secure-login-example.com/verify",
    ]

    results = scan_urls(urls)

    assert len(results) == 2
    assert "risk_score" in results.columns
    assert "risk_level" in results.columns
    assert "ml_prediction" in results.columns
    assert "phishing_probability" in results.columns

    assert results.iloc[0]["ml_prediction"] in {
        "legitimate",
        "phishing",
    }
    assert results.iloc[1]["ml_prediction"] == "phishing"


def test_batch_scanner_handles_empty_url():
    results = scan_urls([""])

    assert len(results) == 1
    assert results.iloc[0]["risk_level"] == "Invalid"
    assert results.iloc[0]["ml_prediction"] == "Unavailable"
    assert results.iloc[0]["error"] != ""
