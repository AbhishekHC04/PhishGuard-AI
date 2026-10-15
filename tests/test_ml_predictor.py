
import pytest

from phishguard.raw_url_predictor import predict_url


def test_predictor_returns_expected_fields():
    result = predict_url("https://www.example.com/")

    assert result["url"] == "https://www.example.com/"
    assert result["prediction"] in {"legitimate", "phishing"}
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["model"] == "TF-IDF + Logistic Regression"
    assert "does not prove" in result["note"]


def test_predictor_handles_phishing_like_url():
    result = predict_url("http://secure-login-example.com/verify")

    assert result["prediction"] == "phishing"
    assert result["phishing_probability"] > 0.5


@pytest.mark.parametrize("url", ["", "   ", None, 123])
def test_predictor_rejects_empty_or_invalid_input(url):
    with pytest.raises(ValueError):
        predict_url(url)
