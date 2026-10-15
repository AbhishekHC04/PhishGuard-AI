
import pytest

from phishguard.url_analyzer import analyze_url


def test_suspicious_url_returns_explanations():
    result = analyze_url("http://secure-login-example.com")

    assert result["risk_level"] == "Medium"
    assert result["risk_score"] == 25
    assert len(result["indicators"]) >= 1


def test_https_url_is_analyzed():
    result = analyze_url("https://example.com")

    assert result["hostname"] == "example.com"
    assert result["scheme"] == "https"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"


def test_ip_address_is_flagged():
    result = analyze_url("http://192.0.2.1/login")

    assert any(
        "IP address" in indicator
        for indicator in result["indicators"]
    )


def test_empty_url_is_rejected():
    with pytest.raises(ValueError):
        analyze_url("")


def test_invalid_hostname_is_rejected():
    with pytest.raises(ValueError):
        analyze_url("https:///")
