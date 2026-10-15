
import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "signin",
    "wallet",
    "banking",
    "payment",
    "recover",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
}


def analyze_url(url: str) -> dict:
    """
    Analyze URL text without visiting or downloading its contents.

    Returns explainable indicators, a heuristic risk score,
    and a preliminary risk classification.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")

    url = url.strip()

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains invalid control characters.")

    # Parse the URL as text. Never make a network request here.
    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Accessing .port also detects malformed port numbers.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL has an invalid structure.") from exc

    if not hostname or not parsed.netloc:
        raise ValueError("Enter a URL with a valid hostname.")

    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError("Enter a valid hostname.")

    if any(char.isspace() for char in hostname):
        raise ValueError("Hostname cannot contain spaces.")

    if "%" in hostname:
        raise ValueError("Percent-encoded hostnames are not supported.")

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        uses_ip_address = True
    except ValueError:
        uses_ip_address = False

    indicators = []
    score = 0

    def flag(points: int, message: str) -> None:
        nonlocal score
        score += points
        indicators.append(message)

    # These are heuristic signals, not proof of phishing.
    if len(url) >= 100:
        flag(15, "Unusually long URL.")

    if len(hostname) >= 45:
        flag(10, "Unusually long hostname.")

    if "@" in parsed.netloc:
        flag(25, "Contains an @ symbol in the authority section.")

    if uses_ip_address:
        flag(25, "Uses an IP address instead of a domain name.")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        flag(20, "Contains a punycode hostname label.")

    labels = hostname.split(".")
    if len(labels) >= 5:
        flag(15, "Contains many hostname labels or subdomains.")

    if "-" in hostname:
        flag(10, "Hostname contains hyphens.")

    lowered_url = url.lower()
    found_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
                     lowered_url)
    )

    if found_keywords:
        flag(10, "Contains potentially sensitive keywords: "
             + ", ".join(found_keywords))

    if hostname in SHORTENER_DOMAINS:
        flag(15, "Uses a known URL-shortening service.")

    scheme = parsed.scheme.lower()
    if scheme != "https":
        flag(5, "Does not use HTTPS.")

    score = min(score, 100)

    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not indicators:
        indicators.append("No configured heuristic indicators were detected.")

    return {
        "url": url,
        "hostname": hostname,
        "scheme": scheme,
        "risk_score": score,
        "risk_level": risk,
        "indicators": indicators,
        "note": (
            "Heuristic assessment only. A low score does not prove a URL "
            "is safe, and a high score does not prove it is malicious."
        ),
    }
