"""
features.py
------------
Single source of truth for URL feature extraction and rule-based heuristics.

Previously, this exact 18-feature extraction logic was duplicated
independently in app.py, detector.py, train_model.py, and train_nn_model.py.
That is a real feature-mismatch risk: if any one copy drifted from the
others, the trained models (model.pkl / nn_model.pkl, which expect exactly
these 18 features in this exact order) would silently receive a different
feature vector than the one they were trained on, producing meaningless
predictions with no error. This module is now the only place this logic
lives; everything else imports it.

This module has NO side effects (no model loading, no I/O) so it is safe
to import from training scripts, the CLI, and the Streamlit app alike.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "at_count", "question_count",
    "equals_count", "percent_count", "is_https", "has_ip_address",
    "has_login_keyword", "has_verify_keyword", "has_update_keyword",
    "has_secure_keyword", "has_account_keyword", "domain_length",
    "subdomain_count", "path_depth", "has_suspicious_tld",
]

SUSPICIOUS_TLDS = (".xyz", ".tk", ".ml", ".ga", ".cf")
SUSPICIOUS_KEYWORDS = ("login", "verify", "update", "secure", "account")

SAFE_DOMAINS = [
    "google.com", "github.com", "openai.com", "microsoft.com", "amazon.com",
    "apple.com", "facebook.com", "instagram.com", "netflix.com", "paypal.com",
]

TRUSTED_BRANDS = {
    "google": "google.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
}

_IP_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
# A conservative hostname shape check used for input validation: at least
# one label, a dot, and a plausible TLD -- OR a dotted-quad IPv4 address.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize_url(raw_url: str) -> str:
    """Lowercases, strips whitespace, and adds an https:// scheme if the
    input doesn't already have one. Does not validate the result."""
    url = str(raw_url or "").strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def validate_url_input(raw_url: str) -> tuple[bool, str]:
    """
    Returns (is_valid, reason). This is a genuine format check, not a
    rubber stamp: garbage input like "asdkjh" or "http://" alone is
    rejected here rather than being silently fed to the model as if it
    were a real URL (which would produce a low-signal feature vector and
    a misleadingly confident "Safe" result).
    """
    raw = str(raw_url or "").strip()
    if not raw:
        return False, "No input provided."

    if len(raw) > 2048:
        return False, "Input is too long to be a valid URL."

    if any(ch.isspace() for ch in raw):
        return False, "URLs cannot contain whitespace."

    url = normalize_url(raw)
    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain:
        return False, "Could not identify a domain/host in the input."

    domain_no_port = domain.split(":")[0]

    if _IP_RE.fullmatch(domain_no_port):
        return True, ""

    if not _HOSTNAME_RE.match(domain_no_port):
        return False, "Input does not look like a valid domain or hostname."

    return True, ""


def extract_features(raw_url: str) -> list[int]:
    """Returns the 18-element feature vector, in the exact order
    model.pkl and nn_model.pkl were trained on. See FEATURE_NAMES for the
    meaning of each position."""
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("%"),
        1 if url.startswith("https://") else 0,
        1 if _IP_RE.search(url) else 0,
        1 if "login" in url else 0,
        1 if "verify" in url else 0,
        1 if "update" in url else 0,
        1 if "secure" in url else 0,
        1 if "account" in url else 0,
        len(domain),
        domain.count("."),
        len([p for p in parsed.path.split("/") if p]),
        1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,
    ]


def suspicious_score(raw_url: str) -> int:
    """A simple additive rule-based score, independent of the ML models.
    Used both as a secondary signal alongside the model scores, and as the
    sole signal in the degraded "heuristics-only" mode when the ML models
    can't be loaded."""
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0
    if _IP_RE.search(url):
        score += 2
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url:
            score += 1
    if len(url) > 75:
        score += 1
    if domain.count(".") > 3:
        score += 1
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 2
    return score


def explain_indicators(raw_url: str) -> list[str]:
    """Human-readable reasons behind the suspicious_score. Used by the CLI
    (detector.py) for a detailed breakdown; not shown in the Streamlit UI
    per the product decision to keep the web result simple."""
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc

    reasons = []
    if _IP_RE.search(url):
        reasons.append("Uses an IP address instead of a domain.")
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url:
            reasons.append(f"Contains '{keyword}' keyword.")
    if len(url) > 75:
        reasons.append("URL is unusually long.")
    if domain.count(".") > 3:
        reasons.append("Contains many subdomains.")
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Uses a suspicious top-level domain.")
    return reasons


def detect_impersonation(raw_url: str) -> str | None:
    """Returns a human-readable impersonation warning, or None. Flags a
    URL that mentions a well-known brand name without actually being on
    that brand's real domain -- a common phishing/typosquatting pattern."""
    url = normalize_url(raw_url)
    for brand, real_domain in TRUSTED_BRANDS.items():
        if brand in url and real_domain not in url:
            return f"Possible impersonation of {brand.capitalize()}"
    return None


def is_trusted_domain(raw_url: str) -> bool:
    url = normalize_url(raw_url)
    domain = urlparse(url).netloc.lower().replace("www.", "")
    return any(domain == trusted or domain.endswith("." + trusted) for trusted in SAFE_DOMAINS)
