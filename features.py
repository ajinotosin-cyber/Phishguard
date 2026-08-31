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
from dataclasses import dataclass
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

# Subdomains that technically end with a SAFE_DOMAINS suffix but must NOT
# inherit that trust: these are free, open-publishing platforms where
# ANYONE can host arbitrary content (including phishing pages) under the
# parent company's own domain. Found via direct testing: a real phishing
# URL on sites.google.com was misclassified as Safe purely because
# "sites.google.com".endswith(".google.com") -- unlike mail.google.com,
# docs.google.com, drive.google.com, or accounts.google.com, which are
# Google's own first-party services and genuinely warrant the inherited
# trust, sites.google.com specifically lets any user publish a page.
USER_CONTENT_HOSTING_SUBDOMAINS = (
    "sites.google.com",
)

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

    # netloc can legitimately include a "user@" or "user:pass@" prefix
    # per URL syntax (RFC 3986's userinfo component) -- this is exactly
    # the classic phishing obfuscation trick (e.g.
    # "https://paypal.com@evil.tk/login" shows a trusted-looking prefix
    # but actually navigates to evil.tk). Found via direct testing: the
    # hostname-shape regex below doesn't allow "@", so a URL using this
    # trick was being rejected outright as "invalid input" -- silently
    # discarding a genuine phishing indicator instead of flagging it.
    # The actual HOST (after the last "@") is what must look like a real
    # hostname; the userinfo part is validated for suspicion separately
    # in suspicious_score()/explain_indicators(), not here.
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]

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
    findings = analyze_indicators(raw_url)
    score = 0
    if findings.has_ip:
        score += 2
    if findings.has_at_symbol:
        score += 2
    score += len(findings.keywords_found)
    if findings.is_long:
        score += 1
    if findings.many_subdomains:
        score += 1
    if findings.suspicious_tld:
        score += 2
    return score


@dataclass
class IndicatorFindings:
    """Structured, per-signal breakdown -- the single source of truth
    that suspicious_score(), explain_indicators(), and the tiered
    explanation builder in model_utils.py all derive from, so they can
    never drift out of sync with each other."""
    has_ip: bool
    has_at_symbol: bool
    keywords_found: list[str]
    is_long: bool
    many_subdomains: bool
    suspicious_tld: bool


def analyze_indicators(raw_url: str) -> IndicatorFindings:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc
    return IndicatorFindings(
        has_ip=bool(_IP_RE.search(url)),
        has_at_symbol="@" in domain,
        keywords_found=[k for k in SUSPICIOUS_KEYWORDS if k in url],
        is_long=len(url) > 75,
        many_subdomains=domain.count(".") > 3,
        suspicious_tld=any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS),
    )


def explain_indicators(raw_url: str) -> list[str]:
    """Flat, human-readable reasons behind the suspicious_score -- kept
    for the CLI (detector.py), which shows a plain list rather than the
    tiered strong/supporting breakdown the Streamlit UI uses (see
    model_utils.build_explanation for that -- it's classification-aware
    in a way a flat list of "what fired" cannot be, since the same
    keyword means something different depending on what else is
    present)."""
    findings = analyze_indicators(raw_url)
    reasons = []
    if findings.has_ip:
        reasons.append("Uses an IP address instead of a domain.")
    if findings.has_at_symbol:
        reasons.append(
            "Contains an '@' in the address -- everything before it is decorative and can "
            "be used to disguise the real destination (e.g. a trusted-looking name before "
            "the actual, unrelated host)."
        )
    for keyword in findings.keywords_found:
        reasons.append(f"Contains '{keyword}' keyword.")
    if findings.is_long:
        reasons.append("URL is unusually long.")
    if findings.many_subdomains:
        reasons.append("Contains many subdomains.")
    if findings.suspicious_tld:
        reasons.append("Uses a suspicious top-level domain.")
    return reasons


def connection_security_note(raw_url: str) -> str | None:
    """A plain security-posture observation about the connection itself
    -- completely separate from suspicious_score()/explain_indicators(),
    which never cite HTTPS presence/absence as phishing evidence. Missing
    HTTPS is real and worth surfacing (an unencrypted connection can be
    intercepted/tampered with), but it is not, on its own, evidence that
    a site IS phishing -- plenty of legitimate, vulnerable-on-purpose, or
    internal sites run over plain HTTP. Kept as a distinct, separately
    labeled note so the UI never conflates the two."""
    url = normalize_url(raw_url)
    if not url.startswith("https://"):
        return "Connection is not encrypted (HTTP)."
    return None


@dataclass
class ImpersonationEvidence:
    brand: str
    real_domain: str
    actual_domain: str


def detect_impersonation_evidence(raw_url: str) -> ImpersonationEvidence | None:
    """The structured version of detect_impersonation() -- exposes WHICH
    brand and WHAT the actual (mismatched) domain is, so a caller can
    build a specific, evidence-based explanation ("the domain contains
    X" + "the domain does not match X's real domain") rather than only
    a single opaque sentence."""
    url = normalize_url(raw_url)
    domain = urlparse(url).netloc.lower().replace("www.", "")
    for brand, real_domain in TRUSTED_BRANDS.items():
        is_genuinely_real_domain = domain == real_domain or domain.endswith("." + real_domain)
        if brand in domain and not is_genuinely_real_domain:
            return ImpersonationEvidence(brand=brand, real_domain=real_domain, actual_domain=domain)
    return None


def detect_impersonation(raw_url: str) -> str | None:
    """Returns a human-readable impersonation warning, or None. Flags a
    URL whose ACTUAL domain mentions a well-known brand name without
    genuinely being that brand's real domain (or a real subdomain of
    it) -- a common phishing/typosquatting pattern.

    Checks the domain specifically, not the whole URL string, and uses
    a proper suffix match (matching is_trusted_domain's own logic) for
    what counts as "genuinely the real domain." Found via direct testing
    that an earlier version checked `real_domain not in url` against the
    ENTIRE url (path included), which meant a domain like
    "www.paypal.com.security-check-update.info" -- a classic phishing
    pattern that embeds the real domain as a decoy prefix before the
    actual (unrelated) domain -- was incorrectly treated as legitimate,
    since the literal substring "paypal.com" IS present somewhere in
    that URL, even though it is not actually the domain being visited.
    """
    evidence = detect_impersonation_evidence(raw_url)
    if evidence:
        return f"Possible impersonation of {evidence.brand.capitalize()}"
    return None


def is_trusted_domain(raw_url: str) -> bool:
    url = normalize_url(raw_url)
    domain = urlparse(url).netloc.lower().replace("www.", "")
    if domain in USER_CONTENT_HOSTING_SUBDOMAINS:
        return False
    return any(domain == trusted or domain.endswith("." + trusted) for trusted in SAFE_DOMAINS)
