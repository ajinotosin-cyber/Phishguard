"""
model_utils.py
---------------
Model loading and the URL classification pipeline. No Streamlit import
here on purpose -- this module is used by app.py, detector.py (CLI), and
the test suite alike.

Classification statuses (never silently collapsed into "Safe"):
    INVALID_INPUT        - input doesn't look like a URL/hostname at all
    MODELS_UNAVAILABLE   - model.pkl/nn_model.pkl missing or failed to load;
                            falls back to heuristic-only scoring, clearly labeled
    ANALYSIS_FAILED      - a genuine, unexpected error occurred during scoring
    OK                   - a real classification was produced

Final classification is one of four labels:
    Safe / Suspicious / Phish / Impersonating

A real audit (direct empirical testing, not assumed) found the previous
binary Safe/Phish design forced every URL into one of two confident
verdicts even when the actual evidence was genuinely ambiguous -- e.g.
https://testphp.vulnweb.com/ (Safe, hybrid score 0.014) versus
http://testphp.vulnweb.com/ (Phish, hybrid score 0.999) for the SAME
site, differing only in URL scheme. That specific case is now fixed at
its root (see "HTTPS bias" below), but forcing a binary decision on
genuinely ambiguous URLs is a real design problem independent of any
one bug: if the evidence doesn't clearly support Safe or clearly
support Phish, the honest answer is "Suspicious / insufficient
evidence," not a confident guess in either direction.

HTTPS bias (found and fixed): the training dataset had 99.99% of
legitimate examples using HTTPS versus only 6.2% of phishing examples
-- confirmed by directly measuring data/url_dataset.csv. This made
is_https alone a ~94%-accurate predictor in training, so both models
learned to treat it as an almost single-handedly deterministic signal:
flipping ONLY the scheme on an otherwise-identical URL swung the
hybrid score from ~0.01 to ~0.99. HTTP absence is a real, legitimate
security-posture signal (see feat.suspicious_score), but it is not
phishing evidence on its own -- a vulnerable/insecure site, an internal
tool, or a security-testing target is not automatically a phishing
site. Fixed by retraining on a rebalanced dataset (legitimate examples'
HTTPS rate reduced from 99.99% to ~90%, phishing examples' HTTPS rate
raised from 6.2% to ~20% -- same row counts, same class balance, just
less extreme scheme-based separability) -- not a scoring-pipeline
patch, since the bias lived in the trained models themselves.
"""

from __future__ import annotations

import os
import pickle
from dataclasses import dataclass, field
from typing import Optional

import features as feat

STATUS_OK = "OK"
STATUS_INVALID_INPUT = "INVALID_INPUT"
STATUS_MODELS_UNAVAILABLE = "MODELS_UNAVAILABLE"
STATUS_ANALYSIS_FAILED = "ANALYSIS_FAILED"

LABEL_SAFE = "Safe"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_PHISH = "Phish"
LABEL_IMPERSONATING = "Impersonating"

# Thresholds for the hybrid ML score (0.70 * gradient-boosting + 0.30 * neural net).
# Three bands, not two -- see module docstring for why a binary
# Safe/Phish split forced confident guesses on genuinely ambiguous URLs.
#   score <  LOW_CONFIDENCE_THRESHOLD  AND no heuristic red flags -> Safe
#   score >= HIGH_CONFIDENCE_PHISH_THRESHOLD                      -> Phish
#   everything in between                                          -> Suspicious
LOW_CONFIDENCE_THRESHOLD = 0.30
HIGH_CONFIDENCE_PHISH_THRESHOLD = 0.80
INDICATOR_PHISH_THRESHOLD = 3  # suspicious_score() at/above this is decisive on its own
INDICATOR_SUSPICIOUS_THRESHOLD = 1  # any heuristic red flag at all rules out a clean "Safe"

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
NN_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nn_model.pkl")


@dataclass
class ModelBundle:
    gb_model: Optional[object] = None
    nn_model: Optional[object] = None
    scaler: Optional[object] = None
    load_error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.gb_model is not None and self.nn_model is not None and self.scaler is not None


def load_models() -> ModelBundle:
    """Never raises. Returns a ModelBundle that's either fully populated
    or carries a human-readable load_error -- callers decide how to
    degrade, rather than the app crashing outright."""
    try:
        with open(MODEL_PATH, "rb") as f:
            gb_model = pickle.load(f)
        with open(NN_MODEL_PATH, "rb") as f:
            nn_model, scaler = pickle.load(f)
        return ModelBundle(gb_model=gb_model, nn_model=nn_model, scaler=scaler)
    except FileNotFoundError as exc:
        return ModelBundle(load_error=f"Model file not found: {exc.filename}")
    except (pickle.UnpicklingError, EOFError, ValueError) as exc:
        return ModelBundle(load_error=f"Model file is corrupted or incompatible: {exc}")
    except Exception as exc:  # last-resort: never let a load failure crash the app
        return ModelBundle(load_error=f"Unexpected error loading models: {exc}")


@dataclass
class ScanResult:
    status: str
    url: str
    label: Optional[str] = None
    impersonation_notice: Optional[str] = None
    heuristic_only: bool = False
    error_message: str = ""
    indicator_score: int = 0
    trusted_domain: bool = False
    hybrid_score: Optional[float] = None
    is_https: bool = False
    security_note: Optional[str] = None


def _hybrid_score(models: ModelBundle, features: list[int]) -> float:
    gb_score = models.gb_model.predict_proba([features])[0][1]
    scaled = models.scaler.transform([features])
    nn_score = models.nn_model.predict_proba(scaled)[0][1]
    return (0.70 * gb_score) + (0.30 * nn_score)


def _classify(hybrid_score: float, indicator_score: int, trusted: bool) -> str:
    """The decision hierarchy, in priority order:
    1. A curated, well-known trusted domain (SAFE_DOMAINS) is Safe,
       unconditionally -- a genuine match against a small, deliberately
       curated allowlist is a more authoritative signal than any ML
       score. Found via direct testing that this was NOT previously
       unconditional (it only overrode scores below the high-confidence
       threshold): a completely legitimate Google URL
       (accounts.google.com/login) was classified Phish at 98%
       confidence purely because its path contains ordinary words like
       "login" and "account" -- exactly the kind of cosmetic pattern an
       opaque ML score can be fooled by, which a curated domain match
       must be able to override regardless of how confident the model
       claims to be.
    2. Strong, independent heuristic evidence (multiple concrete red
       flags -- IP hostname, phishing keywords, suspicious TLD, etc.) is
       decisive on its own, regardless of the ML score.
    3. A high-confidence ML score is Phish.
    4. A low ML score with zero heuristic red flags at all is Safe.
    5. Everything else is genuinely ambiguous -- Suspicious, not a forced
       guess in either direction."""
    if trusted:
        return LABEL_SAFE
    if indicator_score >= INDICATOR_PHISH_THRESHOLD:
        return LABEL_PHISH
    if hybrid_score >= HIGH_CONFIDENCE_PHISH_THRESHOLD:
        return LABEL_PHISH
    if hybrid_score < LOW_CONFIDENCE_THRESHOLD and indicator_score == 0:
        return LABEL_SAFE
    return LABEL_SUSPICIOUS


def scan_url(raw_url: str, models: ModelBundle) -> ScanResult:
    """The full pipeline: validate -> heuristics -> (optional) ML scoring
    -> final label. Never raises; every failure mode gets an explicit
    ScanResult.status instead."""
    is_valid, reason = feat.validate_url_input(raw_url)
    if not is_valid:
        return ScanResult(status=STATUS_INVALID_INPUT, url=raw_url, error_message=reason)

    url = feat.normalize_url(raw_url)
    is_https = url.startswith("https://")
    security_note = feat.connection_security_note(url)

    try:
        impersonation = feat.detect_impersonation(url)
        indicator_score = feat.suspicious_score(url)
        trusted = feat.is_trusted_domain(url)
    except Exception as exc:
        return ScanResult(status=STATUS_ANALYSIS_FAILED, url=url,
                           error_message=f"Heuristic analysis failed: {exc}")

    # Impersonation is a pure heuristic (brand name present, real domain
    # absent) and doesn't require the ML models at all.
    if impersonation:
        return ScanResult(
            status=STATUS_OK, url=url, label=LABEL_IMPERSONATING,
            impersonation_notice=impersonation, indicator_score=indicator_score,
            trusted_domain=trusted, is_https=is_https, security_note=security_note,
        )

    if not models.available:
        # Degrade gracefully: heuristic-only scoring, clearly labeled as
        # such. Never silently reports "Safe" just because the ML layer
        # is down -- any heuristic red flag at all now blocks a clean
        # "Safe" verdict, resolving to Suspicious instead.
        if indicator_score >= INDICATOR_PHISH_THRESHOLD:
            label = LABEL_PHISH
        elif indicator_score >= INDICATOR_SUSPICIOUS_THRESHOLD:
            label = LABEL_SUSPICIOUS
        else:
            label = LABEL_SAFE
        return ScanResult(
            status=STATUS_MODELS_UNAVAILABLE, url=url, label=label,
            heuristic_only=True, indicator_score=indicator_score,
            trusted_domain=trusted, is_https=is_https, security_note=security_note,
            error_message=models.load_error or "ML models unavailable.",
        )

    try:
        features = feat.extract_features(url)
        hybrid_score = _hybrid_score(models, features)
    except Exception as exc:
        return ScanResult(status=STATUS_ANALYSIS_FAILED, url=url,
                           error_message=f"Model scoring failed: {exc}")

    label = _classify(hybrid_score, indicator_score, trusted)

    return ScanResult(
        status=STATUS_OK, url=url, label=label,
        indicator_score=indicator_score, trusted_domain=trusted,
        hybrid_score=hybrid_score, is_https=is_https, security_note=security_note,
    )


# ---------------------------------------------------------------------------
# Explanation generation ("Why this result?")
# ---------------------------------------------------------------------------
# A real audit finding: the previous version of this explanation simply
# listed every heuristic that happened to fire (e.g. "Contains 'login'
# keyword.") with no regard for whether that signal was actually decisive.
# A login keyword appears on countless legitimate sites -- presenting it
# as if it justified a phishing/impersonation verdict on its own was
# misleading, not merely imprecise. This builds a genuinely tiered,
# classification-aware explanation instead: it explains WHY the specific
# verdict was reached, using only the evidence that's actually relevant
# to that verdict, ranked by how much weight it actually carried.

KEYWORD_EXPLANATIONS = {
    "login": "Login-related terminology is present.",
    "verify": "Account-verification terminology is present.",
    "update": "Update/renewal terminology is present.",
    "secure": "\"Secure\"-themed terminology is present.",
    "account": "Account-related terminology is present.",
}


@dataclass
class Explanation:
    strong: list[str] = field(default_factory=list)
    supporting: list[str] = field(default_factory=list)
    informational: list[str] = field(default_factory=list)
    summary: str = ""


def _supporting_bullets(findings) -> list[str]:
    bullets = [KEYWORD_EXPLANATIONS[k] for k in findings.keywords_found]
    if findings.is_long:
        bullets.append("The URL is unusually long.")
    if findings.many_subdomains:
        bullets.append("The domain has an unusually large number of subdomains.")
    if findings.suspicious_tld:
        bullets.append(
            "Uses a top-level domain that is not inherently malicious, but is "
            "disproportionately common among free/low-cost domains abused for phishing."
        )
    return bullets


def build_explanation(result: ScanResult) -> Explanation:
    """Builds a tiered (strong / supporting / informational), classification
    -aware explanation FROM the same evidence that actually produced
    result.label -- never a flat dump of every rule that happened to
    match, and never presented as if a single weak signal (a keyword, a
    long URL) were sufficient justification on its own."""
    findings = feat.analyze_indicators(result.url)
    supporting = _supporting_bullets(findings)
    exp = Explanation()

    if result.label == LABEL_IMPERSONATING:
        evidence = feat.detect_impersonation_evidence(result.url)
        brand_name = evidence.brand.capitalize() if evidence else "a known brand"
        real_domain = evidence.real_domain if evidence else "the real domain"
        exp.strong = [
            f"The domain contains a recognizable {brand_name} brand name.",
            f"The domain does not match {brand_name}'s legitimate domain ({real_domain}).",
        ]
        exp.supporting = supporting
        exp.summary = f"Multiple indicators suggest possible brand impersonation of {brand_name}."

    elif result.label == LABEL_PHISH:
        strong_signals = []
        if findings.has_ip:
            strong_signals.append("The address uses a raw IP address instead of a domain name.")
        if findings.has_at_symbol:
            strong_signals.append(
                "The address uses an '@' symbol to disguise the real destination behind a "
                "trusted-looking prefix."
            )
        if indicator_score := result.indicator_score:
            if indicator_score >= INDICATOR_PHISH_THRESHOLD and not strong_signals:
                # Decisive purely through the COMBINATION of several
                # individually-weak supporting signals, not any one of
                # them alone -- say so explicitly rather than implying
                # one bullet (e.g. a keyword) was independently sufficient.
                strong_signals.append(
                    "Several individually-weak indicators are present together, and that "
                    "specific combination is a recognized phishing pattern."
                )

        if strong_signals:
            exp.strong = strong_signals
            exp.supporting = supporting
            exp.summary = (
                "Multiple independent indicators combine to support a high-confidence "
                "phishing classification."
            )
        else:
            # High-confidence PURELY from the trained model's own
            # assessment of the URL's overall structure, with no single
            # explicit rule decisive on its own -- say that honestly
            # rather than manufacturing a "strong indicator" bullet that
            # doesn't actually correspond to what drove the verdict.
            score_pct = f"{result.hybrid_score * 100:.0f}%" if result.hybrid_score is not None else "high"
            exp.strong = [
                f"The trained detection model assessed this URL's overall structure as "
                f"highly consistent with known phishing patterns (confidence: {score_pct})."
            ]
            exp.supporting = supporting
            exp.summary = (
                "The model's assessment of the URL's overall structure, not any single "
                "explicit rule, is the primary basis for this classification."
            )

    elif result.label == LABEL_SUSPICIOUS:
        exp.supporting = supporting
        if result.hybrid_score is not None:
            exp.informational.append(
                f"Model confidence toward phishing: {result.hybrid_score * 100:.0f}% -- "
                f"in an ambiguous range, not clearly benign or clearly malicious."
            )
        if supporting:
            exp.summary = (
                "Some indicators are present, but not enough to confidently classify this "
                "URL as phishing -- and not clean enough to confidently call it safe."
            )
        else:
            exp.summary = (
                "No specific rule-based indicators were found, but the URL's overall "
                "structure does not clearly resemble typical safe or phishing patterns."
            )

    else:  # LABEL_SAFE
        if result.trusted_domain:
            exp.summary = "This domain matches a known, established website."
        elif supporting:
            # Genuinely rare but possible: weak signals present, yet the
            # overall evidence still wasn't enough to move off Safe.
            exp.supporting = supporting
            exp.summary = (
                "A small number of weak, individually-common signals were present, but "
                "nothing rose to a level that suggests phishing or impersonation."
            )
        else:
            exp.summary = "No significant phishing or impersonation indicators were detected."

    return exp
