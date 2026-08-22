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

Final classification is one of exactly three labels, per product decision:
    Safe / Phish / Impersonating
(The previous four-tier UI -- Safe/Suspicious/Phishing/Impersonation --
is intentionally collapsed to three. The former "Suspicious" score range
now maps to Phish rather than Safe, so an ambiguous signal never quietly
becomes a "Safe" verdict.)
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
LABEL_PHISH = "Phish"
LABEL_IMPERSONATING = "Impersonating"

# Thresholds for the hybrid ML score (0.70 * gradient-boosting + 0.30 * neural net).
# A score below PHISH_THRESHOLD is only "Safe" if no other rule fires.
PHISH_THRESHOLD = 0.55
HIGH_CONFIDENCE_PHISH_THRESHOLD = 0.80
INDICATOR_PHISH_THRESHOLD = 3  # suspicious_score() at/above this also means Phish

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


def _hybrid_score(models: ModelBundle, features: list[int]) -> float:
    gb_score = models.gb_model.predict_proba([features])[0][1]
    scaled = models.scaler.transform([features])
    nn_score = models.nn_model.predict_proba(scaled)[0][1]
    return (0.70 * gb_score) + (0.30 * nn_score)


def scan_url(raw_url: str, models: ModelBundle) -> ScanResult:
    """The full pipeline: validate -> heuristics -> (optional) ML scoring
    -> final label. Never raises; every failure mode gets an explicit
    ScanResult.status instead."""
    is_valid, reason = feat.validate_url_input(raw_url)
    if not is_valid:
        return ScanResult(status=STATUS_INVALID_INPUT, url=raw_url, error_message=reason)

    url = feat.normalize_url(raw_url)

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
            trusted_domain=trusted,
        )

    if not models.available:
        # Degrade gracefully: heuristic-only scoring, clearly labeled as
        # such. Never silently reports "Safe" just because the ML layer
        # is down -- the indicator score still drives the verdict.
        label = LABEL_PHISH if indicator_score >= INDICATOR_PHISH_THRESHOLD else LABEL_SAFE
        return ScanResult(
            status=STATUS_MODELS_UNAVAILABLE, url=url, label=label,
            heuristic_only=True, indicator_score=indicator_score,
            trusted_domain=trusted,
            error_message=models.load_error or "ML models unavailable.",
        )

    try:
        features = feat.extract_features(url)
        hybrid_score = _hybrid_score(models, features)
    except Exception as exc:
        return ScanResult(status=STATUS_ANALYSIS_FAILED, url=url,
                           error_message=f"Model scoring failed: {exc}")

    if trusted and hybrid_score < PHISH_THRESHOLD:
        label = LABEL_SAFE
    elif hybrid_score >= PHISH_THRESHOLD or indicator_score >= INDICATOR_PHISH_THRESHOLD:
        label = LABEL_PHISH
    else:
        label = LABEL_SAFE

    return ScanResult(
        status=STATUS_OK, url=url, label=label,
        indicator_score=indicator_score, trusted_domain=trusted,
    )
