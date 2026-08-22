# PhishGuard

PhishGuard is a hybrid phishing-URL detection tool: a Streamlit web app
plus a terminal CLI, both built on the same shared feature-extraction and
scoring pipeline. It combines two trained ML models with rule-based
heuristics to classify a URL as **Safe**, **Phish**, or **Impersonating**.

**Live app:** https://phishguard-njdwambwj9a4d2j7bnq32z.streamlit.app/
**Author:** Oluwatosin Deborah Ajinomisan

---

## What PhishGuard actually does

You enter a URL. PhishGuard:

1. **Validates** the input — rejects empty input, whitespace, and text
   that doesn't have a plausible domain/hostname shape, rather than
   silently treating garbage as a URL.
2. **Extracts 18 lexical/structural features** from the URL (length,
   punctuation counts, HTTPS usage, IP-address usage, suspicious
   keywords like "login"/"verify", domain length, subdomain count, path
   depth, suspicious TLD).
3. **Scores it two ways**: a Gradient Boosting classifier and a small
   neural network (MLP), both trained on the same 18 features, combined
   into one hybrid score (70% / 30% weighting).
4. **Applies rule-based checks** independently of the ML models: a
   suspicious-indicator score, and a brand-impersonation check (does the
   URL mention a well-known brand — e.g. "paypal" — without actually
   being on that brand's real domain?).
5. **Produces one of three labels** — see below.

## Safe / Phish / Impersonating — what each means

- **Impersonating** — the URL mentions a recognized brand name but isn't
  on that brand's real domain. This check doesn't need the ML models at
  all; it fires first and short-circuits the rest of the pipeline.
- **Phish** — the hybrid ML score is high, or enough individual
  suspicious indicators fired (IP-address URL, suspicious keywords,
  excessive length, suspicious TLD, etc.), regardless of what the ML
  score alone said.
- **Safe** — none of the above triggered, and (if the ML models are
  available) the hybrid score was low.

**Note on a real design change made in this pass:** the earlier version
of this app had a fourth, in-between "Suspicious" label. Per the current
product decision, the UI now shows exactly three outcomes. The score
range that used to trigger "Suspicious" now maps to **Phish** — not
folded into "Safe" — so an ambiguous signal never quietly becomes a
"Safe" verdict.

### Honest failure states (never silently "Safe")

| Situation | What you see |
|---|---|
| Empty input | "Please enter a URL." |
| Garbage / non-URL text | "Invalid Input" — explains why, no verdict shown |
| `model.pkl`/`nn_model.pkl` missing or corrupted | A visible warning banner; PhishGuard keeps working using **rule-based heuristics only**, clearly labeled as such in the result |
| Model scoring throws an unexpected error | "Analysis Failed" — no verdict shown |

---

## Architecture

```
app.py            Streamlit UI. Owns presentation only — validation,
                   scoring, and classification all live in the modules below.
features.py         Pure functions: URL normalization, input validation,
                   the 18-feature extraction, the suspicious-indicator
                   score, brand-impersonation check, trusted-domain check.
                   No I/O, no model loading — safe to import from anywhere.
model_utils.py       Model loading (never raises — reports failures as
                   data) and the scan_url() pipeline that ties features.py
                   + the two trained models into one classification, with
                   an explicit status for every outcome (see table above).
detector.py           Terminal CLI, built on the same features.py /
                   model_utils.py pipeline as the web app. Only runs its
                   interactive loop when executed directly (python
                   detector.py) — importing it does nothing but define
                   functions.
train_model.py        Trains the Gradient Boosting model from
                   data/url_dataset.csv, imports extract_features from
                   features.py (not a separate copy).
train_nn_model.py      Trains the neural network + scaler, same shared
                   feature extraction.
model.pkl / nn_model.pkl   The trained models actually used at inference
                   time. Verified in this pass: both expect exactly the
                   18 features features.py produces, in the same order.
data/url_dataset.csv    ~450k labeled URLs used to train both models.
tests/                Unit tests + Streamlit AppTest end-to-end tests.
```

### What changed from the previous structure

The 18-feature extraction function used to be copy-pasted independently
in `app.py`, the old `detector.py`, `train_model.py`, and
`train_nn_model.py` — four copies that had to be kept manually in sync
with what `model.pkl`/`nn_model.pkl` were actually trained on. That's a
real feature-mismatch risk: if any one copy drifted, the models would
silently receive a different feature vector than they were trained on
and produce meaningless predictions with no error. All four now import
the same `features.py`. The old `detector.py` also loaded models and ran
an **unguarded interactive `input()` loop at module import time** —
meaning `import detector` from anywhere (e.g. to reuse a helper) would
hang waiting on stdin. This is fixed: the CLI loop only runs under
`if __name__ == "__main__":`.

---

## Installation

```bash
git clone https://github.com/ajinotosin-cyber/Phishguard.git
cd Phishguard
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

No `.env` file or API keys are required — PhishGuard doesn't call any
external services; everything runs locally against the shipped models.

### Streamlit Cloud deployment

1. Push this repository to GitHub.
2. On [share.streamlit.io](https://share.streamlit.io), create a new app
   pointing at this repo, branch `main`, main file `app.py`.
3. Deploy — no Secrets configuration is needed for this project.

`runtime.txt` pins the Python version (`python-3.10.13`) for platforms
that read it (e.g. Streamlit Community Cloud's legacy buildpack path).

### Running the CLI

```bash
python detector.py
```

### Retraining the models

```bash
pip install -r requirements.txt -r requirements-train.txt
python train_model.py       # trains model.pkl (Gradient Boosting)
python train_nn_model.py    # trains nn_model.pkl (neural network + scaler)
```

Both scripts read `data/url_dataset.csv` (columns: `url`, `type`) and
import feature extraction from `features.py`, so a retrained model stays
compatible with the app by construction — there's no separate copy of
the feature logic to fall out of sync.

---

## Testing

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

**40 tests, all passing** at the time of this pass — a mix of:
- `tests/test_features.py` — input validation (valid/invalid/garbage/IP/
  too-long), the 18-feature vector shape, suspicious-score behavior,
  impersonation detection, trusted-domain checks.
- `tests/test_model_utils.py` — real model loading (the actual shipped
  `model.pkl`/`nn_model.pkl`), missing/corrupted model files, the full
  `scan_url()` pipeline for Safe/Phish/Impersonating paths, degraded
  heuristics-only mode, and a simulated model-scoring exception
  (confirms it becomes "Analysis Failed," never "Safe").
- `tests/test_app_smoke.py` — Streamlit `AppTest` end-to-end: app boot,
  a real scan for each of the three labels, invalid-input handling,
  empty-input handling, and models-unavailable behavior, all driven
  through the actual `app.py`.

## Limitations

- **No sidebar or multi-page navigation** — PhishGuard is intentionally a
  single-page tool (`layout="centered"`), so there's no
  collapse/reopen-navigation concern to fix here; there's nothing to
  collapse.
- **URL-only.** No email, file, or attachment analysis — this project
  only ever analyzed URLs; nothing in the UI claims otherwise.
- **Heuristic + lexical features only** — PhishGuard does not fetch the
  target URL, inspect page content, check DNS/WHOIS, or query any
  external threat-intelligence API. Classification is based entirely on
  the URL string's own structure and two models trained on that.
- **Small trusted-brand/domain lists** (`SAFE_DOMAINS`, `TRUSTED_BRANDS`
  in `features.py`) — only a handful of well-known brands are checked
  for impersonation; this is not an exhaustive brand-protection list.
- **`data/url_dataset.csv` is ~32MB** — fine for local use, but worth
  knowing before committing it repeatedly; consider Git LFS if it starts
  growing further. Not changed in this pass.
- **Model files are loaded via `pickle`**, which can execute arbitrary
  code if the `.pkl` file is ever tampered with. This is inherent to how
  scikit-learn model persistence normally works and wasn't changed here;
  worth knowing if these files are ever sourced from somewhere untrusted.

## Security notes

- This project does not use any external API keys, tokens, or
  credentials — there was nothing to find or rotate in this audit, and a
  full scan of the repository (excluding a large local `codesenv/`
  virtual environment that was never part of the tracked project)
  confirmed no `.env` file, no hardcoded secrets, and no credentials in
  documentation or test data.
- The personal VS Code workspace file (`Oluwatosin's  Workspace.code-
  workspace`) has been removed from the project — see "Workspace file"
  below.
- `.gitignore` excludes `*.code-workspace`, local virtual environments,
  Python caches, and (defensively, in case this ever changes) `.env`
  files — even though none currently exist in this project.

## Workspace file

The repository contained a personal, multi-project VS Code workspace
file — `Oluwatosin's  Workspace.code-workspace` — listing folders for
several unrelated projects (AARIS-LITE, VulnX, FortiPass, ThreatScope,
etc.) on your machine. That's personal editor metadata, not a PhishGuard
project artifact, so it has been removed from the repository and
`*.code-workspace` added to `.gitignore` so it can't accidentally return.
Your actual VS Code workspace on your machine is untouched — this only
affects what's tracked inside this project's repository.

## What's genuinely implemented vs. excluded

**Implemented and working:** URL validation, 18-feature extraction,
hybrid Gradient Boosting + neural network scoring, rule-based indicator
scoring, brand-impersonation detection, trusted-domain shortcut, graceful
degradation to heuristics-only mode, a terminal CLI sharing the same
pipeline as the web app.

**Intentionally excluded / not implemented:** any external API calls,
live page-content fetching, DNS/WHOIS/certificate inspection, email or
file analysis, a prediction-score display, an indicators list, or a
risk-level bar in the web UI (per the current product decision to keep
the web result simple — the CLI's `detector.py` does print a detailed
indicator breakdown, since that's a terminal tool for a different kind of
user).
