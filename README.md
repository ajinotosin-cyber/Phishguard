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

## Safe / Suspicious / Phish / Impersonating — what each means

- **Impersonating** — the URL's *actual domain* mentions a recognized
  brand name but isn't genuinely that brand's real domain (or a real
  subdomain of it). This check doesn't need the ML models at all; it
  fires first and short-circuits the rest of the pipeline.
- **Phish** — either multiple concrete, independent red flags fired
  (IP-address hostname, `@` obfuscation, phishing keywords, excessive
  subdomains, suspicious TLD), or the hybrid ML score is high-confidence
  (≥0.80).
- **Safe** — a curated, well-known trusted domain, OR the hybrid score is
  low (<0.30) *and* zero heuristic red flags fired at all.
- **Suspicious** — everything in between: the evidence genuinely doesn't
  clearly support Safe or Phish. This is a deliberate design decision — PhishGuard does not force a confident guess when the URL-structure evidence is ambiguous.


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

**66 tests, all passing** at the time of this pass — a mix of:
- `tests/test_features.py` — input validation (valid/invalid/garbage/IP/
  too-long, plus a regression test for `@`-obfuscated URLs that were
  previously rejected outright instead of flagged), the 18-feature
  vector shape, suspicious-score behavior including the `@` indicator,
  impersonation detection including a regression test for the
  real-domain-as-decoy-prefix bypass, trusted-domain checks including a
  regression test for the `sites.google.com` fix.
- `tests/test_model_utils.py` — real model loading (the actual shipped,
  retrained `model.pkl`/`nn_model.pkl`), missing/corrupted model files,
  the full `scan_url()` pipeline for Safe/Suspicious/Phish/Impersonating
  paths, degraded heuristics-only mode, a simulated model-scoring
  exception (confirms it becomes "Analysis Failed," never "Safe"), a
  dedicated regression suite for the subdomain-bias fix, and a dedicated
  regression suite for the HTTP/HTTPS bias fix (including a direct check
  that scheme alone no longer swings the score by more than 0.6, and
  that the security note is correctly separated from the phishing
  verdict).
- `tests/test_app_smoke.py` — Streamlit `AppTest` end-to-end: app boot,
  a real scan for each label, invalid-input handling, empty-input
  handling, and models-unavailable behavior, all driven through the
  actual `app.py`.

Beyond the automated suite, this pass also ran the retrained models
against 200 random held-out legitimate URLs and 200 random held-out
phishing URLs from `data/url_dataset.csv` (not used for training), and
a dedicated evaluation matrix (`eval_matrix.py`) covering legitimate,
security-testing, phishing-like (IP-based, impersonation, `@`
obfuscation, excessive subdomains, suspicious TLDs), and malformed URLs
— see "The HTTP/HTTPS bug" and "Model retraining" above for the results.


open user-content publishing platform — anyone can host a page there)
was being blanket-trusted purely because it technically ends with
`.google.com`, unlike Google's own first-party services
(`mail`/`docs`/`drive`/`accounts.google.com`), which correctly remain
trusted.

**Held-out empirical results after the fix** (200 random legitimate +
200 random phishing URLs from the dataset, not used in training):
- Legitimate: **200/200 (100%) correctly Safe** — zero false positives.
- Phishing: **190/200 (95%) correctly flagged** — the 10 remaining
  misses are a genuinely hard, honestly-documented limitation (see
  below), not a regression from this fix.

## Limitations

- **The HTTPS-bias fix traded some recall for honesty.** Reducing the
  model's over-reliance on `is_https` measurably lowered its raw
  phishing recall (~95% → ~80% on the gradient boosting model in
  isolation) *before* accounting for the new Suspicious tier, which
  absorbs much of that lost certainty rather than silently becoming
  "Safe." This is a deliberate, disclosed trade-off: a model that is
  95% "accurate" by leaning almost entirely on one overweighted, brittle
  signal is not actually a better detector than one that is more modest
  but doesn't break the moment a phishing page adds a free TLS
  certificate (or a legitimate page is tested over plain HTTP).
- **URL-structure-only precision on Phish/Impersonating specifically is
  now ~58%** on a 200-URL held-out phishing sample (116/200 landed
  exactly on Phish/Impersonating; most of the rest correctly landed on
  Suspicious, not Safe — see "The HTTP/HTTPS bug" above for the full
  breakdown). This reflects the tool being deliberately more willing to
  say "I'm not sure" than to guess confidently in either direction.
- **No sidebar or multi-page navigation** — PhishGuard is intentionally a
  single-page tool (`layout="centered"`), so there's no
  collapse/reopen-navigation concern to fix here; there's nothing to
  collapse.
- **URL-only.** No email, file, or attachment analysis — this project
  only ever analyzed URLs; nothing in the UI claims otherwise.
- **Heuristic + lexical features only** — PhishGuard does not fetch the
  target URL, inspect page content, check DNS/WHOIS, or query any
  external threat-intelligence API. Classification is based entirely on
  the URL string's own structure and two models trained on that. This is
  the direct cause of the remaining false negatives in the held-out
  test: phishing pages hosted on entirely legitimate, common free
  platforms (Google Sites, Wix, 000webhostapp) produce a URL that looks
  structurally unremarkable by every available signal — catching these
  would require inspecting the actual page content, which is out of
  scope for a URL-structure-only detector.
- **Small trusted-brand/domain lists** (`SAFE_DOMAINS`, `TRUSTED_BRANDS`
  in `features.py`) — only a handful of well-known brands are checked
  for impersonation; this is not an exhaustive brand-protection list.
- **The `@`/impersonation fixes only cover the patterns tested for.**
  Homograph/punycode domains (e.g. a Cyrillic lookalike of "apple.com")
  are not currently detected at all -- `TRUSTED_BRANDS`/impersonation
  detection operates on the literal ASCII string.
- **`data/url_dataset.csv` is ~32MB** — fine for local use, but worth
  knowing before committing it repeatedly; consider Git LFS if it starts
  growing further. `data/url_dataset_augmented.csv` (the rebalanced
  training set used to retrain the shipped models) is the same size and
  kept alongside it for reproducibility.
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
