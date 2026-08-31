import streamlit as st

import features as feat
import model_utils as mu

# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🔐",
    layout="centered",
)

# ---------------------------------------------------------------------------
# CSS — preserves PhishGuard's existing dark navy / blue identity
# (colors carried over from the project's own design: #0b1f3a background,
# #1f6feb accent, #00c853 safe, #ff5252 danger), tightened for a more
# polished, enterprise feel.
# ---------------------------------------------------------------------------

st.markdown("""
<style>
.stApp{
    background: radial-gradient(circle at top, #12294f 0%, #0b1f3a 55%, #081729 100%);
    color: #eaf1fb;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}
.block-container{ padding-top: 2.2rem; max-width: 720px; }

.pg-title{
    font-size: 34px; font-weight: 700; margin-bottom: 0;
    display: flex; align-items: center; gap: 10px;
}
.pg-subtitle{ color: #9bb3c9; font-size: 15px; margin-top: 2px; margin-bottom: 28px; }

.stTextInput > div > div > input{
    background:#0f2745 !important; color:#eaf1fb !important;
    border:1px solid #23406b !important; border-radius:8px !important;
    padding:12px 14px !important; font-size:15px !important;
}
.stButton > button{
    background:#1f6feb !important; color:white !important; border:none !important;
    border-radius:8px !important; padding:10px 22px !important; font-weight:600 !important;
}
.stButton > button:hover{ background:#3a82f2 !important; }

.pg-card{
    border-radius: 10px; padding: 20px 22px; margin-top: 22px; margin-bottom: 18px;
    border: 1px solid; font-size: 15px;
}
.pg-card-safe{ background: rgba(0,200,83,.08); border-color: #1f9c50; }
.pg-card-suspicious{ background: rgba(255,193,7,.08); border-color: #b5860a; }
.pg-card-phish{ background: rgba(255,82,82,.08); border-color: #c23b3b; }
.pg-card-impersonating{ background: rgba(255,82,82,.10); border-color: #c23b3b; }
.pg-card-invalid{ background: rgba(155,179,201,.08); border-color: #3d5776; }
.pg-card-unavailable{ background: rgba(255,193,7,.08); border-color: #b5860a; }
.pg-card-failed{ background: rgba(255,82,82,.08); border-color: #c23b3b; }

.pg-verdict{ font-size: 20px; font-weight: 700; margin-bottom: 4px; }
.pg-note{ color: #b7c7db; font-size: 13.5px; margin-top: 2px; }
.pg-security-note{
    background: rgba(255,193,7,.06); border: 1px solid #6b5a1f; border-radius: 8px;
    padding: 10px 14px; margin-top: 10px; font-size: 13.5px; color: #d7c88f;
}
.pg-indicators{ margin: 10px 0 0 0; padding-left: 20px; color: #b7c7db; font-size: 13.5px; line-height: 1.7; }
.pg-indicators-strong{ color: #e0a0a0; }
.pg-indicator-tier{
    font-size: 12px; font-weight: 700; color: #7d92a8; margin-top: 14px;
    text-transform: uppercase; letter-spacing: .04em;
}

.pg-rec-title{ font-size: 14px; font-weight: 700; color: #9bb3c9; margin: 22px 0 8px 0;
    text-transform: uppercase; letter-spacing: .04em; }
.pg-rec-list{ margin: 0; padding-left: 20px; color: #d7e2ef; font-size: 14.5px; line-height: 1.8; }

.pg-footer{
    margin-top: 46px; text-align: center; color: #6d8299; font-size: 12.5px;
    border-top: 1px solid #1c3454; padding-top: 16px;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="pg-title">🔐 PhishGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="pg-subtitle">Smart Hybrid Phishing Detection System</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# MODEL LOADING — never crashes the app; degrades to heuristic-only mode
# with a clearly labeled banner if the trained models can't be loaded.
# ---------------------------------------------------------------------------

if "models" not in st.session_state:
    st.session_state.models = mu.load_models()

models: mu.ModelBundle = st.session_state.models

if not models.available:
    st.warning(
        f"⚠️ ML models are unavailable ({models.load_error}). "
        f"PhishGuard will still run using rule-based heuristics only, but results "
        f"will be less accurate than with the trained models. This is shown honestly "
        f"rather than reporting a normal result.",
    )

# ---------------------------------------------------------------------------
# INPUT
# ---------------------------------------------------------------------------

url = st.text_input("Enter a URL to scan:", placeholder="https://example.com")
scan_clicked = st.button("Scan URL")

RECOMMENDATIONS = {
    mu.LABEL_IMPERSONATING: [
        "Do NOT enter usernames, passwords or banking information.",
        "Verify the domain name carefully.",
        "Visit the official website by typing the URL directly.",
        "Report the website if you believe it is malicious.",
    ],
    mu.LABEL_SAFE: [
        "Continue browsing normally.",
        "Always verify the URL before entering sensitive information.",
        "Keep your browser and antivirus software updated.",
    ],
    mu.LABEL_SUSPICIOUS: [
        "The available evidence is not sufficient to confidently call this Safe or Phishing.",
        "Avoid entering passwords, banking details, or personal information until you can verify the site independently.",
        "Consider looking up the domain owner/reputation before proceeding.",
        "If you followed a link to get here, verify it came from a trusted source.",
    ],
    mu.LABEL_PHISH: [
        "Leave the website immediately.",
        "Do NOT enter passwords, banking details, or personal information.",
        "Report the website to your browser or cybersecurity team.",
        "Access the official website directly instead of using the provided link.",
    ],
}

VERDICT_DISPLAY = {
    mu.LABEL_SAFE: ("✅ Safe Website", "pg-card-safe"),
    mu.LABEL_SUSPICIOUS: ("⚠️ Suspicious — Insufficient Evidence to Confirm", "pg-card-suspicious"),
    mu.LABEL_PHISH: ("🚨 Phishing Website", "pg-card-phish"),
    mu.LABEL_IMPERSONATING: ("🚨 Impersonation Website", "pg-card-impersonating"),
}

if scan_clicked:
    if not url.strip():
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing URL..."):
            result = mu.scan_url(url, models)

        if result.status == mu.STATUS_INVALID_INPUT:
            st.markdown(
                f'<div class="pg-card pg-card-invalid">'
                f'<div class="pg-verdict">⚠️ Invalid Input</div>'
                f'<div class="pg-note">{result.error_message} Enter a real URL or domain, e.g. '
                f'https://example.com.</div></div>',
                unsafe_allow_html=True,
            )

        elif result.status == mu.STATUS_ANALYSIS_FAILED:
            st.markdown(
                f'<div class="pg-card pg-card-failed">'
                f'<div class="pg-verdict">⚠️ Analysis Failed</div>'
                f'<div class="pg-note">PhishGuard could not complete this scan: '
                f'{result.error_message} No verdict is being shown because a failed '
                f'analysis is never the same as a "Safe" result.</div></div>',
                unsafe_allow_html=True,
            )

        else:
            verdict_text, card_class = VERDICT_DISPLAY[result.label]

            note = ""
            if result.heuristic_only:
                card_class = "pg-card-unavailable" if result.label == mu.LABEL_SAFE else card_class
                note = "Result based on rule-based heuristics only — ML models were unavailable for this scan."
            if result.impersonation_notice:
                note = (note + " " if note else "") + result.impersonation_notice

            st.markdown(
                f'<div class="pg-card {card_class}">'
                f'<div class="pg-verdict">{verdict_text}</div>'
                + (f'<div class="pg-note">{note}</div>' if note else "")
                + '</div>',
                unsafe_allow_html=True,
            )

            # A missing-HTTPS security note is shown separately from the
            # phishing verdict, on purpose -- an unencrypted connection is
            # a real security-posture observation worth surfacing, but it
            # is never treated as phishing evidence on its own (see
            # features.connection_security_note's docstring).
            if result.security_note:
                st.markdown(
                    f'<div class="pg-security-note">🔓 {result.security_note} '
                    f'This is a connection-security observation, separate from the phishing '
                    f'classification above.</div>',
                    unsafe_allow_html=True,
                )

            # Tiered, classification-aware explanation -- built from the
            # SAME evidence that produced result.label, never a flat dump
            # of every rule that happened to fire (see
            # model_utils.build_explanation's docstring for the full
            # audit finding this replaced: a bare 'login' keyword was
            # previously shown as if it were meaningful evidence on its
            # own, for every classification including Safe).
            explanation = mu.build_explanation(result)
            with st.expander("Why this result?"):
                st.markdown(f'<div class="pg-note">{explanation.summary}</div>', unsafe_allow_html=True)
                if explanation.strong:
                    st.markdown('<div class="pg-indicator-tier">Strong indicators</div>', unsafe_allow_html=True)
                    items = "".join(f"<li>{i}</li>" for i in explanation.strong)
                    st.markdown(f'<ul class="pg-indicators pg-indicators-strong">{items}</ul>', unsafe_allow_html=True)
                if explanation.supporting:
                    st.markdown('<div class="pg-indicator-tier">Supporting indicators</div>', unsafe_allow_html=True)
                    items = "".join(f"<li>{i}</li>" for i in explanation.supporting)
                    st.markdown(f'<ul class="pg-indicators">{items}</ul>', unsafe_allow_html=True)
                if explanation.informational:
                    st.markdown('<div class="pg-indicator-tier">Informational</div>', unsafe_allow_html=True)
                    items = "".join(f"<li>{i}</li>" for i in explanation.informational)
                    st.markdown(f'<ul class="pg-indicators">{items}</ul>', unsafe_allow_html=True)

            st.markdown('<div class="pg-rec-title">Recommendations</div>', unsafe_allow_html=True)
            items = "".join(f"<li>{r}</li>" for r in RECOMMENDATIONS[result.label])
            st.markdown(f'<ul class="pg-rec-list">{items}</ul>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# FOOTER
# ---------------------------------------------------------------------------

st.markdown(
    '<div class="pg-footer"><strong>PhishGuard</strong> © 2026<br>'
    'Engineered by <strong>Oluwatosin Deborah Ajinomisan</strong></div>',
    unsafe_allow_html=True,
)
