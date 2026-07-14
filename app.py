import streamlit as st
import pickle
import re
import numpy as np
from urllib.parse import urlparse

# ---------------- LOAD MODELS ----------------

try:
    with open("model.pkl", "rb") as f:
        gb_model = pickle.load(f)

    with open("nn_model.pkl", "rb") as f:
        nn_model, scaler = pickle.load(f)

except FileNotFoundError:
    st.error("Model files not found. Please train the models first.")
    st.stop()

# ---------------- TRUSTED DOMAINS ----------------

SAFE_DOMAINS = [
    "google.com",
    "github.com",
    "openai.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "paypal.com"
]

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    url = str(url).strip().lower()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    return [

        # 1 URL Length
        len(url),

        # 2 Number of dots
        url.count("."),

        # 3 Number of hyphens
        url.count("-"),

        # 4 Number of @
        url.count("@"),

        # 5 Number of ?
        url.count("?"),

        # 6 Number of =
        url.count("="),

        # 7 Number of %
        url.count("%"),

        # 8 HTTPS
        1 if url.startswith("https://") else 0,

        # 9 Uses IP Address
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,

        # 10 login
        1 if "login" in url else 0,

        # 11 verify
        1 if "verify" in url else 0,

        # 12 update
        1 if "update" in url else 0,

        # 13 secure
        1 if "secure" in url else 0,

        # 14 account
        1 if "account" in url else 0,

        # 15 Domain Length
        len(domain),

        # 16 Number of subdomains
        domain.count("."),

        # 17 URL Path Depth
        len([x for x in parsed.path.split("/") if x]),

        # 18 Suspicious TLD
        1 if any(
            domain.endswith(tld)
            for tld in (
                ".xyz",
                ".tk",
                ".ml",
                ".ga",
                ".cf"
            )
        ) else 0
    ]

# ---------------- NEURAL NETWORK ----------------

def nn_predict_proba(features):

    features = np.array(features).reshape(1, -1)
    features = scaler.transform(features)

    return nn_model.predict_proba(features)[0]

# ---------------- SUSPICIOUS FEATURE SCORE ----------------

def suspicious_score(url):

    url = url.lower()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 2

    if "login" in url:
        score += 1

    if "verify" in url:
        score += 1

    if "update" in url:
        score += 1

    if "secure" in url:
        score += 1

    if "account" in url:
        score += 1

    if len(url) > 75:
        score += 1

    if domain.count(".") > 3:
        score += 1

    if any(
        domain.endswith(tld)
        for tld in (
            ".xyz",
            ".tk",
            ".ml",
            ".ga",
            ".cf"
        )
    ):
        score += 2

    return score

# ---------------- IMPERSONATION DETECTION ----------------

def detect_impersonation(url):

    url = url.lower()

    trusted_brands = {

        "google": "google.com",
        "paypal": "paypal.com",
        "facebook": "facebook.com",
        "microsoft": "microsoft.com",
        "amazon": "amazon.com",
        "apple": "apple.com",
        "instagram": "instagram.com",
        "netflix": "netflix.com"

    }

    for brand, real_domain in trusted_brands.items():

        if brand in url and real_domain not in url:
            return f"Possible impersonation of {brand.capitalize()}"

    return None

# ---------------- TRUSTED DOMAIN CHECK ----------------

def is_trusted_domain(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower().replace("www.", "")

    return any(
        domain == trusted or domain.endswith("." + trusted)
        for trusted in SAFE_DOMAINS
    )


# ---------------- STREAMLIT UI ----------------

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 PhishGuard")
st.subheader("Smart Hybrid Phishing Detection System")

url = st.text_input(
    "Enter a URL to scan:",
    placeholder="https://example.com"
)

if st.button("Scan URL"):

    if not url.strip():

        st.warning("Please enter a URL.")

    else:

        # ---------------- FEATURE EXTRACTION ----------------

        features = extract_features(url)

        # ---------------- MODEL PREDICTIONS ----------------

        gb_score = gb_model.predict_proba([features])[0][1]
        nn_score = nn_predict_proba(features)[1]

        # ---------------- HYBRID SCORE ----------------

        hybrid_score = (0.70 * gb_score) + (0.30 * nn_score)

        # ---------------- RULE-BASED CHECKS ----------------

        indicator_score = suspicious_score(url)
        impersonation = detect_impersonation(url)
        trusted = is_trusted_domain(url)

        # ---------------- FINAL DECISION ----------------

        if impersonation:
            prediction = "impersonation"

        elif trusted and hybrid_score < 0.80:
            prediction = "safe"

        elif hybrid_score >= 0.80:
            prediction = "phishing"

        elif hybrid_score >= 0.55 or indicator_score >= 3:
            prediction = "suspicious"

        else:
            prediction = "safe"

        # ---------------- FINAL VERDICT ----------------

        st.divider()

        if prediction == "impersonation":

            st.error("🚨 Impersonation Website")
            st.warning(impersonation)

        elif prediction == "safe":

            st.success("✅ Safe Website")

        elif prediction == "suspicious":

            st.warning("⚠️ Suspicious Website")

        else:

            st.error("🚨 Phishing Website")

        # ---------------- RECOMMENDATIONS ----------------

        st.divider()
        st.subheader("Recommendations")

        if prediction == "safe":

            st.success("The website appears to be legitimate.")

            st.write("• Proceed normally.")
            st.write("• Continue to verify URLs before entering sensitive information.")
            st.write("• Keep your browser and antivirus software updated.")

        elif prediction == "suspicious":

            st.warning("This website shows some suspicious characteristics.")

            st.write("• Verify the website's domain carefully.")
            st.write("• Avoid entering passwords or financial information unless you are certain the website is legitimate.")
            st.write("• Check for HTTPS and confirm the website belongs to the expected organization.")
            st.write("• If unsure, visit the official website directly.")

        else:

            st.error("This website is likely a phishing website.")

            st.write("• Do NOT enter passwords or financial information.")
            st.write("• Leave the website immediately.")
            st.write("• Report the website if possible.")
            st.write("• Access the official website directly instead of using the provided link.")
