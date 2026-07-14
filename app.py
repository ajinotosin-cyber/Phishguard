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

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    url = str(url).strip().lower()

    # Automatically add HTTPS if omitted
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
            for tld in [
                ".xyz",
                ".tk",
                ".ml",
                ".ga",
                ".cf"
            ]
        ) else 0

    ]

# ---------------- NEURAL NETWORK PREDICTION ----------------

def nn_predict_proba(features):

    features = np.array(features).reshape(1, -1)

    features_scaled = scaler.transform(features)

    return nn_model.predict_proba(features_scaled)[0]

# ---------------- SMART INDICATORS ----------------

def generate_indicators(url):

    url = url.lower()

    parsed = urlparse(url)
    domain = parsed.netloc

    indicators = []

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        indicators.append("Uses an IP address instead of a domain.")

    if "login" in url:
        indicators.append("Contains 'login' keyword.")

    if "verify" in url:
        indicators.append("Contains 'verify' keyword.")

    if "update" in url:
        indicators.append("Contains 'update' keyword.")

    if "secure" in url:
        indicators.append("Contains 'secure' keyword.")

    if "account" in url:
        indicators.append("Contains 'account' keyword.")

    if len(url) > 75:
        indicators.append("URL is unusually long.")

    if domain.count(".") > 3:
        indicators.append("Contains many subdomains.")

    if any(
        domain.endswith(tld)
        for tld in [
            ".xyz",
            ".tk",
            ".ml",
            ".ga",
            ".cf"
        ]
    ):
        indicators.append("Uses a suspicious top-level domain.")

    if not indicators:
        indicators.append("No major phishing indicators detected.")

    return indicators

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

    for brand, domain in trusted_brands.items():

        if brand in url and domain not in url:
            return f"Possible impersonation of {brand.capitalize()}"

    return None

# ---------------- STREAMLIT UI ----------------

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 PhishGuard")
st.subheader("Hybrid Phishing Detection System")

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

        # ---------------- GRADIENT BOOSTING ----------------

        gb_score = gb_model.predict_proba([features])[0][1]

        # ---------------- NEURAL NETWORK ----------------

        nn_score = nn_predict_proba(features)[1]

        # ---------------- HYBRID SCORE ----------------

        hybrid_score = (0.70 * gb_score) + (0.30 * nn_score)

        # ---------------- IMPERSONATION ----------------

        impersonation = detect_impersonation(url)

        # ---------------- FINAL DECISION ----------------

        if hybrid_score >= 0.80:

            prediction = "phishing"
            risk = "High Risk"

        elif hybrid_score >= 0.40:

            prediction = "suspicious"
            risk = "Medium Risk"

        else:

            prediction = "safe"
            risk = "Low Risk"

       
        # ---------------- FINAL VERDICT ----------------

        if prediction == "safe":

            st.success("✅ Safe Website")
            st.info(f"Risk Level: {risk}")

        elif prediction == "suspicious":

            st.warning("⚠️ Suspicious Website")
            st.warning(f"Risk Level: {risk}")

        else:

            st.error("🚨 Phishing Website")
            st.error(f"Risk Level: {risk}")

        # ---------------- IMPERSONATION WARNING ----------------

        if impersonation:

            st.warning(f"🚨 {impersonation}")

       
       # ---------------- RECOMMENDATIONS ----------------

        st.divider()

        st.subheader("Recommendations")

        if prediction == "safe":

            st.success("The website appears to be legitimate.")

            st.write("• Proceed normally.")
            st.write("• Always verify the website URL before entering sensitive information.")
            st.write("• Keep your browser and antivirus software updated.")

        elif prediction == "suspicious":

            st.warning("This website shows some suspicious characteristics.")

            st.write("• Verify the website's domain carefully.")
            st.write("• Avoid entering passwords or financial information unless you are certain the website is legitimate.")
            st.write("• Check for HTTPS and confirm the website belongs to the expected organization.")

        else:

            st.error("This website is likely a phishing website.")

            st.write("• Do NOT enter passwords or financial information.")
            st.write("• Leave the website immediately.")
            st.write("• Report the website if possible.")
            st.write("• Access the official website directly instead of using the provided link.")

# ---------------- FOOTER ----------------

st.markdown(
    """
    <style>
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        text-align: center;
        color: grey;
        font-size: 13px;
        padding: 10px;
        background-color: transparent;
    }
    </style>

    <div class="footer">
        <strong>PhishGuard</strong> © 2026 |
        Engineered by <strong>Oluwatosin Deborah Ajinomisan</strong>
    </div>
    """,
    unsafe_allow_html=True
)



