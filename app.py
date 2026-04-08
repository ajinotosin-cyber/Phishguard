import streamlit as st

import pickle

import re

import numpy as np

from urllib.parse import urlparse



# ---------------- LOAD MODELS ----------------

with open("model.pkl", "rb") as f:

    model = pickle.load(f)



with open("nn_model.pkl", "rb") as f:

    nn_model, scaler = pickle.load(f)



# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    url = str(url).lower()

    parsed = urlparse(url)



    features = []



    features.append(len(url))

    features.append(url.count('.'))

    features.append(url.count('-'))

    features.append(url.count('@'))

    features.append(url.count('?'))

    features.append(url.count('='))

    features.append(url.count('%'))



    features.append(1 if url.startswith("https://") else 0)



    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

    features.append(1 if 'login' in url else 0)

    features.append(1 if 'verify' in url else 0)

    features.append(1 if 'update' in url else 0)

    features.append(1 if 'secure' in url else 0)

    features.append(1 if 'account' in url else 0)



    domain = parsed.netloc

    features.append(len(domain))

    features.append(domain.count('.'))



    features.append(url.count('/'))



    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf']

    features.append(1 if any(tld in domain for tld in suspicious_tlds) else 0)



    return features



# ---------------- NN PREDICTION ----------------

def nn_predict_proba(url):

    features = extract_features(url)

    features = np.array(features).reshape(1, -1)

    features_scaled = scaler.transform(features)

    proba = nn_model.predict_proba(features_scaled)[0]

    return proba



# ---------------- INDICATORS ----------------

def generate_indicators(url):

    indicators = []



    if "login" in url:

        indicators.append("Contains login-related keyword")



    if "verify" in url:

        indicators.append("Requests verification action")



    if "update" in url:

        indicators.append("Requests account update")



    if "@" in url:

        indicators.append("Contains unusual '@' symbol")



    if "http://" in url:

        indicators.append("Not secure (HTTP)")



    if url.count(".") > 3:

        indicators.append("Too many subdomains")



    if re.search(r'\d+\.\d+\.\d+\.\d+', url):

        indicators.append("Uses IP address instead of domain")



    if not indicators:

        indicators.append("No obvious suspicious patterns detected")



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

        "netflix": "netflix.com",

        "bank": "bank.com"

    }



    for brand, real_domain in trusted_brands.items():

        if brand in url and real_domain not in url:

            return f"Possible impersonation of {brand.capitalize()}"



    return None



# ---------------- STREAMLIT UI ----------------

st.set_page_config(page_title="PhishGuard", layout="centered")



st.title("🔐 PhishGuard")

st.subheader("Smart Phishing Detection System")



url = st.text_input("Enter a URL to check:")



if st.button("Check URL"):

    if url:



        # ML prediction

        features = extract_features(url)

        ml_score = model.predict_proba([features])[0][1]



        # NN prediction

        nn_score = nn_predict_proba(url)[1]



        # Hybrid score

        final_score = (ml_score + nn_score) / 2



        # Indicators + impersonation

        indicators = generate_indicators(url)

        impersonation = detect_impersonation(url)



        suspicious_count = len(indicators)

        if impersonation:

            suspicious_count += 1



        # FINAL DECISION LOGIC (balanced)

        if final_score >= 0.65 or suspicious_count >= 2:

            prediction = "phishing"

        else:

            prediction = "safe"



        # ---------------- RESULTS ----------------

        if prediction == "safe":

            st.success("✅ Safe Website")

            st.info("Risk Level: Low Risk")

        else:

            st.error("⚠️ Phishing Website")

            st.error("Risk Level: High Risk")



        # Impersonation warning

        if impersonation:

            st.warning(f"🚨 {impersonation}")



        # Indicators

        st.subheader("Indicators")

        for item in indicators:

            st.write(f"• {item}")



        # Recommendations

        st.subheader("Recommendations")



        if prediction == "safe":

            st.write("• Proceed normally")

            st.write("• Always verify website authenticity")

            st.write("• Avoid entering sensitive data unnecessarily")



        else:

            st.write("• Do NOT enter personal or financial information")

            st.write("• Exit the website immediately")

            st.write("• Report the website if possible")



    else:

        st.warning("Please enter a URL")



# ---------------- FOOTER ----------------

st.write("")

st.write("")

st.write("")



st.markdown("""

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

}

</style>



<div class="footer">

    PhishGuard © • Engineered by Oluwatosin Deborah Ajinomisan

</div>

""", unsafe_allow_html=True)

