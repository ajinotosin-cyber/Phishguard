from flask import Flask, render_template, request

import pickle

import re

import numpy as np

from urllib.parse import urlparse



app = Flask(__name__)



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



    if "login" in url: indicators.append("Contains 'login'")

    if "verify" in url: indicators.append("Contains 'verify'")

    if "update" in url: indicators.append("Contains 'update'")

    if "@" in url: indicators.append("Contains @ symbol")

    if "http://" in url: indicators.append("Uses HTTP (not secure)")

    if url.count(".") > 3: indicators.append("Too many subdomains")



    if not indicators:

        indicators.append("No obvious suspicious patterns")



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



# ---------------- ROUTE ----------------

@app.route("/", methods=["GET", "POST"])

def home():



    result = None

    indicators = []

    recommendations = []

    box_color = ""

    risk_level = None



    ml_score = None

    nn_score = None

    final_score = None



    if request.method == "POST":

        url = request.form["url"]



        # ML prediction

        features = extract_features(url)

        ml_proba = model.predict_proba([features])[0]

        ml_score = ml_proba[1]



        # NN prediction

        nn_proba = nn_predict_proba(url)

        nn_score = nn_proba[1]



        # ---------------- HYBRID DECISION ----------------

        final_score = (ml_score + nn_score) / 2



        if final_score > 0.75:

            prediction = 1

        elif final_score < 0.40:

            prediction = 0

        else:

            prediction = "suspicious"



        # Indicators

        indicators = generate_indicators(url)
        impersonation = detect_impersonation(url)

        if impersonation:
            indicators.append(impersonation)



        # ---------------- RESULTS ----------------

        if prediction == 0:

            result = "Safe Website"

            box_color = "safe"

            risk_level = "Low Risk"

            recommendations = [

                "Proceed normally",

                "Always verify website authenticity",

                "Avoid entering sensitive data unnecessarily"

            ]



        elif prediction == 1:

            result = "⚠️ Phishing Website"

            box_color = "phishing"

            risk_level = "High Risk"

            recommendations = [

                "Do NOT enter personal or financial information",

                "Exit the website immediately",

                "Report the website if possible"

            ]



        else:

            result = "⚠️ Suspicious Website"

            box_color = "phishing"

            risk_level = "Medium Risk"

            recommendations = [

                "Proceed with caution",

                "Verify the domain carefully",

                "Avoid logging in or submitting sensitive data"

            ]



    return render_template(

        "index.html",

        result=result,

        indicators=indicators,

        recommendations=recommendations,

        box_color=box_color,

        risk_level=risk_level,

        ml_score=round(ml_score, 3) if ml_score is not None else None,

        nn_score=round(nn_score, 3) if nn_score is not None else None,

        final_score=round(final_score, 3) if final_score is not None else None

    )


if __name__ == "__main__":

    app.run(host="0.0.0.0", port=10000)