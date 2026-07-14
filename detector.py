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
    print("Error: model.pkl or nn_model.pkl not found.")
    exit()

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

        # 9 IP Address
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


# ---------------- EXPLAIN PREDICTION ----------------

def explain_prediction(url):

    url = url.lower()

    parsed = urlparse(url)
    domain = parsed.netloc

    reasons = []

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        reasons.append("Uses an IP address instead of a domain.")

    if "login" in url:
        reasons.append("Contains 'login' keyword.")

    if "verify" in url:
        reasons.append("Contains 'verify' keyword.")

    if "update" in url:
        reasons.append("Contains 'update' keyword.")

    if "secure" in url:
        reasons.append("Contains 'secure' keyword.")

    if "account" in url:
        reasons.append("Contains 'account' keyword.")

    if len(url) > 75:
        reasons.append("URL is unusually long.")

    if domain.count(".") > 3:
        reasons.append("Contains many subdomains.")

    if any(domain.endswith(tld) for tld in [".xyz", ".tk", ".ml", ".ga", ".cf"]):
        reasons.append("Uses a suspicious top-level domain.")

    return reasons


# ---------------- DETECTOR ----------------

print("=" * 60)
print("      PHISHGUARD HYBRID PHISHING DETECTOR")
print("=" * 60)

while True:

    url = input("\nEnter URL (or type 'exit'): ").strip()

    if url.lower() == "exit":
        print("\nThank you for using PhishGuard.")
        break

    features = extract_features(url)

    # Gradient Boosting Prediction
    gb_score = gb_model.predict_proba([features])[0][1]

    # Neural Network Prediction
    scaled_features = scaler.transform(np.array(features).reshape(1, -1))
    nn_score = nn_model.predict_proba(scaled_features)[0][1]

    # Hybrid Score (Evidence-based weighting)
    hybrid_score = (0.70 * gb_score) + (0.30 * nn_score)

    print("\n================ RESULT ================")
    print(f"Gradient Boosting : {gb_score*100:.2f}%")
    print(f"Neural Network    : {nn_score*100:.2f}%")
    print(f"Hybrid Score      : {hybrid_score*100:.2f}%")

    # Decision
    if hybrid_score >= 0.80:
        prediction = "🚨 PHISHING"
        risk = "HIGH"

    elif hybrid_score >= 0.40:
        prediction = "⚠️ SUSPICIOUS"
        risk = "MEDIUM"

    else:
        prediction = "✅ SAFE"
        risk = "LOW"

    print(f"\nPrediction : {prediction}")
    print(f"Risk Level : {risk}")

    # Indicators
    indicators = explain_prediction(url)

    print("\nIndicators:")

    if indicators:
        for item in indicators:
            print(f" • {item}")
    else:
        print(" • No major phishing indicators detected.")

    # Recommendations
    print("\nRecommendations:")

    if risk == "HIGH":
        print(" • Do NOT enter passwords or banking details.")
        print(" • Leave the website immediately.")
        print(" • Report the website if possible.")

    elif risk == "MEDIUM":
        print(" • Proceed carefully.")
        print(" • Verify the domain before entering sensitive information.")
        print(" • Double-check the URL for spelling or impersonation.")

    else:
        print(" • Website appears safe.")
        print(" • Continue using standard online security practices.")

    print("=" * 60)

