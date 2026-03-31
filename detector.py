import pickle

import re

from urllib.parse import urlparse



with open("model.pkl", "rb") as f:

    model = pickle.load(f)



def extract_features(url):

    url = str(url).lower()

    parsed = urlparse(url)



    return [

        len(url),

        url.count('.'),

        url.count('-'),

        url.count('@'),

        url.count('?'),

        url.count('='),

        url.count('%'),

        1 if url.startswith("https://") else 0,

        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,

        1 if 'login' in url else 0,

        1 if 'verify' in url else 0,

        1 if 'update' in url else 0,

        1 if 'secure' in url else 0,

        1 if 'account' in url else 0,

        len(parsed.netloc),

        parsed.netloc.count('.'),

        url.count('/'),

        1 if any(tld in parsed.netloc for tld in ['.xyz','.tk','.ml','.ga','.cf']) else 0

    ]



while True:

    url = input("\nEnter URL (or 'exit'): ")

    if url == "exit":

        break



    features = extract_features(url)

    proba = model.predict_proba([features])[0]



    print("\nConfidence:", round(max(proba)*100,2), "%")



    if proba[1] > 0.85:

        print("⚠️ Phishing")

    elif proba[1] < 0.30:

        print("✅ Safe")

    else:

        print("⚠️ Suspicious")