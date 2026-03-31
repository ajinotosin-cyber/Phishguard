import pandas as pd

import pickle

from sklearn.model_selection import train_test_split

from sklearn.neural_network import MLPClassifier

from sklearn.preprocessing import StandardScaler

import re

from urllib.parse import urlparse



# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    url = str(url).lower()



    features = []



    try:

        parsed = urlparse(url)

        domain = parsed.netloc

    except:

        domain = ""



    # Basic counts

    features.append(len(url))

    features.append(url.count('.'))

    features.append(url.count('-'))

    features.append(url.count('@'))

    features.append(url.count('?'))

    features.append(url.count('='))

    features.append(url.count('%'))



    features.append(1 if url.startswith("https://") else 0)



    # Risk patterns

    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

    features.append(1 if 'login' in url else 0)

    features.append(1 if 'verify' in url else 0)

    features.append(1 if 'update' in url else 0)

    features.append(1 if 'secure' in url else 0)

    features.append(1 if 'account' in url else 0)



    # Domain features (safe fallback)

    features.append(len(domain))

    features.append(domain.count('.'))



    features.append(url.count('/'))



    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf']

    features.append(1 if any(tld in domain for tld in suspicious_tlds) else 0)



    return features




# ---------------- LOAD DATA ----------------

df = pd.read_csv("data/url_dataset.csv")



# Convert URLs to features

X = df["url"].apply(extract_features).tolist()

y = df["type"]



# Scale

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)



# Split

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)



# Model

model = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42)



# Train

model.fit(X_train, y_train)



# Save

with open("nn_model.pkl", "wb") as f:

    pickle.dump((model, scaler), f)



print("Neural Network Model Saved Successfully")