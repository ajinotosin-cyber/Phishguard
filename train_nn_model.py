import pandas as pd

import pickle

import re

from urllib.parse import urlparse



from sklearn.model_selection import train_test_split

from sklearn.neural_network import MLPClassifier

from sklearn.preprocessing import StandardScaler

from sklearn.metrics import classification_report, accuracy_score



# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    try:

        url = str(url).lower()

        parsed = urlparse(url)

        domain = parsed.netloc



        features = []



        # URL structure

        features.append(len(url))

        features.append(url.count('.'))

        features.append(url.count('-'))

        features.append(url.count('@'))

        features.append(url.count('?'))

        features.append(url.count('='))

        features.append(url.count('%'))



        # Security

        features.append(1 if url.startswith("https://") else 0)



        # IP address detection

        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)



        # Suspicious keywords (STRONGER)

        suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'signin', 'confirm']

        features.append(sum(word in url for word in suspicious_words))



        # Domain features

        features.append(len(domain))

        features.append(domain.count('.'))



        # URL depth

        features.append(url.count('/'))



        # Suspicious TLDs

        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf']

        features.append(1 if any(tld in domain for tld in suspicious_tlds) else 0)



        return features



    except:

        return None



# ---------------- LOAD DATA ----------------

df = pd.read_csv("data/url_dataset.csv")



# Standardize columns

df.columns = ["URL", "Label"]



# Map labels properly (VERY IMPORTANT)

df["Label"] = df["Label"].map({

    "benign": 0,

    "legitimate": 0,

    "good": 0,

    "safe": 0,

    "phishing": 1,

    "bad": 1,

    "malicious": 1,

})



# Clean

df = df.dropna()

df = df.drop_duplicates()



# ---------------- BUILD FEATURES ----------------

X_series = df["URL"].apply(extract_features)

valid_rows = X_series[X_series.notnull()]



X = pd.DataFrame(valid_rows.tolist())

y = df.loc[valid_rows.index, "Label"]



print("Samples:", len(X))



# ---------------- SCALE ----------------

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)



# ---------------- SPLIT ----------------

X_train, X_test, y_train, y_test = train_test_split(

    X_scaled, y, test_size=0.2, random_state=42, stratify=y

)



# ---------------- MODEL ----------------

model = MLPClassifier(

    hidden_layer_sizes=(128, 64),  # stronger network

    activation='relu',

    solver='adam',

    max_iter=500,

    random_state=42

)



# ---------------- TRAIN ----------------

model.fit(X_train, y_train)



# ---------------- EVALUATE ----------------

y_pred = model.predict(X_test)



print("\nNN MODEL PERFORMANCE")

print("Accuracy:", round(accuracy_score(y_test, y_pred), 4))

print("\nClassification Report:\n")

print(classification_report(y_test, y_pred))



# ---------------- SAVE ----------------

with open("nn_model.pkl", "wb") as f:

    pickle.dump((model, scaler), f)



print("\nNeural Network Model Saved Successfully!")







