import pandas as pd

import pickle

import re

from urllib.parse import urlparse



from sklearn.model_selection import train_test_split

from sklearn.ensemble import GradientBoostingClassifier

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report





# ---------------- LOAD DATA ----------------

df = pd.read_csv("data/url_dataset.csv")



# Standardize column names

df.columns = ["URL", "Label"]


df["Label"] = df["Label"].map({
    "benign": 0,
    "legitimate": 0,
    "good": 0,
    "safe": 0,
    "phishing": 1,
    "bad": 1,
    "malicious": 1,
})


# Clean dataset

df = df.dropna()

df = df.drop_duplicates()



print("Dataset distribution:\n", df["Label"].value_counts())





# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    try:

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



    except:

        return None  # skip bad URLs





# ---------------- BUILD FEATURES ----------------

X_series = df["URL"].apply(extract_features)
valid_rows = X_series[X_series.notnull()]
X = pd.DataFrame(valid_rows.tolist())
y = df.loc[valid_rows.index, "Label"]



print("\nAfter cleaning:", len(X), "samples")





# ---------------- SPLIT DATA ----------------

X_train, X_test, y_train, y_test = train_test_split(

    X, y, test_size=0.2, random_state=42, stratify=y

)





# ---------------- TRAIN MODEL ----------------

model = GradientBoostingClassifier()

model.fit(X_train, y_train)





# ---------------- EVALUATION ----------------

y_pred = model.predict(X_test)



accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)



print("\n MODEL PERFORMANCE")

print("Accuracy :", round(accuracy, 4))

print("Precision:", round(precision, 4))

print("Recall   :", round(recall, 4))

print("F1 Score :", round(f1, 4))



print("\n Classification Report:\n")

print(classification_report(y_test, y_pred))





# ---------------- SAVE MODEL ----------------

with open("model.pkl", "wb") as f:

    pickle.dump(model, f)



print("\n Model trained and saved successfully!")