import pandas as pd
import pickle
import re
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# ---------------- LOAD DATA ----------------

df = pd.read_csv("data/url_dataset.csv")

# Standardize column names
df.columns = ["URL", "Label"]

# Standardize labels
df["Label"] = df["Label"].map({
    "benign": 0,
    "legitimate": 0,
    "good": 0,
    "safe": 0,
    "phishing": 1,
    "bad": 1,
    "malicious": 1,
})

# Remove invalid rows
df = df.dropna()
df = df.drop_duplicates()

print("Dataset distribution:")
print(df["Label"].value_counts())

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    try:

        url = str(url).strip().lower()

        # Automatically add HTTPS if omitted
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc

        features = [

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

            # 10 login keyword
            1 if "login" in url else 0,

            # 11 verify keyword
            1 if "verify" in url else 0,

            # 12 update keyword
            1 if "update" in url else 0,

            # 13 secure keyword
            1 if "secure" in url else 0,

            # 14 account keyword
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

        return features

    except Exception:

        return None

# ---------------- BUILD FEATURE MATRIX ----------------

X_series = df["URL"].apply(extract_features)

valid_rows = X_series[X_series.notnull()]

X = pd.DataFrame(valid_rows.tolist())

y = df.loc[valid_rows.index, "Label"]

print(f"\nSamples after cleaning: {len(X)}")

# ---------------- TRAIN TEST SPLIT ----------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# ---------------- TRAIN MODEL ----------------

model = GradientBoostingClassifier(
    n_estimators=150,
    learning_rate=0.08,
    max_depth=3,
    random_state=42
)

model.fit(X_train, y_train)

# ---------------- EVALUATION ----------------

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n========== MODEL PERFORMANCE ==========")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nClassification Report:\n")

print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)

print("Confusion Matrix:")

print(cm)

# ---------------- SAVE MODEL ----------------

with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\nGradient Boosting model saved successfully!")

