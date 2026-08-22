import pandas as pd
import pickle

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

from features import extract_features

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

# ---------------- BUILD FEATURE MATRIX ----------------
# extract_features() is imported from features.py -- the same function
# app.py and detector.py use at inference time, so the trained model's
# expected feature order can never silently drift from what the app sends.


def _safe_extract(url):
    try:
        return extract_features(url)
    except Exception:
        return None


X_series = df["URL"].apply(_safe_extract)

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

