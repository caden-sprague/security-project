"""
SVM Model — Comparison Baseline
Contributor: Widyane Kasbi

Trains a Support Vector Machine on a stratified sample of the ICU dataset
and evaluates it using the same 10 features and 70/30 split as the Random
Forest in CreateRF.py, allowing a direct performance comparison.

Why a sample?
    SVM training complexity is O(n²)–O(n³) in the number of samples. The full
    dataset (~188 k rows) would take hours to train with an RBF kernel. We use
    a stratified 20 % sample (~37 k rows), which is large enough to be
    representative while keeping training time under a minute.

Why StandardScaler?
    Unlike tree-based models (RF, DT), SVMs are sensitive to feature magnitude.
    Without scaling, features with larger numeric ranges (e.g., tcp.time_delta)
    dominate the decision boundary. StandardScaler normalises each feature to
    zero mean and unit variance before fitting.

Usage:
    cd security-project          # must be run from the project root
    python models/svm_model.py
"""

import os
import sys

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing   import LabelEncoder, StandardScaler
from sklearn.svm             import SVC
from sklearn.metrics         import (accuracy_score, precision_score,
                                      recall_score, f1_score, confusion_matrix)

# ── paths (relative to project root) ─────────────────────────────────────────

# Allow running from either the project root or the models/ subdirectory
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR    = os.path.join(BASE_DIR, "ICUDatasetProcessed")
MODEL_OUT   = os.path.join(BASE_DIR, "svm_model.pkl")

FEATURES = [
    "frame.time_delta", "tcp.time_delta",
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver",
    "label",
]

# Fraction of the dataset to use — keeps training time manageable
SAMPLE_FRAC  = 0.20
RANDOM_STATE = 100


# ── 1. Load dataset ───────────────────────────────────────────────────────────

print("Loading dataset…")
frames = []
for fname in ["Attack.csv", "environmentMonitoring.csv", "patientMonitoring.csv"]:
    path = os.path.join(DATA_DIR, fname)
    df   = pd.read_csv(path, low_memory=False)
    df.fillna(0, inplace=True)
    frames.append(df)

full_df = pd.concat(frames, ignore_index=True)
print(f"  Full dataset: {len(full_df):,} rows")


# ── 2. Feature selection ──────────────────────────────────────────────────────

df = full_df[FEATURES].copy()


# ── 3. Encode mqtt.hdrflags (hex strings → integers) ─────────────────────────

label_encoder = LabelEncoder()
df["mqtt.hdrflags"] = label_encoder.fit_transform(df["mqtt.hdrflags"])


# ── 4. Stratified sample to keep SVM training tractable ──────────────────────

# Stratify by label so the sample preserves the class ratio
df = df.groupby("label", group_keys=False).apply(
    lambda g: g.sample(frac=SAMPLE_FRAC, random_state=RANDOM_STATE)
).reset_index(drop=True)

print(f"  Sampled dataset: {len(df):,} rows  ({int(SAMPLE_FRAC*100)}% stratified sample)")
print(f"  Class distribution:\n{df['label'].value_counts().to_string()}")


# ── 5. Train / test split ─────────────────────────────────────────────────────

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=RANDOM_STATE
)


# ── 6. Feature scaling (required for SVM) ────────────────────────────────────

# Fit scaler on training data only to avoid data leakage
scaler  = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)


# ── 7. Train SVM ──────────────────────────────────────────────────────────────

print("\nTraining SVM (RBF kernel, C=1.0)…")
svm = SVC(
    kernel="rbf",
    C=1.0,
    probability=True,       # enables predict_proba for confidence scores
    random_state=RANDOM_STATE,
)
svm.fit(X_train, y_train)
print("  Training complete.")


# ── 8. Evaluate ───────────────────────────────────────────────────────────────

preds = svm.predict(X_test)

accuracy  = accuracy_score(y_test, preds)
precision = precision_score(y_test, preds)
recall    = recall_score(y_test, preds)
f1        = f1_score(y_test, preds)
cm        = confusion_matrix(y_test, preds)

print("\n=== SVM Results ===")
print(f"  Accuracy  : {accuracy  * 100:.4f}%")
print(f"  Precision : {precision * 100:.4f}%")
print(f"  Recall    : {recall    * 100:.4f}%")
print(f"  F1 Score  : {f1        * 100:.4f}%")
print("\n  Confusion Matrix:")
print(f"                 Predicted NORMAL  Predicted ATTACK")
print(f"  Actual NORMAL  TN: {cm[0,0]:<10}  FP: {cm[0,1]}")
print(f"  Actual ATTACK  FN: {cm[1,0]:<10}  TP: {cm[1,1]}")

fp = cm[0, 1]
fn = cm[1, 0]
print(f"\n  False Positives (normal blocked): {fp}")
print(f"  False Negatives (attacks missed): {fn}")


# ── 9. Save model ─────────────────────────────────────────────────────────────

joblib.dump({
    "model":             svm,
    "scaler":            scaler,
    "hdrflags_encoder":  label_encoder,
    "X_test":            X_test,
    "y_test":            y_test,
    "sample_frac":       SAMPLE_FRAC,
}, MODEL_OUT)
print(f"\n  Model saved to: {MODEL_OUT}")
