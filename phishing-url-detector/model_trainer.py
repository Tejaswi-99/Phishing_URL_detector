"""
Machine Learning Model Trainer for Phishing URL Detection.
Trains, evaluates, and persists a Random Forest classifier.
"""

import os
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)

from feature_extractor import extract_features
from dataset import get_dataset

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.json")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


def train_and_save_model(samples_per_class: int = 1500):
    """Generates dataset, extracts features, trains RandomForest, and saves artifacts."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    print(f"[*] Generating balanced dataset ({samples_per_class * 2} samples)...")
    dataset = get_dataset(samples_per_class)

    X_raw = []
    y = []
    feature_names = None

    print("[*] Extracting URL features...")
    for idx, (url, label) in enumerate(dataset):
        try:
            feat_dict = extract_features(url)["features"]
            if feature_names is None:
                feature_names = sorted(list(feat_dict.keys()))
            row = [feat_dict[k] for k in feature_names]
            X_raw.append(row)
            y.append(label)
        except Exception as e:
            continue

    X = np.array(X_raw)
    y = np.array(y)
    print(f"[+] Successfully extracted {X.shape[1]} features from {len(X)} valid samples.")

    # Train / Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print("[*] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Predictions & Probabilities
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n================ EVALUATION RESULTS ================")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  [TN: {cm[0][0]}, FP: {cm[0][1]}]")
    print(f"  [FN: {cm[1][0]}, TP: {cm[1][1]}]")
    print("===================================================\n")

    # Feature Importances
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": feature_names[i], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx
    ]

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm,
        "sample_count": len(X),
        "top_features": top_features[:10]
    }

    # Save Model Artifacts
    print(f"[*] Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)

    print(f"[*] Saving feature names to {FEATURES_PATH}...")
    with open(FEATURES_PATH, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("[+] Model training and export completed successfully!")
    return model, feature_names, metrics


def load_model():
    """Loads the persisted model and feature names. Trains one if not present."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        print("[!] Model file not found. Running training pipeline...")
        model, feature_names, _ = train_and_save_model()
        return model, feature_names

    model = joblib.load(MODEL_PATH)
    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        feature_names = json.load(f)
    return model, feature_names


if __name__ == "__main__":
    train_and_save_model()
