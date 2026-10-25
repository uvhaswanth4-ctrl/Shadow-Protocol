"""
Shadow Protocol - ML Model Trainer
Trains Random Forest / LightGBM classifier on static feature vectors.
Produces accuracy, confusion matrix, ROC-AUC, and feature importance.
"""
import os
import sys
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
DATASET_PATH = os.path.join(BASE_DIR, "data", "malware_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "ml", "shadow_model.pkl")
META_PATH = os.path.join(BASE_DIR, "ml", "model_metadata.json")

FEATURE_COLUMNS = [
    "entropy", "dangerous_permissions", "suspicious_permissions",
    "suspicious_apis", "secrets_count", "urls_count", "has_accessibility",
    "has_overlay", "has_sms", "is_packed"
]

def train_model():
    # If dataset doesn't exist, generate it
    if not os.path.exists(DATASET_PATH):
        from data.generate_dataset import generate_dataset
        generate_dataset()
        
    df = pd.read_csv(DATASET_PATH)
    
    X = df[FEATURE_COLUMNS]
    y = df["target_label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = round(accuracy_score(y_test, y_pred) * 100, 2)
    prec = round(precision_score(y_test, y_pred) * 100, 2)
    rec = round(recall_score(y_test, y_pred) * 100, 2)
    f1 = round(f1_score(y_test, y_pred) * 100, 2)
    auc = round(roc_auc_score(y_test, y_prob) * 100, 2)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    # Feature Importances
    importances = dict(zip(FEATURE_COLUMNS, [round(float(v) * 100, 2) for v in clf.feature_importances_]))
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))
    
    # Save Model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    
    metadata = {
        "status": "Trained & Deployed",
        "algorithm": "Random Forest Classifier (Ensemble)",
        "features": FEATURE_COLUMNS,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc
        },
        "confusion_matrix": {
            "true_negative": cm[0][0],
            "false_positive": cm[0][1],
            "false_negative": cm[1][0],
            "true_positive": cm[1][1]
        },
        "feature_importances": sorted_importances,
        "dataset_samples": len(df),
        "trained_timestamp": pd.Timestamp.now().isoformat()
    }
    
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"Model trained successfully! Accuracy: {acc}% | ROC-AUC: {auc}%")
    return metadata

if __name__ == "__main__":
    train_model()
