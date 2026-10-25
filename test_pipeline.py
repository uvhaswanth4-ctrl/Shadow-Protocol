"""
Shadow Protocol - End-to-End Pipeline Verification Test
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.analyzer import analyze_file
from ml.model import predict_sample, get_metadata
from database.db import get_all_scans

def run_tests():
    print("[1/5] Testing ML Metadata and Model Inference...")
    meta = get_metadata()
    print(f"       Model Accuracy: {meta.get('metrics', {}).get('accuracy')}%")
    
    test_features = {
        "entropy": 7.8,
        "dangerous_permissions": 8,
        "suspicious_permissions": 4,
        "suspicious_apis": 6,
        "secrets_count": 2,
        "urls_count": 4,
        "has_accessibility": 1,
        "has_overlay": 1,
        "has_sms": 1,
        "is_packed": 1
    }
    pred = predict_sample(test_features)
    print(f"       Prediction for malicious vector: {pred['ml_verdict']} ({pred['confidence']}%)")
    assert pred["ml_verdict"] == "MALICIOUS", "Expected malicious classification"

    print("\n[2/5] Testing Static Analysis on Cerberus Banking Trojan APK...")
    cerberus_path = os.path.join(BASE_DIR, "samples", "cerberus_banking_trojan.apk")
    with open(cerberus_path, "rb") as f:
        res_cerberus = analyze_file(f.read(), "cerberus_banking_trojan.apk")
    print(f"       Verdict: {res_cerberus['verdict']} (Score: {res_cerberus['risk_score']}/100)")
    print(f"       Entropy: {res_cerberus['entropy']}")
    print(f"       MITRE Techniques: {[m['id'] for m in res_cerberus['mitre']]}")
    assert res_cerberus["verdict"] in ["CRITICAL", "HIGH"]

    print("\n[3/5] Testing Static Analysis on Clean Calculator APK...")
    clean_path = os.path.join(BASE_DIR, "samples", "clean_calculator.apk")
    with open(clean_path, "rb") as f:
        res_clean = analyze_file(f.read(), "clean_calculator.apk")
    print(f"       Verdict: {res_clean['verdict']} (Score: {res_clean['risk_score']}/100)")
    assert res_clean["verdict"] == "BENIGN"

    print("\n[4/5] Testing Static Analysis on Sample Invoice Dropper PE...")
    pe_path = os.path.join(BASE_DIR, "samples", "sample_invoice.exe")
    with open(pe_path, "rb") as f:
        res_pe = analyze_file(f.read(), "sample_invoice.exe")
    print(f"       Verdict: {res_pe['verdict']} (Score: {res_pe['risk_score']}/100, Entropy: {res_pe['entropy']})")
    assert res_pe["verdict"] in ["CRITICAL", "HIGH"]

    print("\n[5/5] Testing Database Persistence...")
    scans = get_all_scans()
    print(f"       Total Scans in SQLite: {len(scans)}")
    assert len(scans) >= 3

    print("\n" + "=" * 50)
    print("  ALL 5 PIPELINE INTEGRITY TESTS PASSED! ")
    print("=" * 50)

if __name__ == "__main__":
    run_tests()
