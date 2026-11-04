"""
Core URL Phishing Analyzer.
Coordinates feature extraction, ML prediction, feature attribution, and explainability.
"""

import os
import json
import joblib
import numpy as np
from typing import Dict, Any

from feature_extractor import extract_features
from explainability import generate_explanation

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.json")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")

_MODEL = None
_FEATURE_NAMES = None
_METRICS = None


def get_model():
    """Lazily loads and caches the trained ML model and feature configuration."""
    global _MODEL, _FEATURE_NAMES, _METRICS
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
            from model_trainer import train_and_save_model
            _MODEL, _FEATURE_NAMES, _METRICS = train_and_save_model()
        else:
            _MODEL = joblib.load(MODEL_PATH)
            with open(FEATURES_PATH, "r", encoding="utf-8") as f:
                _FEATURE_NAMES = json.load(f)
            if os.path.exists(METRICS_PATH):
                with open(METRICS_PATH, "r", encoding="utf-8") as f:
                    _METRICS = json.load(f)
    return _MODEL, _FEATURE_NAMES, _METRICS


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Performs full end-to-end security analysis on a URL.
    Returns comprehensive report including ML prediction, risk score,
    lexical characteristics, threat detections, and explanations.
    """
    if not url or not isinstance(url, str):
        raise ValueError("A valid non-empty URL string is required.")

    url = url.strip()
    if len(url) > 2048:
        raise ValueError("URL exceeds maximum permissible length of 2048 characters.")

    # 1. Feature Extraction
    extraction = extract_features(url)
    features_dict = extraction["features"]
    components = extraction["components"]
    brand_matched = extraction.get("brand_matched")

    # 2. Machine Learning Prediction
    model, feature_names, metrics = get_model()
    feature_vector = np.array([[features_dict[name] for name in feature_names]])
    
    # Probability [P(legitimate), P(phishing)]
    proba = model.predict_proba(feature_vector)[0]
    ml_phishing_prob = float(proba[1])

    # 3. Generate Human-Centric Explanations & Threat Rules
    explanation = generate_explanation(extraction, ml_phishing_prob)

    # 4. Feature Highlights / Impact summary for this specific URL
    feature_highlights = []
    # Key properties of interest
    notable_keys = [
        ("is_ip_address", "IP Address Host", lambda v: "Yes (Direct IP)" if v else "No (Domain Name)"),
        ("is_https", "Protocol Security", lambda v: "HTTPS (Encrypted)" if v else "HTTP (Unencrypted)"),
        ("domain_entropy", "Domain Entropy", lambda v: f"{v:.2f} bits"),
        ("num_subdomains", "Subdomain Depth", lambda v: f"{v} levels"),
        ("num_hyphens_hostname", "Hyphens in Hostname", lambda v: f"{v}"),
        ("keyword_count", "Suspicious Keyword Count", lambda v: f"{v}"),
        ("is_suspicious_tld", "TLD Risk Category", lambda v: "High Abuse TLD" if v else "Standard / Reputable"),
        ("is_shortened", "URL Shortener", lambda v: "Shortened Link" if v else "Direct Link"),
        ("is_punycode", "Punycode (Homograph)", lambda v: "Active (xn--)" if v else "Standard ASCII"),
        ("brand_spoofed", "Brand Spoofing Flag", lambda v: f"Spoofing {brand_matched}" if v else "None Detected")
    ]

    for key, label, formatter in notable_keys:
        val = features_dict.get(key, 0)
        feature_highlights.append({
            "key": key,
            "label": label,
            "value": val,
            "display": formatter(val)
        })

    # 5. Assemble Final Structured Report
    return {
        "status": "success",
        "input_url": url,
        "normalized_url": components["normalized_url"],
        "components": {
            "scheme": components["scheme"] or "http (assumed)",
            "hostname": components["hostname"],
            "root_domain": components["root_domain"],
            "subdomain": components["subdomain"] or "(none)",
            "domain_name": components["domain_name"],
            "tld": components["tld"],
            "path": components["path"] or "/",
            "query": components["query"] or "(none)",
            "port": components["port"] or (443 if components["scheme"] == "https" else 80)
        },
        "assessment": {
            "risk_score": explanation["risk_score"],
            "verdict": explanation["verdict"],
            "risk_level": explanation["risk_level"],
            "badge_color": explanation["badge_color"],
            "ml_probability": explanation["ml_probability"],
            "heuristic_score": explanation["heuristic_score"]
        },
        "threats": explanation["threats"],
        "trust_signals": explanation["trust_signals"],
        "recommendations": explanation["recommendations"],
        "highlights": feature_highlights,
        "all_features": features_dict,
        "model_metadata": {
            "algorithm": "Random Forest Classifier",
            "accuracy": metrics.get("accuracy", 1.0) if metrics else 1.0,
            "f1_score": metrics.get("f1_score", 1.0) if metrics else 1.0,
            "features_analyzed": len(features_dict)
        }
    }


if __name__ == "__main__":
    # Test on a few diverse URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "http://192.168.1.100/paypal/login.php",
        "http://paypal-security-update.xyz/signin",
        "http://secure-login.bankofamerica.com.attacker-domain.club/auth"
    ]
    for u in test_urls:
        res = analyze_url(u)
        print(f"\nURL: {u}")
        print(f"Risk: {res['assessment']['risk_score']}% | Verdict: {res['assessment']['verdict']}")
        print(f"Threats ({len(res['threats'])}): {[t['title'] for t in res['threats']]}")
