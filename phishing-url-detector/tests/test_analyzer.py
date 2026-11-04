"""
Unit and Integration Test Suite for Phishing URL Detector.
Tests feature extraction, machine learning scoring, explainability, and Flask endpoints.
"""

import unittest
import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from feature_extractor import extract_features, calculate_entropy
from analyzer import analyze_url, get_model
from app import app


class TestFeatureExtractor(unittest.TestCase):
    def test_entropy_calculation(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaaa"), 0.0)
        entropy_high = calculate_entropy("a8f9x2k1q0z")
        self.assertGreater(entropy_high, 3.0)

    def test_legitimate_url_features(self):
        url = "https://www.google.com/search?q=cybersecurity"
        data = extract_features(url)
        features = data["features"]
        components = data["components"]

        self.assertEqual(features["is_https"], 1)
        self.assertEqual(features["is_ip_address"], 0)
        self.assertEqual(features["is_punycode"], 0)
        self.assertEqual(features["num_at"], 0)
        self.assertEqual(components["domain_name"], "google")
        self.assertEqual(components["tld"], "com")

    def test_ip_address_detection(self):
        url = "http://192.168.1.1/login.php"
        data = extract_features(url)
        self.assertEqual(data["features"]["is_ip_address"], 1)

    def test_brand_spoofing_detection(self):
        # Paypal mentioned in subdomain or path, but domain is something else
        url = "http://paypal.com.verify-account.xyz/login"
        data = extract_features(url)
        self.assertEqual(data["features"]["brand_spoofed"], 1)
        self.assertEqual(data["brand_matched"], "paypal")

    def test_at_symbol_detection(self):
        url = "http://www.google.com@phishing-site.com/auth"
        data = extract_features(url)
        self.assertGreater(data["features"]["num_at"], 0)

    def test_punycode_detection(self):
        url = "http://xn--gogle-qra.com/search"
        data = extract_features(url)
        self.assertEqual(data["features"]["is_punycode"], 1)


class TestAnalyzerEngine(unittest.TestCase):
    def setUp(self):
        get_model()

    def test_analyze_legitimate_site(self):
        res = analyze_url("https://www.google.com")
        self.assertEqual(res["status"], "success")
        self.assertLess(res["assessment"]["risk_score"], 35.0)
        self.assertEqual(res["assessment"]["badge_color"], "safe")
        self.assertGreater(len(res["trust_signals"]), 0)

    def test_analyze_blatant_phishing(self):
        res = analyze_url("http://192.168.1.50/paypal/login.php?cmd=verify")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["assessment"]["risk_score"], 70.0)
        self.assertEqual(res["assessment"]["badge_color"], "danger")
        self.assertGreater(len(res["threats"]), 0)

    def test_invalid_url_handling(self):
        with self.assertRaises(ValueError):
            analyze_url("")


class TestFlaskEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_route(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"CyberShield", res.data)
        self.assertIn(b"PhishGuard", res.data)

    def test_api_analyze_valid(self):
        res = self.client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://github.com/torvalds/linux"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("assessment", data)
        self.assertIn("risk_score", data["assessment"])
        self.assertIn("components", data)
        self.assertIn("all_features", data)

    def test_api_analyze_empty(self):
        res = self.client.post(
            "/api/analyze",
            data=json.dumps({"url": ""}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")

    def test_api_batch_analyze(self):
        urls = [
            "https://www.google.com",
            "http://192.168.1.100/paypal/login.php"
        ]
        res = self.client.post(
            "/api/batch-analyze",
            data=json.dumps({"urls": urls}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["total_analyzed"], 2)
        self.assertEqual(len(data["results"]), 2)

    def test_api_model_info(self):
        res = self.client.get("/api/model-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("metrics", data)
        self.assertIn("accuracy", data["metrics"])


if __name__ == "__main__":
    unittest.main()
