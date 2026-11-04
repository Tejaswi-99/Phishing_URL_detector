"""
Flask Web Application for Phishing URL Detection & Explainable Security Analysis.
Provides Web UI routing and REST API endpoints.
"""

import os
from flask import Flask, render_template, request, jsonify
from analyzer import analyze_url, get_model

app = Flask(__name__)

# Ensure model is initialized on startup
get_model()


@app.route("/")
def index():
    """Renders the cybersecurity analysis dashboard."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    REST API endpoint for single URL analysis.
    Request JSON: { "url": "https://example.com" }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "Please enter a valid, non-empty website URL."
        }), 400

    try:
        report = analyze_url(url)
        return jsonify(report), 200
    except ValueError as ve:
        return jsonify({
            "status": "error",
            "message": str(ve)
        }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to analyze URL: {str(e)}"
        }), 500


@app.route("/api/batch-analyze", methods=["POST"])
def api_batch_analyze():
    """
    REST API endpoint for batch URL analysis.
    Request JSON: { "urls": ["https://site1.com", "http://site2.xyz"] }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if not isinstance(urls, list) or not urls:
        return jsonify({
            "status": "error",
            "message": "Please provide an array of URLs in the 'urls' field."
        }), 400

    if len(urls) > 50:
        return jsonify({
            "status": "error",
            "message": "Maximum batch limit is 50 URLs per request."
        }), 400

    results = []
    for raw_url in urls:
        raw_url = str(raw_url).strip()
        if not raw_url:
            continue
        try:
            res = analyze_url(raw_url)
            results.append({
                "url": raw_url,
                "status": "success",
                "risk_score": res["assessment"]["risk_score"],
                "verdict": res["assessment"]["verdict"],
                "risk_level": res["assessment"]["risk_level"],
                "badge_color": res["assessment"]["badge_color"],
                "threat_count": len(res["threats"])
            })
        except Exception as e:
            results.append({
                "url": raw_url,
                "status": "error",
                "message": str(e)
            })

    return jsonify({
        "status": "success",
        "total_analyzed": len(results),
        "results": results
    }), 200


@app.route("/api/model-info", methods=["GET"])
def api_model_info():
    """Returns metadata and performance metrics of the trained ML model."""
    _, feature_names, metrics = get_model()
    return jsonify({
        "status": "success",
        "algorithm": "Random Forest Classifier",
        "total_features": len(feature_names),
        "features": feature_names,
        "metrics": metrics
    }), 200


if __name__ == "__main__":
    # Host on 127.0.0.1:5000 in debug mode
    print("Starting PhishGuard Web Server at http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
