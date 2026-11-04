"""
Explainability and Rule Engine for Phishing Detection.
Translates statistical and ML features into clear, human-understandable
threat indicators, trust signals, and actionable security advice.
"""

from typing import Dict, List, Any


def generate_explanation(analysis_result: Dict[str, Any], ml_probability: float) -> Dict[str, Any]:
    """
    Generates structured, human-readable explanations, threat flags,
    trust indicators, and safety recommendations.
    """
    features = analysis_result["features"]
    components = analysis_result["components"]
    brand_matched = analysis_result.get("brand_matched")

    threats: List[Dict[str, Any]] = []
    trust_signals: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    # Calculate heuristic score modifier
    heuristic_points = 0

    # 1. IP Address Hostname
    if features["is_ip_address"]:
        threats.append({
            "severity": "critical",
            "title": "Raw IP Address Hostname",
            "description": f"The URL uses a raw IP address ({components['hostname']}) instead of a registered domain name. Legitimate services virtually always use domain names; raw IPs are heavily used by attackers to bypass domain blacklists.",
            "points": 35
        })
        heuristic_points += 35

    # 2. Brand Impersonation / Spoofing
    if features["brand_spoofed"]:
        threats.append({
            "severity": "critical",
            "title": f"Targeted Brand Impersonation ('{brand_matched.capitalize()}')",
            "description": f"The brand keyword '{brand_matched}' was detected in the subdomain or URL path, but the actual registered domain is '{components['root_domain']}'. This is a classic phishing technique to deceive users into trusting a fraudulent page.",
            "points": 35
        })
        heuristic_points += 35

    # 3. Userinfo / @ symbol in URL
    if features["num_at"] > 0:
        threats.append({
            "severity": "critical",
            "title": "Credential Obfuscation / Redirection Symbol (@)",
            "description": "The URL contains an '@' character. In the standard URL format, browsers interpret characters preceding '@' as user credentials and silently navigate to the server following '@'. Attackers use this to display a fake trusted site name in the front.",
            "points": 30
        })
        heuristic_points += 30

    # 4. Homograph / Punycode Attack
    if features["is_punycode"]:
        threats.append({
            "severity": "critical",
            "title": "IDN Homograph / Punycode Detected ('xn--')",
            "description": "The domain uses internationalized characters (Punycode). Attackers frequently exploit visually identical characters from Cyrillic or Greek alphabets (e.g. 'а' vs 'a') to forge legitimate website names.",
            "points": 25
        })
        heuristic_points += 25

    # 5. Suspicious Executable / Archive Extension
    if features["has_suspicious_ext"]:
        threats.append({
            "severity": "critical",
            "title": "Malicious / Dangerous File Extension in Path",
            "description": f"The URL path links directly to an executable, script, or archive file ({components['path'].split('.')[-1] if '.' in components['path'] else 'binary'}). Visiting this link may trigger automatic drive-by malware downloads.",
            "points": 25
        })
        heuristic_points += 25

    # 6. Abused / High-Risk TLD
    if features["is_suspicious_tld"]:
        threats.append({
            "severity": "warning",
            "title": f"High-Abuse Top-Level Domain (.{components['tld']})",
            "description": f"The top-level domain '.{components['tld']}' has statistically high correlation with disposable, spam, or malicious domain registrations.",
            "points": 15
        })
        heuristic_points += 15

    # 7. Known URL Shortener
    if features["is_shortened"]:
        threats.append({
            "severity": "warning",
            "title": "URL Shortening Service Detected",
            "description": f"The domain '{components['hostname']}' is a URL shortener. Shorteners conceal the actual target website destination, preventing inspection before clicking.",
            "points": 15
        })
        heuristic_points += 15

    # 8. Protocol Security (HTTP vs HTTPS)
    if not features["is_https"]:
        threats.append({
            "severity": "warning",
            "title": "Insecure Protocol (Unencrypted HTTP)",
            "description": "The website uses plain HTTP without TLS/SSL encryption. Data submitted to this page (passwords, payment info) travels in plaintext and can be intercepted or tampered with.",
            "points": 12
        })
        heuristic_points += 12
    else:
        trust_signals.append({
            "title": "HTTPS Encryption",
            "description": "The URL uses HTTPS protocol with encrypted communication."
        })

    # 9. Excessive Subdomains
    if features["num_subdomains"] >= 3:
        threats.append({
            "severity": "warning",
            "title": f"Excessive Subdomain Chaining ({features['num_subdomains']} levels)",
            "description": f"Subdomain structure '{components['subdomain']}' has {features['num_subdomains']} nested levels. Phishers use deep subdomains so that the true domain is truncated out of view on mobile screens.",
            "points": 15
        })
        heuristic_points += 15

    # 10. High Domain Entropy (DGA / Random generation)
    if features["domain_entropy"] >= 3.6 and len(components["domain_name"]) > 8:
        threats.append({
            "severity": "warning",
            "title": f"High Domain Entropy ({features['domain_entropy']})",
            "description": f"The domain '{components['domain_name']}' exhibits abnormal randomness. This pattern often indicates Domain Generation Algorithms (DGA) used by botnets and fast-flux phishing rings.",
            "points": 14
        })
        heuristic_points += 14

    # 11. Double Slash in Path (Redirect technique)
    if features["has_double_slash_in_path"]:
        threats.append({
            "severity": "warning",
            "title": "Double Slash in URL Path",
            "description": "The URL path contains '//', which can be utilized by open redirect vulnerabilities to forward the user to an external malicious server.",
            "points": 12
        })
        heuristic_points += 12

    # 12. Sensitive Keywords in Suspicious Context
    if features["keyword_count"] >= 2 and not features["brand_spoofed"]:
        threats.append({
            "severity": "info",
            "title": f"Multiple Security / Authentication Keywords ({features['keyword_count']})",
            "description": "The URL contains multiple terms related to login, verification, or banking credentials.",
            "points": 8
        })
        heuristic_points += 8

    # 13. Unusual Port
    if features["has_port"]:
        threats.append({
            "severity": "warning",
            "title": f"Non-Standard Port ({components['port']})",
            "description": f"Traffic is directed to port {components['port']} instead of standard web ports (80/443). Legitimate public consumer portals rarely use custom ports.",
            "points": 10
        })
        heuristic_points += 10

    # 14. Consecutive Hyphens or excessive hyphens in hostname
    if features["consecutive_hyphens"] or features["num_hyphens_hostname"] >= 3:
        threats.append({
            "severity": "warning",
            "title": f"Excessive Hyphenation in Hostname ({features['num_hyphens_hostname']} hyphens)",
            "description": "Multiple hyphens in domain names are frequently used to combine trusted keywords with deceptive terms.",
            "points": 10
        })
        heuristic_points += 10

    # 15. URL Length Anomaly
    if features["url_length"] > 100:
        threats.append({
            "severity": "info",
            "title": f"Unusually Long URL ({features['url_length']} characters)",
            "description": "Excessively long URLs are often used to conceal target payloads or encode phishing telemetry.",
            "points": 6
        })
        heuristic_points += 6

    # Positive Trust Indicators
    if components["tld"] in ["gov", "edu", "mil"]:
        trust_signals.append({
            "title": "Restricted Institutional TLD",
            "description": f"The .{components['tld']} domain requires verified government or educational institutional credentials to register."
        })
    elif components["tld"] in ["com", "org", "net", "io"]:
        trust_signals.append({
            "title": "Standard Commercial / Organization TLD",
            "description": f"Uses standard global top-level domain '.{components['tld']}'."
        })

    if features["num_subdomains"] <= 1 and not features["is_ip_address"]:
        trust_signals.append({
            "title": "Clean Domain Hierarchy",
            "description": "Simple, transparent domain structure without excessive nested subdomains."
        })

    if features["domain_entropy"] < 3.2 and len(components["domain_name"]) > 3:
        trust_signals.append({
            "title": "Natural Linguistic Entropy",
            "description": "Domain name displays natural linguistic character distribution rather than algorithmically generated randomness."
        })

    if features["num_at"] == 0 and not features["has_hex"] and not features["has_double_slash_in_path"]:
        trust_signals.append({
            "title": "No URL Obfuscation",
            "description": "Contains no '@' redirection, hex encoding tricks, or path redirection sequences."
        })

    # Blended Risk Score Calculation (ML probability 60% + Heuristic score 40%)
    # Normalize heuristic points (0 to 100 max)
    heuristic_score = min(100.0, float(heuristic_points))
    ml_score = ml_probability * 100.0

    # If any critical threat is found, floor the minimum risk score
    has_critical = any(t["severity"] == "critical" for t in threats)

    # Weighted blend
    blended_score = (0.55 * ml_score) + (0.45 * heuristic_score)

    if has_critical:
        blended_score = max(blended_score, 75.0)

    # Safe floor if no threats at all and good trust signals
    if not threats and len(trust_signals) >= 3 and ml_score < 30.0:
        blended_score = min(blended_score, 15.0)

    blended_score = round(max(0.0, min(100.0, blended_score)), 1)

    # Classification Category
    if blended_score >= 70.0:
        verdict = "Phishing / Malicious"
        risk_level = "High"
        badge_color = "danger"
        recommendations = [
            "DO NOT enter usernames, passwords, credit card numbers, or personal data on this site.",
            "DO NOT download or execute any files prompted by this web address.",
            "If you arrived here from an email, SMS, or chat message, mark the message as phishing or spam immediately.",
            "If you already entered credentials on this site, immediately change your password on the genuine official service and enable Multi-Factor Authentication (MFA)."
        ]
    elif blended_score >= 35.0:
        verdict = "Suspicious / Potential Risk"
        risk_level = "Medium"
        badge_color = "warning"
        recommendations = [
            "Exercise caution before interacting with this page.",
            "Verify the exact address bar URL in your browser against the official company website.",
            "Inspect the SSL certificate by clicking the padlock icon in your browser to verify domain ownership.",
            "Avoid entering sensitive financial or authentication details until domain authenticity is confirmed."
        ]
    else:
        verdict = "Legitimate / Low Risk"
        risk_level = "Low"
        badge_color = "safe"
        recommendations = [
            "URL displays characteristics consistent with standard legitimate websites.",
            "Continue practicing standard web hygiene: verify SSL certificate and never share one-time passwords (OTP).",
            "Ensure your browser and security software remain updated."
        ]

    return {
        "risk_score": blended_score,
        "ml_probability": round(ml_score, 1),
        "heuristic_score": round(heuristic_score, 1),
        "verdict": verdict,
        "risk_level": risk_level,
        "badge_color": badge_color,
        "threat_count": len(threats),
        "threats": threats,
        "trust_signals": trust_signals,
        "recommendations": recommendations
    }
