"""
URL Feature Extractor for Phishing Detection.
Extracts lexical, structural, statistical, and security features from a URL.
"""

import math
import re
from urllib.parse import urlparse, parse_qs
import tldextract


# Common URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tr.im", "tiny.cc", "tiny.one",
    "cutt.ly", "rb.gy", "shorturl.at", "bl.ink", "hyperurl.co", "rebrand.ly"
}

# Known abused / high-risk TLDs often seen in automated phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "club", "icu", "tk", "ml", "ga",
    "cf", "gq", "loan", "men", "date", "stream", "download", "racing", "win",
    "bid", "country", "kim", "science", "party", "cricket", "link", "casa"
}

# Established reputable TLDs
REPUTABLE_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "uk",
    "de", "ca", "au", "fr", "jp", "in", "ch", "nl", "se", "no", "app", "dev"
}

# Major targeted brand keywords often used in phishing lures
TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "barclays", "ebay", "walmart", "target", "coinbase", "binance",
    "metamask", "dropbox", "onedrive", "adobe", "yahoo", "outlook", "office365",
    "twitter", "linkedin", "steam", "roblox", "dhl", "fedex", "usps", "ups"
]

# Sensitive security / authentication keywords
SENSITIVE_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "auth",
    "authenticate", "authentication", "update", "security", "secure", "account",
    "banking", "password", "credential", "confirm", "wallet", "recovery",
    "billing", "payment", "invoice", "suspended", "restore", "validate", "token"
]

# Suspicious file extensions in paths
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".apk", ".zip", ".rar", ".7z", ".jar", ".iso",
    ".cmd", ".ps1", ".vbs", ".msi", ".dmg", ".tar", ".gz"
]

# Regex patterns
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$")
HEX_REGEX = re.compile(r"%[0-9a-fA-F]{2}")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in prob_dict.values())
    return round(entropy, 4)


def parse_url_components(raw_url: str):
    """
    Safely normalizes and parses a URL into components.
    Returns parsed URL, extracted domain parts, and normalized string.
    """
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL cannot be empty")

    # If scheme missing, prepend http:// for standard parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        normalized_url = "http://" + raw_url
        has_scheme = False
    else:
        normalized_url = raw_url
        has_scheme = True

    parsed = urlparse(normalized_url)
    ext = tldextract.extract(normalized_url)

    hostname = (parsed.hostname or "").lower()
    if ext.domain and ext.suffix:
        root_domain = f"{ext.domain}.{ext.suffix}".lower()
    elif ext.domain:
        root_domain = ext.domain.lower()
    else:
        root_domain = hostname

    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    tld = ext.suffix.lower() if ext.suffix else ""

    return {
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "parsed": parsed,
        "has_scheme": has_scheme,
        "scheme": parsed.scheme.lower() if parsed.scheme else "",
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "subdomain": subdomain,
        "root_domain": root_domain,
        "domain_name": ext.domain.lower() if ext.domain else "",
        "tld": tld,
    }


def extract_features(raw_url: str) -> dict:
    """
    Extracts all numerical and boolean features used by the ML model.
    Returns a dictionary of feature names and numeric values.
    """
    components = parse_url_components(raw_url)
    raw = components["raw_url"]
    norm = components["normalized_url"]
    hostname = components["hostname"]
    path = components["path"]
    query = components["query"]
    subdomain = components["subdomain"]
    domain_name = components["domain_name"]
    tld = components["tld"]
    scheme = components["scheme"]

    # 1. Length features
    url_length = len(raw)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # 2. Structural counts in full URL
    num_dots = raw.count(".")
    num_hyphens = raw.count("-")
    num_underscores = raw.count("_")
    num_slashes = raw.count("/")
    num_questionmarks = raw.count("?")
    num_equals = raw.count("=")
    num_at = raw.count("@")
    num_percent = raw.count("%")
    num_ampersands = raw.count("&")
    num_digits = sum(c.isdigit() for c in raw)

    # 3. Hostname-specific counts
    num_dots_hostname = hostname.count(".")
    num_hyphens_hostname = hostname.count("-")
    num_digits_hostname = sum(c.isdigit() for c in hostname)
    num_subdomains = len(subdomain.split(".")) if subdomain else 0

    # 4. Ratios
    digit_ratio_url = round(num_digits / url_length, 4) if url_length > 0 else 0.0
    digit_ratio_hostname = round(num_digits_hostname / hostname_length, 4) if hostname_length > 0 else 0.0

    vowels = set("aeiou")
    domain_letters = [c for c in domain_name if c.isalpha()]
    vowel_ratio_domain = (
        round(sum(c in vowels for c in domain_letters) / len(domain_letters), 4)
        if domain_letters else 0.0
    )

    # 5. Shannon Entropy
    domain_entropy = calculate_entropy(domain_name)
    url_entropy = calculate_entropy(raw)

    # 6. Boolean indicators (1 / 0)
    is_ip_address = 1 if IPV4_REGEX.match(hostname) else 0
    has_port = 1 if (components["port"] is not None and components["port"] not in (80, 443)) else 0
    is_https = 1 if scheme == "https" else 0
    has_double_slash_in_path = 1 if "//" in path else 0
    is_punycode = 1 if "xn--" in hostname else 0
    is_shortened = 1 if hostname in URL_SHORTENERS or components["root_domain"] in URL_SHORTENERS else 0
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    has_hex = 1 if bool(HEX_REGEX.search(raw)) else 0
    consecutive_hyphens = 1 if "--" in hostname else 0

    # 7. Brand and Keyword patterns
    # Brand appears in subdomain or path, but NOT in the actual registered domain name
    brand_spoofed = 0
    brand_matched = None
    for brand in TARGETED_BRANDS:
        in_sub_or_path = (brand in subdomain) or (brand in path.lower())
        in_actual_domain = brand in domain_name
        if in_sub_or_path and not in_actual_domain:
            brand_spoofed = 1
            brand_matched = brand
            break

    # Count of sensitive keywords across path and query
    combined_path_query = (path + " " + query + " " + subdomain).lower()
    keyword_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in combined_path_query)

    # Suspicious file extension
    has_suspicious_ext = 1 if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else 0

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_questionmarks": num_questionmarks,
        "num_equals": num_equals,
        "num_at": num_at,
        "num_percent": num_percent,
        "num_ampersands": num_ampersands,
        "num_digits": num_digits,
        "num_dots_hostname": num_dots_hostname,
        "num_hyphens_hostname": num_hyphens_hostname,
        "num_digits_hostname": num_digits_hostname,
        "num_subdomains": num_subdomains,
        "digit_ratio_url": digit_ratio_url,
        "digit_ratio_hostname": digit_ratio_hostname,
        "vowel_ratio_domain": vowel_ratio_domain,
        "domain_entropy": domain_entropy,
        "url_entropy": url_entropy,
        "is_ip_address": is_ip_address,
        "has_port": has_port,
        "is_https": is_https,
        "has_double_slash_in_path": has_double_slash_in_path,
        "is_punycode": is_punycode,
        "is_shortened": is_shortened,
        "is_suspicious_tld": is_suspicious_tld,
        "has_hex": has_hex,
        "consecutive_hyphens": consecutive_hyphens,
        "brand_spoofed": brand_spoofed,
        "keyword_count": keyword_count,
        "has_suspicious_ext": has_suspicious_ext
    }

    return {
        "components": components,
        "features": features,
        "brand_matched": brand_matched
    }
