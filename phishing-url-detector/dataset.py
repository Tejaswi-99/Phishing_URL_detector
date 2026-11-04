"""
Curated and Synthetic Training Dataset Generator for Phishing URL Detection.
Produces a balanced, diverse dataset covering key phishing patterns and legitimate web topologies.
"""

import random
from typing import List, Tuple

# Base legitimate root domains
LEGIT_DOMAINS = [
    ("google.com", ["search?q=cybersecurity", "drive/folders/1a2b3c", "maps/place/New+York", "intl/en/about/"]),
    ("youtube.com", ["watch?v=dQw4w9WgXcQ", "channel/UC_x5XG1OV2P6uZZ5FSM9Ttw", "feed/trending", "playlist?list=PL123"]),
    ("facebook.com", ["profile.php?id=1000293847", "groups/developers", "help/123456789", "messages/t/user123"]),
    ("amazon.com", ["dp/B08N5WRWNW", "gp/browse.html?node=16225007011", "gp/help/customer/display.html", "cart/view.html"]),
    ("wikipedia.org", ["wiki/Phishing", "wiki/Machine_learning", "wiki/Computer_security", "wiki/HTTP"]),
    ("reddit.com", ["r/Python/comments/xyz/phishing_detector", "r/cybersecurity", "r/AskNetsec", "user/techguru"]),
    ("github.com", ["torvalds/linux", "psf/requests", "pallets/flask", "scikit-learn/scikit-learn/releases/tag/1.4.0"]),
    ("twitter.com", ["explore", "home", "search?q=technology&src=typed_query", "settings/privacy"]),
    ("linkedin.com", ["in/satyanadella", "jobs/search/?keywords=software", "feed/", "company/google"]),
    ("microsoft.com", ["en-us/windows", "en-us/microsoft-365", "en-us/azure", "support.microsoft.com/en-us/help"]),
    ("apple.com", ["macbook-pro/", "iphone-15-pro/", "support/", "apple-watch-series-9/"]),
    ("netflix.com", ["browse", "title/80186932", "browse/genre/83", "YourAccount"]),
    ("stackoverflow.com", ["questions/11227809/why-is-processing-a-sorted-array-faster", "tags/python/info", "users/12345/alice"]),
    ("python.org", ["doc/3.12/library/urllib.html", "downloads/release/python-3120/", "community/sigs/", "about/"]),
    ("mozilla.org", ["en-US/docs/Web/HTTP/Headers", "en-US/firefox/new/", "en-US/privacy/", "en-US/security/"]),
    ("cloudflare.com", ["products/zero-trust/", "learning/ddos/what-is-a-ddos-attack/", "plans/", "blog/cyber-trends-2024"]),
    ("nytimes.com", ["section/technology", "2024/05/10/business/economy.html", "crosswords", "interactive/2024/opinion"]),
    ("bbc.com", ["news/technology-68930211", "sport/football", "news/world-us-canada", "future/article/2024"]),
    ("cnn.com", ["business/tech", "world/asia", "travel/article/destinations-2024", "health"]),
    ("medium.com", ["@towardsdatascience/machine-learning-guide", "tag/artificial-intelligence", "creators"]),
    ("spotify.com", ["track/4cOdK2wGLETKBW3PvgPWqT", "playlist/37i9dQZF1DXcBWIGoYBM5M", "artist/1dfeR4HaWDbWqFsssgk93Y"]),
    ("slack.com", ["help/articles/202583733-Workspaces", "downloads/windows", "security", "pricing"]),
    ("zoom.us", ["join", "j/1234567890?pwd=xyz", "download", "resources"]),
    ("dropbox.com", ["s/a1b2c3d4e5f6g7h/presentation.pdf", "plans", "security", "features"]),
    ("salesforce.com", ["products/crm/", "solutions/small-business/", "form/signup/freetrial-sales.jsp"]),
    ("mit.edu", ["education/", "research/", "admissions-aid/", "academics/schools-departments/"]),
    ("stanford.edu", ["academics/", "research/", "admissions/", "news/"]),
    ("harvard.edu", ["about/", "programs/", "campus-life/", "faculty-research/"]),
    ("nasa.gov", ["missions/artemis/", "news/releases/2024/", "multimedia/image-of-the-day/"]),
    ("nih.gov", ["health-information", "research-training", "grants-funding", "news-events"]),
    ("irs.gov", ["payments", "refunds", "credits-deductions", "forms-pubs"]),
    ("chase.com", ["personal/banking", "personal/credit-cards", "business", "commercial-banking"]),
    ("bankofamerica.com", ["credit-cards/", "auto-loans/", "deposits/", "investing/"]),
    ("wellsfargo.com", ["checking/", "savings/", "mortgage-loans/", "financial-education/"]),
    ("paypal.com", ["us/webapps/mpp/home", "us/smarthelp/contact-us", "us/webapps/mpp/paypal-safety-and-security"]),
    ("ebay.com", ["itm/1234567890", "str/vintagestore", "help/buying", "deals/electronics"]),
    ("walmart.com", ["ip/Apple-iPhone-15/123456", "cp/grocery/3972", "store/1234-supercenter"]),
    ("etsy.com", ["listing/123456789/handmade-pottery", "c/jewelry-and-accessories", "market/home_decor"]),
    ("docker.com", ["products/docker-desktop/", "resources/what-container/", "pricing/"]),
    ("digitalocean.com", ["products/droplets/", "community/tutorials/how-to-install-nginx-on-ubuntu", "pricing/"])
]

# Legitimate subdomains
LEGIT_SUBDOMAINS = ["www", "api", "docs", "blog", "support", "developer", "mail", "portal", "status", "cdn", "m"]

# Target brands for phishing lures
PHISH_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase",
    "wellsfargo", "bankofamerica", "coinbase", "binance", "metamask", "ebay",
    "facebook", "instagram", "whatsapp", "dropbox", "onedrive", "dhl", "fedex", "usps"
]

# Action words for lure generation
PHISH_ACTIONS = [
    "login", "verify", "signin", "account-update", "security-check", "confirm-identity",
    "wallet-restore", "unlock-account", "billing-update", "suspended-notice",
    "password-reset", "auth-validate", "urgent-action", "invoice-review", "session-expired"
]

# Abused TLDs
PHISH_TLDS = ["xyz", "top", "buzz", "club", "tk", "ml", "ga", "cf", "gq", "work", "click", "icu", "link", "cc"]

# Common fake domains
FAKE_DOMAINS = [
    "security-center", "account-alert", "verify-portal", "helpdesk-service",
    "online-resolution", "protection-gateway", "support-desk", "client-notice",
    "validation-auth", "secure-gateway", "credential-system", "web-notice"
]


def generate_legitimate_urls(target_count: int = 1500) -> List[Tuple[str, int]]:
    """Generate diverse realistic legitimate URLs."""
    urls = []
    schemes = ["https://", "https://", "https://", "http://"]  # majority https

    # Direct samples from list
    for domain, paths in LEGIT_DOMAINS:
        for path in paths:
            scheme = random.choice(schemes)
            sub = random.choice(["", "www.", random.choice(LEGIT_SUBDOMAINS) + "."])
            url = f"{scheme}{sub}{domain}/{path}"
            urls.append((url, 0))

    # Add query parameter variants
    sample_queries = [
        "page=1&limit=20", "id=48291", "search=python+tutorials&lang=en",
        "category=books&sort=recent", "ref=homepage_banner", "utm_source=newsletter&utm_medium=email"
    ]

    while len(urls) < target_count:
        domain, paths = random.choice(LEGIT_DOMAINS)
        path = random.choice(paths)
        scheme = "https://" if random.random() < 0.9 else "http://"
        sub = random.choice(["", "www.", random.choice(LEGIT_SUBDOMAINS) + "."])
        
        if random.random() < 0.4:
            q = random.choice(sample_queries)
            url = f"{scheme}{sub}{domain}/{path}?{q}"
        elif random.random() < 0.2:
            url = f"{scheme}{sub}{domain}/"
        else:
            url = f"{scheme}{sub}{domain}/{path}"
            
        urls.append((url, 0))

    return urls[:target_count]


def generate_phishing_urls(target_count: int = 1500) -> List[Tuple[str, int]]:
    """Generate diverse realistic phishing URLs spanning common threat patterns."""
    urls = []
    
    while len(urls) < target_count:
        archetype = random.choice([
            "brand_in_subdomain",
            "brand_in_domain",
            "ip_address_host",
            "at_symbol_redirection",
            "excessive_subdomains",
            "suspicious_tld_brand",
            "dga_high_entropy",
            "dangerous_extension",
            "punycode_homograph",
            "double_slash_redirect",
            "keyword_stuffing"
        ])

        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTIONS)
        tld = random.choice(PHISH_TLDS)
        fake_domain = random.choice(FAKE_DOMAINS)
        scheme = "http://" if random.random() < 0.75 else "https://"

        if archetype == "brand_in_subdomain":
            # e.g., http://paypal.com.verify-account.xyz/login.php
            url = f"{scheme}{brand}.com.{action}-{fake_domain}.{tld}/{action}.php?user_id={random.randint(1000, 99999)}"

        elif archetype == "brand_in_domain":
            # e.g., http://verify-paypal-account-security.net/signin
            connector = random.choice(["-", "--", "-secure-", "-login-"])
            url = f"{scheme}{action}{connector}{brand}.{tld}/index.html?token={random.randint(10000, 99999)}"

        elif archetype == "ip_address_host":
            # e.g., http://192.168.1.45/paypal/signin.php
            ip = f"{random.randint(11, 215)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8443, 8888, 3000])}" if random.random() < 0.3 else ""
            url = f"http://{ip}{port}/{brand}/{action}.php?session={random.randint(10000, 99999)}"

        elif archetype == "at_symbol_redirection":
            # e.g., http://www.google.com@evil-attacker.xyz/login
            url = f"{scheme}www.{brand}.com@{fake_domain}-{action}.{tld}/auth"

        elif archetype == "excessive_subdomains":
            # e.g., http://login.verify.account.secure.bank.attacker.com/session
            subs = f"login.secure.verify.{brand}.account"
            url = f"{scheme}{subs}.{fake_domain}.{tld}/portal/index.php"

        elif archetype == "suspicious_tld_brand":
            # e.g., http://chase-bank-verify.club/signin
            url = f"{scheme}{brand}-{action}.{tld}/"

        elif archetype == "dga_high_entropy":
            # e.g., http://xjkq87123lasd0912.xyz/login
            random_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(12, 22)))
            url = f"{scheme}{random_str}.{tld}/{action}?id={random.randint(100, 999)}"

        elif archetype == "dangerous_extension":
            # e.g., http://account-update-center.com/invoice_update.exe
            ext = random.choice([".exe", ".scr", ".zip", ".bat", ".apk", ".msi"])
            url = f"{scheme}{fake_domain}-{brand}.com/downloads/{action}{ext}"

        elif archetype == "punycode_homograph":
            # e.g., http://xn--gogle-qra.com/verify
            puny = random.choice(["xn--gogle-qra", "xn--mcrosoft-g1a", "xn--appl-coa", "xn--paypa-q4a", "xn--amazn-p1a"])
            url = f"{scheme}{puny}.com/{action}/"

        elif archetype == "double_slash_redirect":
            # e.g., http://attacker-portal.xyz//www.paypal.com/login
            url = f"{scheme}{fake_domain}.{tld}//www.{brand}.com/{action}"

        else: # keyword_stuffing
            url = f"{scheme}{fake_domain}.{tld}/secure/banking/verify/account/update/login?client_id={random.randint(1000, 9999)}"

        urls.append((url, 1))

    return urls[:target_count]


def get_dataset(samples_per_class: int = 1500) -> List[Tuple[str, int]]:
    """Returns a balanced dataset of (url, label) pairs. Label 0 = Legitimate, 1 = Phishing."""
    legit = generate_legitimate_urls(samples_per_class)
    phish = generate_phishing_urls(samples_per_class)
    combined = legit + phish
    random.seed(42)
    random.shuffle(combined)
    return combined
