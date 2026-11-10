import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "link", "pw", "vip", "space", 
    "site", "click", "cc", "live", "fun", "monster", "bid", "gq", "cf", 
    "tk", "ml", "ru", "biz", "info"
}

SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "banking", 
    "secure", "update", "auth", "portal", "wallet", "claim", "bonus", 
    "confirm", "reactivate", "suspended", "security", "recovery", "deposit", 
    "payout", "refund", "wire", "password", "credential", "session"
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(raw_url: str) -> dict:
    """Extract lexical and structural features for phishing detection."""
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    
    # Domain without port
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    
    # Entropy of domain name
    domain_entropy = calculate_entropy(hostname)
    
    # Check if host is raw IP
    is_ip = 1 if IP_PATTERN.match(hostname) else 0
    
    # Subdomain depth
    subdomain_depth = max(0, len(domain_parts) - 2) if not is_ip else 0
    
    # Suspicious TLD
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Count sensitive keywords in full URL
    url_lower = url.lower()
    sensitive_word_hits = [kw for kw in SENSITIVE_KEYWORDS if kw in url_lower]
    sensitive_word_count = len(sensitive_word_hits)
    
    # Digit analysis
    num_digits = sum(c.isdigit() for c in hostname)
    digit_ratio = (num_digits / len(hostname)) if len(hostname) > 0 else 0.0
    
    # Punycode / IDN
    has_punycode = 1 if "xn--" in hostname else 0
    
    # Hyphens & dots
    num_hyphens = hostname.count("-")
    num_dots = hostname.count(".")
    
    # Path & query length
    path_length = len(path)
    num_subdirs = path.count("/")
    query_length = len(query)

    return {
        "url_length": len(url),
        "domain_length": len(hostname),
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "digit_ratio": round(digit_ratio, 4),
        "domain_entropy": round(domain_entropy, 4),
        "is_ip": is_ip,
        "subdomain_depth": subdomain_depth,
        "is_suspicious_tld": is_suspicious_tld,
        "sensitive_word_count": sensitive_word_count,
        "sensitive_word_hits": sensitive_word_hits,
        "has_punycode": has_punycode,
        "path_length": path_length,
        "num_subdirs": num_subdirs,
        "query_length": query_length
    }

FEATURE_COLUMNS = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_digits",
    "digit_ratio", "domain_entropy", "is_ip", "subdomain_depth",
    "is_suspicious_tld", "sensitive_word_count", "has_punycode",
    "path_length", "num_subdirs", "query_length"
]
