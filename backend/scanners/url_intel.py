import re
import socket
import urllib.parse
import ipaddress
from datetime import datetime, timezone
import requests

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at"
}

def normalize_url_advanced(raw_url: str) -> dict:
    """
    Normalizes target URL and identifies deceptive URL constructions:
    1. Userinfo trick: e.g. 'https://bank.com@evil.com/login' -> destination is evil.com!
    2. Punycode encoding (IDN): e.g. 'xn--...'
    3. Percent-encoded characters in hostname: e.g. '%65%76%69%6c.com'
    4. URL shortener service identification
    """
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    findings = []
    has_userinfo = False
    spoofed_display = None
    is_shortener = False

    parsed = urllib.parse.urlsplit(url)
    
    # 1. Userinfo trick detection
    netloc = parsed.netloc
    if "@" in netloc:
        has_userinfo = True
        userinfo, actual_host = netloc.split("@", 1)
        spoofed_display = userinfo
        # Reconstruct clean destination URL without the deceptive userinfo prefix
        clean_netloc = actual_host
        url = urllib.parse.urlunsplit((parsed.scheme, clean_netloc, parsed.path, parsed.query, parsed.fragment))
        parsed = urllib.parse.urlsplit(url)
        findings.append({
            "id": "URL-USERINFO",
            "module": "url_intel",
            "title": "Deceptive Userinfo URL Obfuscation ('@' Trick)",
            "severity": "critical",
            "technical_evidence": {"userinfo_prefix": userinfo, "actual_destination": actual_host},
            "impact": f"Visually deceives user into believing target is '{userinfo}', while actually routing traffic to '{actual_host}'.",
            "source": "URL normalization & RFC 3986 parse",
            "confidence": 1.0,
            "recommendation": "Do not visit. This is an intentional phishing disguise.",
            "limitations": "Evaluates URI userinfo component."
        })

    hostname = (parsed.hostname or "").lower()

    # 2. Percent-encoding in host
    if "%" in hostname:
        decoded_host = urllib.parse.unquote(hostname)
        findings.append({
            "id": "URL-ENCODED-HOST",
            "module": "url_intel",
            "title": "Percent-Encoded Characters in Hostname",
            "severity": "high",
            "technical_evidence": {"raw_hostname": hostname, "decoded_hostname": decoded_host},
            "impact": "Evades rudimentary keyword and domain blocklist filters.",
            "source": "URL parser",
            "confidence": 0.95,
            "recommendation": "Inspect decoded hostname before proceeding.",
            "limitations": "Evaluates hostname percent-encoding."
        })
        hostname = decoded_host

    # 3. Punycode check
    has_punycode = "xn--" in hostname
    punycode_decoded = None
    if has_punycode:
        try:
            punycode_decoded = hostname.encode("ascii").decode("idna")
            findings.append({
                "id": "URL-PUNYCODE",
                "module": "url_intel",
                "title": f"Internationalized Domain (Punycode): {punycode_decoded}",
                "severity": "high",
                "technical_evidence": {"punycode": hostname, "unicode_representation": punycode_decoded},
                "impact": "Uses lookalike non-ASCII characters that render identically to Latin characters in browsers.",
                "source": "IDNA / Punycode decoder",
                "confidence": 0.95,
                "recommendation": "Verify whether character glyphs belong to expected language script.",
                "limitations": "Decodes standard IDNA punycode format."
            })
        except Exception:
            pass

    # 4. Known shortener
    if hostname in SHORTENER_DOMAINS:
        is_shortener = True
        findings.append({
            "id": "URL-SHORTENER",
            "module": "url_intel",
            "title": f"URL Shortener Service ({hostname})",
            "severity": "medium",
            "technical_evidence": {"shortener_domain": hostname},
            "impact": "Hides true landing destination from initial inspection.",
            "source": "known shorteners list",
            "confidence": 1.0,
            "recommendation": "Expand shortlink to inspect final destination before accessing.",
            "limitations": "Curated shortener domain directory."
        })

    # Domain structure breakdown
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else parts[0]
    subdomains = parts[:-2] if len(parts) > 2 else []

    return {
        "normalized_url": url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "path": parsed.path or "/",
        "query": parsed.query,
        "has_userinfo": has_userinfo,
        "spoofed_display": spoofed_display,
        "has_punycode": has_punycode,
        "punycode_decoded": punycode_decoded,
        "is_shortener": is_shortener,
        "tld": tld,
        "sld": sld,
        "subdomain_depth": len(subdomains),
        "findings": findings
    }

def get_dns_characteristics(domain: str) -> dict:
    """
    Queries DNS characteristics (A, AAAA, NS, MX, TXT records with TTL)
    via DNS-over-HTTPS with socket fallback.
    """
    clean_domain = domain.lower().split(":")[0].strip()
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "ttl": 300,
        "has_active_dns": False
    }
    errors = []

    # 1. Local socket resolution for A & AAAA
    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        for item in addr_info:
            family = item[0]
            ip = item[4][0]
            if family == socket.AF_INET and ip not in records["A"]:
                records["A"].append(ip)
            elif family == socket.AF_INET6 and ip not in records["AAAA"]:
                records["AAAA"].append(ip)
        if records["A"] or records["AAAA"]:
            records["has_active_dns"] = True
    except socket.gaierror as exc:
        errors.append(f"System DNS lookup failed: {exc}")

    # 2. Query DoH (Google Public DNS) with 2.0s timeout for MX, TXT, NS
    try:
        for rtype in ["MX", "TXT", "NS"]:
            url = f"https://dns.google/resolve?name={clean_domain}&type={rtype}"
            resp = requests.get(url, timeout=2.0, headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    data_val = ans.get("data", "").strip('"')
                    records[rtype].append(data_val)
                    records["ttl"] = ans.get("TTL", records["ttl"])
            else:
                errors.append(f"DNS-over-HTTPS {rtype} query returned HTTP {resp.status_code}")
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"DNS-over-HTTPS lookup failed: {exc}")

    findings = []
    # Flag missing MX records if site claims to be a major institution
    if not records["has_active_dns"]:
        findings.append({
            "id": "DNS-NO-RECORD",
            "module": "url_intel",
            "title": "No Active DNS Resolution",
            "severity": "medium",
            "technical_evidence": {"domain": clean_domain},
            "impact": "Host does not resolve to an active IP address (taken down, suspended, or NXDOMAIN).",
            "source": "DNS resolution",
            "confidence": 0.95,
            "recommendation": "Monitor domain; fraudulent sites frequently rotate across nameservers.",
            "limitations": "Evaluates real-time authoritative DNS resolution."
        })

    return {
        "domain": clean_domain,
        "records": records,
        "errors": errors,
        "findings": findings
    }

def get_domain_rdap_registration(domain: str) -> dict:
    """
    Query RDAP for domain registration date, registrar, and calculated age.
    Includes 2.5s timeout and graceful fallback.
    """
    clean_domain = domain.lower().split(":")[0].strip()
    result = {
        "domain": clean_domain,
        "registrar": "Unknown",
        "registration_date": None,
        "age_days": None,
        "is_young_domain": False,
        "error": None,
        "findings": []
    }

    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        resp = requests.get(url, timeout=2.5, headers={"Accept": "application/rdap+json", "User-Agent": "ThreatLens/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            # Extract registrar
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                result["registrar"] = item[3]
                                break

            # Extract registration date
            for event in data.get("events", []):
                action = event.get("eventAction")
                date_str = event.get("eventDate")
                if action in ("registration", "created") and date_str:
                    clean_date = date_str[:10]
                    result["registration_date"] = clean_date
                    try:
                        reg_dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        age_days = (now_dt - reg_dt).days
                        result["age_days"] = age_days
                        if age_days < 30:
                            result["is_young_domain"] = True
                            result["findings"].append({
                                "id": "DNS-YOUNG-DOMAIN",
                                "module": "url_intel",
                                "title": f"Newly Registered Domain ({age_days} days old)",
                                "severity": "high",
                                "technical_evidence": {"registration_date": clean_date, "age_days": age_days, "registrar": result["registrar"]},
                                "impact": "Over 70% of malicious phishing domains are registered less than 30 days prior to attack campaigns.",
                                "source": "RDAP Registration Query",
                                "confidence": 0.90,
                                "recommendation": "Treat new domains with elevated scrutiny before trusting with credentials or payments.",
                                "limitations": "Subject to registry RDAP availability."
                            })
                    except Exception:
                        result["error"] = "RDAP registration date could not be parsed"
                    break
        else:
            result["error"] = f"RDAP lookup returned HTTP {resp.status_code}"
    except (requests.RequestException, ValueError) as exc:
        result["error"] = f"RDAP lookup failed: {exc}"

    return result
