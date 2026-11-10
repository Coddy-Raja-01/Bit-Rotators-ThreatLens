import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from backend.scanners.ssrf import validate_target_host, SSRFSecurityException, create_pinned_session

MAX_BODY_SIZE = 2 * 1024 * 1024  # 2MB limit
TIMEOUT_SECONDS = 5.0
SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatLens-Scanner/1.0"

OBFUSCATION_PATTERNS = [
    (re.compile(r"eval\s*\(\s*(?:unescape|atob|decodeURIComponent|window\[|document\[)", re.I), "Dynamic eval of decoded payloads"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}", re.I), "Dense hex-encoded string arrays (anti-analysis obfuscation)"),
    (re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}\d+\s*\)", re.I), "CharCode sequence reconstruction"),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I), "document.write with unescaped markup injection"),
    (re.compile(r"(?:_0x[a-f0-9]{4,6}\s*\[|\bvar\s+_0x[a-f0-9]{4,6}\b)", re.I), "Automated JS Obfuscator variable signature (_0x)"),
]

SCAM_TEXT_PATTERNS = [
    (re.compile(r"\b(?:enter|confirm|verify)\s+your\s+(?:12|24)[-\s]+word\s+seed\s+phrase\b", re.I), "Crypto wallet seed phrase theft"),
    (re.compile(r"\b(?:send|transfer)\s+\d+(?:\.\d+)?\s*(?:btc|eth|sol)\s+(?:to\s+receive|and\s+get\s+double)\b", re.I), "Fake cryptocurrency giveaway multiplier scam"),
    (re.compile(r"\b(?:urgent|immediate)\s+(?:action\s+required|account\s+suspension|lockout\s+warning)\b", re.I), "Urgency / account suspension coercion"),
    (re.compile(r"\b(?:congratulations|selected\s+winner)\s+(?:claim\s+your|reward\s+card|free\s+gift)\b", re.I), "Deceptive prize / reward lure"),
    (re.compile(r"\b(?:remote\s+job\s+offer|earn\s+\$\d{3,4}\s+per\s+day|no\s+experience\s+needed\s+daily\s+pay)\b", re.I), "Fake recruitment / advance-fee job scam pattern"),
    (re.compile(r"\b(?:unpaid\s+toll\s+invoice|final\s+notice\s+court\s+summons|arrest\s+warrant\s+issued)\b", re.I), "Law enforcement / toll fee extortion lure")
]

def analyze_page_content(target_url: str, pinned_ips: list[str] | None = None) -> dict:
    """
    Fetch target HTML statically with strict limits and inspect DOM/scripts.
    Returns:
        {
            "fetched": bool,
            "title": str,
            "forms": list[dict],
            "cross_domain_forms": list[dict],
            "hidden_iframes": list[dict],
            "obfuscated_scripts": list[dict],
            "scam_indicators": list[str],
            "brand_title_mismatch": dict | None,
            "has_password_field": bool,
            "risk_score_points": int,
            "reasons": list[str]
        }
    """
    parsed = urlparse(target_url)
    origin_host = parsed.hostname or ""

    # Check SSRF before making connection
    try:
        resolved_ips = pinned_ips or validate_target_host(origin_host)
    except SSRFSecurityException as e:
        return {
            "fetched": False,
            "error": f"Target blocked by SSRF filter: {e}",
            "forms": [],
            "cross_domain_forms": [],
            "hidden_iframes": [],
            "obfuscated_scripts": [],
            "scam_indicators": [],
            "has_password_field": False,
            "risk_score_points": 0,
            "reasons": [],
            "findings": [
                {
                    "id": "CONT-SSRF",
                    "module": "content",
                    "title": "Page Fetch Blocked by SSRF Guard",
                    "severity": "critical",
                    "technical_evidence": {"url": target_url, "error": str(e)},
                    "impact": "Prevented outbound fetch to non-public network address.",
                    "source": "SSRF Guard (backend/scanners/ssrf.py)",
                    "confidence": 1.0,
                    "recommendation": "Reject requests targeting internal or cloud metadata IPs.",
                    "limitations": "Passive static fetch check."
                }
            ]
        }

    try:
        with create_pinned_session(resolved_ips[0], origin_host) as session:
            response = session.get(
                target_url,
                timeout=TIMEOUT_SECONDS,
                headers={"User-Agent": SAFE_USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
                stream=True
            )
            try:
                content_chunks = []
                bytes_read = 0
                for chunk in response.iter_content(chunk_size=8192):
                    bytes_read += len(chunk)
                    content_chunks.append(chunk)
                    if bytes_read >= MAX_BODY_SIZE:
                        break
                raw_html = b"".join(content_chunks).decode("utf-8", errors="replace")
            finally:
                response.close()
    except Exception as e:
        return {
            "fetched": False,
            "error": f"Failed to fetch page statically: {str(e)[:80]}",
            "forms": [],
            "cross_domain_forms": [],
            "hidden_iframes": [],
            "obfuscated_scripts": [],
            "scam_indicators": [],
            "has_password_field": False,
            "risk_score_points": 0,
            "reasons": []
        }

    soup = BeautifulSoup(raw_html, "html.parser")
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")[:120]

    reasons = []
    risk_points = 0
    has_password_input = False
    all_forms = []
    cross_domain_forms = []

    # 1. Analyze forms
    for form in soup.find_all("form"):
        action = form.get("action", "") or ""
        method = (form.get("method", "GET") or "GET").upper()
        
        # Check inputs
        inputs = form.find_all("input")
        input_types = [inp.get("type", "text").lower() for inp in inputs]
        has_pwd = "password" in input_types
        if has_pwd:
            has_password_input = True

        full_action = urljoin(target_url, action)
        action_host = urlparse(full_action).hostname or origin_host

        is_cross_domain = (action_host.lower() != origin_host.lower()) and bool(action.startswith("http"))

        form_summary = {
            "action": full_action,
            "method": method,
            "action_domain": action_host,
            "has_password": has_pwd,
            "is_cross_domain": is_cross_domain
        }
        all_forms.append(form_summary)

        if is_cross_domain and has_pwd:
            cross_domain_forms.append(form_summary)
            reasons.append(f"High-Risk: Password input form posts credentials to a completely different external domain ({action_host})")
            risk_points += 40
        elif is_cross_domain:
            cross_domain_forms.append(form_summary)
            reasons.append(f"Warning: Form submits input data to external domain ({action_host})")
            risk_points += 15

    # 2. Hidden iframes
    hidden_iframes = []
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        style = (iframe.get("style", "") or "").lower()
        width = iframe.get("width", "100")
        height = iframe.get("height", "100")
        
        is_hidden = False
        if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
            is_hidden = True
        if width in ("0", "1", "0px") or height in ("0", "1", "0px"):
            is_hidden = True

        if is_hidden:
            hidden_iframes.append({"src": src[:100], "style": style[:80]})
            reasons.append(f"Suspicious: Hidden 0-pixel or invisible iframe detected ({src[:50] or 'inline'})")
            risk_points += 20

    # 3. Obfuscated JavaScript
    obfuscated_scripts = []
    script_tags = soup.find_all("script")
    full_script_content = "\n".join([s.string for s in script_tags if s.string])

    for regex, desc in OBFUSCATION_PATTERNS:
        matches = regex.findall(full_script_content)
        if matches:
            obfuscated_scripts.append({"pattern": desc, "count": len(matches)})
            reasons.append(f"Obfuscation: {desc} (detected {len(matches)} occurrences)")
            risk_points += 15

    # 4. Scam content patterns
    page_text = soup.get_text(separator=" ", strip=True)
    scam_hits = []
    for regex, desc in SCAM_TEXT_PATTERNS:
        if regex.search(page_text):
            scam_hits.append(desc)
            reasons.append(f"Social engineering trigger: {desc}")
            risk_points += 25

    # 5. Brand in title vs actual domain
    well_known_brands = ["PayPal", "Chase", "Bank of America", "Wells Fargo", "Netflix", "Microsoft", "Apple", "Amazon", "MetaMask"]
    brand_title_mismatch = None
    title_lower = title.lower()
    for brand in well_known_brands:
        b_low = brand.lower()
        if b_low in title_lower and b_low not in origin_host.lower():
            brand_title_mismatch = {
                "claimed_brand": brand,
                "domain": origin_host
            }
            reasons.append(f"Brand deception: Webpage title claims to be '{brand}', but domain '{origin_host}' has no association.")
            risk_points += 30
            break

    findings = []
    if cross_domain_forms:
        has_pwd = any(f.get("has_password") for f in cross_domain_forms)
        findings.append({
            "id": "CONT-01" if has_pwd else "CONT-02",
            "module": "content",
            "title": "Password Input Posts to Foreign External Domain" if has_pwd else "Form Submits Data to External Domain",
            "severity": "critical" if has_pwd else "medium",
            "technical_evidence": {"cross_domain_forms": cross_domain_forms},
            "impact": "Exfiltrates submitted credentials or personal data directly to an attacker-controlled foreign server.",
            "source": "static DOM analysis (HTML parser)",
            "confidence": 0.95,
            "recommendation": "Do not enter login credentials or sensitive data on this webpage.",
            "limitations": "Inspects static HTML without running dynamic JS-generated forms."
        })

    if obfuscated_scripts:
        findings.append({
            "id": "CONT-03",
            "module": "content",
            "title": "Obfuscated Client-Side JavaScript Detected",
            "severity": "high",
            "technical_evidence": {"patterns": obfuscated_scripts},
            "impact": "Hides malicious payload from static analysis and security scanners.",
            "source": "static JavaScript pattern matching",
            "confidence": 0.90,
            "recommendation": "Audit underlying script logic in an isolated sandbox environment.",
            "limitations": "Pattern matching based on known obfuscation entropy signatures."
        })

    if scam_hits:
        findings.append({
            "id": "CONT-04",
            "module": "content",
            "title": "Social Engineering / Fraud Lure Phrasing",
            "severity": "high",
            "technical_evidence": {"detected_patterns": scam_hits},
            "impact": "Coerces victim into providing credentials, wallet seed phrases, or fraudulent payments.",
            "source": "social engineering lexicon",
            "confidence": 0.85,
            "recommendation": "Be aware of urgent language, seed phrase requests, and fake reward claims.",
            "limitations": "Text matching evaluates keywords in context."
        })

    if hidden_iframes:
        findings.append({
            "id": "CONT-05",
            "module": "content",
            "title": "Hidden Zero-Pixel or Concealed iframe",
            "severity": "medium",
            "technical_evidence": {"hidden_iframes": hidden_iframes},
            "impact": "May secretly load exploit kits, background clickjacking, or tracker payloads.",
            "source": "DOM iframe inspector",
            "confidence": 0.85,
            "recommendation": "Inspect source of embedded iframe.",
            "limitations": "Detects CSS-hidden or zero-dimension iframes."
        })

    if brand_title_mismatch:
        findings.append({
            "id": "CONT-06",
            "module": "content",
            "title": f"Title Claims Identity '{brand_title_mismatch['claimed_brand']}' on Unrelated Domain",
            "severity": "high",
            "technical_evidence": brand_title_mismatch,
            "impact": "Pretends to be an established brand while hosted on an unaffiliated domain name.",
            "source": "page title vs domain correlation",
            "confidence": 0.90,
            "recommendation": "Navigate only to the verified official portal for this brand.",
            "limitations": "Evaluates HTML <title> tag."
        })

    return {
        "fetched": True,
        "title": title,
        "forms_count": len(all_forms),
        "forms": all_forms[:5],
        "cross_domain_forms": cross_domain_forms,
        "hidden_iframes": hidden_iframes,
        "obfuscated_scripts": obfuscated_scripts,
        "scam_indicators": scam_hits,
        "brand_title_mismatch": brand_title_mismatch,
        "has_password_field": has_password_input,
        "risk_score_points": min(risk_points, 60),
        "reasons": reasons,
        "findings": findings
    }
