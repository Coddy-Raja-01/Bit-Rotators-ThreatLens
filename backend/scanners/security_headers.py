import requests
from urllib.parse import urlparse
from backend.scanners.ssrf import validate_target_host, SSRFSecurityException, create_pinned_session

SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatLens-Scanner/1.0"

def evaluate_headers_and_grade(target_url: str, pinned_ips: list[str] | None = None) -> dict:
    """
    Evaluates HTTP response security headers and assigns an A-F letter grade.
    Returns:
        {
            "grade": "A+" | "A" | "B" | "C" | "D" | "F",
            "score_numeric": int (0-100),
            "headers_present": dict,
            "headers_missing": list[dict],
            "cookie_analysis": list[dict],
            "findings": list[dict]
        }
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    try:
        resolved_ips = pinned_ips or validate_target_host(hostname)
    except SSRFSecurityException as e:
        return {
            "grade": "F",
            "score_numeric": 0,
            "error": str(e),
            "headers_present": {},
            "headers_missing": [],
            "cookie_analysis": [],
            "findings": [{"severity": "HIGH", "message": f"SSRF blocked: {e}"}]
        }

    try:
        with create_pinned_session(resolved_ips[0], hostname) as session:
            resp = session.get(
                target_url,
                timeout=5.0,
                headers={"User-Agent": SAFE_USER_AGENT},
                allow_redirects=False,
                stream=True
            )
            try:
                headers = resp.headers
            finally:
                resp.close()
    except Exception as e:
        return {
            "grade": "F",
            "score_numeric": 0,
            "error": f"Failed to retrieve headers: {str(e)[:80]}",
            "headers_present": {},
            "headers_missing": [],
            "cookie_analysis": [],
            "findings": [{"severity": "HIGH", "message": "Host failed to respond to HTTP requests."}]
        }

    score = 100
    findings = []
    headers_present = {}
    headers_missing = []

    # 1. HSTS (Strict-Transport-Security)
    hsts = headers.get("Strict-Transport-Security")
    if hsts:
        headers_present["Strict-Transport-Security"] = hsts
        if "max-age" in hsts:
            try:
                max_age_val = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age_val < 10886400: # Less than ~126 days
                    score -= 5
                    findings.append({"header": "HSTS", "status": "WARN", "penalty": 5, "issue": "HSTS max-age is short (under 180 days)."})
                else:
                    findings.append({"header": "HSTS", "status": "PASS", "penalty": 0, "issue": "HSTS strongly configured."})
            except Exception:
                pass
    else:
        score -= 25
        headers_missing.append({
            "name": "Strict-Transport-Security",
            "description": "Protects against man-in-the-middle SSL stripping attacks by enforcing HTTPS connection.",
            "penalty": 25
        })
        findings.append({"header": "HSTS", "status": "FAIL", "penalty": 25, "issue": "Missing HTTP Strict Transport Security header."})

    # 2. CSP (Content-Security-Policy)
    csp = headers.get("Content-Security-Policy")
    if csp:
        headers_present["Content-Security-Policy"] = csp[:120] + ("..." if len(csp) > 120 else "")
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            score -= 10
            findings.append({"header": "CSP", "status": "WARN", "penalty": 10, "issue": "CSP includes 'unsafe-inline' or 'unsafe-eval' directives, weakening XSS mitigation."})
        else:
            findings.append({"header": "CSP", "status": "PASS", "penalty": 0, "issue": "Content Security Policy actively defined."})
    else:
        score -= 25
        headers_missing.append({
            "name": "Content-Security-Policy",
            "description": "Restricts sources of executable scripts, stylesheets, and frames, preventing Cross-Site Scripting (XSS).",
            "penalty": 25
        })
        findings.append({"header": "CSP", "status": "FAIL", "penalty": 25, "issue": "Missing Content-Security-Policy header."})

    # 3. X-Frame-Options
    xfo = headers.get("X-Frame-Options")
    if xfo:
        headers_present["X-Frame-Options"] = xfo
        findings.append({"header": "X-Frame-Options", "status": "PASS", "penalty": 0, "issue": f"Clickjacking protection enabled ({xfo})."})
    else:
        if not (csp and "frame-ancestors" in csp):
            score -= 15
            headers_missing.append({
                "name": "X-Frame-Options",
                "description": "Prevents clickjacking attacks by forbidding the page from being embedded inside foreign iframes.",
                "penalty": 15
            })
            findings.append({"header": "X-Frame-Options", "status": "FAIL", "penalty": 15, "issue": "Missing X-Frame-Options header (vulnerable to clickjacking)."})

    # 4. X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options")
    if xcto and xcto.lower() == "nosniff":
        headers_present["X-Content-Type-Options"] = xcto
        findings.append({"header": "X-Content-Type-Options", "status": "PASS", "penalty": 0, "issue": "MIME-sniffing protection enabled."})
    else:
        score -= 10
        headers_missing.append({
            "name": "X-Content-Type-Options",
            "description": "Instructs browsers to respect declared Content-Type and avoid sniffing executable content in plain files.",
            "penalty": 10
        })
        findings.append({"header": "X-Content-Type-Options", "status": "FAIL", "penalty": 10, "issue": "Missing 'nosniff' MIME protection."})

    # 5. Referrer-Policy
    ref = headers.get("Referrer-Policy")
    if ref:
        headers_present["Referrer-Policy"] = ref
        findings.append({"header": "Referrer-Policy", "status": "PASS", "penalty": 0, "issue": f"Referrer policy configured ({ref})."})
    else:
        score -= 5
        headers_missing.append({
            "name": "Referrer-Policy",
            "description": "Controls what referral path information is shared when users click outbound links.",
            "penalty": 5
        })

    # 6. Permissions-Policy
    perm = headers.get("Permissions-Policy")
    if perm:
        headers_present["Permissions-Policy"] = perm[:80]
    else:
        score -= 5
        headers_missing.append({
            "name": "Permissions-Policy",
            "description": "Explicitly disables browser hardware APIs like camera, microphone, and geolocation.",
            "penalty": 5
        })

    # 7. Cookie Flags Analysis
    cookie_analysis = []
    if "set-cookie" in headers:
        raw_cookie = headers["set-cookie"]
        is_secure = "secure" in raw_cookie.lower()
        is_httponly = "httponly" in raw_cookie.lower()
        is_samesite = "samesite" in raw_cookie.lower()

        cookie_analysis.append({
            "cookie": raw_cookie.split(";")[0],
            "secure": is_secure,
            "httponly": is_httponly,
            "samesite": is_samesite
        })

        if not is_secure:
            score -= 10
            findings.append({"header": "Set-Cookie", "status": "FAIL", "penalty": 10, "issue": "Cookie set without Secure flag (can leak over plain HTTP)."})
        if not is_httponly:
            score -= 5
            findings.append({"header": "Set-Cookie", "status": "WARN", "penalty": 5, "issue": "Cookie set without HttpOnly flag (accessible to JavaScript XSS)."})

    # Normalize score
    final_score = max(0, min(100, score))
    
    # Calculate grade
    if final_score >= 95 and "Strict-Transport-Security" in headers_present and "Content-Security-Policy" in headers_present:
        grade = "A+"
    elif final_score >= 85:
        grade = "A"
    elif final_score >= 70:
        grade = "B"
    elif final_score >= 50:
        grade = "C"
    elif final_score >= 35:
        grade = "D"
    else:
        grade = "F"

    standardized_findings = []
    # Build unified model findings from missing headers and issues
    if "Strict-Transport-Security" not in headers_present:
        standardized_findings.append({
            "id": "HDR-01",
            "module": "security_headers",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "severity": "medium",
            "technical_evidence": {"header": "Strict-Transport-Security", "status": "missing"},
            "impact": "Leaves users susceptible to SSL-stripping and active network eavesdropping.",
            "source": "HTTP Response Headers",
            "confidence": 0.95,
            "recommendation": "Configure Strict-Transport-Security header with max-age >= 31536000 and includeSubDomains.",
            "limitations": "Evaluates initial HTTP/HTTPS response header set."
        })
    if "Content-Security-Policy" not in headers_present:
        standardized_findings.append({
            "id": "HDR-02",
            "module": "security_headers",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "medium",
            "technical_evidence": {"header": "Content-Security-Policy", "status": "missing"},
            "impact": "Fails to restrict script execution origins, increasing exposure to Cross-Site Scripting (XSS).",
            "source": "HTTP Response Headers",
            "confidence": 0.95,
            "recommendation": "Deploy a restrictive Content-Security-Policy disallowing 'unsafe-inline' and 'unsafe-eval'.",
            "limitations": "Passive evaluation of declared HTTP response policy."
        })
    if "X-Frame-Options" not in headers_present and not (csp and "frame-ancestors" in csp):
        standardized_findings.append({
            "id": "HDR-03",
            "module": "security_headers",
            "title": "Missing X-Frame-Options / frame-ancestors Directives",
            "severity": "low",
            "technical_evidence": {"header": "X-Frame-Options", "status": "missing"},
            "impact": "Vulnerable to UI clickjacking where site is embedded in attacker-controlled frames.",
            "source": "HTTP Response Headers",
            "confidence": 0.95,
            "recommendation": "Set X-Frame-Options: DENY or frame-ancestors 'none'.",
            "limitations": "Inspects top-level response headers."
        })
    if "X-Content-Type-Options" not in headers_present:
        standardized_findings.append({
            "id": "HDR-04",
            "module": "security_headers",
            "title": "Missing X-Content-Type-Options Header",
            "severity": "low",
            "technical_evidence": {"header": "X-Content-Type-Options", "status": "missing"},
            "impact": "Allows browsers to perform MIME-type sniffing, potentially interpreting non-executable types as HTML/JS.",
            "source": "HTTP Response Headers",
            "confidence": 0.95,
            "recommendation": "Set X-Content-Type-Options: nosniff on all HTTP responses.",
            "limitations": "Passive response header check."
        })
    for c in cookie_analysis:
        if not c.get("secure") or not c.get("httponly"):
            standardized_findings.append({
                "id": "HDR-05",
                "module": "security_headers",
                "title": f"Insecure Cookie Configuration: {c['cookie']}",
                "severity": "medium" if not c.get("secure") else "low",
                "technical_evidence": c,
                "impact": "Cookie can be intercepted over unencrypted HTTP or read by client JavaScript during XSS attacks.",
                "source": "Set-Cookie response headers",
                "confidence": 0.95,
                "recommendation": "Set 'Secure', 'HttpOnly', and 'SameSite=Lax' or 'Strict' on all session cookies.",
                "limitations": "Evaluates cookies sent on root request."
            })
            break

    return {
        "grade": grade,
        "score_numeric": final_score,
        "headers_present": headers_present,
        "headers_missing": headers_missing,
        "cookie_analysis": cookie_analysis,
        "findings": findings,
        "standardized_findings": standardized_findings
    }
