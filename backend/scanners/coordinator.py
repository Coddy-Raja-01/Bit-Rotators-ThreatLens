import time
import ipaddress
from urllib.parse import urlparse
from backend.scanners.ssrf import validate_url_for_scan, SSRFSecurityException
from backend.ml.classifier import predict_phishing
from backend.scanners.lookalike import check_lookalike
from backend.scanners.redirects import trace_redirects
from backend.scanners.content import analyze_page_content
from backend.scanners.security_headers import evaluate_headers_and_grade
from backend.scanners.certificate import inspect_tls_certificate
from backend.scanners.fingerprint import fingerprint_technology
from backend.scanners.intel import check_external_threat_intel
from backend.scanners.scoring import calculate_unified_risk_score
from backend.scanners.url_intel import (
    normalize_url_advanced,
    get_dns_characteristics,
    get_domain_rdap_registration,
)
from backend.database import save_assessment
from backend.correlation.engine import record_report_indicators

def execute_full_scan(raw_url: str, db_community_getter=None, authorized_target: bool = False) -> dict:
    """
    Coordinates all four inspection pillars to produce a unified threat report:
    1. Threat Analysis (ML, Lookalike, Redirects, Static Content)
    2. Web Security Assessment (Headers, TLS Grade, Tech Fingerprint)
    3. Certificate Validation (Trust Chain, Weak Keys, CT Timeline, Revocation)
    4. Collaborative Intelligence (Community Reports, Confirmations, Verification)
    """
    start_ts = time.time()
    
    # Step 1: Pre-scan SSRF validation and normalization
    try:
        url_normalization = normalize_url_advanced(raw_url)
        normalized_url, hostname, resolved_ips, is_live_dns = validate_url_for_scan(
            url_normalization["normalized_url"]
        )
    except SSRFSecurityException as e:
        return {
            "success": False,
            "error_type": "SSRF_VIOLATION",
            "message": str(e),
            "input_url": raw_url,
            "scan_timestamp": int(time.time()),
            "elapsed_ms": round((time.time() - start_ts) * 1000)
        }

    dns_characteristics = get_dns_characteristics(hostname)
    try:
        ipaddress.ip_address(hostname)
        rdap_registration = {
            "domain": hostname,
            "registrar": "Not applicable",
            "registration_date": None,
            "age_days": None,
            "is_young_domain": False,
            "error": "RDAP domain registration lookup does not apply to IP literals.",
            "findings": []
        }
    except ValueError:
        rdap_registration = get_domain_rdap_registration(hostname)

    # Step 2: Pillar 1 - Threat Analysis
    ml_result = predict_phishing(normalized_url)
    lookalike_result = check_lookalike(normalized_url)

    if is_live_dns:
        if authorized_target:
            redirect_result = trace_redirects(normalized_url, initial_ips=resolved_ips)
            final_destination_url = redirect_result.get("final_url", normalized_url)
            final_host = urlparse(final_destination_url).hostname
            content_ips = resolved_ips if final_host == hostname else None
            content_result = analyze_page_content(final_destination_url, pinned_ips=content_ips)
        else:
            redirect_result = {
                "final_url": normalized_url,
                "hop_count": 0,
                "has_cross_domain_hop": False,
                "has_downgrade_hop": False,
                "hops": [],
                "skipped": True,
                "error": "Redirect inspection requires explicit target authorization."
            }
            final_destination_url = normalized_url
            content_result = {
                "fetched": False,
                "skipped": True,
                "error": "HTML inspection requires explicit target authorization.",
                "forms": [],
                "cross_domain_forms": [],
                "hidden_iframes": [],
                "obfuscated_scripts": [],
                "scam_indicators": [],
                "has_password_field": False,
                "risk_score_points": 0,
                "reasons": []
            }
        external_intel = check_external_threat_intel(final_destination_url)
        final_host = urlparse(final_destination_url).hostname
        pinned_ips = resolved_ips if final_host == hostname else None
        security_headers = evaluate_headers_and_grade(final_destination_url, pinned_ips=pinned_ips)
        headers_dict = security_headers.get("headers_present", {})
        tech_fingerprint = fingerprint_technology(headers_dict, "")
        certificate_data = inspect_tls_certificate(final_destination_url, pinned_ips=pinned_ips)
    else:
        redirect_result = {
            "final_url": normalized_url,
            "hop_count": 0,
            "has_cross_domain_hop": False,
            "has_downgrade_hop": False,
            "hops": [],
            "error": "Host not currently resolvable via DNS (domain offline or taken down)."
        }
        final_destination_url = normalized_url
        content_result = {
            "fetched": False,
            "error": "Domain has no active DNS record. Page content unreachable.",
            "forms": [],
            "cross_domain_forms": [],
            "hidden_iframes": [],
            "obfuscated_scripts": [],
            "scam_indicators": [],
            "has_password_field": False,
            "risk_score_points": 0,
            "reasons": []
        }
        external_intel = check_external_threat_intel(normalized_url)
        security_headers = {
            "grade": "F",
            "score_numeric": 0,
            "error": "Host offline / Unreachable",
            "headers_present": {},
            "headers_missing": [],
            "cookie_analysis": [],
            "findings": [{"severity": "INFO", "message": "Domain does not resolve to an active IP address."}]
        }
        tech_fingerprint = {"detected_technologies": [], "vulnerabilities": [], "has_vulnerabilities": False}
        certificate_data = {
            "has_ssl": False,
            "error": "Domain has no active DNS record",
            "cipher": None,
            "tls_version": None,
            "chain": [],
            "weak_key_analysis": {"is_weak": True, "reasons": ["Domain does not resolve; no certificate available"]},
            "ct_timeline": [],
            "revocation": {"status": "Unknown", "details": "No DNS record"}
        }

    threat_module = {
        "ml_probability": ml_result["probability"],
        "ml_engine": ml_result["engine"],
        "ml_accuracy": ml_result.get("accuracy", 0.95),
        "ml_features": ml_result["features"],
        "ml_findings": ml_result.get("findings", []),
        "lookalike": lookalike_result,
        "redirects": redirect_result,
        "content": content_result,
        "external_intel": external_intel,
        "url_normalization": url_normalization
    }

    security_module = {
        "headers_grade": security_headers.get("grade", "C"),
        "headers_score": security_headers.get("score_numeric", 50),
        "headers_present": security_headers.get("headers_present", {}),
        "headers_missing": security_headers.get("headers_missing", []),
        "cookie_analysis": security_headers.get("cookie_analysis", []),
        "findings": security_headers.get("findings", []),
        "fingerprint": tech_fingerprint
    }

    # Step 5: Pillar 4 - Collaborative Threat Intelligence
    community_intel = {
        "report_count": 0,
        "confirmations": 0,
        "disputes": 0,
        "is_verified": False,
        "recent_reports": []
    }
    if db_community_getter:
        try:
            community_intel = db_community_getter(hostname)
        except Exception:
            pass

    # Step 6: Unified Risk Score Calculation
    unified_scoring = calculate_unified_risk_score(
        threat_analysis=threat_module,
        security_assessment=security_module,
        certificate_validation=certificate_data,
        community_intelligence=community_intel,
        tech_fingerprint=tech_fingerprint,
        is_live_dns=is_live_dns,
        target_url=normalized_url,
        domain=hostname,
        url_normalization=url_normalization,
        dns_characteristics=dns_characteristics,
        rdap_registration=rdap_registration,
        authorized_target=authorized_target
    )

    elapsed_ms = round((time.time() - start_ts) * 1000)
    report_id = unified_scoring.get("report_id")

    full_report = {
        "success": True,
        "report_id": report_id,
        "target": {
            "input_url": raw_url,
            "normalized_url": normalized_url,
            "final_url": final_destination_url,
            "hostname": hostname,
            "resolved_ips": resolved_ips,
            "authorized_target": authorized_target
        },
        "scan_timestamp": int(time.time()),
        "elapsed_ms": elapsed_ms,
        "unified_scoring": unified_scoring,
        "threat_analysis": threat_module,
        "web_security": security_module,
        "certificate_validation": certificate_data,
        "community_intelligence": community_intel,
        "url_normalization": url_normalization,
        "dns_characteristics": dns_characteristics,
        "rdap_registration": rdap_registration
    }

    # Save to SQLite DB for persistent lookup and verification
    try:
        save_assessment(
            report_id=report_id,
            target_url=normalized_url,
            domain=hostname,
            classification=unified_scoring.get("classification", "Inconclusive"),
            score=unified_scoring.get("score", 0),
            report_dict=full_report
        )
        record_report_indicators(report_id, full_report)
    except Exception as e:
        print(f"Warning: Could not persist assessment {report_id} to database: {e}")

    return full_report
