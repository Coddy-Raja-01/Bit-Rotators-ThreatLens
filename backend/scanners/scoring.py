import time
import uuid
from datetime import datetime, timezone

from backend.models.evidence import Finding


def calculate_unified_risk_score(
    threat_analysis: dict,
    security_assessment: dict,
    certificate_validation: dict,
    community_intelligence: dict,
    tech_fingerprint: dict,
    is_live_dns: bool = True,
    target_url: str = "",
    domain: str = "",
    url_normalization: dict | None = None,
    dns_characteristics: dict | None = None,
    rdap_registration: dict | None = None,
    authorized_target: bool = False
) -> dict:
    """
    Blends all detection modules into a 5-Class RiskAssessment:
    Classifications:
      - Confirmed Malicious: Authoritative threat intel listing OR multiple independently validated critical signals.
      - High Risk: Single high-confidence critical signal or cumulative score >= 50.
      - Suspicious: Anomalous characteristics, weak security posture, or score 25-49.
      - Low Risk: Score < 25 and no high/critical indicators. Always carries mandatory disclaimer.
      - Inconclusive: Host unreachable/DNS failed with thin signals, or critical sources timed out.
    """
    score = 0
    evidence_breakdown = []
    all_findings = []
    threat_indicators = []
    recommended_actions = []
    limitations = [
        "Absence of known threats is not proof of safety.",
        "A valid TLS certificate does not prove the site is legitimate.",
        "ThreatLens cannot independently detect a Certificate Authority's internal key-generation weakness from a URL.",
        "Passive static inspection does not execute dynamic JavaScript client-side applications."
    ]

    # Track evidence coverage across modules
    active_scan_status = "completed" if authorized_target and is_live_dns else "skipped"
    checks_coverage = [
        {"name": "DNS Resolution & SSRF Guard", "status": "completed" if is_live_dns else "failed", "details": "Active public IP resolution" if is_live_dns else "No active DNS resolution"},
        {"name": "URL Normalization", "status": "completed", "details": "Normalized host, userinfo, IDN, and shortener indicators"},
        {"name": "DNS Characteristics", "status": "completed" if dns_characteristics and not dns_characteristics.get("errors") else "failed", "details": "; ".join(dns_characteristics.get("errors", [])) if dns_characteristics else "No DNS response"},
        {"name": "RDAP Registration", "status": "completed" if rdap_registration and rdap_registration.get("registration_date") else "failed", "details": rdap_registration.get("error") if rdap_registration else "No RDAP response"},
        {"name": "Lexical & Lookalike Detection", "status": "completed", "details": "Evaluated against 120+ brand catalog"},
        {"name": "Redirect Chain Tracer", "status": active_scan_status, "details": "Hop-by-hop protocol audit" if authorized_target else "Requires explicit target authorization"},
        {"name": "Static Content & Form Inspector", "status": active_scan_status, "details": "Passive DOM analysis" if authorized_target else "Requires explicit target authorization"},
        {"name": "HTTP Security Headers", "status": "completed" if is_live_dns else "skipped", "details": "HSTS, CSP, XFO, XCTO evaluation"},
        {"name": "TLS Certificate & Chain Trust", "status": "completed" if certificate_validation.get("has_ssl") else ("skipped" if not is_live_dns else "failed"), "details": "Cryptographic key and CT timeline audit"},
        {"name": "Threat Intelligence Feeds", "status": "completed", "details": "URLhaus, OpenPhish, and bundled threat feed"},
        {"name": "Machine Learning Phishing Model", "status": "completed", "details": "Random Forest lexical feature evaluation"},
        {"name": "Collaborative Community Database", "status": "completed", "details": "Consensus voting and report verification"}
    ]

    # Gather module findings
    all_findings.extend(threat_analysis.get("ml_findings", []))
    all_findings.extend((url_normalization or {}).get("findings", []))
    all_findings.extend((dns_characteristics or {}).get("findings", []))
    all_findings.extend((rdap_registration or {}).get("findings", []))
    all_findings.extend(threat_analysis.get("lookalike", {}).get("findings", []))
    all_findings.extend(threat_analysis.get("content", {}).get("findings", []))
    all_findings.extend(threat_analysis.get("redirects", {}).get("findings", []))
    all_findings.extend(threat_analysis.get("external_intel", {}).get("findings", []))
    all_findings.extend(security_assessment.get("standardized_findings", []))
    all_findings.extend(tech_fingerprint.get("findings", []))
    all_findings.extend(certificate_validation.get("findings", []))

    # -------------------------------------------------------------
    # 1. THREAT ANALYSIS MODULE
    # -------------------------------------------------------------
    # ML Phishing Probability
    ml_prob = threat_analysis.get("ml_probability", 0.0)
    if ml_prob >= 0.85:
        points = 35
        score += points
        threat_indicators.append("Machine learning classifier indicates extremely high phishing likelihood (>=85%)")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Machine Learning",
            "points": f"+{points}",
            "evidence": f"Random Forest classifier indicates extremely high phishing probability ({ml_prob*100:.1f}%).",
            "severity": "CRITICAL"
        })
    elif ml_prob >= 0.50:
        points = 20
        score += points
        threat_indicators.append(f"Elevated machine learning phishing probability ({ml_prob*100:.1f}%)")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Machine Learning",
            "points": f"+{points}",
            "evidence": f"Classifier detected structural and lexical phishing characteristics ({ml_prob*100:.1f}% probability).",
            "severity": "HIGH"
        })

    # Lookalike Domain / Brand Squatting
    lookalike = threat_analysis.get("lookalike", {})
    if lookalike.get("is_lookalike"):
        points = 35
        score += points
        technique = lookalike.get("technique", "Brand Impersonation")
        target_brand = lookalike.get("matched_brand", "known brand")
        threat_indicators.append(f"Lookalike brand impersonation: mimicking {target_brand}")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Lookalike Detector",
            "points": f"+{points}",
            "evidence": f"{technique}: Deceptively impersonates official brand '{target_brand}'.",
            "severity": "CRITICAL"
        })

    # Page Content Findings (Forms, Obfuscated JS, Social Engineering)
    content = threat_analysis.get("content", {})
    if content.get("cross_domain_forms"):
        has_pwd = any(f.get("has_password") for f in content["cross_domain_forms"])
        points = 35 if has_pwd else 15
        score += points
        if has_pwd:
            threat_indicators.append("Credential theft form posting passwords to external domain")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Content Inspector",
            "points": f"+{points}",
            "evidence": "Webpage contains login/password forms transmitting credentials to a foreign external domain.",
            "severity": "CRITICAL" if has_pwd else "HIGH"
        })

    if content.get("obfuscated_scripts"):
        points = 15
        score += points
        threat_indicators.append("Obfuscated client-side JavaScript anti-analysis patterns")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Content Inspector",
            "points": f"+{points}",
            "evidence": f"Detected heavily obfuscated client-side JavaScript ({len(content['obfuscated_scripts'])} patterns).",
            "severity": "HIGH"
        })

    if content.get("brand_title_mismatch"):
        points = 25
        score += points
        claimed = content["brand_title_mismatch"]["claimed_brand"]
        threat_indicators.append(f"Title claims brand '{claimed}' on unrelated domain")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Content Inspector",
            "points": f"+{points}",
            "evidence": f"Title claims to be '{claimed}', but domain is unaffiliated.",
            "severity": "HIGH"
        })

    # Redirect Hops (Protocol Downgrade or Cross-domain redirect)
    redirects = threat_analysis.get("redirects", {})
    if redirects.get("has_downgrade_hop"):
        points = 20
        score += points
        threat_indicators.append("Insecure redirect protocol downgrade (HTTPS -> HTTP)")
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Redirect Tracer",
            "points": f"+{points}",
            "evidence": "Redirect chain executed an insecure protocol downgrade from HTTPS to HTTP.",
            "severity": "HIGH"
        })
    elif redirects.get("has_cross_domain_hop") and redirects.get("hop_count", 0) > 2:
        points = 10
        score += points
        evidence_breakdown.append({
            "category": "Threat Analysis",
            "module": "Redirect Tracer",
            "points": f"+{points}",
            "evidence": f"Multi-hop cross-domain redirect sequence ({redirects.get('hop_count')} hops).",
            "severity": "MEDIUM"
        })

    # -------------------------------------------------------------
    # 2. WEB SECURITY ASSESSMENT MODULE
    # -------------------------------------------------------------
    grade = security_assessment.get("headers_grade", security_assessment.get("grade", "C"))
    if grade == "F":
        points = 20
        score += points
        evidence_breakdown.append({
            "category": "Web Security",
            "module": "Security Headers",
            "points": f"+{points}",
            "evidence": "Security header assessment received failing grade 'F' (missing HSTS, CSP, and X-Frame-Options).",
            "severity": "HIGH"
        })
    elif grade == "D":
        points = 12
        score += points
        evidence_breakdown.append({
            "category": "Web Security",
            "module": "Security Headers",
            "points": f"+{points}",
            "evidence": "Weak defense posture: received poor grade 'D' with vital protection headers absent.",
            "severity": "MEDIUM"
        })
    elif grade == "C":
        points = 5
        score += points
        evidence_breakdown.append({
            "category": "Web Security",
            "module": "Security Headers",
            "points": f"+{points}",
            "evidence": "Sub-optimal HTTP header configuration (Grade 'C').",
            "severity": "LOW"
        })

    # Vulnerable Software / CVEs
    vulns = tech_fingerprint.get("vulnerabilities", [])
    if vulns:
        critical_count = sum(1 for v in vulns if v.get("severity", "").upper() == "CRITICAL")
        points = 25 if critical_count > 0 else 15
        score += points
        cve_ids = ", ".join([v.get("cve", "CVE") for v in vulns[:2]])
        threat_indicators.append(f"Exposed vulnerable software: {cve_ids}")
        evidence_breakdown.append({
            "category": "Web Security",
            "module": "Tech Fingerprint",
            "points": f"+{points}",
            "evidence": f"Exposed outdated web software with known unpatched vulnerabilities ({cve_ids}).",
            "severity": "CRITICAL" if critical_count > 0 else "HIGH"
        })

    # -------------------------------------------------------------
    # 3. CERTIFICATE VALIDATION MODULE
    # -------------------------------------------------------------
    if not certificate_validation.get("has_ssl", True):
        points = 30
        score += points
        threat_indicators.append("Missing TLS encryption / Plaintext HTTP only")
        evidence_breakdown.append({
            "category": "Certificate Validation",
            "module": "TLS Handshake",
            "points": f"+{points}",
            "evidence": "No valid TLS certificate or plaintext HTTP only. Traffic is unencrypted and vulnerable to interception.",
            "severity": "CRITICAL"
        })
    else:
        weak_key = certificate_validation.get("weak_key_analysis", {})
        if weak_key.get("is_weak"):
            for r in weak_key.get("reasons", [])[:2]:
                points = 20
                score += points
                evidence_breakdown.append({
                    "category": "Certificate Validation",
                    "module": "Key Strength",
                    "points": f"+{points}",
                    "evidence": r,
                    "severity": "HIGH"
                })

        chain = certificate_validation.get("chain", [])
        if chain and chain[0].get("is_self_signed"):
            points = 25
            score += points
            threat_indicators.append("Self-signed TLS certificate untrusted by browser store")
            evidence_breakdown.append({
                "category": "Certificate Validation",
                "module": "Trust Anchor",
                "points": f"+{points}",
                "evidence": "Certificate is self-signed and not signed by any recognized Certificate Authority.",
                "severity": "CRITICAL"
            })
        elif chain and chain[0].get("is_expired"):
            points = 20
            score += points
            threat_indicators.append(f"Expired TLS certificate ({chain[0].get('days_until_expiry', 0)} days past validity)")
            evidence_breakdown.append({
                "category": "Certificate Validation",
                "module": "Validity Period",
                "points": f"+{points}",
                "evidence": f"Certificate has expired ({chain[0].get('days_until_expiry', 0)} days past validity).",
                "severity": "HIGH"
            })

    # -------------------------------------------------------------
    # 4. THREAT INTEL & COMMUNITY CONSENSUS
    # -------------------------------------------------------------
    comm_reports = community_intelligence.get("report_count", 0)
    is_verified_community = community_intelligence.get("is_verified", False)

    if is_verified_community:
        points = 35
        score += points
        threat_indicators.append(f"ThreatLens community consensus verified ({comm_reports} reports)")
        evidence_breakdown.append({
            "category": "Threat Intelligence",
            "module": "Community Verification",
            "points": f"+{points}",
            "evidence": f"ThreatLens community consensus verified: confirmed as phishing/fraud across {comm_reports} user reports.",
            "severity": "CRITICAL"
        })
    elif comm_reports > 0:
        points = min(comm_reports * 8, 20)
        score += points
        evidence_breakdown.append({
            "category": "Threat Intelligence",
            "module": "Community Reports",
            "points": f"+{points}",
            "evidence": f"Domain reported {comm_reports} time(s) by community members for suspicious activity.",
            "severity": "MEDIUM"
        })

    # External Feeds
    ext_intel = threat_analysis.get("external_intel", {})
    authoritative_intel_flagged = False
    if ext_intel.get("urlhaus", {}).get("is_listed") or ext_intel.get("safe_browsing", {}).get("is_listed") or ext_intel.get("openphish", {}).get("is_listed") or ext_intel.get("phishtank", {}).get("is_listed") or len(ext_intel.get("offline_hits", [])) > 0:
        authoritative_intel_flagged = True
    elif ext_intel.get("virustotal", {}).get("malicious_votes", 0) >= 4:
        authoritative_intel_flagged = True

    if authoritative_intel_flagged:
        points = 40
        score += points
        threat_indicators.append("Flagged by authoritative threat intelligence database (URLhaus / GSB / OpenPhish / VT)")
        evidence_breakdown.append({
            "category": "Threat Intelligence",
            "module": "External Feeds",
            "points": f"+{points}",
            "evidence": "Target actively listed as confirmed malicious/phishing host in authoritative threat database.",
            "severity": "CRITICAL"
        })
    elif ext_intel.get("intel_flagged"):
        points = 20
        score += points
        evidence_breakdown.append({
            "category": "Threat Intelligence",
            "module": "External Feeds",
            "points": f"+{points}",
            "evidence": "Suspicious listing or vendor detection in external intelligence database.",
            "severity": "HIGH"
        })

    if rdap_registration and rdap_registration.get("is_young_domain"):
        points = 12
        score += points
        threat_indicators.append(
            f"Domain was registered recently ({rdap_registration.get('age_days')} days ago)"
        )
        evidence_breakdown.append({
            "category": "Domain Intelligence",
            "module": "RDAP Registration",
            "points": f"+{points}",
            "evidence": f"Domain was registered {rdap_registration.get('age_days')} days ago.",
            "severity": "MEDIUM"
        })

    final_score = max(0, min(100, score))

    # -------------------------------------------------------------
    # 5-CLASS CLASSIFICATION LOGIC
    # -------------------------------------------------------------
    # Check for multiple independently validated evidence
    critical_findings_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    high_findings_count = sum(1 for f in all_findings if f.get("severity") == "high")

    is_lookalike = lookalike.get("is_lookalike", False)
    has_cred_theft_form = content.get("has_password_field", False) and bool(content.get("cross_domain_forms"))
    has_high_ml = ml_prob >= 0.85

    multiple_independent_evidence = (
        (is_lookalike and has_cred_theft_form) or
        (is_lookalike and has_high_ml) or
        (has_cred_theft_form and has_high_ml) or
        (is_verified_community and (is_lookalike or has_cred_theft_form or has_high_ml)) or
        (critical_findings_count >= 2)
    )

    if not is_live_dns and not authoritative_intel_flagged and not is_lookalike and ml_prob < 0.60:
        classification = "Inconclusive"
        verdict_color = "grey"
        summary = "Assessment inconclusive: target domain does not currently resolve via DNS and authoritative threat signals are sparse."
        recommended_actions.append("Re-verify destination URL spelling. If host was recently registered or suspended, monitor via Watchlist.")
    elif authoritative_intel_flagged or multiple_independent_evidence:
        classification = "Confirmed Malicious"
        verdict_color = "red"
        summary = "Confirmed Malicious: verified by authoritative threat intelligence or corroborated across multiple independent security checks. High danger of credential theft or fraud."
        recommended_actions.extend([
            "Do NOT visit this website or click links pointing to this domain.",
            "Never enter passwords, bank credentials, seed phrases, or personal contact info.",
            "Report domain to your organization's IT/SOC team and submit to ThreatLens Threat Database.",
            "If credentials were submitted previously, reset them immediately and revoke active sessions."
        ])
    elif final_score >= 50 or is_lookalike or has_cred_theft_form or has_high_ml or critical_findings_count >= 1:
        classification = "High Risk"
        verdict_color = "orange"
        summary = "High Risk: significant deceptive markers, unpatched vulnerabilities, or aggressive credential harvesting structures detected."
        recommended_actions.extend([
            "Avoid interacting with this domain. Check domain identity against genuine official channels.",
            "Do not input authentication details or download files from this site.",
            "Verify the authentic brand address in the ThreatLens Lookalike comparison table."
        ])
    elif final_score >= 25 or high_findings_count >= 1 or redirects.get("has_downgrade_hop"):
        classification = "Suspicious"
        verdict_color = "amber"
        summary = "Suspicious: anomalous characteristics, weak transport controls, or atypical redirect behavior detected. Caution advised."
        recommended_actions.extend([
            "Proceed with heightened awareness; verify transport encryption and domain spelling.",
            "Ensure multi-factor authentication (MFA) is enabled on accounts associated with this provider."
        ])
    else:
        classification = "Low Risk"
        verdict_color = "green"
        summary = "Low Risk: no known malicious heuristics or threat listings identified across tested engines. Note: absence of known threats is not proof of safety."
        recommended_actions.extend([
            "Standard security hygiene applies. Always verify domain identity and SSL certificate details.",
            "Remain vigilant against unsolicited communication and unexpected payment requests."
        ])

    normalized_findings = [Finding.from_legacy(f).to_dict() for f in all_findings]
    evidence_sources = sorted(list({f.get("source", "ThreatLens") for f in normalized_findings}))
    coverage = {
        "total_checks": len(checks_coverage),
        "executed_checks": sum(1 for c in checks_coverage if c["status"] == "completed"),
        "skipped_checks": sum(1 for c in checks_coverage if c["status"] == "skipped"),
        "failed_checks": sum(1 for c in checks_coverage if c["status"] == "failed"),
        "checks": checks_coverage
    }
    report_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    confidence = round(max(0.0, min(1.0, final_score / 100.0)), 3)

    return {
        "report_id": report_id,
        "classification": classification,
        "score": final_score,
        "verdict": classification,
        "verdict_color": verdict_color,
        "summary": summary,
        "disclaimer": "Absence of known threats is not proof of safety. ThreatLens provides evidence-based assessment at the time of inspection.",
        "threat_indicators": threat_indicators,
        "indicators": threat_indicators,
        "findings": normalized_findings,
        "per_finding_sources": evidence_sources,
        "evidence_count": len(evidence_breakdown),
        "evidence_breakdown": evidence_breakdown,
        "evidence_sources": evidence_sources,
        "coverage": coverage,
        "evidence_coverage": coverage,
        "recommended_actions": recommended_actions,
        "limitations": limitations,
        "analysis_timestamp": now_iso,
        "confidence": confidence,
    }
