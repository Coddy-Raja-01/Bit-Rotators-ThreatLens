import time
import requests
from urllib.parse import urlparse, urljoin
from backend.scanners.ssrf import validate_target_host, SSRFSecurityException, create_pinned_session

SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatLens-Scanner/1.0 Security-Auditor"

def trace_redirects(start_url: str, max_hops: int = 8, initial_ips: list[str] | None = None) -> dict:
    """
    Follow redirect hops safely with strict SSRF validation at every step.
    Returns:
        {
            "final_url": str,
            "hop_count": int,
            "has_cross_domain_hop": bool,
            "has_downgrade_hop": bool,
            "hops": list[dict],
            "error": str | None
        }
    """
    current_url = start_url.strip()
    if not (current_url.startswith("http://") or current_url.startswith("https://")):
        current_url = "https://" + current_url

    hops = []
    has_cross_domain = False
    has_downgrade = False
    visited = set()

    for hop_index in range(max_hops):
        if current_url in visited:
            hops.append({
                "hop_index": hop_index,
                "url": current_url,
                "domain": urlparse(current_url).hostname or "",
                "status_code": 310,
                "status_text": "Redirect Loop Detected",
                "latency_ms": 0,
                "is_ssl": current_url.startswith("https://"),
                "ip": "N/A",
                "flag": "loop"
            })
            break

        visited.add(current_url)
        parsed = urlparse(current_url)
        hostname = parsed.hostname
        if not hostname:
            break

        # Strict SSRF check before connection
        try:
            resolved_ips = initial_ips if hop_index == 0 and initial_ips else validate_target_host(hostname)
            ip_str = resolved_ips[0] if resolved_ips else "unknown"
        except SSRFSecurityException as e:
            hops.append({
                "hop_index": hop_index,
                "url": current_url,
                "domain": hostname,
                "status_code": 403,
                "status_text": f"Blocked by SSRF Filter: {e}",
                "latency_ms": 0,
                "is_ssl": current_url.startswith("https://"),
                "ip": "blocked",
                "flag": "blocked"
            })
            return {
                "final_url": current_url,
                "hop_count": len(hops),
                "has_cross_domain_hop": has_cross_domain,
                "has_downgrade_hop": has_downgrade,
                "hops": hops,
                "error": f"SSRF Guard triggered: {e}",
                "findings": [
                    {
                        "id": "REDIR-04",
                        "module": "redirects",
                        "title": "Redirect Destination Blocked by SSRF Guard",
                        "severity": "critical",
                        "technical_evidence": {"target_url": current_url, "hostname": hostname, "violation": str(e)},
                        "impact": "Redirect target resolved to private, internal, or cloud metadata network address.",
                        "source": "SSRF Guard (backend/scanners/ssrf.py)",
                        "confidence": 1.0,
                        "recommendation": "Block this redirect chain; target attempts internal network probing.",
                        "limitations": "Evaluates IP addresses against RFC 1918, link-local, and cloud metadata."
                    }
                ]
            }

        start_time = time.time()
        session = None
        try:
            session = create_pinned_session(ip_str, hostname)
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=4.0,
                headers={"User-Agent": SAFE_USER_AGENT, "Accept": "*/*"},
                stream=True # do not download large bodies
            )
            elapsed_ms = round((time.time() - start_time) * 1000)
            status_code = response.status_code
            status_text = response.reason or str(status_code)
            response_headers = response.headers
            response.close()

            # Check if this hop downgraded protocol
            is_ssl = current_url.startswith("https://")
            
            hop_data = {
                "hop_index": hop_index,
                "url": current_url,
                "domain": hostname,
                "status_code": status_code,
                "status_text": status_text,
                "latency_ms": elapsed_ms,
                "is_ssl": is_ssl,
                "ip": ip_str,
                "flag": "normal"
            }

            # Check for redirect headers
            if 300 <= status_code < 400 and "Location" in response_headers:
                next_url = response_headers["Location"].strip()
                # Resolve relative redirects
                next_url = urljoin(current_url, next_url)
                
                next_parsed = urlparse(next_url)
                if next_parsed.hostname != hostname:
                    has_cross_domain = True
                    hop_data["flag"] = "cross_domain"
                    
                if current_url.startswith("https://") and next_url.startswith("http://"):
                    has_downgrade = True
                    hop_data["flag"] = "ssl_downgrade"

                hops.append(hop_data)
                current_url = next_url
            else:
                hops.append(hop_data)
                break # Reached final destination

        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS failed on initial attempt
            elapsed_ms = round((time.time() - start_time) * 1000)
            hops.append({
                "hop_index": hop_index,
                "url": current_url,
                "domain": hostname,
                "status_code": 495,
                "status_text": "SSL Certificate Verification Failed",
                "latency_ms": elapsed_ms,
                "is_ssl": current_url.startswith("https://"),
                "ip": ip_str,
                "flag": "ssl_error"
            })
            break
        except requests.exceptions.Timeout:
            hops.append({
                "hop_index": hop_index,
                "url": current_url,
                "domain": hostname,
                "status_code": 504,
                "status_text": "Connection Timed Out (4000ms limit)",
                "latency_ms": 4000,
                "is_ssl": current_url.startswith("https://"),
                "ip": ip_str,
                "flag": "timeout"
            })
            break
        except requests.exceptions.RequestException as e:
            hops.append({
                "hop_index": hop_index,
                "url": current_url,
                "domain": hostname,
                "status_code": 502,
                "status_text": f"Connection Refused or Network Error: {str(e)[:60]}",
                "latency_ms": round((time.time() - start_time) * 1000),
                "is_ssl": current_url.startswith("https://"),
                "ip": ip_str,
                "flag": "error"
            })
            break
        finally:
            if session is not None:
                session.close()

    # Format spatial 3D coordinates for Three.js visualization
    for i, h in enumerate(hops):
        h["x"] = i * 6.0 - ((len(hops) - 1) * 3.0) # centered along X axis
        h["y"] = (i % 2) * 1.5                      # slight alternate Y elevation
        h["z"] = 0.0

    findings = []
    if has_downgrade:
        findings.append({
            "id": "REDIR-01",
            "module": "redirects",
            "title": "Insecure Protocol Downgrade (HTTPS -> HTTP)",
            "severity": "high",
            "technical_evidence": {"hops_count": len(hops), "has_downgrade_hop": True},
            "impact": "Exposes traffic to plaintext interception and SSL-stripping man-in-the-middle attacks.",
            "source": "redirect tracer (hop validation)",
            "confidence": 0.95,
            "recommendation": "Enforce strict HTTPS-only redirects and deploy HSTS.",
            "limitations": "Traces up to 8 redirect hops."
        })
    if has_cross_domain and len(hops) > 2:
        findings.append({
            "id": "REDIR-02",
            "module": "redirects",
            "title": "Multi-Hop Cross-Domain Redirection Sequence",
            "severity": "medium",
            "technical_evidence": {"hop_count": len(hops), "domains": list({h.get('domain') for h in hops})},
            "impact": "Obfuscates ultimate landing page to evade simple domain filtering and automated scanners.",
            "source": "redirect tracer (cross-domain hop analysis)",
            "confidence": 0.85,
            "recommendation": "Examine final destination domain reputation and SSL certificate.",
            "limitations": "Evaluates domain hops without running client JavaScript."
        })

    return {
        "final_url": current_url,
        "hop_count": len(hops),
        "has_cross_domain_hop": has_cross_domain,
        "has_downgrade_hop": has_downgrade,
        "hops": hops,
        "error": None,
        "findings": findings
    }
