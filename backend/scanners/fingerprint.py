import re
import json
from pathlib import Path
from bs4 import BeautifulSoup

def load_vulnerable_rules():
    """Load vulnerable software definitions."""
    rules_file = Path(__file__).resolve().parent.parent.parent / "data" / "vulnerable_versions.json"
    if rules_file.exists():
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def version_is_less_or_equal(ver_a: str, ver_b: str) -> bool:
    """Compare two semantic version strings (e.g. '2.4.49' <= '2.4.50')."""
    try:
        def parse_parts(v):
            return [int(p) for p in re.findall(r"\d+", v)]
        parts_a = parse_parts(ver_a)
        parts_b = parse_parts(ver_b)
        # Pad to equal length
        max_len = max(len(parts_a), len(parts_b))
        parts_a += [0] * (max_len - len(parts_a))
        parts_b += [0] * (max_len - len(parts_b))
        return parts_a <= parts_b
    except Exception:
        return ver_a <= ver_b

def fingerprint_technology(headers: dict, html_content: str = "") -> dict:
    """
    Fingerprints server software, CMS, and runtime engines,
    then correlates against known vulnerable version databases.
    """
    rules = load_vulnerable_rules()
    detected = []
    vulnerabilities = []

    server_header = headers.get("Server", "") or headers.get("server", "")
    x_powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")

    # 1. Search in headers
    header_text = f"{server_header} {x_powered_by}"

    for r in rules:
        pattern = re.compile(r["pattern"], re.I)
        match = pattern.search(header_text)
        if match:
            version = match.group(1) if match.groups() else ""
            detected.append({
                "product": r["product"],
                "version": version or "Detected",
                "source": "HTTP Response Headers"
            })
            
            # Check vulnerable ranges
            if version:
                for vrange in r.get("vulnerable_ranges", []):
                    if version_is_less_or_equal(version, vrange["max"]):
                        vulnerabilities.append({
                            "product": r["product"],
                            "version": version,
                            "cve": vrange["cve"],
                            "severity": vrange["severity"],
                            "summary": vrange["summary"],
                            "threshold_max": vrange["max"]
                        })

    # 2. Search in HTML meta tags / generator
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        generator = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if generator and generator.get("content"):
            gen_content = generator.get("content")
            for r in rules:
                pattern = re.compile(r["pattern"], re.I)
                match = pattern.search(gen_content)
                if match:
                    version = match.group(1) if match.groups() else ""
                    # Check if already added
                    if not any(d["product"] == r["product"] for d in detected):
                        detected.append({
                            "product": r["product"],
                            "version": version or "Detected",
                            "source": "HTML Generator Meta Tag"
                        })
                        if version:
                            for vrange in r.get("vulnerable_ranges", []):
                                if version_is_less_or_equal(version, vrange["max"]):
                                    vulnerabilities.append({
                                        "product": r["product"],
                                        "version": version,
                                        "cve": vrange["cve"],
                                        "severity": vrange["severity"],
                                        "summary": vrange["summary"],
                                        "threshold_max": vrange["max"]
                                    })

    # General headers fingerprint fallback
    if not detected and server_header:
        detected.append({
            "product": server_header.split("/")[0] if "/" in server_header else server_header[:30],
            "version": server_header.split("/")[1] if "/" in server_header else "Unknown",
            "source": "HTTP Server Header"
        })

    findings = []
    for vuln in vulnerabilities:
        findings.append({
            "id": f"TECH-{vuln['cve']}",
            "module": "fingerprint",
            "title": f"Vulnerable Software Version: {vuln['product']} ({vuln['cve']})",
            "severity": vuln.get("severity", "high").lower(),
            "technical_evidence": vuln,
            "impact": vuln.get("summary", "Exposes server to known unpatched exploit vectors."),
            "source": "version fingerprint matching (data/vulnerable_versions.json)",
            "confidence": 0.90,
            "recommendation": f"Upgrade {vuln['product']} past version {vuln.get('threshold_max')}.",
            "limitations": "Inferred from HTTP Server and X-Powered-By banners; banners may be modified or backported."
        })

    return {
        "detected_technologies": detected,
        "vulnerabilities": vulnerabilities,
        "has_vulnerabilities": len(vulnerabilities) > 0,
        "server_header": server_header,
        "x_powered_by": x_powered_by,
        "findings": findings
    }
