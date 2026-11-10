import os
import time
import csv
from pathlib import Path
from urllib.parse import urlparse
import threading
import requests
from datetime import datetime, timezone
from backend.config import load_env

# In-memory threat intel cache: {key: (data, timestamp)}
_INTEL_CACHE = {}
CACHE_TTL = 3600  # 1 hour
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "openphish_feed.txt"
OPENPHISH_REFRESH_SECONDS = 3600
_OPENPHISH_REFRESH_LOCK = threading.Lock()

def load_offline_threat_feed() -> list[dict]:
    """Load bundled sample threat feed from data/threat_feed_sample.csv."""
    feed_path = Path(__file__).resolve().parent.parent.parent / "data" / "threat_feed_sample.csv"
    entries = []
    if feed_path.exists():
        try:
            with open(feed_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entries.append(row)
        except Exception:
            pass
    return entries

def _check_offline_feed(target_url: str, domain: str) -> list[dict]:
    """Check target against bundled offline threat dataset."""
    entries = load_offline_threat_feed()
    hits = []
    norm_url = target_url.lower().rstrip("/")
    clean_domain = domain.lower()

    for item in entries:
        indicator = item.get("indicator", "").lower().strip()
        itype = item.get("indicator_type", "domain")
        
        if itype == "domain" and (clean_domain == indicator or clean_domain.endswith("." + indicator)):
            hits.append(item)
        elif itype == "url" and (norm_url == indicator.rstrip("/") or indicator in norm_url):
            hits.append(item)
            
    return hits

def _refresh_openphish_feed() -> Path | None:
    """Refresh the OpenPhish cache at most once per hour; retain stale cache on failure."""
    cache_path = OPENPHISH_CACHE_PATH
    try:
        if cache_path.exists() and time.time() - cache_path.stat().st_mtime < OPENPHISH_REFRESH_SECONDS:
            return cache_path
    except OSError:
        pass

    with _OPENPHISH_REFRESH_LOCK:
        try:
            if cache_path.exists() and time.time() - cache_path.stat().st_mtime < OPENPHISH_REFRESH_SECONDS:
                return cache_path
        except OSError:
            pass

        try:
            response = requests.get(
                os.getenv("OPENPHISH_FEED_URL", OPENPHISH_FEED_URL),
                timeout=5.0,
                headers={"User-Agent": "ThreatLens/1.0"}
            )
            response.raise_for_status()
            feed = response.content
            if len(feed) > 5 * 1024 * 1024:
                raise ValueError("OpenPhish feed exceeded the 5 MB size limit")
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = cache_path.with_suffix(".tmp")
            temporary_path.write_bytes(feed)
            temporary_path.replace(cache_path)
            return cache_path
        except (requests.RequestException, OSError, ValueError):
            return cache_path if cache_path.exists() else None

class BaseIntelProvider:
    name: str = "base"
    
    def check(self, target_url: str, domain: str) -> dict:
        raise NotImplementedError

class URLhausProvider(BaseIntelProvider):
    name = "urlhaus"
    
    def check(self, target_url: str, domain: str) -> dict:
        api_key = os.getenv("URLHAUS_API_KEY", "").strip()
        if not api_key:
            return {
                "configured": False,
                "is_listed": False,
                "status": "Auth-Key not configured",
                "url_count": 0,
            }
        result = {"configured": True, "is_listed": False, "status": "No match", "url_count": 0}
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=3.0,
                headers={"User-Agent": "ThreatLens/1.0", "Auth-Key": api_key}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    result["is_listed"] = True
                    result["url_count"] = data.get("url_count", 0)
                    result["status"] = f"Listed in URLhaus ({data.get('url_count', 0)} active malware URLs)"
                else:
                    result["status"] = "Not listed in URLhaus"
            else:
                result["status"] = f"URLhaus HTTP {resp.status_code}"
        except Exception:
            result["status"] = "URLhaus API unreachable / timed out"
        return result


def get_intelligence_source_status() -> list[dict]:
    """Report source configuration and cached feed freshness without triggering requests."""
    load_env()
    cache_path = OPENPHISH_CACHE_PATH
    sources = []
    try:
        cache_age = max(0, time.time() - cache_path.stat().st_mtime)
        with cache_path.open("r", encoding="utf-8") as feed:
            record_count = sum(1 for line in feed if line.strip())
        last_refresh = datetime.fromtimestamp(
            cache_path.stat().st_mtime, timezone.utc
        ).isoformat()
        sources.append({
            "name": "OpenPhish",
            "configured": True,
            "status": "fresh" if cache_age < OPENPHISH_REFRESH_SECONDS else "stale",
            "last_refresh": last_refresh,
            "record_count": record_count,
            "details": "Cached community feed; stale cache is retained if refresh fails.",
        })
    except OSError:
        sources.append({
            "name": "OpenPhish",
            "configured": True,
            "status": "not loaded",
            "last_refresh": None,
            "record_count": 0,
            "details": "Feed refreshes during scans; no cached feed is available yet.",
        })

    source_keys = [
        ("URLhaus", "URLHAUS_API_KEY"),
        ("PhishTank", "PHISHTANK_API_KEY"),
        ("Google Safe Browsing", "SAFE_BROWSING_API_KEY"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
    ]
    for name, env_key in source_keys:
        configured = bool(os.getenv(env_key, "").strip())
        sources.append({
            "name": name,
            "configured": configured,
            "status": "configured" if configured else "not configured",
            "last_refresh": None,
            "record_count": None,
            "details": "Queried per target; source does not expose a locally cached feed.",
        })
    return sources


class OpenPhishProvider(BaseIntelProvider):
    name = "openphish"
    
    def check(self, target_url: str, domain: str) -> dict:
        result = {"configured": True, "is_listed": False, "status": "Not listed in OpenPhish"}
        normalized_target = target_url.lower().rstrip("/")
        cached_feed = _refresh_openphish_feed()
        if cached_feed:
            try:
                with cached_feed.open("r", encoding="utf-8") as feed:
                    for line in feed:
                        indicator = line.strip()
                        if not indicator:
                            continue
                        indicator_domain = (urlparse(indicator).hostname or "").lower()
                        if indicator.lower().rstrip("/") == normalized_target or indicator_domain == domain:
                            result.update({
                                "is_listed": True,
                                "status": "Listed in OpenPhish (cached feed)",
                                "matched_url": indicator
                            })
                            return result
            except OSError:
                pass

        # Always retain the bundled CSV as the offline fallback.
        offline_hits = _check_offline_feed(target_url, domain)
        for hit in offline_hits:
            if hit.get("source") == "OpenPhish":
                result["is_listed"] = True
                result["status"] = f"Listed in OpenPhish ({hit.get('threat_type')})"
                return result
        return result

class PhishTankProvider(BaseIntelProvider):
    name = "phishtank"

    def check(self, target_url: str, domain: str) -> dict:
        offline_hits = _check_offline_feed(target_url, domain)
        offline_hit = next((hit for hit in offline_hits if hit.get("source") == "PhishTank"), None)
        api_key = os.getenv("PHISHTANK_API_KEY")
        if not api_key:
            return {
                "configured": False,
                "is_listed": bool(offline_hit),
                "status": "Listed in offline PhishTank rows" if offline_hit else "Not configured",
                "offline_match": offline_hit
            }
        try:
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": target_url, "format": "json", "app_key": api_key},
                timeout=4.0,
                headers={"User-Agent": "phishtank/ThreatLens"}
            )
            response.raise_for_status()
            payload = response.json().get("results", {})
            listed = payload.get("in_database") is True and payload.get("valid") is True
            return {
                "configured": True,
                "is_listed": listed,
                "status": "Listed in PhishTank" if listed else "Not listed in PhishTank",
                "phish_id": payload.get("phish_id") if listed else None
            }
        except (requests.RequestException, ValueError):
            return {"configured": True, "is_listed": False, "status": "PhishTank API unreachable or invalid"}

class GoogleSafeBrowsingProvider(BaseIntelProvider):
    name = "safe_browsing"
    
    def check(self, target_url: str, domain: str) -> dict:
        sb_key = os.getenv("SAFE_BROWSING_API_KEY")
        if not sb_key:
            return {"configured": False, "status": "Not configured", "threat_type": None, "is_listed": False}
            
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={sb_key}"
            payload = {
                "client": {"clientId": "threatlens", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": target_url}]
                }
            }
            resp = requests.post(endpoint, json=payload, timeout=4.0)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType")
                    return {
                        "configured": True,
                        "is_listed": True,
                        "status": f"Flagged by Google Safe Browsing ({threat_type})",
                        "threat_type": threat_type
                    }
                return {"configured": True, "is_listed": False, "status": "Clean / No match", "threat_type": None}
            return {"configured": True, "is_listed": False, "status": f"GSB HTTP {resp.status_code}", "threat_type": None}
        except Exception:
            return {"configured": True, "is_listed": False, "status": "API query timed out", "threat_type": None}

class VirusTotalProvider(BaseIntelProvider):
    name = "virustotal"
    
    def check(self, target_url: str, domain: str) -> dict:
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return {"configured": False, "status": "Not configured", "malicious_votes": 0, "is_listed": False}
            
        try:
            headers = {"x-apikey": vt_key}
            resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                is_flagged = malicious >= 3
                return {
                    "configured": True,
                    "is_listed": is_flagged,
                    "status": f"{malicious} vendors flagged",
                    "malicious_votes": malicious
                }
            return {"configured": True, "is_listed": False, "status": f"VT HTTP {resp.status_code}", "malicious_votes": 0}
        except Exception:
            return {"configured": True, "is_listed": False, "status": "API query timed out", "malicious_votes": 0}

def check_external_threat_intel(target_url: str) -> dict:
    """
    Checks external and bundled threat intelligence feeds.
    Emits standardized findings alongside backward-compatible results dict.
    """
    load_env()
    parsed = urlparse(target_url)
    domain = (parsed.hostname or target_url).lower()
    cache_key = f"{target_url.lower()}::{domain}"

    now = time.time()
    if cache_key in _INTEL_CACHE:
        cached_result, cached_time = _INTEL_CACHE[cache_key]
        if now - cached_time < CACHE_TTL:
            return cached_result

    urlhaus_prov = URLhausProvider()
    openphish_prov = OpenPhishProvider()
    phishtank_prov = PhishTankProvider()
    gsb_prov = GoogleSafeBrowsingProvider()
    vt_prov = VirusTotalProvider()

    urlhaus_res = urlhaus_prov.check(target_url, domain)
    openphish_res = openphish_prov.check(target_url, domain)
    phishtank_res = phishtank_prov.check(target_url, domain)
    gsb_res = gsb_prov.check(target_url, domain)
    vt_res = vt_prov.check(target_url, domain)
    offline_hits = _check_offline_feed(target_url, domain)

    intel_flagged = bool(
        urlhaus_res.get("is_listed") or
        openphish_res.get("is_listed") or
        phishtank_res.get("is_listed") or
        gsb_res.get("is_listed") or
        vt_res.get("is_listed") or
        len(offline_hits) > 0
    )

    findings = []
    if urlhaus_res.get("is_listed"):
        findings.append({
            "id": "INTEL-01",
            "module": "intel",
            "title": "Listed in URLhaus Malware/Phishing Database",
            "severity": "critical",
            "technical_evidence": urlhaus_res,
            "impact": "Authoritatively verified malicious distribution host by abuse.ch security researchers.",
            "source": "URLhaus (abuse.ch API)",
            "confidence": 1.0,
            "recommendation": "Block domain at firewall/DNS gateway immediately.",
            "limitations": "Live lookup against abuse.ch threat registry."
        })

    if gsb_res.get("is_listed"):
        findings.append({
            "id": "INTEL-02",
            "module": "intel",
            "title": f"Flagged by Google Safe Browsing ({gsb_res.get('threat_type')})",
            "severity": "critical",
            "technical_evidence": gsb_res,
            "impact": "Domain actively identified as hosting malicious content, social engineering, or malware.",
            "source": "Google Safe Browsing v4",
            "confidence": 0.98,
            "recommendation": "Do not visit. Browsers will trigger warning interstitials.",
            "limitations": "Live query against Google Safe Browsing API."
        })

    if vt_res.get("is_listed"):
        findings.append({
            "id": "INTEL-03",
            "module": "intel",
            "title": f"Multi-Vendor Antivirus Detection ({vt_res.get('malicious_votes')} engines)",
            "severity": "critical" if vt_res.get("malicious_votes", 0) >= 5 else "high",
            "technical_evidence": vt_res,
            "impact": "Multiple commercial security vendors have independently identified this target as hostile.",
            "source": "VirusTotal v3 API",
            "confidence": 0.95,
            "recommendation": "Block and quarantine target.",
            "limitations": "Multi-engine aggregate analysis."
        })

    if openphish_res.get("is_listed"):
        findings.append({
            "id": "INTEL-04",
            "module": "intel",
            "title": "Identified in OpenPhish Intelligence Feed",
            "severity": "critical",
            "technical_evidence": openphish_res,
            "impact": "Verified active phishing target harvesting user credentials.",
            "source": "OpenPhish Community Feed",
            "confidence": 0.95,
            "recommendation": "Block domain immediately.",
            "limitations": "Correlated with OpenPhish feed dataset."
        })

    if phishtank_res.get("is_listed"):
        findings.append({
            "id": "INTEL-05",
            "module": "intel",
            "title": "Identified in PhishTank",
            "severity": "critical",
            "technical_evidence": phishtank_res,
            "impact": "The target is present in the PhishTank community-verified phishing database.",
            "source": "PhishTank API",
            "confidence": 0.95,
            "recommendation": "Avoid visiting the target or entering information.",
            "limitations": "Live lookup requires a configured PhishTank API key."
        })

    for hit in offline_hits:
        findings.append({
            "id": f"INTEL-SAMPLE-{hit.get('indicator_type', 'domain').upper()}",
            "module": "intel",
            "title": f"Matched Bundled Threat Dataset ({hit.get('threat_type')})",
            "severity": "critical",
            "technical_evidence": hit,
            "impact": f"Known hostile indicator categorized as '{hit.get('threat_type')}' from source {hit.get('source')}.",
            "source": f"ThreatLens Offline Feed ({hit.get('source')})",
            "confidence": float(hit.get("confidence", 0.95)),
            "recommendation": "Treat host as confirmed hostile indicator.",
            "limitations": "Curated offline dataset (data/threat_feed_sample.csv) for zero-network validation."
        })

    # Summary string
    summary_parts = []
    if intel_flagged:
        summary_parts.append("Threat intelligence alert: Target listed in authoritative threat database(s).")
    else:
        summary_parts.append("No active listings found across checked threat intelligence feeds.")

    result = {
        "virustotal": vt_res,
        "safe_browsing": gsb_res,
        "urlhaus": urlhaus_res,
        "openphish": openphish_res,
        "phishtank": phishtank_res,
        "offline_hits": offline_hits,
        "intel_flagged": intel_flagged,
        "summary": " ".join(summary_parts),
        "findings": findings,
        "sources": get_intelligence_source_status(),
    }

    _INTEL_CACHE[cache_key] = (result, now)
    return result
