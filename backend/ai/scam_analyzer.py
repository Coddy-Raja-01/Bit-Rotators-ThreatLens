import re
import io
from urllib.parse import urlparse
from backend.scanners.url_intel import normalize_url_advanced
from backend.scanners.lookalike import check_lookalike
from backend.scanners.intel import check_external_threat_intel
from backend.ai.privacy import redact_pii
from backend.ai.injection_defense import sanitize_and_wrap_untrusted_data
from backend.ai.provider import call_llm

# Regex Extractors
URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
UPI_REGEX = re.compile(r"\b[\w\.\-_]+@(?:upi|okhdfcbank|okaxis|okicici|paytm|ybl|axl|ibl|ptsbi|barodampay|postbank)\b", re.I)
CRYPTO_BTC_REGEX = re.compile(r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
CRYPTO_ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
CRYPTO_SOL_REGEX = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
ACCOUNT_REGEX = re.compile(r"\b(?:a/c|ac|account|acc)[\s:=#]+(\d{9,18})\b", re.I)

# Social Engineering Pattern Rules
SCAM_LEXICON = [
    {
        "category": "Urgency & Coercion",
        "is_proof": False, # Explicitly a signal, never proof of fraud on its own
        "points": 15,
        "patterns": [
            (re.compile(r"\b(?:immediately|immediate\s+action|within\s+24\s+hours|today\s+only|final\s+notice|last\s+chance|before\s+it\s+is\s+too\s+late)\b", re.I), "Time-pressure urgency tactic"),
            (re.compile(r"\b(?:account\s+will\s+be\s+suspended|deactivated\s+within|service\s+will\s+stop)\b", re.I), "Service termination threat")
        ]
    },
    {
        "category": "Authority Impersonation",
        "is_proof": False,
        "points": 25,
        "patterns": [
            (re.compile(r"\b(?:income\s+tax\s+department|tax\s+refund|irs\s+audit|hmrc\s+rebate)\b", re.I), "Tax authority refund/penalty impersonation"),
            (re.compile(r"\b(?:police\s+department|customs\s+enforcement|cbi\s+cyber|federal\s+investigation|arrest\s+warrant)\b", re.I), "Law enforcement extortion lure"),
            (re.compile(r"\b(?:central\s+bank|rbi|fraud\s+prevention\s+cell|security\s+division)\b", re.I), "Banking regulator impersonation")
        ]
    },
    {
        "category": "KYC & Banking Panics",
        "is_proof": True,
        "points": 30,
        "patterns": [
            (re.compile(r"\b(?:kyc\s+expired|update\s+your\s+pan|aadhaar\s+link|sim\s+will\s+be\s+blocked|card\s+locked)\b", re.I), "Mandatory KYC renewal lure"),
            (re.compile(r"\b(?:unauthorized\s+transaction\s+detected|fraudulent\s+charge\s+of\s+\$?\d+)\b", re.I), "Fake unauthorized transaction panic")
        ]
    },
    {
        "category": "Utility Disconnection Extortion",
        "is_proof": True,
        "points": 30,
        "patterns": [
            (re.compile(r"\b(?:electricity\s+(?:power\s+)?will\s+be\s+disconnected|power\s+cutoff\s+tonight|unpaid\s+electricity\s+bill)\b", re.I), "Imminent electricity cutoff extortion")
        ]
    },
    {
        "category": "Advance-Fee & Fake Job Scams",
        "is_proof": True,
        "points": 25,
        "patterns": [
            (re.compile(r"\b(?:part[- ]time\s+job|earn\s+\$?\d{2,4}\s+per\s+day|daily\s+salary\s+credited|like\s+videos\s+and\s+earn)\b", re.I), "Part-time rating/task recruitment scam"),
            (re.compile(r"\b(?:congratulations\s+you\s+won|selected\s+as\s+winner|claim\s+your\s+lottery\s+prize|free\s+gift\s+card)\b", re.I), "Deceptive lottery/sweepstakes lure")
        ]
    },
    {
        "category": "Cryptocurrency & Seed Phrase Theft",
        "is_proof": True,
        "points": 40,
        "patterns": [
            (re.compile(r"\b(?:12|24)[-\s]+word\s+(?:seed|recovery)\s+phrase\b", re.I), "Direct secret recovery phrase theft request"),
            (re.compile(r"\b(?:send\s+\d+\s*(?:btc|eth|sol)\s+(?:and\s+get|to\s+receive\s+double))\b", re.I), "Giveaway multiplier giveaway lure")
        ]
    },
    {
        "category": "Remote Desktop Installation",
        "is_proof": True,
        "points": 35,
        "patterns": [
            (re.compile(r"\b(?:install|download)\s+(?:anydesk|teamviewer|rustdesk|quicksupport|zoho\s+assist)\b", re.I), "Remote desktop software installation request")
        ]
    }
]

def extract_digital_indicators(text: str) -> dict:
    """Extracts atomic indicators from message text."""
    urls = list(set(URL_REGEX.findall(text)))
    emails = list(set(EMAIL_REGEX.findall(text)))
    phones = list(set(PHONE_REGEX.findall(text)))
    upis = list(set(UPI_REGEX.findall(text)))
    eth_wallets = list(set(CRYPTO_ETH_REGEX.findall(text)))
    btc_wallets = list(set(CRYPTO_BTC_REGEX.findall(text)))
    sol_wallets = list(set(CRYPTO_SOL_REGEX.findall(text)))
    ifscs = list(set(IFSC_REGEX.findall(text)))
    
    accounts = []
    for match in ACCOUNT_REGEX.finditer(text):
        accounts.append(match.group(1))

    return {
        "urls": urls,
        "emails": emails,
        "phone_numbers": phones,
        "upi_ids": upis,
        "crypto_wallets": {
            "ethereum": eth_wallets,
            "bitcoin": btc_wallets,
            "solana": sol_wallets
        },
        "bank_accounts": list(set(accounts)),
        "ifsc_codes": ifscs
    }

def analyze_scam_message(raw_text: str) -> dict:
    """
    Comprehensive social-engineering and scam analysis:
    1. Extracts all digital identifiers (URLs, phones, UPI, crypto wallets, accounts).
    2. Runs lexicon pattern matcher with transparent scoring.
    3. Runs extracted URLs through ThreatLens inspection pipeline.
    4. Distinguishes 'Suspicious language' from 'Verified evidence of fraud'.
    5. Returns grounded safety recommendations.
    """
    text = raw_text.strip()
    if not text:
        return {"error": "Message text is empty"}

    # 1. Prompt Injection Defense
    envelope, injection_detected, injection_sigs = sanitize_and_wrap_untrusted_data(text, label="USER_SCAM_MESSAGE")

    # 2. Extract atomic indicators
    indicators = extract_digital_indicators(text)

    # 3. Analyze social-engineering patterns
    detected_patterns = []
    suspicious_language_signals = []
    verified_fraud_evidence = []
    total_score = 0
    only_urgent_language = True

    for cat in SCAM_LEXICON:
        cat_name = cat["category"]
        is_proof = cat["is_proof"]
        points = cat["points"]
        matched_in_cat = []

        for regex, desc in cat["patterns"]:
            matches = regex.findall(text)
            if matches:
                matched_in_cat.append(desc)

        if matched_in_cat:
            total_score += points
            if is_proof:
                only_urgent_language = False
                for m in matched_in_cat:
                    verified_fraud_evidence.append(f"{cat_name}: {m}")
            else:
                for m in matched_in_cat:
                    suspicious_language_signals.append(f"{cat_name}: {m}")

            detected_patterns.append({
                "category": cat_name,
                "matches": matched_in_cat,
                "is_proof": is_proof,
                "points": points
            })

    # 4. Analyze Extracted URLs through URL and Intel pipeline
    analyzed_urls = []
    has_flagged_url = False
    for u in indicators["urls"][:3]: # Cap to first 3 URLs
        norm = normalize_url_advanced(u)
        clean_url = norm["normalized_url"]
        hostname = norm["hostname"]
        look = check_lookalike(clean_url)
        intel = check_external_threat_intel(clean_url)

        is_bad = look.get("is_lookalike", False) or intel.get("intel_flagged", False)
        if is_bad:
            has_flagged_url = True
            only_urgent_language = False
            verified_fraud_evidence.append(f"Deceptive Link Detected: {hostname} ({look.get('technique') or 'Threat Intel listed'})")

        analyzed_urls.append({
            "url": clean_url,
            "hostname": hostname,
            "is_lookalike": look.get("is_lookalike", False),
            "lookalike_brand": look.get("matched_brand"),
            "intel_flagged": intel.get("intel_flagged", False),
            "findings": norm.get("findings", []) + look.get("findings", []) + intel.get("findings", [])
        })

    # Check for direct seed phrase theft or crypto drainer indicators
    has_seed_theft = any("seed phrase" in p.lower() for p in verified_fraud_evidence)

    # 5. Determine Classification adhering to Strict Rules
    # RULE: Urgent language alone must NEVER produce 'Confirmed Malicious' and must be labelled as a signal, not proof.
    if has_flagged_url or has_seed_theft or (len(verified_fraud_evidence) >= 2 and (indicators["upi_ids"] or indicators["crypto_wallets"]["ethereum"] or indicators["crypto_wallets"]["bitcoin"])):
        classification = "Confirmed Malicious"
        verdict_color = "red"
        summary = "Confirmed fraudulent scam message. Contains explicit credential/wallet harvesting structures or verified malicious links."
    elif total_score >= 40 or len(verified_fraud_evidence) >= 1 or has_flagged_url:
        classification = "High Risk"
        verdict_color = "orange"
        summary = "High Risk: Strong social engineering patterns and impersonation indicators identified. Do not comply with requests."
    elif total_score >= 15 or len(suspicious_language_signals) >= 1:
        classification = "Suspicious"
        verdict_color = "amber"
        summary = "Suspicious: Urgent or persuasive language detected. Labelled as a behavioral signal, not proof of fraud."
    else:
        classification = "Low Risk"
        verdict_color = "green"
        summary = "Low Risk: No prominent social engineering lures or payment diversion patterns identified in this text."

    # Safety Advice
    safety_advice = [
        "Never share OTPs, passwords, or 12/24-word recovery phrases with anyone, including customer support.",
        "Legitimate banks and government agencies will never demand immediate payment via personal UPI handles or cryptocurrency.",
        "Do not download remote control software (AnyDesk, TeamViewer) at the request of unsolicited callers or messages."
    ]
    if indicators["upi_ids"]:
        safety_advice.append(f"Payment handle detected: {', '.join(indicators['upi_ids'])}. Verify recipient identity before approving any transaction.")
    if indicators["urls"]:
        safety_advice.append("Do not click links provided in urgent SMS/emails. Manually type the official address into your browser.")

    return {
        "classification": classification,
        "score": min(total_score, 100),
        "verdict_color": verdict_color,
        "summary": summary,
        "only_urgent_language": only_urgent_language,
        "suspicious_language_signals": suspicious_language_signals,
        "verified_fraud_evidence": verified_fraud_evidence,
        "detected_patterns": detected_patterns,
        "extracted_indicators": indicators,
        "analyzed_urls": analyzed_urls,
        "injection_attempt_detected": injection_detected,
        "safety_advice": safety_advice
    }

def decode_qr_code_from_bytes(image_bytes: bytes) -> str | None:
    """
    Attempts to decode a QR code from image bytes using standard computer vision or fallback.
    Returns decoded URL string if found, else None.
    """
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        # Try pyzbar if installed
        try:
            from pyzbar.pyzbar import decode
            decoded_objs = decode(img)
            for obj in decoded_objs:
                url_str = obj.data.decode("utf-8", errors="ignore").strip()
                if url_str:
                    return url_str
        except ImportError:
            pass
    except Exception:
        pass
    return None

