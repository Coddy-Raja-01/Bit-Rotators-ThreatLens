import json
import difflib
from pathlib import Path
from urllib.parse import urlparse

# Cyrillic / Greek to Latin homoglyph mappings
HOMOGLYPH_MAP = {
    # Cyrillic
    '\u0430': 'a', # Cyrillic small letter a
    '\u0441': 'c', # Cyrillic small letter es (c)
    '\u0435': 'e', # Cyrillic small letter ie (e)
    '\u043e': 'o', # Cyrillic small letter o
    '\u0440': 'p', # Cyrillic small letter er (p)
    '\u0455': 's', # Cyrillic small letter dze (s)
    '\u0443': 'y', # Cyrillic small letter u (y)
    '\u0445': 'x', # Cyrillic small letter ha (x)
    '\u0456': 'i', # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j', # Cyrillic small letter je
    '\u04bb': 'h', # Cyrillic small letter shha
    '\u0501': 'd', # Cyrillic small letter komi de
    # Greek
    '\u03b1': 'a', # Greek alpha
    '\u03bf': 'o', # Greek omicron
    '\u03bd': 'v', # Greek nu
    '\u03c1': 'p', # Greek rho
    '\u03c4': 't', # Greek tau
    # Digits commonly used as letters
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '5': 's',
    '8': 'b',
}

# Visual multi-character substitutions
MULTI_CHAR_CONFUSIONS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
    ("cj", "g"),
    ("l", "i"),
]

def load_brands():
    """Load canonical brand database."""
    brand_file = Path(__file__).resolve().parent.parent.parent / "data" / "brands.json"
    if brand_file.exists():
        try:
            with open(brand_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def normalize_homoglyphs(domain: str) -> tuple[str, bool, list[str]]:
    """
    Replace homoglyphic characters with their standard Latin equivalents.
    Returns (normalized_string, had_homoglyphs, list_of_detected_homoglyphs).
    """
    normalized_chars = []
    had_homoglyphs = False
    detected = []

    for char in domain:
        if char in HOMOGLYPH_MAP:
            rep = HOMOGLYPH_MAP[char]
            if ord(char) > 127: # Non-ASCII homoglyph
                had_homoglyphs = True
                detected.append(f"'{char}' (U+{ord(char):04X}) mimicking '{rep}'")
            normalized_chars.append(rep)
        else:
            normalized_chars.append(char)

    return "".join(normalized_chars), had_homoglyphs, detected

def check_lookalike(target_url_or_domain: str) -> dict:
    """
    Analyzes a domain for typosquatting, homoglyphs, and brand impersonation.
    Returns:
        {
            "is_lookalike": bool,
            "suspicious_domain": str,
            "matched_brand": str | None,
            "canonical_domain": str | None,
            "category": str | None,
            "technique": str | None,
            "similarity_score": float,
            "diff_segments": list[dict], # for highlighting
            "reasons": list[str]
        }
    """
    raw = target_url_or_domain.strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        domain = parsed.hostname or raw
    else:
        domain = raw.split("/")[0].split(":")[0]

    # Clean domain
    domain = domain.lower()
    brands = load_brands()
    
    # Check if exact canonical domain of a trusted brand
    for b in brands:
        if domain == b["canonical"] or domain == f"www.{b['canonical']}":
            return {
                "is_lookalike": False,
                "is_legitimate_brand": True,
                "suspicious_domain": domain,
                "matched_brand": b["brand"],
                "canonical_domain": b["canonical"],
                "category": b["category"],
                "technique": None,
                "similarity_score": 1.0,
                "diff_segments": [{"text": domain, "type": "match"}],
                "reasons": [f"Exact match for genuine official domain of {b['brand']}."],
                "findings": [
                    {
                        "id": "LOOK-00",
                        "module": "lookalike",
                        "title": f"Official Brand Domain ({b['brand']})",
                        "severity": "info",
                        "technical_evidence": {"canonical_domain": b["canonical"], "domain": domain},
                        "impact": "Domain matches official known authentic domain for brand.",
                        "source": "curated brand catalog (data/brands.json)",
                        "confidence": 1.0,
                        "recommendation": "Confirm TLS certificate matches brand identity.",
                        "limitations": "Catalog covers 120+ high-value brands."
                    }
                ]
            }

    # Normalize homoglyphs
    homo_normalized, had_homoglyphs, detected_homoglyphs = normalize_homoglyphs(domain)

    best_match = None
    highest_similarity = 0.0
    detected_technique = None
    specific_reasons = []

    # Check against each brand
    for b in brands:
        canonical = b["canonical"].lower()
        brand_name_slug = b["brand"].lower().replace(" ", "").replace("/", "").replace("-", "")
        canonical_base = canonical.split(".")[0]
        
        # 1. Homoglyph check
        if had_homoglyphs and (homo_normalized == canonical or homo_normalized.endswith("." + canonical)):
            similarity = 0.98
            technique = "Homoglyph spoofing (IDN character substitution)"
            reasons = [f"Uses deceptive Unicode homoglyphs: {', '.join(detected_homoglyphs)}"]
            return _build_lookalike_result(domain, b, technique, similarity, reasons)

        # 2. Multi-character visual substitutions within a hostname label.
        labels = domain.split(".")
        for label in labels[:-1]:
            for seq, rep in MULTI_CHAR_CONFUSIONS:
                if seq not in label:
                    continue
                candidate = label.replace(seq, rep)
                if _contains_brand_label(candidate, canonical_base):
                    technique = f"Visual glyph substitution ('{seq}' disguised as '{rep}')"
                    reasons = [f"Domain replaces '{rep}' with visual twin '{seq}' to impersonate {b['brand']}."]
                    return _build_lookalike_result(domain, b, technique, 0.95, reasons)

        # 3. Brand keyword embedding / squatting (e.g. paypal-security-verify.com or chase-login.net)
        domain_without_tld = domain.rsplit(".", 1)[0]
        homo_domain_without_tld = homo_normalized.rsplit(".", 1)[0]

        if (
            _contains_brand_label(domain_without_tld, canonical_base)
            or _contains_brand_label(domain_without_tld, brand_name_slug)
        ) and not domain.endswith("." + canonical):
            technique = "Brand name keyword squatting (phishing portal prefix/suffix)"
            reasons = [f"Illegitimately includes brand identity '{canonical_base}' within an unauthorized domain."]
            return _build_lookalike_result(domain, b, technique, 0.90, reasons)

        if (
            _contains_brand_label(homo_domain_without_tld, canonical_base)
            or _contains_brand_label(homo_domain_without_tld, brand_name_slug)
        ) and not homo_normalized.endswith("." + canonical):
            technique = "Homoglyph & brand keyword squatting (visual character substitution with brand embedding)"
            reasons = [f"Substitutes characters and embeds brand identity '{canonical_base}' within an unauthorized domain."]
            return _build_lookalike_result(domain, b, technique, 0.92, reasons)

        # 4. Conservative edit-distance check on the registrable-name candidate.
        base_domain = domain_without_tld.split(".")[-1]
        normalized_base_domain = homo_domain_without_tld.split(".")[-1]
        candidates = {base_domain, normalized_base_domain}
        max_edits = 1 if len(canonical_base) < 10 else 2
        close_candidates = [
            candidate for candidate in candidates
            if len(canonical_base) >= 4
            and abs(len(candidate) - len(canonical_base)) <= max_edits
            and _levenshtein_distance(candidate, canonical_base) <= max_edits
        ]
        if close_candidates:
            similarity = max(
                difflib.SequenceMatcher(None, candidate, canonical_base).ratio()
                for candidate in close_candidates
            )
            if similarity > highest_similarity:
                highest_similarity = similarity
                best_match = b
                detected_technique = "Typosquatting (character distance proximity)"
                specific_reasons = [f"Domain differs by few character edits from the genuine {b['brand']} domain."]

    if best_match and highest_similarity >= 0.75:
        return _build_lookalike_result(domain, best_match, detected_technique, highest_similarity, specific_reasons)

    return {
        "is_lookalike": False,
        "is_legitimate_brand": False,
        "suspicious_domain": domain,
        "matched_brand": None,
        "canonical_domain": None,
        "category": None,
        "technique": None,
        "similarity_score": round(highest_similarity, 3),
        "diff_segments": [{"text": domain, "type": "neutral"}],
        "reasons": [],
        "findings": []
    }

def _contains_brand_label(value: str, brand: str) -> bool:
    if not brand:
        return False
    for label in value.split("."):
        if label == brand or label.startswith(f"{brand}-") or label.endswith(f"-{brand}"):
            return True
        if f"-{brand}-" in label:
            return True
    return False


def _levenshtein_distance(first: str, second: str) -> int:
    previous = list(range(len(second) + 1))
    for row_index, first_char in enumerate(first, start=1):
        current = [row_index]
        for column_index, second_char in enumerate(second, start=1):
            current.append(min(
                current[-1] + 1,
                previous[column_index] + 1,
                previous[column_index - 1] + (first_char != second_char),
            ))
        previous = current
    return previous[-1]


def _build_lookalike_result(domain: str, brand: dict, technique: str, similarity: float, reasons: list[str]) -> dict:
    """Build structured comparison object with character-level diff segments."""
    canonical = brand["canonical"]
    
    # Generate character diff segments
    matcher = difflib.SequenceMatcher(None, canonical, domain)
    diff_segments_suspicious = []
    diff_segments_canonical = []
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        sub_can = canonical[i1:i2]
        sub_sus = domain[j1:j2]
        
        if tag == "equal":
            diff_segments_suspicious.append({"text": sub_sus, "type": "match"})
            diff_segments_canonical.append({"text": sub_can, "type": "match"})
        elif tag == "replace":
            diff_segments_suspicious.append({"text": sub_sus, "type": "diff"})
            diff_segments_canonical.append({"text": sub_can, "type": "diff"})
        elif tag == "insert":
            diff_segments_suspicious.append({"text": sub_sus, "type": "insert"})
        elif tag == "delete":
            diff_segments_canonical.append({"text": sub_can, "type": "delete"})

    finding = {
        "id": "LOOK-01",
        "module": "lookalike",
        "title": f"Lookalike Impersonation: {technique}",
        "severity": "critical" if similarity >= 0.85 else "high",
        "technical_evidence": {
            "suspicious_domain": domain,
            "target_brand": brand["brand"],
            "canonical_domain": canonical,
            "similarity_score": round(similarity, 3),
            "technique": technique
        },
        "impact": f"Tricks users into believing they are visiting {brand['brand']}, facilitating credential theft or financial fraud.",
        "source": "lookalike detector (homoglyphs/typosquatting)",
        "confidence": round(similarity, 2),
        "recommendation": f"Verify domain spelling. Legitimate domain is https://{canonical}. Do not enter sensitive info.",
        "limitations": "Detected by lexical and glyph distance matching against known brand catalogs."
    }

    return {
        "is_lookalike": True,
        "is_legitimate_brand": False,
        "suspicious_domain": domain,
        "matched_brand": brand["brand"],
        "canonical_domain": canonical,
        "category": brand["category"],
        "technique": technique,
        "similarity_score": round(similarity, 3),
        "diff_suspicious": diff_segments_suspicious,
        "diff_canonical": diff_segments_canonical,
        "reasons": reasons,
        "findings": [finding]
    }

def generate_lookalike_monitoring(brand_domain: str, max_check: int = 12) -> list[dict]:
    """
    Generate typosquat, confusable, and homoglyph variants for a brand domain,
    audit their DNS resolution and risk profile, returning a structured monitoring list.
    """
    import socket
    clean = brand_domain.lower().strip()
    if clean.startswith("http://") or clean.startswith("https://"):
        clean = urlparse(clean).hostname or clean
    clean = clean.split("/")[0].split(":")[0]

    parts = clean.split(".")
    base = parts[0]
    tld = ".".join(parts[1:]) if len(parts) > 1 else "com"

    candidates = []

    # 1. Confusable visual substitutions
    subs = [
        ("o", "0", "Digit zero substitution"),
        ("l", "1", "Digit one substitution"),
        ("m", "rn", "Multi-char visual glyph ('rn' for 'm')"),
        ("w", "vv", "Multi-char visual glyph ('vv' for 'w')"),
        ("i", "l", "Lowercase L substitution"),
        ("e", "3", "Digit three substitution"),
    ]
    for src, rep, tech in subs:
        if src in base:
            var_base = base.replace(src, rep, 1)
            candidates.append((f"{var_base}.{tld}", tech))

    # 2. Character omission
    if len(base) > 4:
        for i in range(1, len(base) - 1):
            omitted = base[:i] + base[i+1:]
            candidates.append((f"{omitted}.{tld}", "Character omission typosquat"))
            if len(candidates) >= 5:
                break

    # 3. Keyword squatting variants
    keywords = ["login", "security", "verify", "auth", "portal"]
    for kw in keywords[:3]:
        candidates.append((f"{base}-{kw}.{tld}", f"Brand keyword suffix ('-{kw}')"))
        candidates.append((f"{kw}-{base}.{tld}", f"Brand keyword prefix ('{kw}-')"))

    # 4. TLD variations
    alt_tlds = ["xyz", "top", "online", "net", "info"]
    for at in alt_tlds:
        if at != tld:
            candidates.append((f"{base}.{at}", f"Alternative TLD hijack (.{at})"))

    # Deduplicate
    seen = set()
    unique_candidates = []
    for dom, tech in candidates:
        if dom not in seen and dom != clean:
            seen.add(dom)
            unique_candidates.append((dom, tech))

    results = []
    for dom, tech in unique_candidates[:max_check]:
        seq_matcher = difflib.SequenceMatcher(None, clean, dom)
        sim = round(seq_matcher.ratio(), 3)
        
        # Check if resolves via DNS
        is_live = False
        resolved_ip = None
        try:
            addr = socket.gethostbyname(dom)
            is_live = True
            resolved_ip = addr
        except Exception:
            pass

        risk = "HIGH" if is_live else ("MEDIUM" if sim >= 0.85 else "LOW")
        results.append({
            "variant_domain": dom,
            "target_brand_domain": clean,
            "technique": tech,
            "similarity_score": sim,
            "is_live_dns": is_live,
            "resolved_ip": resolved_ip,
            "risk_level": risk
        })

    # Sort live and high-similarity first
    results.sort(key=lambda x: (x["is_live_dns"], x["similarity_score"]), reverse=True)
    return results
