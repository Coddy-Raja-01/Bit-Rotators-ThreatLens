"""Strip personal data before any text leaves the process for an external model."""
from __future__ import annotations

import re

_EMAIL = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\-\s().]{7,}\d)")
_CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_OTP = re.compile(r"\b(?:otp|code|pin)\s*[:#-]?\s*\d{4,8}\b", re.I)
_TOKEN = re.compile(r"\b(?:sk|pk|api|bearer|tok)[-_][A-Za-z0-9_\-]{12,}\b", re.I)
_NAME_LINE = re.compile(r"\b(?:my name is|i am|this is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})")


def redact(text: str) -> str:
    if not text:
        return ""
    out = _EMAIL.sub("[redacted-email]", text)
    out = _CARD.sub("[redacted-number]", out)
    out = _OTP.sub("[redacted-otp]", out)
    out = _TOKEN.sub("[redacted-token]", out)
    out = _PHONE.sub("[redacted-phone]", out)
    out = _NAME_LINE.sub(lambda m: m.group(0).split()[0] + " [redacted-name]", out)
    return out
