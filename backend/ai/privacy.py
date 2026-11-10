import os
import re

# PII Detection and Redaction RegExes
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b")
OTP_REGEX = re.compile(r"(?:code|otp|pin|verification\s+code)[\s:=]+(\b\d{4,8}\b)", re.I)
TOKEN_REGEX = re.compile(r"\b(?:Bearer\s+|key-|sk-|pk-|api-)[A-Za-z0-9_\-\.]{16,}\b", re.I)
ACCOUNT_REGEX = re.compile(r"\b(?:ac|a/c|account\s+no\.?|account\s+number)[\s:=]+(\d{9,18})\b", re.I)

def is_external_ai_enabled() -> bool:
    """Check if external AI egress is permitted by user configuration."""
    flag = os.getenv("USE_EXTERNAL_AI", "false").strip().lower()
    return flag in ("1", "true", "yes", "on")

def redact_pii(text: str) -> str:
    """
    Sanitizes message or text before transmission to external AI services.
    Redacts emails, phone numbers, credit card numbers, OTPs, account numbers, and tokens.
    """
    if not text:
        return ""

    sanitized = text

    # Redact tokens
    sanitized = TOKEN_REGEX.sub("[REDACTED_TOKEN]", sanitized)

    # Redact credit/debit cards
    sanitized = CARD_REGEX.sub("[REDACTED_CARD]", sanitized)

    # Redact OTPs
    def replace_otp(match):
        full = match.group(0)
        otp = match.group(1)
        return full.replace(otp, "[REDACTED_OTP]")
    sanitized = OTP_REGEX.sub(replace_otp, sanitized)

    # Redact Bank Accounts
    def replace_acc(match):
        full = match.group(0)
        acc = match.group(1)
        return full.replace(acc, "[REDACTED_ACCOUNT]")
    sanitized = ACCOUNT_REGEX.sub(replace_acc, sanitized)

    # Redact emails
    sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)

    # Redact phone numbers
    sanitized = PHONE_REGEX.sub("[REDACTED_PHONE]", sanitized)

    return sanitized

