"""Treat page text and user messages as untrusted data, never as instructions."""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(above|system|previous)", re.I),
    re.compile(r"mark\s+this\s+(site|url|page)\s+safe", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
    re.compile(r"system\s+prompt", re.I),
    re.compile(r"override\s+(the\s+)?(score|classification|verdict)", re.I),
    re.compile(r"</\s*(system|instructions)\s*>", re.I),
]

_NEUTRALISE = re.compile(
    r"(?i)\b(ignore|disregard|override|forget)\b.{0,40}\b(instruction|prompt|system|score|safe)\b"
)


def detect_injection(text: str) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in _PATTERNS)


def neutralise(text: str) -> str:
    """Keep the words for evidence, but break imperative phrasing the model might follow."""
    if not text:
        return ""
    return _NEUTRALISE.sub("[neutralised untrusted text]", text)
