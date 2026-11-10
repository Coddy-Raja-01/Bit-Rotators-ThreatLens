"""Pluggable chat completion. Any failure returns None so the template explainer runs."""
from __future__ import annotations

import os
from typing import Optional

import requests

from backend.config import load_env

_TIMEOUT = 8.0


def get_ai_mode_status() -> dict:
    load_env()
    enabled = os.getenv("USE_EXTERNAL_AI", "false").strip().lower() in {"1", "true", "yes", "on"}
    providers = [
        ("GEMINI_API_KEY", "Gemini"),
        ("ANTHROPIC_API_KEY", "Anthropic"),
        ("OPENAI_API_KEY", "OpenAI"),
    ]
    if enabled:
        for env_key, provider_name in providers:
            if os.getenv(env_key, "").strip():
                return {"mode": "external", "provider": provider_name}
        if os.getenv("OLLAMA_HOST", "").strip():
            return {
                "mode": "ollama",
                "provider": "Ollama",
                "model": os.getenv("OLLAMA_MODEL", "llama3.2"),
            }
    return {"mode": "local", "provider": "Local deterministic engine"}


def external_ai_allowed(requested: Optional[bool]) -> bool:
    load_env()
    env_on = os.getenv("USE_EXTERNAL_AI", "false").strip().lower() in {"1", "true", "yes", "on"}
    if requested is None:
        return env_on
    return bool(requested) and env_on


def complete_json(prompt: str) -> Optional[str]:
    """Return raw model text, or None when no provider is configured or the call fails."""
    load_env()
    gemini = os.getenv("GEMINI_API_KEY", "").strip()
    anthropic = os.getenv("ANTHROPIC_API_KEY", "").strip()
    openai = os.getenv("OPENAI_API_KEY", "").strip()
    ollama = os.getenv("OLLAMA_HOST", "").strip()

    if gemini:
        text = _gemini(prompt, gemini)
        if text:
            return text
    if anthropic:
        text = _anthropic(prompt, anthropic)
        if text:
            return text
    if openai:
        text = _openai(prompt, openai)
        if text:
            return text
    if ollama:
        text = _ollama(prompt, ollama)
        if text:
            return text
    return None


def _gemini(prompt: str, key: str) -> Optional[str]:
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:generateContent"
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    try:
        resp = requests.post(url, params={"key": key}, json=body, timeout=_TIMEOUT)
        if resp.status_code != 200:
            return None
        parts = resp.json()["candidates"][0]["content"]["parts"]
        return parts[0].get("text")
    except Exception:
        return None


def _anthropic(prompt: str, key: str) -> Optional[str]:
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
                "max_tokens": 900,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        return resp.json()["content"][0]["text"]
    except Exception:
        return None


def _openai(prompt: str, key: str) -> Optional[str]:
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        return resp.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _ollama(prompt: str, host: str) -> Optional[str]:
    try:
        resp = requests.post(
            host.rstrip("/") + "/api/generate",
            json={"model": os.getenv("OLLAMA_MODEL", "llama3.2"), "prompt": prompt, "stream": False},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("response")
    except Exception:
        return None

def call_llm(prompt: str, system_prompt: str = "", json_mode: bool = True) -> tuple[Optional[str], str]:
    """
    Standard interface for LLM completion.
    Returns (raw_response_text, provider_name_or_status).
    """
    if not external_ai_allowed(None):
        return None, "local_deterministic"
    full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
    res = complete_json(full_prompt)
    if res:
        return res, "external_ai"
    return None, "local_deterministic"
