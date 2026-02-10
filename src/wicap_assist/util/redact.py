"""Redaction utilities for operational snippets."""

from __future__ import annotations

import hashlib
import re

_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|connection[_-]?string|connstr|dsn)\s*[:=]\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_URL_CRED_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@")
_ENV_SECRET_RE = re.compile(
    r"\b([A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)[A-Z0-9_]*)=([^\s]+)",
    re.IGNORECASE,
)


def redact_text(text: str) -> str:
    """Redact common secret/token patterns from text."""
    redacted = _SECRET_KV_RE.sub(r"\1=<redacted>", text)
    redacted = _BEARER_RE.sub(r"\1 <redacted>", redacted)
    redacted = _URL_CRED_RE.sub(r"\1<redacted>@", redacted)
    redacted = _ENV_SECRET_RE.sub(r"\1=<redacted>", redacted)
    return redacted


def to_snippet(text: str, max_len: int = 200) -> str:
    """Return a short redacted snippet with a stable max length."""
    return redact_text(text.strip())[:max_len]


def sha1_text(text: str) -> str:
    """SHA1 fingerprint for full matched source line."""
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()
