"""Shared evidence normalization and matching helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Iterable

from wicap_assist.util.time import to_iso

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*", re.IGNORECASE)
_HEX_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\b\d+\b")


def normalize_signature(snippet: str, *, max_len: int = 120) -> str:
    """Normalize event snippet for stable clustering and joins."""
    value = snippet.lower()
    value = _HEX_RE.sub("<hex>", value)
    value = _MAC_RE.sub("<mac>", value)
    value = _NUMBER_RE.sub("<n>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:max_len]


def extract_tokens(
    text: str,
    *,
    limit: int = 8,
    min_len: int = 4,
    stopwords: Iterable[str] | None = None,
) -> list[str]:
    """Extract distinct lowercase tokens for fuzzy evidence matching."""
    stop = {word.lower() for word in (stopwords or ())}
    out: list[str] = []
    seen: set[str] = set()

    for token in _TOKEN_RE.findall(text.lower()):
        if token in stop:
            continue
        if len(token) < min_len:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= limit:
            break
    return out


def parse_utc_datetime(value: object) -> datetime | None:
    """Parse common timestamp shapes to timezone-aware UTC datetime."""
    iso = to_iso(value)
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def commit_overlap_score(commit_files: list[str], path_hints: set[str]) -> int:
    """Score file-path overlap between a commit and inferred path hints."""
    if not commit_files or not path_hints:
        return 0

    score = 0
    for hint in path_hints:
        for changed in commit_files:
            if changed == hint or changed.startswith(hint) or hint.startswith(changed):
                score += 1
                break
    return score

