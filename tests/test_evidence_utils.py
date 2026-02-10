"""Tests for shared evidence utility primitives."""

from __future__ import annotations

from wicap_assist.util.evidence import (
    commit_overlap_score,
    extract_tokens,
    normalize_signature,
    parse_utc_datetime,
)


def test_normalize_signature_masks_variable_tokens() -> None:
    raw = "Error 500 from 00:0D:97:00:98:AA hash deadbeefcafebabe in 123 records"
    value = normalize_signature(raw)
    assert "500" not in value
    assert "00:0d:97:00:98:aa" not in value
    assert "deadbeefcafebabe" not in value
    assert "<n>" in value
    assert "<mac>" in value
    assert "<hex>" in value


def test_extract_tokens_applies_stopwords_and_dedup() -> None:
    text = "pyodbc timeout n pyodbc hex redis timeout"
    tokens = extract_tokens(text, limit=8, stopwords={"n", "hex"})
    assert tokens == ["pyodbc", "timeout", "redis"]


def test_parse_utc_datetime_handles_soak_and_iso() -> None:
    soak = parse_utc_datetime("2026-01-30 02:52:13,585")
    iso = parse_utc_datetime("2026-01-30T02:52:13Z")
    assert soak is not None
    assert iso is not None
    assert soak.year == 2026
    assert soak.month == 1
    assert soak.day == 30


def test_commit_overlap_score_counts_hint_matches_once_each() -> None:
    files = ["src/wicap/core/processor.py", "wicap-ui/app/main.py"]
    hints = {"src/wicap/core", "wicap-ui/app", "scripts/other.py"}
    assert commit_overlap_score(files, hints) == 2
