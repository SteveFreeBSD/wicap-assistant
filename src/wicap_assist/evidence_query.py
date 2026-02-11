"""Shared SQL query helpers for tokenized evidence correlation."""

from __future__ import annotations

import sqlite3
from typing import Any

from wicap_assist.util.evidence import extract_tokens

_DEFAULT_STOPWORDS = {"n", "hex", "mac"}


def signature_tokens(signature: str, *, limit: int = 8) -> list[str]:
    return extract_tokens(signature, limit=limit, stopwords=_DEFAULT_STOPWORDS)


def where_like(column_sql: str, tokens: list[str]) -> tuple[str, list[str]]:
    if not tokens:
        return "", []
    where = " OR ".join(f"lower({column_sql}) LIKE ?" for _ in tokens)
    args = [f"%{token}%" for token in tokens]
    return where, args


def query_related_session_ids(
    conn: sqlite3.Connection,
    signature: str,
    *,
    limit: int = 50,
) -> list[str]:
    tokens = signature_tokens(signature, limit=8)
    where, args = where_like("sg.snippet", tokens)
    if not where:
        return []
    rows = conn.execute(
        f"""
        SELECT
            s.session_id,
            max(coalesce(sg.ts, s.ts_last, '')) AS sort_ts
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE s.is_wicap = 1
          AND ({where})
        GROUP BY s.session_id
        ORDER BY sort_ts DESC, s.session_id ASC
        LIMIT ?
        """,
        [*args, max(1, int(limit))],
    ).fetchall()
    return [str(row["session_id"]) for row in rows if str(row["session_id"]).strip()]


def query_recent_related_session(
    conn: sqlite3.Connection,
    signature: str,
) -> tuple[str | None, str | None]:
    tokens = signature_tokens(signature, limit=6)
    where, args = where_like("sg.snippet", tokens)
    if not where:
        return None, None
    rows = conn.execute(
        f"""
        SELECT s.session_id, s.ts_last
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE s.is_wicap = 1
          AND sg.category IN ('errors', 'commands', 'file_paths', 'outcomes')
          AND ({where})
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        LIMIT 1
        """,
        args,
    ).fetchall()
    if not rows:
        return None, None
    row = rows[0]
    return str(row["session_id"]), str(row["ts_last"]) if row["ts_last"] is not None else None


def query_verification_track_record(
    conn: sqlite3.Connection,
    signature: str,
) -> dict[str, Any] | None:
    tokens = signature_tokens(signature, limit=6)
    where, args = where_like("signature", tokens)
    if not where:
        return None
    rows = conn.execute(
        f"""
        SELECT outcome, ts
        FROM verification_outcomes
        WHERE {where}
        ORDER BY coalesce(ts, '') ASC
        """,
        args,
    ).fetchall()
    if not rows:
        return None

    passes = 0
    fails = 0
    unknowns = 0
    seen_pass = False
    relapse = False
    for row in rows:
        outcome = str(row["outcome"]).strip().lower()
        if outcome == "pass":
            passes += 1
            seen_pass = True
        elif outcome == "fail":
            fails += 1
            if seen_pass:
                relapse = True
        else:
            unknowns += 1

    positive = min(2, passes)
    negative = min(4, fails * 2)
    net_effect = positive - negative
    return {
        "passes": int(passes),
        "fails": int(fails),
        "unknowns": int(unknowns),
        "relapse_detected": bool(relapse),
        "net_confidence_effect": int(net_effect),
    }
