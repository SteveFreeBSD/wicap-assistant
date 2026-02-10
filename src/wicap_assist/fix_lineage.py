"""Fix lineage – trace resolution chains for failure signatures."""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import Any

from wicap_assist.util.evidence import extract_tokens


@dataclass(slots=True)
class FixAttempt:
    """A conversation's attempt to fix a signature."""
    conversation_id: str
    title: str | None
    ts_start: str | None
    ts_end: str | None
    commands: list[str]
    verification_outcomes: list[dict[str, Any]]
    relevance_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "title": self.title,
            "ts_start": self.ts_start,
            "ts_end": self.ts_end,
            "commands": self.commands,
            "verification_outcomes": self.verification_outcomes,
            "relevance_score": self.relevance_score,
        }

def resolve_fix_lineage(
    conn: sqlite3.Connection,
    signature: str,
    limit: int = 10,
) -> list[FixAttempt]:
    """Find past conversations that addressed this signature."""
    tokens = extract_tokens(signature, limit=8)
    if not tokens:
        return []

    # Find conversations with relevant signals
    # We look for signal snippets matching ANY token, but we'll score them later
    where = " OR ".join("lower(cs.snippet) LIKE ?" for _ in tokens)
    args: list[Any] = [f"%{token}%" for token in tokens]

    # First get candidate conversation PKs
    rows = conn.execute(
        f"""
        SELECT DISTINCT c.id, c.conversation_id, c.title, c.ts_first, c.ts_last
        FROM conversation_signals AS cs
        JOIN conversations AS c ON c.id = cs.conversation_pk
        WHERE ({where})
        ORDER BY c.ts_last DESC
        LIMIT ?
        """,
        args + [limit * 2],  # Fetch more candidates for scoring
    ).fetchall()

    attempts: list[FixAttempt] = []
    
    for row in rows:
        conv_pk = row["id"]
        
        # Get all signals for this conversation to compute relevance and extract commands
        signals = conn.execute(
            """
            SELECT category, snippet
            FROM conversation_signals
            WHERE conversation_pk = ?
            ORDER BY ts ASC
            """,
            (conv_pk,),
        ).fetchall()

        # Score relevance: token overlap count / total tokens
        match_count = 0
        commands: list[str] = []
        
        for sig in signals:
            snippet_lower = str(sig["snippet"]).lower()
            if any(t in snippet_lower for t in tokens):
                match_count += 1
            
            if sig["category"] in {"command", "commands"}:
                cmd = str(sig["snippet"]).strip()
                if cmd and cmd not in commands: # simple dedup
                    commands.append(cmd)

        relevance = match_count / (len(tokens) + 1.0) # Simple heuristic
        if relevance < 0.1:
            continue

        # Get verification outcomes
        outcomes_rows = conn.execute(
            """
            SELECT outcome, ts, evidence_snippet
            FROM verification_outcomes
            WHERE conversation_pk = ?
            ORDER BY ts ASC
            """,
            (conv_pk,),
        ).fetchall()
        
        outcomes = [
            {
                "outcome": row["outcome"],
                "ts": row["ts"],
                "evidence": row["evidence_snippet"],
            }
            for row in outcomes_rows
        ]

        attempts.append(FixAttempt(
            conversation_id=row["conversation_id"],
            title=row["title"],
            ts_start=row["ts_first"],
            ts_end=row["ts_last"],
            commands=commands[:10], # limit command noise
            verification_outcomes=outcomes,
            relevance_score=round(relevance, 2),
        ))

    # Sort solely by recency (assuming rows generally returned that way, but let's be sure)
    # Actually, simpler to just rely on initial query sorting + Python stable sort if needed.
    attempts.sort(key=lambda x: x.ts_end or "", reverse=True)
    
    return attempts[:limit]


def format_fix_lineage_text(attempts: list[FixAttempt]) -> str:
    """Render lineage chain as text."""
    if not attempts:
        return "No fix lineage found for this signature."

    lines = ["=== Fix Lineage: Resolution History ===", ""]
    
    for attempt in attempts:
        lines.append(f"Conversation: {attempt.conversation_id}")
        lines.append(f"  Title: {attempt.title or '(no title)'}")
        lines.append(f"  Time: {attempt.ts_start} -> {attempt.ts_end}")
        lines.append(f"  Relevance: {attempt.relevance_score}")
        
        if attempt.commands:
            lines.append("  Commands:")
            for cmd in attempt.commands:
                lines.append(f"    $ {cmd}")
        else:
            lines.append("  Commands: (none recorded)")

        if attempt.verification_outcomes:
            lines.append("  Verification:")
            for outcome in attempt.verification_outcomes:
                lines.append(f"    [{outcome['outcome'].upper()}] {outcome['evidence']}")
        else:
            lines.append("  Verification: (none)")
            
        lines.append("---")

    return "\n".join(lines)


def fix_lineage_to_json(attempts: list[FixAttempt]) -> str:
    """Encode lineage chain as JSON."""
    return json.dumps([a.to_dict() for a in attempts], indent=2)
