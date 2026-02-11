"""CHANGELOG.md ingestion for WICAP assistant."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3

from wicap_assist.config import wicap_changelog_path
from wicap_assist.db import (
    delete_changelog_entries_for_source,
    get_source,
    upsert_changelog_entry,
    upsert_source,
)
from wicap_assist.util.redact import sha1_text, to_snippet

WICAP_CHANGELOG = wicap_changelog_path()

_RELEASE_RE = re.compile(r"^##\s+\[(.+?)\]")
_SECTION_RE = re.compile(r"^###\s+(Added|Fixed|Changed)\b", re.IGNORECASE)
_ENTRY_RE = re.compile(r"^\s*-\s+\*\*(.+?)\*\*[:\s]+(.+)")
_ENTRY_PLAIN_RE = re.compile(r"^\s*-\s+(.+)")


@dataclass(slots=True)
class ChangelogEntry:
    """One parsed changelog entry."""

    release_tag: str
    section: str
    snippet: str
    fingerprint: str


def parse_changelog(text: str) -> list[ChangelogEntry]:
    """Parse CHANGELOG markdown into structured entries."""
    entries: list[ChangelogEntry] = []
    current_release: str | None = None
    current_section: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Check for release heading
        release_match = _RELEASE_RE.match(stripped)
        if release_match:
            current_release = release_match.group(1).strip()
            current_section = None
            continue

        # Check for section heading
        section_match = _SECTION_RE.match(stripped)
        if section_match:
            current_section = section_match.group(1).strip().lower()
            continue

        if current_release is None or current_section is None:
            continue

        # Check for entry line
        entry_match = _ENTRY_RE.match(line)
        if entry_match:
            snippet_text = f"{entry_match.group(1)}: {entry_match.group(2)}"
        else:
            plain_match = _ENTRY_PLAIN_RE.match(line)
            if plain_match:
                snippet_text = plain_match.group(1)
            else:
                continue

        snippet = to_snippet(snippet_text.strip(), max_len=300)
        fingerprint = sha1_text(f"{current_release}:{current_section}:{snippet}")

        entries.append(ChangelogEntry(
            release_tag=current_release,
            section=current_section,
            snippet=snippet,
            fingerprint=fingerprint,
        ))

    return entries


def ingest_changelog(
    conn: sqlite3.Connection,
    changelog_path: Path = WICAP_CHANGELOG,
) -> tuple[int, int]:
    """Ingest CHANGELOG.md entries into SQLite.

    Returns (1, entries_added) on success or (0, 0) if file not found.
    """
    if not changelog_path.exists():
        return 0, 0

    stat = changelog_path.stat()
    source_path = str(changelog_path)
    source_row = get_source(conn, source_path)

    if source_row is not None:
        if (
            float(source_row["mtime"]) == float(stat.st_mtime)
            and int(source_row["size"]) == int(stat.st_size)
        ):
            return 1, 0

    source_id = upsert_source(
        conn,
        kind="changelog",
        path=source_path,
        mtime=stat.st_mtime,
        size=stat.st_size,
    )

    delete_changelog_entries_for_source(conn, source_id)

    text = changelog_path.read_text(encoding="utf-8", errors="replace")
    entries = parse_changelog(text)
    entries_added = 0

    for entry in entries:
        was_inserted = upsert_changelog_entry(
            conn,
            source_id=source_id,
            release_tag=entry.release_tag,
            section=entry.section,
            snippet=entry.snippet,
            fingerprint=entry.fingerprint,
        )
        if was_inserted:
            entries_added += 1

    return 1, entries_added
