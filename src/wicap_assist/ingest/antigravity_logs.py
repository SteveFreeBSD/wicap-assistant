"""Antigravity conversation artifact ingestion for WICAP assistant."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any

from wicap_assist.db import (
    delete_conversation_signals,
    delete_verification_outcomes_for_conversation,
    get_source,
    insert_conversation,
    insert_conversation_signal,
    insert_verification_outcome,
    upsert_source,
)
from wicap_assist.extract.signals import extract_operational_signals
from wicap_assist.settings import codex_home
from wicap_assist.util.redact import sha1_text, to_snippet

_DEFAULT_ANTIGRAVITY_ROOT = Path.home() / ".gemini" / "antigravity" / "brain"

_ARTIFACT_NAMES = ("task.md", "walkthrough.md", "implementation_plan.md")
_METADATA_SUFFIX = ".metadata.json"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_CHECKLIST_DONE_RE = re.compile(r"^\s*-\s*\[x\]\s+(.+)", re.IGNORECASE)
_CHECKLIST_PENDING_RE = re.compile(r"^\s*-\s*\[\s?\]\s+(.+)")
_CHECKLIST_INPROGRESS_RE = re.compile(r"^\s*-\s*\[/\]\s+(.+)")
_TEST_RESULT_RE = re.compile(
    r"(\d+)\s+passed(?:.*?(\d+)\s+(?:skipped|failed|error))?",
    re.IGNORECASE,
)
_RENDER_DIFFS_RE = re.compile(r"render_diffs\(file:///(.+?)\)")
_H1_RE = re.compile(r"^#\s+(.+)")
_VERIFY_PASS_RE = re.compile(
    r"\b(?:pass|passed|all\s+tests?\s+passed|soak\s+clean|verified|success(?:ful(?:ly)?)?|fixed|resolved)\b",
    re.IGNORECASE,
)
_VERIFY_FAIL_RE = re.compile(
    r"\b(?:fail|failed|still\s+broken|still\s+fail\w*|regression|broke\w*|did\s+not\s+work|didn't\s+work)\b",
    re.IGNORECASE,
)
_WICAP_GATE_RE = re.compile(r"\bwicap\b", re.IGNORECASE)
_WICAP_CWD_RE = re.compile(r"/[^\s]*/wicap(?:/|\b)", re.IGNORECASE)
_WICAP_REPO_RE = re.compile(r"stevefreebsd/wicap", re.IGNORECASE)


@dataclass(slots=True)
class ConversationSignal:
    """Single signal extracted from a conversation artifact."""

    ts: str | None
    category: str
    fingerprint: str
    snippet: str
    artifact_name: str
    extra: dict[str, Any]


@dataclass(slots=True)
class VerificationOutcome:
    """Parsed verification outcome from a walkthrough."""

    signature: str
    outcome: str  # "pass" | "fail" | "unknown"
    evidence_snippet: str
    ts: str | None


@dataclass(slots=True)
class ParsedConversation:
    """Parsed conversation from Antigravity brain directory."""

    conversation_id: str
    title: str | None
    ts_first: str | None
    ts_last: str | None
    task_summary: str | None
    artifact_type: str | None
    dir_path: str
    signals: list[ConversationSignal] = field(default_factory=list)
    verification_outcomes: list[VerificationOutcome] = field(default_factory=list)


def antigravity_root() -> Path:
    """Resolve antigravity artifact root from env with portable defaults."""
    explicit = os.environ.get("WICAP_ASSIST_ANTIGRAVITY_ROOT", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    legacy = os.environ.get("ANTIGRAVITY_ROOT", "").strip()
    if legacy:
        return Path(legacy).expanduser()

    codex_based = codex_home() / "antigravity" / "brain"
    if codex_based.exists():
        return codex_based
    return _DEFAULT_ANTIGRAVITY_ROOT


def scan_antigravity_paths(root: Path | None = None) -> list[Path]:
    """List conversation directories containing at least one markdown artifact."""
    resolved_root = root if root is not None else antigravity_root()
    if not resolved_root.is_dir():
        return []

    results: list[Path] = []
    for child in sorted(resolved_root.iterdir()):
        if not child.is_dir():
            continue
        if not _UUID_RE.match(child.name):
            continue
        if any((child / name).exists() for name in _ARTIFACT_NAMES):
            results.append(child)
    return results


def _read_text_safe(path: Path) -> str:
    """Read text file with UTF-8, replacing errors."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_title(text: str) -> str | None:
    """Extract the first H1 heading from markdown."""
    for line in text.splitlines():
        match = _H1_RE.match(line.strip())
        if match:
            return match.group(1).strip()
    return None


def _load_metadata_timestamps(conv_dir: Path) -> tuple[str | None, str | None]:
    """Extract earliest and latest updatedAt from metadata JSON files."""
    timestamps: list[str] = []
    for path in conv_dir.iterdir():
        if not path.name.endswith(_METADATA_SUFFIX):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ts = data.get("updatedAt")
        if isinstance(ts, str) and ts.strip():
            timestamps.append(ts.strip())

    if not timestamps:
        return None, None
    timestamps.sort()
    return timestamps[0], timestamps[-1]


def _extract_checklist_signals(
    text: str, artifact_name: str, ts: str | None
) -> list[ConversationSignal]:
    """Extract completed/pending/in-progress checklist items as signals."""
    signals: list[ConversationSignal] = []
    seen: set[str] = set()

    for line in text.splitlines():
        match = _CHECKLIST_DONE_RE.match(line)
        if match:
            item = match.group(1).strip()
            fp = sha1_text(f"completed_task:{item}")
            if fp not in seen:
                seen.add(fp)
                signals.append(ConversationSignal(
                    ts=ts, category="completed_task", fingerprint=fp,
                    snippet=to_snippet(item, max_len=200),
                    artifact_name=artifact_name, extra={},
                ))
            continue

        match = _CHECKLIST_INPROGRESS_RE.match(line)
        if match:
            item = match.group(1).strip()
            fp = sha1_text(f"in_progress_task:{item}")
            if fp not in seen:
                seen.add(fp)
                signals.append(ConversationSignal(
                    ts=ts, category="in_progress_task", fingerprint=fp,
                    snippet=to_snippet(item, max_len=200),
                    artifact_name=artifact_name, extra={},
                ))
            continue

        match = _CHECKLIST_PENDING_RE.match(line)
        if match:
            item = match.group(1).strip()
            fp = sha1_text(f"pending_task:{item}")
            if fp not in seen:
                seen.add(fp)
                signals.append(ConversationSignal(
                    ts=ts, category="pending_task", fingerprint=fp,
                    snippet=to_snippet(item, max_len=200),
                    artifact_name=artifact_name, extra={},
                ))

    return signals


def _extract_test_result_signals(
    text: str, artifact_name: str, ts: str | None
) -> list[ConversationSignal]:
    """Extract test result lines (e.g. '424 passed, 21 skipped')."""
    signals: list[ConversationSignal] = []
    seen: set[str] = set()

    for line in text.splitlines():
        match = _TEST_RESULT_RE.search(line)
        if match:
            snippet = to_snippet(line.strip(), max_len=200)
            fp = sha1_text(f"test_result:{snippet}")
            if fp not in seen:
                seen.add(fp)
                extra: dict[str, Any] = {"passed": int(match.group(1))}
                if match.group(2):
                    extra["other"] = int(match.group(2))
                signals.append(ConversationSignal(
                    ts=ts, category="test_result", fingerprint=fp,
                    snippet=snippet, artifact_name=artifact_name, extra=extra,
                ))

    return signals


def _extract_file_changed_signals(
    text: str, artifact_name: str, ts: str | None
) -> list[ConversationSignal]:
    """Extract render_diffs() references as file_changed signals."""
    signals: list[ConversationSignal] = []
    seen: set[str] = set()

    for match in _RENDER_DIFFS_RE.finditer(text):
        file_path = match.group(1)
        fp = sha1_text(f"file_changed:{file_path}")
        if fp not in seen:
            seen.add(fp)
            signals.append(ConversationSignal(
                ts=ts, category="file_changed", fingerprint=fp,
                snippet=to_snippet(file_path, max_len=200),
                artifact_name=artifact_name, extra={},
            ))

    return signals


def _extract_verification_outcomes(
    text: str, ts: str | None
) -> list[VerificationOutcome]:
    """Extract verification outcomes from walkthrough text."""
    outcomes: list[VerificationOutcome] = []
    seen: set[str] = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        has_pass = bool(_VERIFY_PASS_RE.search(stripped))
        has_fail = bool(_VERIFY_FAIL_RE.search(stripped))
        outcome: str | None = None
        if has_fail:
            outcome = "fail"
        elif has_pass:
            outcome = "pass"

        if outcome is None:
            continue

        # Build a signature from the line content
        signature = to_snippet(stripped, max_len=200)
        key = f"{outcome}:{signature}"
        if key in seen:
            continue
        seen.add(key)

        outcomes.append(VerificationOutcome(
            signature=signature,
            outcome=outcome,
            evidence_snippet=to_snippet(stripped, max_len=200),
            ts=ts,
        ))

    return outcomes


def _extract_metadata_strings(value: Any) -> list[str]:
    """Flatten metadata JSON content into string values for gate checks."""
    out: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            out.extend(_extract_metadata_strings(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(_extract_metadata_strings(item))
    elif isinstance(value, str):
        out.append(value)
    return out


def _load_metadata_gate_strings(conv_dir: Path) -> list[str]:
    """Load metadata files and flatten all string fields used for gating."""
    values: list[str] = []
    for path in conv_dir.iterdir():
        if not path.name.endswith(_METADATA_SUFFIX):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        values.extend(_extract_metadata_strings(payload))
    return values


def _conversation_gate(texts: list[str], metadata_strings: list[str]) -> bool:
    """Return True if conversation is WICAP-related by cwd/repo/tag gate."""
    combined = [*texts, *metadata_strings]

    for value in combined:
        if _WICAP_CWD_RE.search(value):
            return True
        if _WICAP_REPO_RE.search(value):
            return True

    for text in texts:
        if _WICAP_GATE_RE.search(text):
            return True
    return False


def parse_conversation_dir(conv_dir: Path) -> ParsedConversation | None:
    """Parse one Antigravity conversation directory into a ParsedConversation.

    Returns None if the conversation is not WICAP-related.
    """
    conversation_id = conv_dir.name
    ts_first, ts_last = _load_metadata_timestamps(conv_dir)

    # Read all artifact texts
    artifact_texts: dict[str, str] = {}
    for name in _ARTIFACT_NAMES:
        path = conv_dir / name
        if path.exists():
            artifact_texts[name] = _read_text_safe(path)

    if not artifact_texts:
        return None

    # Apply WICAP gate
    metadata_gate_strings = _load_metadata_gate_strings(conv_dir)
    if not _conversation_gate(list(artifact_texts.values()), metadata_gate_strings):
        return None

    # Extract title from task.md (preferred) or first available artifact
    title: str | None = None
    task_summary: str | None = None
    artifact_type: str | None = None

    task_text = artifact_texts.get("task.md", "")
    if task_text:
        title = _extract_title(task_text)
        task_summary = to_snippet(task_text, max_len=500)
        artifact_type = "task"

    if title is None:
        for name, text in artifact_texts.items():
            title = _extract_title(text)
            if title:
                artifact_type = name.replace(".md", "")
                break

    # Load metadata for artifact type if available
    meta_path = conv_dir / "task.md.metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_type = meta.get("artifactType", "")
            if isinstance(raw_type, str) and raw_type.strip():
                artifact_type = raw_type.strip()
        except (OSError, json.JSONDecodeError):
            pass

    # Extract signals from all artifacts
    all_signals: list[ConversationSignal] = []
    all_outcomes: list[VerificationOutcome] = []
    seen_fps: set[tuple[str, str]] = set()

    for artifact_name, text in artifact_texts.items():
        # Structured signals
        all_signals.extend(_extract_checklist_signals(text, artifact_name, ts_last))
        all_signals.extend(_extract_test_result_signals(text, artifact_name, ts_last))
        all_signals.extend(_extract_file_changed_signals(text, artifact_name, ts_last))

        # Operational signals (errors, commands, paths, outcomes)
        for op_signal in extract_operational_signals(text, ts=ts_last):
            fp_key = (op_signal.category, op_signal.fingerprint)
            if fp_key in seen_fps:
                continue
            seen_fps.add(fp_key)
            all_signals.append(ConversationSignal(
                ts=op_signal.ts,
                category=op_signal.category,
                fingerprint=op_signal.fingerprint,
                snippet=op_signal.snippet,
                artifact_name=artifact_name,
                extra=op_signal.extra,
            ))

        # Verification outcomes (from walkthrough only)
        if artifact_name == "walkthrough.md":
            all_outcomes.extend(_extract_verification_outcomes(text, ts_last))

    return ParsedConversation(
        conversation_id=conversation_id,
        title=title,
        ts_first=ts_first,
        ts_last=ts_last,
        task_summary=task_summary,
        artifact_type=artifact_type,
        dir_path=str(conv_dir),
        signals=all_signals,
        verification_outcomes=all_outcomes,
    )


def _is_unchanged_source(
    row: sqlite3.Row | None, *, mtime: float, size: int
) -> bool:
    """Check if source is unchanged since last ingest."""
    if row is None:
        return False
    return float(row["mtime"]) == float(mtime) and int(row["size"]) == int(size)


def _dir_mtime_and_size(conv_dir: Path) -> tuple[float, int]:
    """Compute aggregate mtime and size for a conversation directory."""
    max_mtime = 0.0
    total_size = 0
    for name in _ARTIFACT_NAMES:
        path = conv_dir / name
        if path.exists():
            stat = path.stat()
            max_mtime = max(max_mtime, stat.st_mtime)
            total_size += stat.st_size
        # Also check metadata files
        meta = conv_dir / f"{name}{_METADATA_SUFFIX}"
        if meta.exists():
            stat = meta.stat()
            max_mtime = max(max_mtime, stat.st_mtime)
            total_size += stat.st_size
    return max_mtime, total_size


def ingest_antigravity_logs(
    conn: sqlite3.Connection,
    root: Path | None = None,
) -> tuple[int, int, int, int]:
    """Ingest Antigravity conversation artifacts.

    Returns (dirs_seen, conversations_added, signals_added, verification_outcomes_added).
    """
    dirs = scan_antigravity_paths(root=root)
    conversations_added = 0
    signals_added = 0
    verification_outcomes_added = 0

    for conv_dir in dirs:
        mtime, size = _dir_mtime_and_size(conv_dir)
        source_path = str(conv_dir)
        source_row = get_source(conn, source_path)

        if _is_unchanged_source(source_row, mtime=mtime, size=size):
            continue

        parsed = parse_conversation_dir(conv_dir)
        if parsed is None:
            continue

        source_id = upsert_source(
            conn,
            kind="antigravity",
            path=source_path,
            mtime=mtime,
            size=size,
        )

        conv_pk, inserted = insert_conversation(
            conn,
            source_id=source_id,
            conversation_id=parsed.conversation_id,
            title=parsed.title,
            ts_first=parsed.ts_first,
            ts_last=parsed.ts_last,
            task_summary=parsed.task_summary,
            artifact_type=parsed.artifact_type,
        )
        if inserted:
            conversations_added += 1

        # Clear and re-insert signals
        delete_conversation_signals(conn, conv_pk)
        delete_verification_outcomes_for_conversation(conn, conv_pk)

        for signal in parsed.signals:
            was_inserted = insert_conversation_signal(
                conn,
                conversation_pk=conv_pk,
                ts=signal.ts,
                category=signal.category,
                fingerprint=signal.fingerprint,
                snippet=signal.snippet,
                artifact_name=signal.artifact_name,
                extra_json=signal.extra,
            )
            if was_inserted:
                signals_added += 1

        for outcome in parsed.verification_outcomes:
            inserted = insert_verification_outcome(
                conn,
                conversation_pk=conv_pk,
                signature=outcome.signature,
                outcome=outcome.outcome,
                evidence_snippet=outcome.evidence_snippet,
                ts=outcome.ts,
            )
            if inserted:
                verification_outcomes_added += 1

    return len(dirs), conversations_added, signals_added, verification_outcomes_added
