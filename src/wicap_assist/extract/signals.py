"""Operational signal extraction for Codex response text."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.settings import codex_home, repo_url_matches_wicap
from wicap_assist.util.redact import sha1_text, to_snippet


@dataclass(slots=True)
class Signal:
    """Single extracted operational signal."""

    ts: str | None
    category: str
    fingerprint: str
    snippet: str
    extra: dict[str, Any]


_COMMAND_RE = re.compile(
    r"^(?:\$\s+.+|(?:sudo|systemctl|journalctl|apt(?:-get)?|pip(?:3)?|python(?:3)?|git|docker|ss|ip|nmcli|ls|cd)\b.*)",
    re.IGNORECASE,
)
_COMMAND_WORD_RE = re.compile(
    r"^(?:\$\s+|(?:sudo|systemctl|journalctl|apt(?:-get)?|pip(?:3)?|python(?:3)?|git|docker|ss|ip|nmcli|ls|cd)\b)",
    re.IGNORECASE,
)
_COMMAND_ANY_WORD_RE = re.compile(
    r"\b(?:sudo|systemctl|journalctl|apt(?:-get)?|pip(?:3)?|python(?:3)?|git|docker|ss|ip|nmcli|ls|cd)\b",
    re.IGNORECASE,
)
_COMMAND_REJECT_RE = re.compile(
    r"(?:\bOR\b|Return ONLY|Output format|Rules:|Task:|regex:|example:|Step\s)",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"(/home/[^\s'\"<>`]+|\./[^\s'\"<>`]+|\.\./[^\s'\"<>`]+|\b[^\s'\"<>`]+\.(?:py|json|yaml|service|log)\b)",
    re.IGNORECASE,
)
_ERROR_EXCEPTION_TOKEN_RE = re.compile(r"\b(?:[A-Za-z_]*Error|Exception)\b")
_ERROR_ERRNO_RE = re.compile(r"\b(?:ENOENT|EACCES|ECONNREFUSED|ETIMEDOUT)\b")
_ERROR_ACCEPT_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|\b(?:ENOENT|EACCES|ECONNREFUSED|ETIMEDOUT)\b|permission denied|No such file or directory|^chown:|^sudo:)",
    re.IGNORECASE,
)
_ERROR_REJECT_RE = re.compile(
    r"(?:Traceback,\s*Exception,\s*Error:|stack trace hints|regex:|Output format|Return ONLY|Rules:|Task:|Constraints:|Step\s|^\s*-\s*contains\s+\")",
    re.IGNORECASE,
)
_OUTCOME_RE = re.compile(
    r"\b(?:fixed|works now|resolved|still broken|didn't work|did not work|success|failed)\b",
    re.IGNORECASE,
)
_COMPONENT_RE = re.compile(r"\b(?:wicap|sql|redis|odbc|docker|systemd|coral|otel)\b", re.IGNORECASE)
_COMMIT_HASH_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_PATH_CONTEXT_RE = re.compile(r"\b(?:open|edit|diff|cd|cwd|file|path|log|config)\b", re.IGNORECASE)
_PROMPT_NOISE_RE = re.compile(
    r"(?:Task:|Rules:|Return ONLY|Output format|regex:|example:|Step\s|FOR EACH RECORD TYPE|wicap-assist triage)",
    re.IGNORECASE,
)
_JSONISH_RE = re.compile(r'^\s*(?:\{|\[|"[^"]+"\s*:|\}|\])')
_LIST_ONLY_PATH_RE = re.compile(
    r"^\s*(?:[-*]|\d+\.)\s*(?:/home/\S+|\./\S+|\.\./\S+|\S+\.(?:py|json|yaml|service|log))\s*$",
    re.IGNORECASE,
)


def session_gate(
    cwd: str | None,
    repo_url: str | None,
    has_wicap_text: bool,
    has_operational_signals: bool,
) -> bool:
    """Apply WICAP gate rules for a session."""
    repo_root = str(wicap_repo_root())
    if cwd and cwd.startswith(repo_root):
        return True
    if repo_url_matches_wicap(repo_url):
        return True
    return bool(has_wicap_text and has_operational_signals)


def _normalize_command_line(line: str) -> str:
    normalized = re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", line.strip())
    if normalized.startswith("`") and normalized.endswith("`") and len(normalized) > 1:
        normalized = normalized[1:-1].strip()
    return normalized


def _clean_extracted_path(path_value: str) -> str:
    cleaned = path_value.strip().strip("`'\"()[]{}<>")
    return cleaned.rstrip(".,;:!?)")


def _is_noise(line: str) -> bool:
    if not line.strip():
        return True
    if _PROMPT_NOISE_RE.search(line):
        return True
    if line.strip().startswith("FILE:"):
        return True
    if _JSONISH_RE.search(line):
        return True
    return False


def extract_operational_signals(text: str, ts: str | None = None) -> list[Signal]:
    """Extract command/path/error/outcome signals from text block."""
    results: list[Signal] = []
    seen: set[tuple[str, str]] = set()
    codex_root = str(codex_home()).rstrip("/") + "/"

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if _is_noise(raw_line):
            continue

        stripped = raw_line.strip()
        lower_stripped = stripped.lower()
        command_line = _normalize_command_line(raw_line)
        is_command = False
        if _COMMAND_RE.match(command_line) and _COMMAND_WORD_RE.match(command_line):
            if not _COMMAND_REJECT_RE.search(command_line):
                if not (
                    ("i'm" in lower_stripped or "i’m" in lower_stripped)
                    and _COMMAND_ANY_WORD_RE.search(command_line)
                ):
                    looks_like_sentence = "." in command_line and len(command_line.split()) > 8
                    starts_allowed = command_line.startswith("$ ") or command_line.lower().startswith("sudo")
                    if (not looks_like_sentence) or starts_allowed:
                        is_command = True

        path_matches = [_clean_extracted_path(match) for match in _PATH_RE.findall(stripped)]
        path_matches = [
            value
            for value in path_matches
            if value
            and not value.startswith(codex_root)
            and "sessions/YYYY/MM/DD" not in value
            and "sessions/yyyy/mm/dd" not in value
        ]
        has_path = bool(path_matches)
        has_component = bool(_COMPONENT_RE.search(stripped))

        def add(category: str, fingerprint_input: str, snippet_input: str) -> None:
            fingerprint = sha1_text(fingerprint_input)
            key = (category, fingerprint)
            if key in seen:
                return
            seen.add(key)
            results.append(
                Signal(
                    ts=ts,
                    category=category,
                    fingerprint=fingerprint,
                    snippet=to_snippet(snippet_input, max_len=200),
                    extra={"line_number": line_number},
                )
            )

        if is_command:
            add("commands", command_line, command_line)

        if has_path and not _LIST_ONLY_PATH_RE.match(stripped):
            starts_prompt_path = lower_stripped.startswith("- /home/") and not _PATH_CONTEXT_RE.search(stripped)
            has_prompt_sessions_pattern = "sessions/yyyy/mm/dd" in lower_stripped
            is_env_path_assignment = stripped.upper().startswith("PATH=")
            if not starts_prompt_path and not has_prompt_sessions_pattern and not is_env_path_assignment:
                for matched_path in path_matches:
                    add("file_paths", raw_line, matched_path)

        has_error_exception = bool(_ERROR_EXCEPTION_TOKEN_RE.search(stripped)) and (
            ":" in stripped or "(" in stripped
        )
        is_error = bool(_ERROR_ACCEPT_RE.search(stripped) or _ERROR_ERRNO_RE.search(stripped) or has_error_exception)
        if is_error and not _ERROR_REJECT_RE.search(stripped):
            add("errors", raw_line, raw_line)

        if _OUTCOME_RE.search(stripped) and (has_path or has_component or bool(_COMMIT_HASH_RE.search(stripped))):
            reject_doc_bullet = stripped.startswith("- -") and not (has_path or is_command)
            reject_fixed_real = "fixed the real" in lower_stripped and not (has_path or is_command)
            has_next_i_will = (
                "next i'll" in lower_stripped
                or "next i’ll" in lower_stripped
                or " next i'll" in lower_stripped
                or " next i’ll" in lower_stripped
            )
            first_person_meta = (
                ("i've fixed" in lower_stripped or "i’ve fixed" in lower_stripped)
                and (
                    "revalidated the tests" in lower_stripped
                    or "next " in lower_stripped
                    or "i'll " in lower_stripped
                    or "i’ll " in lower_stripped
                )
            )
            looks_like_planning = (
                lower_stripped.startswith("besides the")
                or lower_stripped.startswith("next ")
                or lower_stripped.startswith("we should")
                or lower_stripped.startswith("i will")
                or lower_stripped.startswith("i'm going to")
                or lower_stripped.startswith("i’m going to")
                or has_next_i_will
                or first_person_meta
            )
            if not reject_doc_bullet and not reject_fixed_real and not looks_like_planning:
                add("outcomes", raw_line, raw_line)

    return results
