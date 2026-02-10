"""Harness correlation helpers for playbooks, incidents, and guardian alerts."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import sqlite3
from typing import Any

_ENV_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*", re.IGNORECASE)
_RUN_CMD_RE = re.compile(r"run\s+`([^`]+)`\.?", re.IGNORECASE)
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def normalize_command(value: str) -> str:
    """Normalize command text for stable overlap checks."""
    out = _normalize_space(value.strip().strip("`").strip())
    out = out.rstrip(".")
    return out


def commands_from_steps(steps: list[str]) -> list[str]:
    """Extract concrete commands from playbook fix-step lines."""
    commands: list[str] = []
    seen: set[str] = set()

    for step in steps:
        text = step.strip()
        if not text:
            continue

        match = _RUN_CMD_RE.search(text)
        if match:
            cmd = normalize_command(match.group(1))
        else:
            backtick = _BACKTICK_RE.search(text)
            if backtick:
                cmd = normalize_command(backtick.group(1))
            else:
                cmd = normalize_command(text)

        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        commands.append(cmd)

    return commands


def _safe_json_list(raw: object) -> list[str]:
    if not isinstance(raw, str):
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


def _tool_from_command(command: str) -> str | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return None
    first = parts[0].lower()
    if first in {"sudo", "env"} and len(parts) > 1:
        return parts[1].lower()
    return first


def _tools_from_commands(commands: set[str]) -> set[str]:
    tools: set[str] = set()
    for command in commands:
        tool = _tool_from_command(command)
        if tool:
            tools.add(tool)
    return tools


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text.lower())}


def _env_from_text(texts: list[str]) -> set[str]:
    envs: set[str] = set()
    for text in texts:
        for match in _ENV_RE.findall(text):
            envs.add(match)
    return envs


def find_relevant_harness_scripts(
    conn: sqlite3.Connection,
    *,
    category: str,
    signature: str,
    fix_steps: list[str] | None = None,
    context_texts: list[str] | None = None,
    top_n: int = 3,
) -> list[dict[str, Any]]:
    """Score and return top harness script matches."""
    steps = fix_steps or []
    extra_texts = context_texts or []

    fix_commands = {normalize_command(value) for value in commands_from_steps(steps) if normalize_command(value)}
    context_tools = _tools_from_commands(fix_commands)
    context_tokens = _tokens(signature)
    context_tools.update(token for token in context_tokens if token in {"docker", "iw", "airmon-ng", "systemctl", "journalctl", "pytest"})
    context_tools.update(token for token in _tokens(" ".join(extra_texts)) if token in {"docker", "iw", "airmon-ng", "systemctl", "journalctl", "pytest"})

    context_envs = _env_from_text([signature, *steps, *extra_texts])

    category_keywords = [token for token in re.split(r"[^a-z0-9]+", category.lower()) if token]

    rows = conn.execute(
        """
        SELECT script_path, role, commands_json, tools_json, env_vars_json
        FROM harness_scripts
        ORDER BY script_path ASC
        """
    ).fetchall()

    ranked: list[dict[str, Any]] = []
    for row in rows:
        script_path = str(row["script_path"])
        role = str(row["role"])
        harness_commands = {normalize_command(value) for value in _safe_json_list(row["commands_json"]) if normalize_command(value)}
        harness_tools = {value.lower() for value in _safe_json_list(row["tools_json"])}
        harness_envs = set(_safe_json_list(row["env_vars_json"]))

        matched_commands = sorted(harness_commands & fix_commands)
        matched_tools = sorted(harness_tools & context_tools)
        matched_envs = sorted(harness_envs & context_envs)

        score = 0
        if matched_commands:
            score += 2
        if matched_tools:
            score += 2
        if matched_envs:
            score += 1
        filename = Path(script_path).name.lower()
        if any(keyword in filename for keyword in category_keywords):
            score += 1
        if role in {"runner", "cleanup"}:
            score += 1

        if score <= 0:
            continue

        ranked.append(
            {
                "script_path": script_path,
                "role": role,
                "score": score,
                "matched_commands": matched_commands,
                "matched_tools": matched_tools,
                "matched_env_vars": matched_envs,
                "commands": sorted(harness_commands),
            }
        )

    ranked.sort(
        key=lambda item: (
            -int(item["score"]),
            item["script_path"],
        )
    )
    return ranked[: max(1, int(top_n))]

