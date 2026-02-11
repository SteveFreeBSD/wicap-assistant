"""Static harness script inventory ingestion."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
import re
import shlex
import sqlite3

from wicap_assist.config import wicap_repo_root
from wicap_assist.db import upsert_harness_script

_INCLUDE_PATTERNS = (
    "*soak*.py",
    "*runner*.py",
    "*harness*.py",
    "*soak*.sh",
    "*runner*.sh",
    "*harness*.sh",
)
_INCLUDE_NAMES = {
    "start_wicap.py",
    "stop_wicap.py",
    "run_soak.sh",
    "run_docker_soak.sh",
    "run_live_verification.sh",
}
_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
}

_CLEANUP_RE = re.compile(
    r"\b(?:cleanup|remove|unlink|rmtree|rm\s+-f|docker\s+rm|docker\s+stop|kill|pkill|pid)\b",
    re.IGNORECASE,
)
_SETUP_RE = re.compile(
    r"\b(?:setup|init|initialize|migrate|config|environment|export|install|mkdir|create)\b",
    re.IGNORECASE,
)
_MONITOR_RE = re.compile(
    r"\b(?:monitor|watch|tail|journalctl|status|logs?|poll)\b",
    re.IGNORECASE,
)
_CHECK_RE = re.compile(r"\b(?:assert|pytest|status|health|check)\b", re.IGNORECASE)

_COMMAND_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
}
_SHELL_KEYWORDS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "for",
    "while",
    "do",
    "done",
    "case",
    "esac",
    "function",
    "{",
    "}",
}


@dataclass(slots=True)
class HarnessScript:
    script_path: str
    role: str
    commands: list[str]
    tools: list[str]
    env_vars: list[str]
    last_modified: str


@dataclass(slots=True)
class HarnessSummary:
    total_scripts: int
    roles: dict[str, int]
    top_commands: list[tuple[str, int]]


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _command_from_arg(node: ast.AST) -> str | None:
    literal = _literal_str(node)
    if literal is not None:
        return literal.strip()

    if isinstance(node, (ast.List, ast.Tuple)):
        parts: list[str] = []
        for elt in node.elts:
            token = _literal_str(elt)
            if token is None:
                break
            parts.append(token.strip())
        if parts:
            return " ".join(part for part in parts if part)
    return None


def _extract_commands(tree: ast.AST) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _attr_name(node.func)
        if func_name not in _COMMAND_CALLS:
            continue

        arg_node: ast.AST | None = None
        if node.args:
            arg_node = node.args[0]
        else:
            for kw in node.keywords:
                if kw.arg == "args":
                    arg_node = kw.value
                    break

        if arg_node is None:
            continue

        command = _command_from_arg(arg_node)
        if not command:
            continue
        command = re.sub(r"\s+", " ", command).strip()
        if not command or command in seen:
            continue
        seen.add(command)
        commands.append(command)

    commands.sort()
    return commands


def _tool_from_command(command: str) -> str | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return None

    idx = 0
    first = parts[idx]
    if first == "sudo":
        idx += 1
        while idx < len(parts) and parts[idx].startswith("-"):
            idx += 1
        if idx >= len(parts):
            return None
        first = parts[idx]

    if first == "env":
        idx += 1
        while idx < len(parts):
            token = parts[idx]
            if "=" in token and not token.startswith("="):
                idx += 1
                continue
            return token
        return None

    return first


def _extract_tools(commands: list[str]) -> list[str]:
    tools: set[str] = set()
    for command in commands:
        tool = _tool_from_command(command)
        if tool:
            tools.add(tool)
    return sorted(tools)


def _extract_env_vars(tree: ast.AST) -> list[str]:
    names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _attr_name(node.func)
            if func_name in {"os.getenv", "getenv", "os.environ.get", "environ.get"} and node.args:
                value = _literal_str(node.args[0])
                if value and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
                    names.add(value)

        if isinstance(node, ast.Subscript):
            owner = _attr_name(node.value)
            if owner not in {"os.environ", "environ"}:
                continue

            target = node.slice
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                value = target.value
            else:
                value = None

            if value and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
                names.add(value)

    return sorted(names)


def _extract_env_vars_shell(text: str) -> list[str]:
    names: set[str] = set()
    for match in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", text):
        names.add(match)
    for match in re.findall(r"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=", text, flags=re.MULTILINE):
        names.add(match)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("env "):
            continue
        for token in stripped.split()[1:]:
            if "=" not in token:
                break
            key = token.split("=", 1)[0].strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                names.add(key)
    return sorted(names)


def _extract_shell_commands(text: str) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"\s+#.*$", "", line).strip()
        if not line:
            continue
        fragments = [part.strip() for part in re.split(r"\s*(?:&&|\|\||;)\s*", line) if part.strip()]
        for fragment in fragments:
            token = fragment.split(maxsplit=1)[0].strip()
            if token in _SHELL_KEYWORDS:
                continue
            if fragment.startswith(("export ", "local ", "readonly ", "declare ")):
                continue
            normalized = re.sub(r"\s+", " ", fragment).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            commands.append(normalized)
    commands.sort()
    return commands


def _role_from_features(path: Path, tree: ast.AST, text: str, commands: list[str]) -> str:
    lower_text = text.lower()
    lower_name = path.name.lower()

    has_loop = any(isinstance(node, (ast.For, ast.While, ast.AsyncFor)) for node in ast.walk(tree))
    has_sleep = any(_attr_name(node.func) in {"sleep", "time.sleep"} for node in ast.walk(tree) if isinstance(node, ast.Call))
    has_assert = any(isinstance(node, ast.Assert) for node in ast.walk(tree))

    scores = {
        "runner": 0,
        "verifier": 0,
        "cleanup": 0,
        "monitor": 0,
        "setup": 0,
    }

    if has_loop and commands:
        scores["runner"] += 3
    if has_sleep:
        scores["runner"] += 1
    if commands:
        scores["runner"] += 1
    if any(token in lower_name for token in ("runner", "soak", "harness")):
        scores["runner"] += 1

    if has_assert:
        scores["verifier"] += 3
    if any("pytest" in cmd.lower() for cmd in commands):
        scores["verifier"] += 3
    if _CHECK_RE.search(text):
        scores["verifier"] += 1
    if any(token in lower_name for token in ("verify", "verifier", "test")):
        scores["verifier"] += 1

    if _CLEANUP_RE.search(text):
        scores["cleanup"] += 3
    if any(
        re.search(r"\b(?:rm|unlink|kill|pkill|docker\s+rm|docker\s+stop)\b", cmd, re.IGNORECASE)
        for cmd in commands
    ):
        scores["cleanup"] += 2
    if any(token in lower_name for token in ("cleanup", "stop")):
        scores["cleanup"] += 1

    if _MONITOR_RE.search(text):
        scores["monitor"] += 2
    if any(re.search(r"\b(?:tail|watch|journalctl|logs?|status)\b", cmd, re.IGNORECASE) for cmd in commands):
        scores["monitor"] += 2
    if any(token in lower_name for token in ("monitor", "watch")):
        scores["monitor"] += 1

    if _SETUP_RE.search(text):
        scores["setup"] += 2
    if any(re.search(r"\b(?:setup|init|migrate|install|mkdir|create)\b", cmd, re.IGNORECASE) for cmd in commands):
        scores["setup"] += 2
    if any(token in lower_name for token in ("setup", "init")):
        scores["setup"] += 1

    role_order = ("runner", "verifier", "cleanup", "monitor", "setup")
    return max(role_order, key=lambda role: (scores[role], -role_order.index(role)))


def analyze_harness_script(path: Path) -> HarnessScript:
    """Analyze one harness-like script file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".py":
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            # Fall back to an empty AST-like module; regex based features still work.
            tree = ast.parse("")
        commands = _extract_commands(tree)
        env_vars = _extract_env_vars(tree)
    else:
        tree = ast.parse("")
        commands = _extract_shell_commands(text)
        env_vars = _extract_env_vars_shell(text)

    tools = _extract_tools(commands)
    role = _role_from_features(path, tree, text, commands)
    last_modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")

    return HarnessScript(
        script_path=str(path),
        role=role,
        commands=commands,
        tools=tools,
        env_vars=env_vars,
        last_modified=last_modified,
    )


def scan_harness_paths(repo_root: Path | None = None) -> list[Path]:
    """Find harness-like scripts under repo root."""
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    files: list[Path] = []
    seen: set[str] = set()

    for path in resolved_repo_root.rglob("*"):
        if path.suffix not in {".py", ".sh"}:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue

        name = path.name
        if name in _INCLUDE_NAMES or any(fnmatch.fnmatch(name, pattern) for pattern in _INCLUDE_PATTERNS):
            key = str(path)
            if key not in seen:
                seen.add(key)
                files.append(path)

    files.sort(key=lambda item: str(item))
    return files


def ingest_harness_scripts(
    conn: sqlite3.Connection,
    *,
    repo_root: Path | None = None,
) -> tuple[int, HarnessSummary]:
    """Ingest harness script inventory and return file count + summary."""
    paths = scan_harness_paths(repo_root=repo_root)

    for path in paths:
        analyzed = analyze_harness_script(path)
        upsert_harness_script(
            conn,
            script_path=analyzed.script_path,
            role=analyzed.role,
            commands=analyzed.commands,
            tools=analyzed.tools,
            env_vars=analyzed.env_vars,
            last_modified=analyzed.last_modified,
        )

    rows = conn.execute(
        """
        SELECT role, commands_json
        FROM harness_scripts
        """
    ).fetchall()

    role_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    for row in rows:
        role = str(row["role"])
        role_counts[role] += 1

        raw_commands = row["commands_json"]
        try:
            commands = json.loads(raw_commands)
        except (TypeError, json.JSONDecodeError):
            commands = []
        if not isinstance(commands, list):
            continue
        for command in commands:
            if isinstance(command, str) and command.strip():
                command_counts[command.strip()] += 1

    summary = HarnessSummary(
        total_scripts=len(rows),
        roles=dict(sorted(role_counts.items())),
        top_commands=sorted(command_counts.items(), key=lambda item: (-item[1], item[0]))[:10],
    )
    return len(paths), summary
