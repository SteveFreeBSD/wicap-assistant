from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex

from wicap_assist.cli import build_parser


_README_PATH = Path(__file__).resolve().parents[1] / "README.md"
_COMMAND_REF_RE = re.compile(r"^- `wicap-assist\s+([a-z0-9-]+)\b")
_PLACEHOLDER_RE = re.compile(r"<[^>]+>")


def _subparser_commands() -> set[str]:
    parser = build_parser()
    action = next(
        (item for item in parser._actions if isinstance(item, argparse._SubParsersAction)),
        None,
    )
    assert action is not None
    return set(action.choices.keys())


def _readme_command_reference_commands() -> set[str]:
    commands: set[str] = set()
    lines = _README_PATH.read_text(encoding="utf-8").splitlines()

    in_command_section = False
    for raw in lines:
        line = raw.rstrip()
        if line.startswith("## "):
            in_command_section = line == "## Command Reference"
            continue
        if not in_command_section:
            continue

        match = _COMMAND_REF_RE.match(line.strip())
        if match:
            commands.add(match.group(1))

    return commands


def _readme_example_commands() -> list[str]:
    commands: list[str] = []
    in_bash_block = False
    for raw in _README_PATH.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped == "```bash":
            in_bash_block = True
            continue
        if stripped == "```":
            in_bash_block = False
            continue
        if not in_bash_block:
            continue
        if stripped.startswith("wicap-assist "):
            commands.append(stripped)

    return commands


def test_readme_command_reference_matches_cli_surface() -> None:
    cli_commands = _subparser_commands()
    documented_commands = _readme_command_reference_commands()

    assert documented_commands == cli_commands


def test_readme_example_commands_parse_with_cli_parser() -> None:
    parser = build_parser()
    cli_commands = _subparser_commands()

    examples = _readme_example_commands()
    assert examples

    for command in examples:
        normalized = _PLACEHOLDER_RE.sub("sample", command)
        argv = shlex.split(normalized)
        assert argv[0] == "wicap-assist"
        parsed = parser.parse_args(argv[1:])
        assert parsed.command in cli_commands
