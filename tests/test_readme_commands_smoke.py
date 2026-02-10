from __future__ import annotations

import argparse

import pytest

from wicap_assist.cli import build_parser, main


def _subparser_names() -> list[str]:
    parser = build_parser()
    action = next(
        (item for item in parser._actions if isinstance(item, argparse._SubParsersAction)),
        None,
    )
    assert action is not None
    return sorted(action.choices.keys())


def test_top_level_help_is_runnable() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_each_subcommand_help_is_runnable() -> None:
    for command in _subparser_names():
        with pytest.raises(SystemExit) as exc:
            main([command, "--help"])
        assert exc.value.code == 0
