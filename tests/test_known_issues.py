from __future__ import annotations

from wicap_assist.known_issues import match_known_issue


def test_match_known_issue_detects_internal_allowlist_block() -> None:
    match = match_known_issue(
        signature='wicap.processor: ui push failed: 403 {"detail":"client not allowed"}',
        category="error",
        example="UI push failed: 403",
    )
    assert match is not None
    assert match["issue_id"] == "ui_internal_allowlist_block"


def test_match_known_issue_returns_none_for_unrelated_signature() -> None:
    match = match_known_issue(
        signature="totally unrelated warning",
        category="error",
        example="no signal",
    )
    assert match is None
