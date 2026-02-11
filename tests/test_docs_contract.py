from __future__ import annotations

from pathlib import Path


_DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"


def _read_doc(name: str) -> str:
    return (_DOCS_DIR / name).read_text(encoding="utf-8")


def test_docs_index_references_authoritative_and_handoff_docs() -> None:
    index_text = _read_doc("DOCS_INDEX.md")

    required = [
        "ASSISTANT_MISSION.md",
        "ASSISTANT_ROADMAP.md",
        "AGENT_ALIGNMENT.md",
        "HANDOFF_PLAN.md",
        "CROSS_REPO_INTELLIGENCE_WORKSLICES.md",
    ]
    for doc_name in required:
        assert doc_name in index_text
        assert (_DOCS_DIR / doc_name).exists()


def test_alignment_authority_hierarchy_matches_contract() -> None:
    alignment = _read_doc("AGENT_ALIGNMENT.md")

    ordered_markers = [
        "1. `docs/ASSISTANT_MISSION.md`",
        "2. `docs/ASSISTANT_ROADMAP.md`",
        "3. `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`",
        "4. `docs/AGENT_ALIGNMENT.md`",
        "5. Existing code and implementation details",
    ]

    positions = [alignment.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)


def test_guardrail_statements_are_present_and_non_conflicting() -> None:
    mission = _read_doc("ASSISTANT_MISSION.md")
    roadmap = _read_doc("ASSISTANT_ROADMAP.md")
    handoff = _read_doc("HANDOFF_PLAN.md")

    # Mission hard constraints must stay explicit.
    assert "## What This Assistant Must Never Do" in mission
    assert "allowlisted" in mission.lower()
    assert "speculative fixes" in mission.lower()
    assert "otlp" in mission.lower()

    # Roadmap and handoff must retain equivalent guardrails.
    assert "## Guardrails" in roadmap
    assert "kill-switch" in roadmap.lower()
    assert "## Non-goals" in handoff
    assert "Do not add LLM-driven" in handoff
    assert "internet lookups" in handoff.lower()


def test_otlp_spec_reference_is_provider_neutral() -> None:
    workslices = _read_doc("CROSS_REPO_INTELLIGENCE_WORKSLICES.md")
    assert "https://opentelemetry.io/docs/specs/otlp/" in workslices
    assert "provider-neutral" in workslices.lower()


def test_control_mode_terminology_is_observe_with_monitor_alias_note() -> None:
    mission = _read_doc("ASSISTANT_MISSION.md")
    assert "`observe`" in mission
    assert "monitor" in mission.lower()
    assert "alias" in mission.lower()
