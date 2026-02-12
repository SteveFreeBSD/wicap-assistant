# WICAP Assistant Quality Gates

Date: 2026-02-10

## Purpose
Define the deterministic checks that must pass before release freezes or major commits.

## Mandatory Gates
1. Full test suite passes.
2. Confidence saturation regression is blocked.
3. Recommendation JSON contract remains stable.
4. Ingest reruns on unchanged sources are idempotent.
5. CLI surface and docs stay in sync.
6. Mission/roadmap/alignment/handoff guardrails remain coherent.
7. Replay and chaos certification harnesses remain deterministic and bounded.

## Enforced Test Mapping

### Confidence reliability
- `tests/test_confidence_audit.py`
  - Blocks non-strict confidence saturation (`>= 0.95`) on fixture data.
  - Asserts `high95_count`, `one_count`, and distribution guardrails.
- `tests/test_calibration_regression_fixture.py`
  - Regression fixture prevents silent confidence drift.
- `tests/test_recommend_confidence.py`
  - Recurrence, pass/fail/unknown outcomes, and confidence cap behavior.
- `tests/test_recommend.py`
  - Stable recommendation JSON schema and confidence breakdown keys.

### Correlation determinism
- `tests/test_bundle_smoke.py`
  - Deterministic bundle output over fixed fixture.
- `tests/test_rollup.py`
  - Deterministic rollup ranking and stable item fields.
- `tests/test_git_context.py`
  - Stable git-context aggregation and output integration.

### Ingest idempotency
- `tests/test_codex_parser_smoke.py`
  - Re-ingest unchanged codex sources does not inflate rows.
- `tests/test_soak_ingest_smoke.py`
  - Re-ingest unchanged soak logs adds zero new events.
- `tests/test_antigravity_ingest.py`
  - Re-ingest unchanged antigravity dirs adds zero rows.

### Documentation and contract coherence
- `tests/test_cli_surface_docs.py`
  - README command reference matches actual CLI parser surface.
- `tests/test_readme_commands_smoke.py`
  - Top-level and per-command help is runnable.
- `tests/test_docs_contract.py`
  - Authority hierarchy and guardrail text are present and consistent.

### Certification scaffolds
- `tests/replay/test_replay_certification.py`
  - Replay certification runs deterministic fixture-case replays (`tests/replay/fixtures/default.json`) and writes certification records.
- `tests/chaos/test_chaos_certification.py`
  - Chaos certification runs deterministic outage scenarios (`tests/chaos/fixtures/default.json`), enforces action allowlists, and persists bounded degraded-cycle rates.

## Release Checklist
1. `pytest -q`
2. `PYTHONPATH=src python -m wicap_assist.cli confidence-audit --limit 100`
3. Confirm `docs/ASSISTANT_MISSION.md`, `docs/ASSISTANT_ROADMAP.md`, and `docs/HANDOFF_PLAN.md` reflect current status.
4. Confirm README command reference has no drift from parser commands.

## Non-goal Reminder
Quality gates are for stabilization and trust hardening. They are not a place to introduce new product features or ingestion scope.
