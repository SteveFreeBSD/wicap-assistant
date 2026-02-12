# WICAP Assistant Handoff Plan

## Execution Status
- Milestones 1 through 4 are implemented and covered by the default test suite.
- Remaining work is roadmap-driven and includes approved cross-repo expansion for memory, adaptive control, network intelligence, and OTLP telemetry.
- Parity+ seed pass implemented: control/anomaly/telemetry v2+ contracts, sandbox policy trace, failover persistence, mission graph, and deterministic replay/chaos certification harnesses.

## Canonical Operator Workflow
Program contract reference: `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md` (cross-repo execution contract).

WICAP Assistant should be operated as a deterministic evidence pipeline: ingest trusted local artifacts, derive normalized signals, produce ranked triage outputs, and validate recommendations against measurable confidence and recurrence constraints before operational use. Every operator run should be reproducible from local data and testable without network dependencies.

1. Run ingest scans for approved sources (`codex`, `soaks`, `harness`, `antigravity`, `changelog`) into `data/assistant.db`.
2. Run analysis commands (`cross-patterns`, `daily-report`, `rollup`) to identify recurring and trending failures.
3. Generate response artifacts (`bundle`, `incident`, `playbooks`) for high-priority signatures.
4. Run `recommend` for the target signature/incident and inspect `confidence_breakdown` plus verification ordering.
5. Run quality checks (`confidence-audit`, `pytest -q`) before accepting recommendations as release-ready guidance.

## Milestones

### Milestone 1: Phase 4 Closeout – Confidence Reliability Gates

#### Work Slice 1.1
- Goal: Enforce anti-saturation thresholds in tests so regression to inflated confidence fails fast.
- Files likely touched: `tests/test_confidence_audit.py`, `tests/test_calibration_regression_fixture.py`.
- Tests to add/update: `tests/test_confidence_audit.py`.
- Demo command(s): `pytest -q tests/test_confidence_audit.py tests/test_calibration_regression_fixture.py`.
- Exit criteria: fixture and audit tests fail if `high95_count` exceeds expected threshold for non-strict cases.

#### Work Slice 1.2
- Goal: Complete edge-case matrix for recurrence and verification outcome interactions in calibration.
- Files likely touched: `src/wicap_assist/recommend_confidence.py`, `tests/test_recommend_confidence.py`.
- Tests to add/update: `tests/test_recommend_confidence.py`.
- Demo command(s): `pytest -q tests/test_recommend_confidence.py`.
- Exit criteria: deterministic pass/fail/unknown and recurrence assertions all pass with bounded confidence in `[0.0, 1.0]`.

#### Work Slice 1.3
- Goal: Freeze explainable confidence component contract used by downstream tooling.
- Files likely touched: `src/wicap_assist/recommend.py`, `tests/test_recommend.py`, `README.md`.
- Tests to add/update: `tests/test_recommend.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli recommend logs_soak_1769746905`.
- Exit criteria: recommend JSON top-level schema remains stable and includes required `confidence_breakdown` component keys.

### Milestone 2: Phase 5 Closeout – Correlation Quality and Determinism

#### Work Slice 2.1
- Goal: Lock shared evidence primitives as single-source by adding regression checks against helper drift.
- Files likely touched: `src/wicap_assist/util/evidence.py`, `tests/test_evidence_utils.py`.
- Tests to add/update: `tests/test_evidence_utils.py`.
- Demo command(s): `pytest -q tests/test_evidence_utils.py`.
- Exit criteria: normalization/tokenization/timestamp/overlap behavior is test-locked and deterministic.

#### Work Slice 2.2
- Goal: Validate cross-artifact correlation outputs stay deterministic across `bundle`, `rollup`, and `recommend`.
- Files likely touched: `tests/test_bundle_smoke.py`, `tests/test_rollup.py`, `tests/test_recommend.py`.
- Tests to add/update: `tests/test_rollup.py`.
- Demo command(s): `pytest -q tests/test_bundle_smoke.py tests/test_rollup.py tests/test_recommend.py`.
- Exit criteria: repeated test runs produce stable ranking and matching outputs for fixed fixtures.

#### Work Slice 2.3
- Goal: Verify git-context evidence aggregation remains consistent and non-empty when metadata exists.
- Files likely touched: `src/wicap_assist/git_context.py`, `tests/test_git_context.py`.
- Tests to add/update: `tests/test_git_context.py`.
- Demo command(s): `pytest -q tests/test_git_context.py`.
- Exit criteria: git context includes correct commit/branch counts and source attribution in fixture scenarios.

### Milestone 3: Phase 7 Closeout – Documentation and Contract Coherence

#### Work Slice 3.1
- Goal: Keep command documentation aligned with implemented CLI surface and canonical workflow.
- Files likely touched: `README.md`, `docs/DOCS_INDEX.md`, `tests/test_cli_surface_docs.py`.
- Tests to add/update: `tests/test_cli_surface_docs.py` (new).
- Demo command(s): `pytest -q tests/test_cli_surface_docs.py`.
- Exit criteria: docs test fails if README command list diverges from CLI parser command set.

#### Work Slice 3.2
- Goal: Add doc coherence checks for mission/roadmap/alignment/handoff authority consistency.
- Files likely touched: `docs/ASSISTANT_MISSION.md`, `docs/ASSISTANT_ROADMAP.md`, `docs/AGENT_ALIGNMENT.md`, `docs/HANDOFF_PLAN.md`, `tests/test_docs_contract.py`.
- Tests to add/update: `tests/test_docs_contract.py` (new).
- Demo command(s): `pytest -q tests/test_docs_contract.py`.
- Exit criteria: test-validated hierarchy and guardrail statements are present and non-contradictory.

#### Work Slice 3.3
- Goal: Ensure operator-facing examples remain runnable and deterministic.
- Files likely touched: `README.md`, `tests/test_readme_commands_smoke.py`.
- Tests to add/update: `tests/test_readme_commands_smoke.py` (new, lightweight command/help checks).
- Demo command(s): `pytest -q tests/test_readme_commands_smoke.py`.
- Exit criteria: all documented demo commands are syntactically valid and executable in test mode.

### Milestone 4: Release Readiness – Build Safety and Regression Bar

#### Work Slice 4.1
- Goal: Define and enforce mandatory pre-merge quality gates for reliability-critical paths.
- Files likely touched: `pyproject.toml` (if pytest config needed), `tests/test_confidence_audit.py`, `tests/test_calibration_regression_fixture.py`.
- Tests to add/update: `tests/test_confidence_audit.py`.
- Demo command(s): `pytest -q`.
- Exit criteria: full suite passes and confidence regression tests are part of default test run.

#### Work Slice 4.2
- Goal: Add deterministic ingest idempotency checks so reruns do not inflate evidence counts.
- Files likely touched: `tests/test_codex_parser_smoke.py`, `tests/test_soak_ingest_smoke.py`, `tests/test_antigravity_ingest.py`.
- Tests to add/update: `tests/test_soak_ingest_smoke.py`.
- Demo command(s): `pytest -q tests/test_codex_parser_smoke.py tests/test_soak_ingest_smoke.py tests/test_antigravity_ingest.py`.
- Exit criteria: repeated ingest on unchanged sources yields zero unexpected new rows.

#### Work Slice 4.3
- Goal: Finalize handoff verification checklist for maintainers and reviewers.
- Files likely touched: `docs/HANDOFF_PLAN.md`, `docs/DOCS_INDEX.md`.
- Tests to add/update: `tests/test_docs_contract.py`.
- Demo command(s): `pytest -q tests/test_docs_contract.py && pytest -q`.
- Exit criteria: checklist is complete, linked in docs index, and all required gates pass.

### Milestone 5: Live Control Agent – Managed Soak Operations (In Progress)

#### Work Slice 5.1
- Goal: Learn deterministic soak startup profiles from historical session commands/outcomes and apply them in supervised runs.
- Files likely touched: `src/wicap_assist/soak_profiles.py`, `src/wicap_assist/soak_run.py`, `tests/test_soak_profiles.py`, `tests/test_soak_run.py`.
- Tests to add/update: `tests/test_soak_profiles.py`, `tests/test_soak_run.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli soak-run --dry-run`.
- Exit criteria: `soak-run` shows selected learned profile evidence and resolved effective args without executing arbitrary commands.

#### Work Slice 5.2
- Goal: Add a managed soak session state machine that executes allowlisted phases in order: preflight/init, soak run, observe, ingest, incident summary.
- Files likely touched: `src/wicap_assist/soak_run.py`, `src/wicap_assist/live.py`, `src/wicap_assist/db.py`, `tests/test_soak_run.py`, `tests/test_live_monitor.py`.
- Tests to add/update: `tests/test_soak_run.py`, `tests/test_live_monitor.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli soak-run --duration-minutes 30 --playwright-interval-minutes 5`.
- Exit criteria: one command produces run log, live observation rows, ingest updates, and incident output with a single final run summary.

#### Work Slice 5.3
- Goal: Add deterministic babysit metrics during managed soak sessions (service uptime/restarts, error signature rate, verification check snapshots).
- Files likely touched: `src/wicap_assist/live.py`, `src/wicap_assist/probes/docker_probe.py`, `src/wicap_assist/db.py`, `tests/test_live_monitor.py`.
- Tests to add/update: `tests/test_live_monitor.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli live --once`.
- Exit criteria: observation panel includes service state + top signatures + safe verify steps, and data is persisted in `live_observations`.

#### Work Slice 5.4
- Goal: Add guardrails for live control sessions so only allowlisted WICAP harness entrypoints and flags can execute.
- Files likely touched: `src/wicap_assist/soak_run.py`, `src/wicap_assist/cli.py`, `tests/test_soak_run.py`, `tests/test_readme_commands_smoke.py`.
- Tests to add/update: `tests/test_soak_run.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli soak-run --dry-run`.
- Exit criteria: invalid/non-allowlisted execution paths are rejected deterministically and covered by tests.

#### Work Slice 5.5
- Goal: Consolidate live soak operator output into one concise session report artifact for review and handoff.
- Files likely touched: `src/wicap_assist/soak_run.py`, `src/wicap_assist/incident.py`, `README.md`, `tests/test_soak_run.py`.
- Tests to add/update: `tests/test_soak_run.py`.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli soak-run --duration-minutes 10 --playwright-interval-minutes 2`.
- Exit criteria: final output includes run id, exit code, newest soak dir, incident path, and key live metrics in one deterministic summary block.

### Milestone 6: Cross-Repo Agentic Intelligence Program (Planned)

#### Work Slice 6.1
- Goal: Freeze cross-repo contracts (`wicap.event.v1`, `wicap.control.v1`, `wicap.telemetry.v1`) and parity tests.
- Files likely touched: `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`, runtime contract modules, contract fixture tests in both repos.
- Tests to add/update: cross-repo parity tests.
- Demo command(s): `wicap-assist contract-check --enforce --json`.
- Exit criteria: schema/version drift fails CI in both repos.

#### Work Slice 6.2
- Goal: Implement plane-separated policy enforcement (runtime/tool/elevated) with deny precedence.
- Files likely touched: `src/wicap_assist/soak_control.py`, `src/wicap_assist/actuators.py`, `src/wicap_assist/cli.py`.
- Tests to add/update: control policy matrix tests (observe/assist/autonomous).
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli live --once --control-mode autonomous`.
- Exit criteria: no action executes unless all policy planes allow it.

#### Work Slice 6.3
- Goal: Add memory tiers (episodic, semantic retrieval, working memory) and adaptive ranking in shadow mode.
- Files likely touched: `src/wicap_assist/db.py`, new memory/ranker modules, `src/wicap_assist/live.py`.
- Tests to add/update: migration tests, retrieval/ranker determinism tests, shadow-mode validation tests.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli soak-run --dry-run --control-mode autonomous`.
- Exit criteria: learned ranking is available, auditable, and not executed outside shadow gates.

#### Work Slice 6.4
- Goal: Integrate WiCAP-native network anomaly envelopes and route anomaly classes into control guidance.
- Files likely touched: WiCAP event export modules + assistant network ingestion/correlation modules.
- Tests to add/update: network fixture ingest/correlation tests and control mapping tests.
- Demo command(s): `PYTHONPATH=src python -m wicap_assist.cli live --once --control-mode assist`.
- Exit criteria: anomalies produce deterministic, policy-bounded guidance/action proposals.

#### Work Slice 6.5
- Goal: Add provider-neutral OTLP telemetry emission with redaction governance.
- Files likely touched: telemetry modules, collector config, redaction policy/tests, docs.
- Tests to add/update: telemetry contract tests and redaction regression tests.
- Demo command(s): telemetry smoke command documented in README/HANDOFF.
- Exit criteria: traces/metrics/logs export via OTLP without sensitive-field leakage.

## Non-goals
- Do not add unapproved ingestion sources; only add sources explicitly authorized in mission/roadmap/workslices.
- Do not add new CLI commands unless required to enforce existing quality gates.
- Do not add LLM-driven or speculative recommendation generation.
- Do not add unallowlisted autonomous execution of live operational commands.
- Do not make external internet lookups the source of truth for control/recommendation decisions.

## CI Gates
- Fail build if `pytest -q` fails anywhere.
- Fail build if confidence regression tests detect non-strict recommendations at `>= 0.95`.
- Fail build if recommend JSON schema contract changes unintentionally.
- Fail build if docs/CLI command surface drift is detected.
- Fail build if ingest idempotency tests show row inflation on unchanged sources.

## Agent Split
- Codex:
  - Implements approved roadmap slices, writes tests, enforces schema/output contracts, and closes measurable exit criteria.
  - Owns code-level determinism, migration safety, and regression prevention.
- Antigravity (Claude):
  - Produces evidence analysis, failure pattern hypotheses, and validation targets scoped to approved phases.
  - Supplies deterministic test case ideas and cross-artifact traceability inputs.
  - Does not approve scope changes or implement unapproved features.

## Handoff Verification Checklist
1. `pytest -q` passes in the default repository environment.
2. Confidence hardening gates are part of the default suite:
- anti-saturation fixture guard
- confidence breakdown contract checks
- recurrence/verification matrix checks
3. Cross-artifact determinism checks pass for `bundle`, `rollup`, and `recommend` on fixed fixtures.
4. Ingest idempotency checks pass for unchanged `codex`, `soaks`, and `antigravity` sources.
5. Documentation contract checks pass:
- CLI command surface matches `README.md` command reference
- authority hierarchy and guardrails are present and consistent across mission/roadmap/alignment/handoff.
