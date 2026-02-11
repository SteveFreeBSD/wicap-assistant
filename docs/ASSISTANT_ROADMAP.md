# WICAP Assistant Engineering Roadmap

## Phase 1 – Evidence Ingestion Layer (Completed)
- Implemented deterministic local ingestion for Codex chat logs, soak log files, and harness scripts.
- Implemented ingestion gating for WICAP-relevant sessions and scoped file-pattern scanning for soak/harness artifacts.
- Incident history, playbooks, and regression data are consumed as trusted local project artifacts (generated docs + database-backed trend data).
- Current ingestion scope aligns with `ASSISTANT_MISSION.md` Trusted Inputs.

## Phase 2 – Evidence Structuring Layer (Completed)
- Implemented structured storage in SQLite for sources, sessions, signals, log events, harness inventory, and ingest runs.
- Implemented signal extraction with redaction, fingerprinting, category classification, and prompt-noise filtering.
- Implemented correlation and deduplication across artifacts using normalized signatures, unique keys, and source change tracking.
- Implemented bundle-level joins across soak failures, related Codex sessions/signals, and nearby git history windows.

## Phase 3 – Knowledge Output Layer (Completed)
- Implemented deterministic incident report generation with indexed history.
- Implemented deterministic playbook generation from recurring signatures with fix/verify sections.
- Implemented guardian alert output for live soak monitoring and known-signature matching.
- Implemented daily regression reporting for recent-vs-baseline trend detection.
- Implemented deterministic recommendation generation (JSON only) from historical evidence.

## Phase 4 – Confidence and Verification Layer (Completed)
- Implemented recommendation confidence calibration from observed fix outcomes, recurrence penalties, and verification evidence.
- Implemented verification-step ranking using historically successful verifier commands and harness verifier role weighting.
- Implemented verification outcome tracking from Antigravity walkthrough artifacts with confidence boost/penalty integration.
- Improved failure signature clustering to better merge near-duplicate operational failures while preserving determinism.
- Added confidence distribution hardening and CI-style reliability gates enforced in the default test suite.

## Phase 5 – Cross-Artifact Correlation Layer (In Progress)
- Implemented cross-conversation chronic pattern detection across conversation signals, soak events, and Codex sessions.
- Implemented relapse detection for failure signatures reappearing after time gaps.
- Standardized shared join keys (normalized fingerprint, time window, source type tokens).
- Linked CHANGELOG entries to failure evidence for release-aware correlation.
- Remaining: consolidate duplicated evidence primitives into one shared core to eliminate drift across modules.

## Phase 6 – Antigravity and Extended Adapters (Completed)
- Implemented Antigravity conversation artifact ingestion (task.md, walkthrough.md, implementation_plan.md).
- Implemented structured signal extraction for checklists, test results, and file changes.
- Implemented CHANGELOG.md ingestion with release-tag-scoped section parsing.
- All adapters are local-first, deterministic, and compliant with mission guardrails.

## Phase 7 – Stabilization and Single Source of Truth (Completed)
- Consolidated signature normalization, token extraction, timestamp parsing, and commit overlap scoring into one shared evidence utility.
- Removed redundant implementations from recommendation, rollup, bundle, playbooks, guardian, daily report, and lineage modules.
- Aligned documentation to one canonical workflow and complete CLI command inventory.
- Kept existing functionality stable while reducing maintenance and calibration drift risk.

## Phase 8 – Live Control Foundation (In Progress)
- Implemented deterministic supervised control state machine for operator-initiated soak lifecycle runs.
- Restricted all state-changing actions to explicit allowlisted actuator call points.
- Persisted control state, actions, and escalation outcomes for resume/audit workflows.
- Expanded real-time observability coverage for WICAP runtime and soak ecosystem logs.

## Phase 9 – Plane-Separated Agentic Control (Planned)
- Implement OpenClaw-style runtime/tool-policy/elevated plane separation with deny-precedence evaluation.
- Enforce cross-repo control intent contracts (`wicap.control.v1`) and strict policy profile validation.
- Expand autonomous profiles with explicit rollout gates, shadow mode, and rollback budget controls.

## Phase 10 – Memory Tiers and Learning (Planned)
- Add episodic memory for action/outcome timelines.
- Add semantic retrieval over historical incidents and control episodes.
- Add working-memory context for active sessions and resumable handoffs.
- Add adaptive action ranking (shadow-mode first, guarded promotion after quality gates).

## Phase 11 – WiCAP-Native Network Intelligence (Planned)
- Ingest WiCAP-native network envelopes with Suricata/Zeek-compatible field contracts.
- Correlate anomaly classes to control ladders and verification playbooks.
- Close false-positive loops with bounded operator feedback and deterministic recalibration.

## Phase 12 – OTLP Telemetry and Observability (Planned)
- Add provider-neutral OTLP traces/metrics/logs for live control loops and recovery workflows.
- Add telemetry redaction policy and compliance tests.
- Add backpressure/failure handling so telemetry delivery never destabilizes control.

## Active Program Plan
- Detailed cross-repo milestones and work slices live in:
  - `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`

## Guardrails
- All state-changing actions must remain allowlisted and auditable.
- No freeform shell command synthesis from ingested text.
- No internet lookup may become a runtime recommendation/control source of truth.
- Cloud/OTLP telemetry is observability only and must pass redaction/security policy.
- Autonomous execution requires kill-switch, rollback, and explicit profile gates.

## Success Metrics
- Reduction in manual triage steps per incident (baseline vs current median).
- Recommendation verification success rate (recommended steps that validate successfully).
- Mean time to resolution improvement for recurring failure signatures.
- Recurrence detection accuracy (precision/recall against confirmed recurring incidents).
- Guardian alert precision for known failure signatures (actionable vs noisy alerts).
- Autonomous recovery durability (no-relapse window after automated recovery).
- OTLP telemetry delivery SLO without leaking sensitive fields.
