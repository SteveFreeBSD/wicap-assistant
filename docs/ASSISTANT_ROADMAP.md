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
- Remaining: periodic drift audit only; shared evidence primitives are centralized and regression-tested.

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

## Phase 9 – Plane-Separated Agentic Control (In Progress)
- Implemented OpenClaw-style runtime/tool-policy/elevated plane separation with deny-precedence evaluation in actuator flow.
- Implemented cross-repo control intent policy gate (`wicap.control.v1`) with accept/reject audit metadata in WiCAP intake surfaces.
- Implemented autonomous rollout gate evaluation with shadow/risk/rollback SLO checks and promotion readiness history.

## Phase 10 – Memory Tiers and Learning (In Progress)
- Implemented episodic memory for action/outcome timelines (`episodes`, `episode_events`, `episode_outcomes`) with additive migration safety.
- Implemented semantic retrieval over historical control episodes with top-k memory attachment in recommendation payloads.
- Implemented additive decision feature store persistence (`decision_features`) for deterministic per-decision learning vectors.
- Implemented working-memory context cache for active sessions and resumable live handoffs.
- Implemented shadow-only action ranking baseline for allowlisted actions with auditable score traces.
- Implemented deterministic reward modeling + outcome labels for decision feature persistence.
- Implemented shadow quality gate metrics (sample/agreement/success thresholds) with telemetry emission in live/soak loops.
- Implemented scheduled memory-maintenance job baseline with stale working-memory pruning and reflection reports.
- Implemented guarded promotion policy via rollout gate history and consecutive-pass readiness checks.

## Phase 11 – WiCAP-Native Network Intelligence (In Progress)
- Implemented ingest adapter for WiCAP-native network envelopes and integrated network categories into recommendation/playbook/rollup/guardian evidence paths.
- Implemented WiCAP-side event normalization + Zeek conn and Suricata EVE compatibility exporters for contract-aligned flow semantics.
- Implemented ingestion support for `wicap.anomaly.v1` scored anomaly stream artifacts.
- Implemented ingestion support for `wicap.feedback.v1` anomaly feedback artifacts.
- Implemented deterministic anomaly-class routing to control/playbook verification ladders in guardian, soak control, and recommendation paths.
- Implemented bounded false-positive calibration from feedback artifacts (`network_anomaly_feedback`) into anomaly recommendation confidence.

## Phase 12 – OTLP Telemetry and Observability (In Progress)
- Implemented provider-neutral OTLP-aligned traces/metrics/log payload emission for live and supervised soak control cycles.
- Implemented telemetry redaction hooks and regression tests for secret/token masking.
- Implemented optional WiCAP OpenTelemetry Collector compose profile baseline.
- Implemented WiCAP fail-open OTLP exporter queueing/backoff so telemetry delivery never destabilizes capture/control paths.
- Implemented assistant OTLP endpoint/auth profile validation and fail-open HTTP export hooks.
- Implemented assistant canonical OTLP signal transport (`logs/metrics/traces`) with endpoint derivation, batch splitting, retry/backoff, optional gzip, and partial-success parsing.

## Phase 13 – Next-Gen Agentic Intelligence (In Progress)
- Implemented `wicap.anomaly.v2` and `wicap.prediction.v1` cross-repo contract fixtures/parity checks.
- Implemented seed parity+ contracts `wicap.control.v2`, `wicap.anomaly.v3`, and `wicap.telemetry.v2` with cross-repo fixture coverage.
- Implemented assistant ingestion + storage for forecast, drift, model-shadow, and proactive-outcome artifacts.
- Implemented policy explainability snapshot surfaces (`agent explain-policy`) and policy snapshot persistence in live/soak session metadata.
- Implemented deterministic sandbox policy trace surface (`agent sandbox-explain`) with action/elevated budget state reporting.
- Implemented failover profile persistence baseline (`failover_events`, `auth_profile_state`) and `agent failover-state` snapshot surface.
- Implemented command-center and forecast CLI surfaces (`agent control-center`, `agent forecast`) for operator-grade runtime context.
- Implemented mission graph persistence (`mission_runs`, `mission_steps`) and `agent mission-graph` snapshot surface.
- Implemented certification scaffolds (`agent replay-certify`, `agent chaos-certify`) with persisted `certification_runs`.
- Implemented sidecar-intel readiness hooks in status surfaces and contract fixtures for additive rollout-gated adoption.

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
