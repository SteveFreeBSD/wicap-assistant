# Cross-Repo Intelligent Agent Integration Plan

Status: In Progress (M0-M4 foundations implemented; M5.1-M5.3 telemetry baselines implemented; M6/M7 rollout intelligence in progress)
Owners: WiCAP Core + wicap-assistant
Canonical chain: `ASSISTANT_MISSION.md` -> `ASSISTANT_ROADMAP.md` -> this file

## 0. Implementation Snapshot
- Implemented M0 baseline artifacts in both repos:
  - WiCAP: `ops/contracts/wicap.event.v1.json`, `ops/contracts/wicap.control.v1.json`, contract fixture exports, schema tests.
  - Assistant: `ops/contracts/wicap.telemetry.v1.json`, WiCAP contract fixtures, parity tests.
- Implemented M1 control-plane gates:
  - Assistant: deny-precedence runtime/tool/elevated plane checks in allowlisted actuators.
  - WiCAP: policy-gated `/api/system/control-intent` intake + plane audit records + status-script intent validator.
- Implemented M2.1 episodic memory tier:
  - Assistant DB tables: `episodes`, `episode_events`, `episode_outcomes` with additive migration.
  - Live and soak control loops now write episode timelines per control action.
- Implemented M2.2 semantic memory retrieval baseline:
  - Assistant semantic episode retrieval module (`memory_semantic.py`) with deterministic top-k matching.
  - Recommendation payloads now include `memory_episodes` and memory-backed action fallback when direct fix/playbook evidence is sparse.
- Implemented M2.3 working memory baseline:
  - Session-scoped working memory state for unresolved signatures, pending actions, and recent transitions.
  - Live control session resume paths now restore working-memory state from prior metadata.
- Implemented M3 network semantics baseline:
  - WiCAP: `wicap.event.v1` normalization helpers + Zeek conn and Suricata EVE compatibility exports.
  - Assistant: network event ingest adapter (`--scan-network-events`) and routing into recommendation/playbook/rollup/guardian categories.
- Implemented M4.1 decision feature store baseline:
  - Assistant DB table: `decision_features` with additive migration and indexes.
  - Live and soak control loops persist one deterministic feature vector per control decision.
- Implemented M4.2 shadow action ranking baseline:
  - Assistant shadow ranker scores allowlisted actions from context + historical success rates.
  - Ranking output is persisted in decision features and remains non-executing (shadow only).
- Implemented M4.3 reward modeling baseline:
  - Deterministic reward model computes outcome/durability/TTR/recurrence/verification components.
  - Decision feature vectors now persist reward value, label, and component traces.
- Implemented M4.4 shadow quality gate baseline:
  - Shadow ranker now emits gate metrics (samples, agreement rate, success rate, pass/fail).
  - Gate telemetry fields are emitted in live/soak cycles while execution remains policy-gated.
- Implemented WiCAP anomaly output contract baseline for M6/W3 bridge:
  - WiCAP anomaly envelope contract `wicap.anomaly.v1` and runtime append path from stream scoring.
  - Assistant ingest adapter now scans `captures/wicap_anomaly_events.jsonl`.
- Implemented WiCAP feedback capture baseline for M6/W3 bridge:
  - WiCAP feedback artifact stream `wicap.feedback.v1` (`captures/wicap_anomaly_feedback.jsonl`).
  - Assistant ingest adapter now scans anomaly feedback artifacts.
- Implemented M5 baseline telemetry:
  - WiCAP optional OTLP collector profile (`profiles: [otel]`) with required processors.
  - Assistant OTLP-aligned telemetry envelopes with redaction hooks and tests.
- Implemented M7 rollout-gate baseline:
  - deterministic `rollout-gates` evaluator for shadow quality, reward stability, autonomous escalation rate, and rollback budget.
  - CLI gate output for canary/promotion readiness checks in CI or scheduled runs.
- Remaining: M6/M7 rollout intelligence gates and production promotion SLO hardening.

## 1. Program Goal
Build a WiCAP-native autonomous control agent with durable memory, adaptive learning, network anomaly intelligence, and secure cloud telemetry without breaking deterministic safety guarantees.

Program intent: OpenClaw/Nanobot-inspired WiCAP Assistant as a new breed of network-aware agentic assistants.

This plan is integration-first:
- Do not require Suricata/Zeek daemons in production by default.
- Add Suricata/Zeek-compatible event semantics inside WiCAP.
- Use shadow validation against Suricata/Zeek when needed.

## 2. External Design Inputs (Primary Sources)
- OpenClaw: split control planes (sandbox runtime, tool policy, elevated execution) and deny-precedence policy composition.
- OpenClaw: deterministic failover/cooldown behavior for resilient control loops.
- Nanobot: persistent memory + scheduled jobs + workspace-restricted tools.
- Suricata: EVE JSON event model (typed network security events).
- Zeek: structured connection logs (`conn.log`) with stable correlation fields.
- OTLP specification: provider-neutral telemetry protocol for traces/metrics/logs across vendors and self-hosted backends.

References are listed in Section 12.

## 3. Non-Negotiable Guardrails
1. All state-changing actions remain allowlisted.
2. Autonomous mode must retain kill-switch + rollback semantics.
3. Memory and learning can rank actions, never bypass safety policy.
4. Cloud telemetry must redact secrets/PII and support encryption/auth.
5. Schema evolution remains additive and backward-compatible.

## 4. Integration Contracts (Target)

### Contract A: WiCAP -> Assistant Event Envelope
- Versioned schema: `event_contract_version: "wicap.event.v1"`.
- Required fields:
  - `ts`
  - `source` (`wifi`, `ble`, `service`, `runtime`)
  - `category`
  - `signature`
  - `severity`
  - `flow` (5-tuple when available)
  - `community_id` (when derivable)
  - `sensor_id`
  - `evidence_ref` (file + offset/row id)
- Output surfaces:
  - JSONL file stream under WiCAP runtime artifacts.
  - Internal API endpoint for bounded polling.

### Contract B: Assistant -> WiCAP Control Intent
- Versioned schema: `control_intent_version: "wicap.control.v1"`.
- Assistant output fields:
  - `decision_id`, `policy_profile`, `reasoning_class`
  - `recommended_action` (allowlisted identifier)
  - `confidence`
  - `required_prechecks`
  - `verification_steps`
  - `safety_class`
- WiCAP execution must reject intents outside allowlist or policy profile.

### Contract C: Cross-Repo Telemetry Envelope
- Versioned schema: `telemetry_event_version: "wicap.telemetry.v1"`.
- OTLP mapping requirements:
  - traces: decision/action lifecycle spans
  - metrics: control loop health, anomaly rates, recovery success
  - logs: structured control/audit records

## 5. Milestone Sequence

## Milestone M0: Program Bootstrap and Contracts

### Work Slice M0.1 - Contract Spec Freeze (Implemented)
- Goal: Freeze v1 event/control/telemetry contracts before feature expansion.
- WiCAP files:
  - `ops/contracts/wicap.event.v1.json` (new)
  - `ops/contracts/wicap.control.v1.json` (new)
- Assistant files:
  - `ops/contracts/wicap.telemetry.v1.json` (new)
  - `src/wicap_assist/runtime_contract.py`
- Tests:
  - contract schema validation tests in both repos.
- Demo:
  - `wicap-assist contract-check --enforce --json`
- Exit criteria:
  - both repos validate same schema versions in CI.

### Work Slice M0.2 - Cross-Repo Fixture Harness (Implemented)
- Goal: deterministic integration tests against fixture snapshots from both repos.
- WiCAP files:
  - `tests/fixtures/contracts/*` (new)
- Assistant files:
  - `tests/fixtures/wicap_contracts/*` (new)
  - `tests/test_runtime_contract_parity.py`
- Tests:
  - parity tests in both repos.
- Exit criteria:
  - contract drift fails CI immediately.

## Milestone M1: OpenClaw-Style Control Plane Separation

### Work Slice M1.1 - Split Control Planes in Assistant (Implemented)
- Goal: separate runtime plane vs tool-policy plane vs elevated plane.
- Assistant files:
  - `src/wicap_assist/soak_control.py`
  - `src/wicap_assist/actuators.py`
  - `src/wicap_assist/settings.py`
  - `src/wicap_assist/cli.py`
- Tests:
  - new tests for deny precedence and escalation behavior.
- Exit criteria:
  - action can run only when all three planes permit.

### Work Slice M1.2 - WiCAP Control Surface Policy Gate (Implemented)
- Goal: WiCAP refuses control intents not signed by policy profile.
- WiCAP files:
  - `scripts/check_wicap_status.py`
  - internal control API/service modules.
- Tests:
  - intent validation tests + reject-path tests.
- Exit criteria:
  - non-compliant intents never execute.

### Work Slice M1.3 - Deterministic Recovery Ladder Profiles
- Goal: profile packs for `observe`, `assist`, `autonomous` with explicit thresholds.
- Assistant files:
  - `src/wicap_assist/soak_control.py`
  - `src/wicap_assist/soak_run.py`
- Tests:
  - profile matrix tests including kill-switch and rollback caps.
- Exit criteria:
  - every profile has documented defaults + tests.

## Milestone M2: Nanobot-Style Memory Tiers (Deterministic)

### Work Slice M2.1 - Episodic Memory Store (Implemented)
- Goal: persist action episodes with pre-state, action, result, and post-state windows.
- Assistant files:
  - `src/wicap_assist/db.py` (new tables)
  - `src/wicap_assist/live.py`
  - `src/wicap_assist/soak_run.py`
- New tables:
  - `episodes`
  - `episode_events`
  - `episode_outcomes`
- Tests:
  - migration + write/read integrity tests.
- Exit criteria:
  - each control action has an episode id and outcome row.

### Work Slice M2.2 - Semantic Memory Retrieval Layer (Implemented Baseline)
- Goal: add retrieval over historical episodes/signatures for action ranking.
- Assistant files:
  - `src/wicap_assist/memory_semantic.py` (new)
  - `src/wicap_assist/recommend.py`
  - `src/wicap_assist/evidence_query.py`
- Tests:
  - deterministic retrieval ranking tests with fixtures.
- Exit criteria:
  - top-k prior episodes attached to recommendations.

### Work Slice M2.3 - Working Memory Window (Implemented Baseline)
- Goal: session-scoped context cache for recent state transitions and unresolved anomalies.
- Assistant files:
  - `src/wicap_assist/live.py`
  - `src/wicap_assist/agent_console.py`
- Tests:
  - context carryover and resume tests.
- Exit criteria:
  - resumed sessions restore unresolved context and pending actions.

### Work Slice M2.4 - Scheduled Reflection Jobs (Implemented Baseline)
- Goal: periodic memory maintenance (summaries, stale pruning, drift labeling).
- Assistant files:
  - `src/wicap_assist/memory_maintenance.py`
  - `scripts/cron_memory_maintenance.sh`
- Tests:
  - maintenance idempotency and bounded-runtime tests.
- Exit criteria:
  - maintenance can run unattended without mutating behavior contracts.

## Milestone M3: WiCAP-Native Network Intelligence (Suricata/Zeek-Compatible)

### Work Slice M3.1 - Canonical Network Event Schema in WiCAP (Implemented Baseline)
- Goal: emit stable flow/session events compatible with Suricata EVE + Zeek conn semantics.
- WiCAP files:
  - `event_processor.py`
  - `parser.py`
  - `nexus/intel/*`
  - `ops/contracts/wicap.event.v1.json`
- Tests:
  - schema conformance + fixture replay tests.
- Exit criteria:
  - events include `flow`, `community_id`, `proto`, `service`, `duration`, `bytes`, `packets` when available.

### Work Slice M3.2 - Zeek-Compatible Connection Summary Export (Implemented Baseline)
- Goal: produce `conn`-like summaries from WiCAP runtime data.
- WiCAP files:
  - new exporter module under `src/wicap/telemetry/`.
- Tests:
  - conn export fixture tests.
- Exit criteria:
  - generated output supports direct downstream comparison with Zeek conn fields.

### Work Slice M3.3 - Suricata-Compatible Security Event Export (Implemented Baseline)
- Goal: produce EVE-like typed events (`alert`, `dns`, `http`, `flow`, etc.) where signal exists.
- WiCAP files:
  - event normalization modules + export writer.
- Tests:
  - category coverage and required field tests.
- Exit criteria:
  - event categories map to a documented compatibility matrix.

### Work Slice M3.4 - Assistant Ingestion Adapter for WiCAP Network Events (Implemented Baseline)
- Goal: consume WiCAP-native network events and link them to current recommendation and guardian pipelines.
- Assistant files:
  - `src/wicap_assist/ingest/network_events.py` (new)
  - `src/wicap_assist/guardian.py`
  - `src/wicap_assist/recommend.py`
- Tests:
  - ingestion + correlation tests across existing signal categories.
- Exit criteria:
  - anomaly events influence control guidance deterministically.

## Milestone M4: Adaptive Learning for Autonomous Action Selection

### Work Slice M4.1 - Feature Store for Decision Context (Implemented Baseline)
- Goal: persist per-decision features (state, anomaly vectors, prior outcomes).
- Assistant files:
  - `src/wicap_assist/db.py` (feature tables)
  - `src/wicap_assist/soak_control.py`
- Tests:
  - feature schema and deterministic encoding tests.
- Exit criteria:
  - every autonomous decision writes one feature vector row.

### Work Slice M4.2 - Contextual Bandit Action Ranker (Guarded Baseline Implemented)
- Goal: rank allowlisted actions by expected recovery reward.
- Assistant files:
  - `src/wicap_assist/action_ranker.py` (new)
  - `src/wicap_assist/soak_control.py`
- Tests:
  - offline replay tests with fixed seeds.
- Exit criteria:
  - ranker suggests only allowlisted actions and logs rationale.

### Work Slice M4.3 - Reward Model + Outcome Labeling (Implemented Baseline)
- Goal: compute reward from durability, TTR, recurrence, and verification outcomes.
- Assistant files:
  - `src/wicap_assist/reward_model.py` (new)
  - `src/wicap_assist/decision_features.py`
  - `src/wicap_assist/live.py`
  - `src/wicap_assist/soak_run.py`
- Tests:
  - reward correctness tests across pass/fail/relapse scenarios.
- Exit criteria:
  - reward calculation is deterministic and traceable.

### Work Slice M4.4 - Shadow Mode Learning Gate (Implemented Baseline)
- Goal: run learned ranking in shadow mode before live control use.
- Assistant files:
  - `src/wicap_assist/action_ranker.py`
  - `src/wicap_assist/decision_features.py`
  - `src/wicap_assist/live.py`
  - `src/wicap_assist/soak_run.py`
- Tests:
  - shadow-vs-executed comparison tests.
- Exit criteria:
  - no learned action is executed until shadow quality thresholds pass.

## Milestone M5: Provider-Neutral OTLP Cloud Telemetry

### Work Slice M5.1 - Collector Deployment Profile (WiCAP) (Implemented)
- Goal: provide optional OpenTelemetry Collector profile in WiCAP compose.
- WiCAP files:
  - `docker-compose.yml` (profile additions)
  - `ops/otel/collector-config.yaml` (new)
- Requirements:
  - OTLP receiver on 4317/4318.
  - batch + memory_limiter + resourcedetection processors.
- Tests:
  - compose profile startup + config lint tests.
- Exit criteria:
  - local stack exports telemetry to configured backend in test mode.

### Work Slice M5.2 - Assistant Telemetry Spans/Metrics/Logs (Implemented Baseline)
- Goal: emit control loop telemetry from assistant.
- Assistant files:
  - `src/wicap_assist/telemetry.py` (new)
  - `src/wicap_assist/live.py`
  - `src/wicap_assist/soak_run.py`
- Tests:
  - unit tests for span/metric/log emission shape.
- Exit criteria:
  - one live cycle creates trace spans + metrics + structured logs.

### Work Slice M5.3 - OTLP Endpoint Profiles + Auth (Implemented Baseline)
- Goal: support provider-neutral OTLP endpoints and auth/header profiles (self-hosted, vendor-managed, cloud-native).
- WiCAP files:
  - `docs/CONFIGURATION.md`
  - `ops/otel/collector-config.yaml`
- Assistant files:
  - `src/wicap_assist/otlp_profile.py`
  - `src/wicap_assist/telemetry.py`
  - `README.md`
- Tests:
  - config validation tests for endpoint/auth profile completeness.
- Exit criteria:
  - cloud export works with selected OTLP endpoint and secure auth material.

### Work Slice M5.4 - Redaction and Data Governance
- Goal: enforce sensitive-data stripping before cloud export.
- WiCAP files:
  - telemetry processor config + redaction module.
- Assistant files:
  - `src/wicap_assist/util/redact.py`
  - telemetry emitter hooks.
- Tests:
  - redaction regression tests for secrets, tokens, and disallowed fields.
- Exit criteria:
  - blocked fields never leave host boundary.

## Milestone M6: Network Anomaly Intelligence Loop

### Work Slice M6.1 - Baseline Feature Windows
- Goal: generate 30s/60s/5m windows for traffic behavior per sensor/site.
- WiCAP files:
  - `nexus/intel/*`
  - feature aggregation modules.
- Tests:
  - replay-based window aggregation tests.
- Exit criteria:
  - deterministic feature windows persisted with timestamps.

### Work Slice M6.2 - Online Anomaly Scoring
- Goal: combine baseline z-score (MAD/EWMA) with existing WiCAP anomaly stack.
- WiCAP files:
  - `nexus/intel/anomaly/*`
- Tests:
  - synthetic anomaly replay tests.
- Exit criteria:
  - anomaly score + confidence + contributing features emitted per event.

### Work Slice M6.3 - Assistant Correlation and Action Routing
- Goal: map anomaly classes to action families and verification ladders.
- Assistant files:
  - `src/wicap_assist/guardian.py`
  - `src/wicap_assist/soak_control.py`
  - `src/wicap_assist/playbooks.py`
- Tests:
  - mapping contract tests and control-event assertions.
- Exit criteria:
  - anomaly classes deterministically select approved action ladders.

### Work Slice M6.4 - False Positive Feedback Loop
- Goal: operator feedback updates anomaly thresholds and action ranking safely.
- WiCAP files:
  - feedback capture endpoints/tables.
- Assistant files:
  - reward + confidence calibration updates.
- Tests:
  - threshold adjustment boundedness tests.
- Exit criteria:
  - feedback modifies model parameters only within bounded safe ranges.

## Milestone M7: Release Waves and Production Gates

### Work Slice M7.1 - Shadow Rollout
- Goal: deploy all new intelligence paths read-only.
- Exit criteria:
  - no autonomous action change; telemetry + memory + anomaly pipelines stable.

### Work Slice M7.2 - Canary Autonomous Rollout
- Goal: enable learned ranking for one site/profile with strict kill-switch.
- Exit criteria:
  - no unrecoverable escalations for N days; rollback budget not exceeded.

### Work Slice M7.3 - Full Rollout with SLO Gates
- Goal: scale to default profiles once canary SLOs pass.
- SLOs:
  - recovery success rate
  - mean time to recovery
  - recurrence reduction
  - false positive alert rate
- Exit criteria:
  - all SLOs pass for two consecutive release windows.

## 6. Test Strategy (Mandatory)
1. Unit tests for every new contract parser, policy evaluator, and scoring function.
2. Replay tests using fixed packet/event fixtures.
3. Integration tests with both repos checked out and shared fixtures.
4. Chaos tests for service-down, intermittent network loss, and telemetry backpressure.
5. Security tests for redaction, auth, and policy-denied actions.

## 7. CI Gates (Both Repos)
- Contract parity gate: fail on schema drift.
- Autonomous safety gate: fail if unallowlisted action can be executed.
- Kill-switch gate: fail if active kill-switch still allows recovery action.
- Telemetry gate: fail if exporter emits unredacted sensitive fields.
- Migration gate: fail if legacy DB cannot be opened and migrated.

## 8. Delivery Timeline (Recommended)
- Wave A (2-3 weeks): M0 + M1
- Wave B (2-3 weeks): M2 + M3
- Wave C (2-3 weeks): M4 + M5
- Wave D (2-3 weeks): M6 + M7 shadow/canary

## 9. Immediate Next 10-Day Execution Plan
1. Freeze v1 contracts and parity tests (M0.1/M0.2).
2. Implement plane-separated policy checks and deny precedence (M1.1).
3. Add episodic memory tables and episode writes for all control events (M2.1).
4. Define WiCAP event schema v1 with Suricata/Zeek-compatible field mappings (M3.1).
5. Stand up OTLP collector profile in non-production mode (M5.1).

## 10. Out of Scope for This Program
- Free-form autonomous shell command generation.
- Disabling existing rollback/kill-switch behavior.
- Shipping raw packet payloads to cloud telemetry sinks.

## 11. Document Update Rules
- Update this file when milestones/slices move states.
- Update `docs/ASSISTANT_ROADMAP.md` phase status in the same PR.
- Keep WiCAP `docs/ROADMAP.md` synchronized with milestone ids in this file.

## 12. References
- OpenClaw policy planes: https://raw.githubusercontent.com/openclaw/openclaw/main/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md
- OpenClaw failover concepts: https://raw.githubusercontent.com/openclaw/openclaw/main/docs/concepts/model-failover.md
- Nanobot repository (memory/cron/workspace restriction): https://github.com/HKUDS/nanobot
- Suricata EVE JSON output: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Zeek connection log reference: https://docs.zeek.org/en/current/logs/conn.html
- Zeek log formats: https://docs.zeek.org/en/current/log-formats.html
- OTLP specification: https://opentelemetry.io/docs/specs/otlp/
- OpenTelemetry Collector: https://opentelemetry.io/docs/collector/
- OpenTelemetry security best practices: https://opentelemetry.io/docs/security/config-best-practices/
