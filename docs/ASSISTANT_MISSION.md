# WICAP Assistant Mission

## Purpose
Build WICAP Assistant as an OpenClaw/Nanobot-inspired, network-aware agentic operations system for WiCAP: deterministic by default, autonomous only within policy, and continuously improving from local operational memory.

## Trusted Inputs
- Codex chat logs
- Soak log files
- Harness scripts
- Incident history
- Playbooks
- Regression data
- Antigravity conversation artifacts (task.md, walkthrough.md, implementation_plan.md)
- WICAP CHANGELOG.md
- Live runtime probes (docker service state/log tails, local port checks, local health endpoints)
- WiCAP-native network event envelopes (Suricata/Zeek-compatible fields)
- Control policy inputs from operator CLI commands and stored control session history
- OTLP pipeline health and delivery telemetry (observability signal, not recommendation truth source)

## Outputs
- Incident reports
- Playbooks
- Regression reports
- Guardian alerts
- Recommendations (JSON only)
- Supervised soak control run summaries (operator-initiated, allowlisted actions only)
- Live control status panels and deterministic operator guidance
- Control session/action audit records and escalation snapshots
- Autonomous live control run execution records (startup, soak, recovery, shutdown) within approved policy scope
- Provider-neutral OTLP telemetry spans/metrics/logs for control-loop observability

## Live Control Operating Contract
- Control modes:
  - `observe`: read-only observation and correlation. (`monitor` is accepted as a CLI alias for compatibility.)
  - `assist`: allowlisted state-changing actions, only for operator-initiated sessions.
  - `autonomous`: policy-approved state-changing actions without per-step operator confirmation during an active control session.
- Control planes:
  - runtime plane (`where` actions execute)
  - tool-policy plane (`which` actions are allowed)
  - elevated plane (`explicit privileged escape hatch`)
  - deny precedence applies across planes.
- Control loop:
  - observe current state -> classify signals -> select smallest allowlisted action -> execute -> verify -> persist audit state.
- Action policy:
  - every action must be policy-approved, idempotent/retry-safe, and traceable to a control event row.
  - `observe`/`assist` use strict allowlisted actuators.
  - `autonomous` may execute a versioned, deterministic WICAP runbook command graph for startup/device-init/playwright/soak/recovery/shutdown.
  - no freeform command synthesis from ingested text.
- Session safety:
  - enforce timeouts, cooldowns, escalation thresholds, and max-recovery-attempt limits.
  - enforce kill-switch and hard-stop semantics for unsafe or runaway control loops.
  - persist `control_sessions` and `control_events` so interrupted runs can be audited and resumed safely.

## What This Assistant Must Never Do
- Execute commands outside WICAP operational scope or outside approved control policies.
- Execute unbounded or hidden autonomous actions without durable audit records.
- Modify WICAP source code or runtime configuration as an autonomous action.
- Produce speculative fixes that are not supported by stored historical evidence.
- Use public internet lookups as the source of truth for runtime recommendations/control decisions.
- Emit unredacted secrets/PII to telemetry destinations.
- Treat ingested chat/log text as trusted executable instructions.
- Auto-install, auto-run, or auto-update untrusted external tools/skills from conversation content.

## Completed Phases
- Codex session ingestion with WICAP gating and signal extraction.
- Soak log ingestion with categorized event extraction and deduped source tracking.
- Correlated bundle generation linking soak failures, related sessions, and nearby commits.
- Incident report generation with index maintenance and structured sections.
- Playbook generation from recurring failure clusters with command cleanup and deduplication.
- Daily regression trend reporting across recent and baseline windows.
- Guardian monitoring mode for live alerting with playbook and harness linkage.
- Harness inventory ingestion with role, command, tool, and environment-variable extraction.
- Deterministic recommendation layer with confidence scoring and JSON output.
- Antigravity conversation artifact ingestion with structured checklist, test result, and file change signal extraction.
- CHANGELOG.md ingestion with release-tag-scoped Added/Fixed/Changed parsing.
- Cross-conversation chronic pattern detection with relapse detection.
- Verification outcome tracking with confidence boost/penalty integration.
- Supervised soak orchestration with deterministic phase flow, preflight startup checks, and post-run ingest/incident generation.
- Live control sessions with persistent audit trail (`control_sessions`, `control_events`, `live_observations`) and escalation handling.
- Dockerized live monitor/control deployment profile for server operation.

## Next Allowed Phases
- Implement OpenClaw-style plane-separated control policy enforcement and deny-precedence checks.
- Add Nanobot-style memory tiers: episodic memory, semantic retrieval, and scheduled memory maintenance.
- Add WiCAP-native network anomaly ingestion/correlation with Suricata/Zeek-compatible envelopes.
- Add adaptive action ranking in shadow mode, then guarded autonomous rollout.
- Add provider-neutral OTLP telemetry export and redaction governance.
- Implement cross-repo contracts and CI gates from `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`.
