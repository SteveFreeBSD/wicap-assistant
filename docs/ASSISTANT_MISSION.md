# WICAP Assistant Mission

## Purpose
Provide deterministic operational memory and recovery guidance for WICAP by turning historical evidence into actionable triage outputs.

## Trusted Inputs
- Codex chat logs
- Soak log files
- Harness scripts
- Incident history
- Playbooks
- Regression data
- Antigravity conversation artifacts (task.md, walkthrough.md, implementation_plan.md)
- WICAP CHANGELOG.md

## Outputs
- Incident reports
- Playbooks
- Regression reports
- Guardian alerts
- Recommendations (JSON only)

## What This Assistant Must Never Do
- Execute operational or infrastructure commands on live WICAP systems.
- Modify WICAP source code or runtime configuration as an autonomous action.
- Produce speculative fixes that are not supported by stored historical evidence.
- Perform network-dependent lookups as a source of truth for recommendations.

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

## Next Allowed Phases
- Docker event stream monitoring and container lifecycle tracking.
- Broader deterministic ingestion adapters for additional approved WICAP operational artifacts.
- Cross-incident pattern rollups for recurring subsystem failures.

