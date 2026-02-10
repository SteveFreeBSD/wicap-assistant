# WICAP Assistant Agent Alignment

## Purpose
Define clear role boundaries, authority order, and change-control rules for Codex, Antigravity (Claude), and the WICAP Assistant project.

## Roles
- Codex:
  - Primary implementation owner for repository changes, tests, migrations, and release-safe integration.
  - Responsible for deterministic behavior, schema safety, and preserving existing output contracts.
  - Must not expand scope without explicit approval.
- Antigravity (Claude):
  - Analysis and pattern-mining collaborator focused on evidence interpretation and cross-artifact signal discovery.
  - May propose roadmap-aligned improvements and validation ideas.
  - Must not directly redefine project scope or bypass approval workflow.
- WICAP Assistant:
  - Deterministic reliability system that ingests trusted evidence and produces mission-approved outputs.
  - Must operate within guardrails defined by mission and roadmap.

## Authority Hierarchy
1. `docs/ASSISTANT_MISSION.md`
2. `docs/ASSISTANT_ROADMAP.md`
3. `docs/AGENT_ALIGNMENT.md`
4. Existing code and implementation details

If any lower-level artifact conflicts with a higher-level artifact, the higher-level artifact is authoritative.

## Strict Roadmap Change Workflow
1. Propose:
  - Submit a written change proposal tied to a specific roadmap phase.
  - Include: objective, scope, non-goals, evidence basis, risk, test plan, and affected files.
  - Explicitly state mission alignment and guardrail compliance.
2. Approve:
  - Human approval is required before implementation.
  - No autonomous feature additions, source additions, or command additions before approval.
3. Implement:
  - Keep changes minimal and phase-scoped.
  - Preserve stable output contracts unless contract change is explicitly approved.
  - Include safe migration logic for schema changes.
4. Verify:
  - Add or update deterministic tests for all changed behavior.
  - Run full relevant test suite and record results.
  - Provide concrete evidence (test outputs, deterministic fixture results, or query-backed validation).
5. Close:
  - Update roadmap status only after verified implementation.
  - Document residual risks and follow-up work items.

## Autonomous Scope Expansion Prohibited
- No agent may autonomously expand project scope beyond approved mission and roadmap boundaries.
- Prohibited without explicit approval:
  - New product features outside approved phase scope
  - New ingestion sources
  - New output types
  - New operational control paths
- If scope is ambiguous, stop and request direction before coding.

## Evidence and Test Requirements
- Every behavioral change must be backed by evidence from trusted inputs or deterministic fixtures.
- Every behavioral change must include tests that would fail on regression.
- Required for completion:
  - Deterministic test coverage for changed logic
  - Passing test run (`pytest -q`) unless explicitly waived by approver
  - Clear mapping from evidence -> change -> expected outcome
- No speculative logic may be merged without evidence.
