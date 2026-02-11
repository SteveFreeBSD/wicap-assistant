# WICAP Assistant Agent Alignment

## Purpose
Define role boundaries, authority order, and change-control rules for Codex, Antigravity (Claude), and the WICAP Assistant program while enabling approved cross-repo expansion for network-aware agentic capabilities.

## Roles
- Codex:
  - Primary implementation owner for repository changes, tests, migrations, and release-safe integration.
  - Responsible for deterministic behavior, schema safety, and preserving output contracts.
  - May implement scope expansion only when the scope is explicitly approved in mission/roadmap/handoff contracts.
- Antigravity (Claude):
  - Analysis and pattern-mining collaborator focused on evidence interpretation and cross-artifact signal discovery.
  - May propose roadmap-aligned improvements and validation ideas.
  - Must not bypass approval workflow or safety guardrails.
- WICAP Assistant:
  - Deterministic reliability/control system operating within mission and policy constraints.
  - Must keep autonomous behavior auditable, bounded, and kill-switch governed.

## Authority Hierarchy
1. `docs/ASSISTANT_MISSION.md`
2. `docs/ASSISTANT_ROADMAP.md`
3. `docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`
4. `docs/AGENT_ALIGNMENT.md`
5. Existing code and implementation details

If any lower-level artifact conflicts with a higher-level artifact, the higher-level artifact is authoritative.

## Strict Change Workflow
1. Propose:
  - Submit a written change proposal tied to a roadmap phase or workslice id.
  - Include: objective, scope, non-goals, evidence basis, risk, test plan, and affected files.
  - Explicitly state mission alignment and guardrail compliance.
2. Approve:
  - Human approval is required before implementation.
  - No autonomous feature/source/surface additions before approval.
3. Implement:
  - Keep changes minimal and phase-scoped.
  - Preserve stable output contracts unless contract change is explicitly approved.
  - Include additive migrations for schema changes.
4. Verify:
  - Add/update deterministic tests for all changed behavior.
  - Run relevant suite(s) and record results.
  - Provide evidence mapping: source -> change -> expected outcome.
5. Close:
  - Update roadmap/workslice status only after verification.
  - Document residual risks and follow-up items.

## Scope Expansion Control
- No agent may autonomously expand scope beyond approved mission/roadmap/workslice boundaries.
- Scope expansion is allowed only when explicitly approved and contract-defined.
- Prohibited without explicit approval:
  - Unbounded autonomous actions
  - Unallowlisted operational control paths
  - Unredacted external telemetry export
  - Runtime dependence on external internet lookups for control decisions

## Evidence and Test Requirements
- Every behavioral change must be backed by trusted evidence or deterministic fixtures.
- Every behavioral change must include regression tests.
- Required for completion:
  - Deterministic test coverage for changed logic
  - Passing `pytest -q` (unless explicitly waived)
  - Contract parity checks for cross-repo integration changes
  - Clear mapping from evidence -> change -> expected outcome
- No speculative logic may be merged without evidence and tests.
