# Live Control Agent Research Notes

This document summarizes proven patterns from widely used automation/controller projects and maps them to a safe, deterministic “live control agent” design for WICAP.

Scope: architecture patterns, safety controls, and operator workflow. Not a feature spec.

## Reference Projects (Patterns Worth Copying)

### Kubernetes Controllers (Reconciliation Loop)
- Key idea: a non-terminating control loop continuously moves current state toward desired state.
- Useful properties:
  - Level-triggered: recompute from current state each cycle (robust to missed events).
  - Idempotent actions: safe to retry; no reliance on “exactly once”.
  - Separation: desired state vs. observed state; store observed status back for other loops.
- Why it matters for WICAP: WICAP is a stateful docker-compose system; a reconciling controller makes “keep it running + keep soak progressing” practical.
- References:
  - https://kubernetes.io/docs/concepts/architecture/controller/

### StackStorm (Event-Driven Automation + ChatOps + Audit)
- Key idea: “IFTTT for Ops”: sensors emit triggers, rules map triggers + criteria to actions/workflows, with an audit trail.
- Useful properties:
  - Explicit trigger → rule → action/workflow model.
  - Auditable executions with context (what fired, what ran, what happened).
  - Pack/plugin approach to integrate new tools deterministically.
- Why it matters for WICAP: WICAP failures can be detected as triggers (signature spikes, service down, UI checks failing) and mapped to allowlisted recovery workflows with full audit.
- References:
  - https://github.com/StackStorm/st2
  - https://docs.stackstorm.com/latest/

### Rundeck (Runbook Automation + Self-Service)
- Key idea: standardize runbooks as jobs/workflows; provide controlled self-service execution with logs and audit.
- Useful properties:
  - “Runbook as code” mindset (jobs/workflows are first-class).
  - Access control and auditable execution history.
  - Clear separation between building automation and granting operators safe execution.
- Why it matters for WICAP: WICAP soak startup/shutdown is a runbook problem; encode it as deterministic phases with safe parameters and strict allowlists.
- References:
  - https://github.com/rundeck/rundeck

### Botkube (ChatOps Monitoring + Secure Commands)
- Key idea: combine real-time alerting with controlled operational actions (commands) via a chat interface, gated by security/permissions.
- Useful properties:
  - “Alert → take action” feedback loop.
  - Plugin-driven sources and actions.
  - “Securely run commands” is a first-class design requirement.
- Why it matters for WICAP: the WICAP assistant should behave like “ChatOps for a single host” with a strict allowlist and audit trail.
- References:
  - https://github.com/kubeshop/botkube

### OpenClaw (Policy Planes + Fallback Chains)
- Key idea: separate safety/control concerns into independent planes and make failover deterministic.
- Useful properties:
  - Distinct runtime planes: sandbox runtime (`where` tools run), tool policy (`which` tools are callable), and elevated execution (`explicit host escape hatch`), with deny-precedence.
  - Deterministic auth/profile rotation and model fallback with cooldown/disable windows.
  - Operator-visible inspectability (`sandbox explain`) for current effective policy state.
- Why it matters for WICAP: deterministic control needs clear mode/profile semantics, explicit kill-switch behavior, and bounded fallback/rollback chains that can be audited post-incident.
- References:
  - https://github.com/openclaw/openclaw
  - https://raw.githubusercontent.com/openclaw/openclaw/main/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md
  - https://raw.githubusercontent.com/openclaw/openclaw/main/docs/concepts/model-failover.md

### nanobot (Lightweight Agent Structure + Cron + Tool Sandboxing)
- Key idea: keep an agent core small and composable; provide persistent memory, skills/tools, scheduled tasks, and deployment via Docker with persisted config.
- Useful properties:
  - Clear internal boundaries: loop, memory, skills/tools, cron, heartbeat, channels.
  - Tool restriction flag (`restrictToWorkspace`) to enforce sandboxing.
  - Portable deployment with persisted config/“workspace” volume.
- Why it matters for WICAP: a portable “agent shell” can host the WICAP controller loop and tools, but WICAP control must remain deterministic and allowlisted (no arbitrary execution).
- References:
  - https://github.com/HKUDS/nanobot

## What Works Best For WICAP (Synthesis)

### 1) Reconciliation First, Events Second
Use a reconciliation loop as the backbone:
- Each cycle:
  1. Probe current WICAP state (containers, ports, health endpoints, log tails).
  2. Normalize/cluster signatures and classify severity.
  3. Compare to desired state (soak running, services up, UI checks passing).
  4. If drift exists, plan the smallest allowlisted action that reduces drift.
  5. Execute only if in an operator-initiated control session.
  6. Persist observations and actions (audit trail).

Events/triggers should augment the loop (wake-ups, alerts), not replace it.

### 2) Allowlisted Actuators + Idempotency
Every state-changing operation must be:
- Allowlisted by name (not arbitrary shell).
- Idempotent or “safe to retry”.
- Guardrailed with:
  - strict timeouts
  - preconditions (only run if it can help)
  - postconditions (verification probes)
  - backoff/cooldown

### 3) Strong Safety + Operator Intent
Borrow from ChatOps automation systems:
- Split modes:
  - `monitor`: read-only, always safe
  - `assist`: allowlisted recovery actions, only when operator starts a session
- Within `assist`, tier actions:
  - safe (status/logs/health checks)
  - caution (compose up/down, restarts)
  - destructive (disallowed by default; require explicit operator override)

### 4) Durable State + Audit Trail
Like controllers and runbook systems:
- Persist control sessions and phase events.
- Persist every action execution with commands, exit status, and redacted output snippets.
- Persist “snapshot packs” around failures/escalations so postmortems are reproducible.

### 5) Portable Deployment (But Don’t Hide the Host)
Containerization helps portability, but WICAP control needs host integration:
- Prefer a sidecar-style deployment:
  - assistant runs in its own container/service
  - mounts only required WICAP paths + dedicated `data/` volume
  - control mode optionally mounts `docker.sock`
- Avoid “fully privileged container does everything” as the default.

## Recommended Validation Strategy
- Shadow mode first: run full probe+planning loop, do not execute actions, record what it would do.
- Canary: allow one or two recovery actions (status_check, compose_up) with strict stop rules.
- Regression: replay past incident signatures and ensure:
  - actions chosen are allowlisted
  - escalation happens deterministically
  - audit trail and snapshot packs are produced
