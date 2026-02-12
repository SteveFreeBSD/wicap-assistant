# wicap-assistant

Deterministic reliability/control assistant for WiCAP. It can run as:
- A read-only runtime observer
- A supervised assist controller with allowlisted actions
- A guarded autonomous control loop with rollback and kill-switches

It is network-aware and memory-backed, but policy-bounded: it does not execute arbitrary commands.

## What It Does
- Ingests evidence from WiCAP logs, harness scripts, network contract streams, changelogs, and Codex artifacts.
- Correlates recurring failures and generates deterministic recommendations/playbooks.
- Runs live control loops (`observe`, `assist`, `autonomous`) with audit trails.
- Persists memory artifacts for decisions, outcomes, and working context across sessions.
- Emits OTLP-aligned telemetry envelopes with redaction controls.
- Includes deterministic known-issue routing for common rollout failures (allowlist 403s, UI startup races, capture permission errors, compose misuse).

## Live Control Modes
- `observe` (alias: `monitor`)
  - Read-only; reports health, signatures, and recommended next actions.
- `assist`
  - Executes allowlisted recovery actions under policy controls.
- `autonomous`
  - Enables autonomous policy profile with rollback sequence + kill-switch checks.

## Agent Behavior Model
The assistant follows a deterministic sense-decide-act loop:
1. Sense: probe docker/network/http status and ingest recent signatures/anomaly events.
2. Decide: combine historical evidence, anomaly routing, and shadow-ranked action context.
3. Act: execute only allowlisted actions when mode/policy permits.
4. Learn: persist decision features, episodes, outcomes, and working-memory state.
5. Guide: emit operator guidance and promotion gate metrics.

## Safety Model
- Action allowlist only (`status_check`, `compose_up`, `shutdown`, `restart_service:<allowlisted>`).
- Plane-separated policy checks (runtime/tool/elevated).
- Autonomous kill-switches:
  - env: `WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH=1`
  - sentinel file: `<WICAP_REPO_ROOT>/.wicap_assist_autonomous.kill`
- Rollback ladder support in autonomous policy profile.
- Runtime contract gate available pre-run (`contract-check --enforce`).

## Requirements
- Python 3.11+
- Local filesystem access to WiCAP and local evidence directories
- No network required for ingest/recommend/report workflows

## Key Configuration
- `WICAP_REPO_ROOT`: override WiCAP repo path (auto-discovery order: `/wicap`, `./wicap`, `../wicap`, then `~/apps/wicap`).
- `CODEX_HOME`: override Codex artifact root (default: `~/.codex`).
- `WICAP_ASSIST_ANTIGRAVITY_ROOT`: override Antigravity ingest root (fallback: `ANTIGRAVITY_ROOT`, then `<CODEX_HOME>/antigravity/brain`, then `~/.gemini/antigravity/brain`).
- `WICAP_ASSIST_OTLP_PROFILE`: telemetry export profile (`disabled`, `self_hosted`, `vendor`, `cloud`).
- `WICAP_ASSIST_OTLP_HTTP_ENDPOINT`: OTLP HTTP endpoint for control-loop telemetry export.
- `WICAP_ASSIST_OTLP_HEADERS`: optional OTLP headers (`k=v,k2=v2` or JSON object).
- `WICAP_ASSIST_OTLP_AUTH_BEARER`: optional bearer token (added as `Authorization` header).
- `WICAP_ASSIST_OTLP_API_KEY`: optional API key (added as `x-api-key` header).
- `WICAP_ASSIST_OTLP_TIMEOUT_SECONDS`: OTLP request timeout (default `1.5`).

## Install
```bash
cd wicap-assistant
python -m pip install -e .
```
If the `wicap-assist` entrypoint is not on your shell `PATH`, run commands as
`PYTHONPATH=src python -m wicap_assist.cli <command> ...`.

## Fresh System Bootstrap
Use the assistant to interactively generate/update WiCAP's `.env` for headless hosts:
```bash
wicap-assist setup-wicap-env --repo-root /opt/wicap
```
The wizard now covers:
- Required boot values (SQL + internal secret + Redis)
- Headless-safe internal UI target (`WICAP_UI_URL`, loopback default on host-network deploys) plus LAN access guidance
- Safe Wi-Fi capture selection with management-interface protection (`wlo1` exclusion by default)
- Bluetooth sniffer wiring from `/dev/serial/by-id` when enabled
- Optional queue/dwell/OTLP tuning

It also supports:
- `--dry-run` to preview `.env` without writing
- Timestamped `.env` backup before overwrite (disable with `--no-backup`)
- Final next-step commands for `docker compose up -d --build`

Recommended first-run sequence on a new server:
```bash
wicap-assist setup-wicap-env --repo-root /opt/wicap
wicap-assist validate-wicap-env --repo-root /opt/wicap
cd /opt/wicap
docker compose up -d --build redis processor ui
docker compose ps
curl -fsS http://127.0.0.1:8080/health || true
docker compose up -d scout
```

## Live Control Quickstart
Preflight runtime contract:
```bash
wicap-assist contract-check --enforce
```

Read-only live monitor:
```bash
wicap-assist live --interval 10 --once --control-mode observe
```

Assist mode live control:
```bash
wicap-assist live --interval 10 --control-mode assist
```

Autonomous supervised soak:
```bash
wicap-assist soak-run --duration-minutes 30 --playwright-interval-minutes 5 --control-mode autonomous
```

Interactive agent console:
```bash
wicap-assist agent --control-mode assist
```
Policy explain snapshot:
```bash
wicap-assist agent explain-policy --json
```
Forecast + control-center snapshots:
```bash
wicap-assist agent forecast --lookback-hours 6
wicap-assist agent control-center --control-mode assist
```
The console supports prompts like:
- `status` or `stats` (command-center snapshot with control/memory metrics)
- `mode assist` / `mode autonomous`
- `action status_check` / `action compose_up` / `action restart_service:wicap-ui`
- `start soak for 10 minutes assist`
- `recommend <target>`, `incident <target>`

## Docker Sidecar (Optional)
Build/run with compose:
```bash
docker compose -f compose.assistant.yml --profile observe up -d --build wicap-assist-live
```
Run always-on control mode service:
```bash
docker compose -f compose.assistant.yml --profile control up -d --build wicap-assist-control
```
Run ad-hoc assistant commands inside the container:
```bash
docker compose -f compose.assistant.yml --profile control run --rm wicap-assist recommend "<signature>"
docker compose -f compose.assistant.yml --profile control run --rm -it wicap-assist agent --control-mode assist
```
Notes:
- The compose file mounts the WiCAP repo at `/wicap` and sets `WICAP_REPO_ROOT=/wicap`.
- By default it expects WiCAP checked out next to this repo (`../wicap`). Override with `WICAP_HOST_REPO_ROOT=/opt/wicap`.
- `wicap-assist-live` is monitor-only (`--control-mode observe`) and does not mount `/var/run/docker.sock`.
- `wicap-assist-control` is the live control loop (`--control-mode assist`) using allowlisted recovery actions.
- `wicap-assist-control` and interactive `wicap-assist` mount `/var/run/docker.sock` for allowlisted control actions.

## Memory and Learning Surfaces
- Episodic memory: control episodes/events/outcomes persisted per decision path.
- Working memory: unresolved signatures + pending actions retained across resumed sessions.
- Decision feature store: contextual vectors, shadow ranking output, and reward labels.
- Shadow quality gate: learned ranking remains non-authoritative until gate thresholds pass.

## Canonical Workflow
1. Bootstrap WiCAP `.env` on fresh systems
```bash
wicap-assist setup-wicap-env
```
2. Validate runtime contract gate (recommended before startup/deploy/soak promotion)
```bash
wicap-assist contract-check --enforce
```
3. Run supervised soak (optional one-command orchestration)
```bash
wicap-assist soak-run --duration-minutes 10 --playwright-interval-minutes 2 --baseline-path /tmp/baseline.json --baseline-update
```
If duration/interval flags are omitted, `soak-run` can use learned defaults from successful historical WICAP session commands.
`soak-run` also performs live babysit observation cycles during the run and reports live metrics at completion.
`soak-run --dry-run` prints learned runbook steps inferred from successful historical sessions.
`soak-run` executes deterministic managed phases: preflight, soak execute, observe, soak ingest, incident report, finalize.
`soak-run` executes deterministic preflight startup actions (`compose_up`, `status_check`) and records them for audit.
`soak-run --control-mode assist` prefers the full live harness (`scripts/run_live_soak.py`) when available.
`soak-run --control-mode autonomous` applies the autonomous policy profile (`autonomous-v1`) with rollback sequencing and kill-switch checks.
Autonomous kill-switches: `WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH=1` or sentinel file `<WICAP_REPO_ROOT>/.wicap_assist_autonomous.kill`.
`soak-run` reports deterministic learning readiness (`ready|partial|insufficient`) from historical evidence quality.
`soak-run` emits deterministic manager actions (explicit next steps) from learned history and run outcome.
`soak-run` prints simple live CLI progress lines during execution (phase and observation cycle updates).
`soak-run` and `live` both include operator guidance lines (what to check next) during monitoring output.
`soak-run` persists control session state/events (`control_sessions`, `control_session_events`) for audit and resume safety.
`soak-run` performs an explicit post-run cleanup actuator pass (`shutdown`) in assist mode and records cleanup status.
4. Ingest evidence
```bash
wicap-assist ingest --scan-codex --scan-soaks --scan-harness --scan-antigravity --scan-changelog
```
5. Analyze recurrence and trends
```bash
wicap-assist cross-patterns
wicap-assist daily-report --days 3 --top 10
wicap-assist rollup --days 30 --top 10
```
6. Generate operational artifacts
```bash
wicap-assist bundle <target>
wicap-assist incident <target>
wicap-assist playbooks --top 5
```
7. Run deterministic recommendations and audits
```bash
wicap-assist recommend <target-or-signature>
wicap-assist fix-lineage "<signature>"
wicap-assist confidence-audit --limit 100
```
8. Monitor live soak/runtime status
```bash
wicap-assist guardian
wicap-assist live --interval 10 --once
wicap-assist agent --control-mode assist
```
Guardian default monitoring covers soak, verification, and runtime logs under `<WICAP_REPO_ROOT>`:
`logs_soak_*`, `logs_verification_*`, `soak_test_*.log`, `wicap.log`, `wicap_verified.log`, `wicap-ui/ui.log`.

Data is stored in `./data/assistant.db`.

## Command Reference
- `wicap-assist ingest [--scan-codex] [--scan-soaks] [--scan-harness] [--scan-network-events] [--scan-antigravity] [--scan-changelog]`
- `wicap-assist setup-wicap-env [--repo-root <path>] [--env-file <file>] [--yes] [--dry-run] [--no-backup]`
- `wicap-assist validate-wicap-env [--repo-root <path>] [--env-file <file>] [--no-live-probe] [--require-live] [--json]`
- `wicap-assist triage "<query>"`
- `wicap-assist bundle <target> [--json]`
- `wicap-assist incident <target> [--json-input <file>] [--overwrite]`
- `wicap-assist playbooks [--top N]`
- `wicap-assist daily-report [--days N] [--top N] [--json]`
- `wicap-assist guardian [--path <path>] [--interval <seconds>] [--once] [--json]`
- `wicap-assist recommend <incident-id-or-signature>`
- `wicap-assist rollup [--days N] [--top N] [--json]`
- `wicap-assist changelog-stats`
- `wicap-assist contract-check [--contract-path <file>] [--json] [--enforce|--no-enforce]`
- `wicap-assist cross-patterns [--min-occurrences N] [--min-span-days X] [--top N] [--json]`
- `wicap-assist backfill-report [--json]`
- `wicap-assist fix-lineage "<signature>" [--json]`
- `wicap-assist confidence-audit [--limit N] [--json]`
- `wicap-assist memory-maintenance [--lookback-days N] [--stale-days N] [--max-decision-rows N] [--max-session-rows N] [--prune-stale] [--output <file>] [--json]`
- `wicap-assist rollout-gates [--lookback-days N] [--min-shadow-samples N] [--min-shadow-agreement-rate F] [--min-shadow-success-rate F] [--min-reward-avg F] [--max-autonomous-escalation-rate F] [--min-autonomous-runs N] [--max-rollback-failures N] [--min-proactive-samples N] [--min-proactive-success-rate F] [--max-proactive-relapse-rate F] [--history-file <file>] [--required-consecutive-passes N] [--enforce] [--json]`
- `wicap-assist soak-run [--duration-minutes N] [--playwright-interval-minutes N] [--baseline-path <file>] [--baseline-update|--no-baseline-update] [--observe-interval-seconds N] [--control-mode monitor|observe|assist|autonomous] [--control-check-threshold N] [--control-recover-threshold N] [--control-max-recover-attempts N] [--control-action-cooldown-cycles N] [--require-runtime-contract|--no-require-runtime-contract] [--runtime-contract-path <file>] [--stop-on-escalation|--no-stop-on-escalation] [--dry-run]`
- `wicap-assist live [--interval N] [--once] [--control-mode monitor|observe|assist|autonomous] [--control-check-threshold N] [--control-recover-threshold N] [--control-max-recover-attempts N] [--control-action-cooldown-cycles N] [--stop-on-escalation]`
- `wicap-assist agent [console|explain-policy|forecast|control-center] [--control-mode monitor|observe|assist|autonomous] [--observe-interval-seconds N] [--lookback-hours N] [--json]`

## Calibration Rules
- Confidence is hard-capped below `0.95` unless strict criteria are met.
- Confidence can reach `>= 0.95` only when all are true:
  - at least 2 historical fix sessions for the signature
  - verification success score is high (`>= 8`)
  - verification outcomes include positive pass evidence
  - no recurrence penalty is present
- Recurrence without verified success applies extra penalty.
- Verification outcomes affect confidence deterministically:
  - `pass` outcomes increase confidence (capped effect)
  - `fail` outcomes decrease confidence
  - `unknown` outcomes do not increase confidence

## Documentation Sources of Truth
- Mission contract: `docs/ASSISTANT_MISSION.md`
- Engineering roadmap: `docs/ASSISTANT_ROADMAP.md`
- Agent governance and authority: `docs/AGENT_ALIGNMENT.md`
- Execution plan and release gates: `docs/HANDOFF_PLAN.md`
- Quality gate definitions: `docs/QUALITY_GATES.md`
- Documentation map: `docs/DOCS_INDEX.md`
- Historical audit records: `docs/archive/ARCHITECT_REVIEW.md`, `docs/archive/REVIEW_WALKTHROUGH.md`

## Dev Checks
```bash
python -m compileall src
python -m pytest -q
./scripts/smoke_matrix.sh
./scripts/live_testing_gate.sh
```
