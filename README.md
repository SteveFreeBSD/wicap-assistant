# wicap-assistant

Deterministic WICAP reliability assistant: ingest local operational evidence, correlate failures, and generate structured triage outputs.

## Requirements
- Python 3.11+
- Local filesystem access to WICAP and local evidence directories
- No network required for ingest/recommend/report workflows

## Configuration
- `WICAP_REPO_ROOT`: override the WICAP repo path (default: `~/apps/wicap`).
- `CODEX_HOME`: override Codex artifact root (default: `~/.codex`).

## Install
```bash
cd wicap-assistant
python -m pip install -e .
```
If the `wicap-assist` entrypoint is not on your shell `PATH`, run commands as
`PYTHONPATH=src python -m wicap_assist.cli <command> ...`.

## Docker (Optional Sidecar)
Build/run with docker compose:
```bash
docker compose -f compose.assistant.yml build
docker compose -f compose.assistant.yml --profile observe up -d wicap-assist-live
```
Run always-on control mode service:
```bash
docker compose -f compose.assistant.yml --profile control up -d wicap-assist-control
```
Run ad-hoc assistant commands inside the container:
```bash
docker compose -f compose.assistant.yml --profile control run --rm wicap-assist recommend "<signature>"
docker compose -f compose.assistant.yml --profile control run --rm -it wicap-assist agent --control-mode assist
```
Notes:
- The compose file mounts the WICAP repo at `/wicap` and sets `WICAP_REPO_ROOT=/wicap`.
- `wicap-assist-live` is monitor-only (`--control-mode observe`) and does not mount `/var/run/docker.sock`.
- `wicap-assist-control` is the live control loop (`--control-mode assist`) using allowlisted recovery actions.
- `wicap-assist-control` and interactive `wicap-assist` mount `/var/run/docker.sock` for allowlisted control actions.

## Canonical Workflow
1. Validate runtime contract gate (recommended before startup/deploy/soak promotion)
```bash
wicap-assist contract-check --enforce
```
2. Run supervised soak (optional one-command orchestration)
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
3. Ingest evidence
```bash
wicap-assist ingest --scan-codex --scan-soaks --scan-harness --scan-antigravity --scan-changelog
```
4. Analyze recurrence and trends
```bash
wicap-assist cross-patterns
wicap-assist daily-report --days 3 --top 10
wicap-assist rollup --days 30 --top 10
```
5. Generate operational artifacts
```bash
wicap-assist bundle <target>
wicap-assist incident <target>
wicap-assist playbooks --top 5
```
6. Run deterministic recommendations and audits
```bash
wicap-assist recommend <target-or-signature>
wicap-assist fix-lineage "<signature>"
wicap-assist confidence-audit --limit 100
```
7. Monitor live soak/runtime status
```bash
wicap-assist guardian
wicap-assist live --interval 10 --once
wicap-assist agent --control-mode assist
```
Guardian default monitoring covers soak, verification, and runtime logs under `<WICAP_REPO_ROOT>`:
`logs_soak_*`, `logs_verification_*`, `soak_test_*.log`, `wicap.log`, `wicap_verified.log`, `wicap-ui/ui.log`.

Data is stored in `./data/assistant.db`.

## Command Reference
- `wicap-assist ingest [--scan-codex] [--scan-soaks] [--scan-harness] [--scan-antigravity] [--scan-changelog]`
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
- `wicap-assist backfill-report [--min-occurrences N] [--min-span-days X] [--json]`
- `wicap-assist fix-lineage "<signature>" [--limit N] [--json]`
- `wicap-assist confidence-audit [--limit N] [--json]`
- `wicap-assist soak-run [--duration-minutes N] [--playwright-interval-minutes N] [--baseline-path <file>] [--baseline-update|--no-baseline-update] [--observe-interval-seconds N] [--control-mode monitor|observe|assist|autonomous] [--control-check-threshold N] [--control-recover-threshold N] [--control-max-recover-attempts N] [--control-action-cooldown-cycles N] [--require-runtime-contract|--no-require-runtime-contract] [--runtime-contract-path <file>] [--stop-on-escalation|--no-stop-on-escalation] [--dry-run]`
- `wicap-assist live [--interval N] [--once] [--control-mode monitor|observe|assist|autonomous] [--control-check-threshold N] [--control-recover-threshold N] [--control-max-recover-attempts N] [--control-action-cooldown-cycles N] [--stop-on-escalation]`
- `wicap-assist agent [--control-mode monitor|observe|assist|autonomous] [--observe-interval-seconds N]`

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
```
