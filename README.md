# wicap-assistant

Deterministic WICAP reliability assistant: ingest local operational evidence, correlate failures, and generate structured triage outputs.

## Requirements
- Python 3.11+
- Local filesystem access to WICAP and local evidence directories
- No network required for ingest/recommend/report workflows

## Install
```bash
cd wicap-assistant
python -m pip install -e .
```
If the `wicap-assist` entrypoint is not on your shell `PATH`, run commands as
`PYTHONPATH=src python -m wicap_assist.cli <command> ...`.

## Canonical Workflow
1. Ingest evidence
```bash
wicap-assist ingest --scan-codex --scan-soaks --scan-harness --scan-antigravity --scan-changelog
```
2. Analyze recurrence and trends
```bash
wicap-assist cross-patterns
wicap-assist daily-report --days 3 --top 10
wicap-assist rollup --days 30 --top 10
```
3. Generate operational artifacts
```bash
wicap-assist bundle <target>
wicap-assist incident <target>
wicap-assist playbooks --top 5
```
4. Run deterministic recommendations and audits
```bash
wicap-assist recommend <target-or-signature>
wicap-assist fix-lineage "<signature>"
wicap-assist confidence-audit --limit 100
```
5. Monitor live soak logs
```bash
wicap-assist guardian
```

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
- `wicap-assist cross-patterns [--min-occurrences N] [--min-span-days X] [--top N] [--json]`
- `wicap-assist backfill-report [--min-occurrences N] [--min-span-days X] [--json]`
- `wicap-assist fix-lineage "<signature>" [--limit N] [--json]`
- `wicap-assist confidence-audit [--limit N] [--json]`

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
- Historical audit records: `docs/ARCHITECT_REVIEW.md`, `docs/REVIEW_WALKTHROUGH.md`

## Dev Checks
```bash
python -m compileall src
python -m pytest -q
```
