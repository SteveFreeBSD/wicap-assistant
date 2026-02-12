#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DB_PATH="${1:-data/assistant.db}"
REPORT_DIR="${2:-data/reports}"
ROLL_HISTORY="${3:-${REPORT_DIR}/rollout_gates_history.jsonl}"

mkdir -p "${REPORT_DIR}"

echo "[live-gate] contract-check --enforce"
PYTHONPATH=src python3 -m wicap_assist.cli --db "${DB_PATH}" contract-check --enforce --json > "${REPORT_DIR}/contract_check_latest.json"

echo "[live-gate] rollout-gates --enforce"
PYTHONPATH=src python3 -m wicap_assist.cli \
  --db "${DB_PATH}" \
  rollout-gates \
  --history-file "${ROLL_HISTORY}" \
  --required-consecutive-passes 2 \
  --enforce \
  --json > "${REPORT_DIR}/rollout_gates_latest.json"

echo "[live-gate] memory-maintenance --prune-stale"
PYTHONPATH=src python3 -m wicap_assist.cli \
  --db "${DB_PATH}" \
  memory-maintenance \
  --prune-stale \
  --output "${REPORT_DIR}/memory_maintenance_latest.json" \
  --json > "${REPORT_DIR}/memory_maintenance_last_run.json"

echo "[live-gate] PASS"
