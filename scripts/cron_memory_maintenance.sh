#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DB_PATH="${1:-data/assistant.db}"
REPORT_DIR="${2:-data/reports}"
LATEST_REPORT="${REPORT_DIR}/memory_maintenance_latest.json"
RUN_LOG="${REPORT_DIR}/memory_maintenance_last_run.json"

mkdir -p "${REPORT_DIR}"

PYTHONPATH=src python3 -m wicap_assist.cli \
  --db "${DB_PATH}" \
  memory-maintenance \
  --prune-stale \
  --output "${LATEST_REPORT}" \
  --json > "${RUN_LOG}"

echo "[memory-maintenance] report=${LATEST_REPORT} run_log=${RUN_LOG}"
