#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DB_PATH="data/assistant.db"
REPORT_DIR="data/reports"
ROLL_HISTORY=""
ENFORCE_CONTRACT=1
ENFORCE_ROLLOUT=1

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-enforce-contract)
      ENFORCE_CONTRACT=0
      shift
      ;;
    --no-enforce-rollout)
      ENFORCE_ROLLOUT=0
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Usage: scripts/live_testing_gate.sh [db_path] [report_dir] [roll_history] [options]

Options:
  --no-enforce-contract   Run contract-check without enforce
  --no-enforce-rollout    Run rollout-gates without enforce
EOF
      exit 0
      ;;
    --*)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ "${#POSITIONAL[@]}" -ge 1 ]]; then
  DB_PATH="${POSITIONAL[0]}"
fi
if [[ "${#POSITIONAL[@]}" -ge 2 ]]; then
  REPORT_DIR="${POSITIONAL[1]}"
fi
if [[ "${#POSITIONAL[@]}" -ge 3 ]]; then
  ROLL_HISTORY="${POSITIONAL[2]}"
fi
if [[ -z "${ROLL_HISTORY}" ]]; then
  ROLL_HISTORY="${REPORT_DIR}/rollout_gates_history.jsonl"
fi

mkdir -p "${REPORT_DIR}"

echo "[live-gate] contract-check"
if [[ "${ENFORCE_CONTRACT}" -eq 1 ]]; then
  PYTHONPATH=src python3 -m wicap_assist.cli --db "${DB_PATH}" contract-check --enforce --json > "${REPORT_DIR}/contract_check_latest.json"
else
  PYTHONPATH=src python3 -m wicap_assist.cli --db "${DB_PATH}" contract-check --no-enforce --json > "${REPORT_DIR}/contract_check_latest.json"
fi

echo "[live-gate] rollout-gates"
if [[ "${ENFORCE_ROLLOUT}" -eq 1 ]]; then
  PYTHONPATH=src python3 -m wicap_assist.cli \
    --db "${DB_PATH}" \
    rollout-gates \
    --history-file "${ROLL_HISTORY}" \
    --required-consecutive-passes 2 \
    --enforce \
    --json > "${REPORT_DIR}/rollout_gates_latest.json"
else
  PYTHONPATH=src python3 -m wicap_assist.cli \
    --db "${DB_PATH}" \
    rollout-gates \
    --history-file "${ROLL_HISTORY}" \
    --required-consecutive-passes 2 \
    --json > "${REPORT_DIR}/rollout_gates_latest.json"
fi

echo "[live-gate] memory-maintenance --prune-stale"
PYTHONPATH=src python3 -m wicap_assist.cli \
  --db "${DB_PATH}" \
  memory-maintenance \
  --prune-stale \
  --output "${REPORT_DIR}/memory_maintenance_latest.json" \
  --json > "${REPORT_DIR}/memory_maintenance_last_run.json"

echo "[live-gate] PASS"
