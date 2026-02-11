#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DB_PATH="${1:-data/assistant.db}"

echo "[smoke] contract-check"
PYTHONPATH=src python -m wicap_assist.cli --db "${DB_PATH}" contract-check --no-enforce

echo "[smoke] live --once (observe)"
PYTHONPATH=src python -m wicap_assist.cli --db "${DB_PATH}" live --once --control-mode observe

echo "[smoke] soak-run --dry-run (observe)"
PYTHONPATH=src python -m wicap_assist.cli --db "${DB_PATH}" soak-run --dry-run --control-mode observe --no-require-runtime-contract

echo "[smoke] ingest --scan-harness"
PYTHONPATH=src python -m wicap_assist.cli --db "${DB_PATH}" ingest --scan-harness

echo "[smoke] PASS"
