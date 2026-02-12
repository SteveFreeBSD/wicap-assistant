#!/usr/bin/env bash
set -euo pipefail

DB_PATH=${1:-data/assistant.db}
PROFILE=${2:-default}

PYTHONPATH=src python3 -m wicap_assist.cli --db "$DB_PATH" agent replay-certify --profile "$PROFILE" --json
