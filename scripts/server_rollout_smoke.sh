#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/server_rollout_smoke.sh [options]

SSH-safe cross-repo rollout smoke for WiCAP + wicap-assistant.

Options:
  --wicap-root PATH           Override WiCAP repo root (auto-detected by default)
  --assistant-db PATH         Assistant DB path (default: <assistant-root>/data/assistant.db)
  --with-scout                Start scout service (can disrupt SSH on single-NIC hosts)
  --skip-build                Skip docker compose --build
  --ui-timeout-seconds N      Wait budget for http://127.0.0.1:8080/health (default: 180)
  --min-conn-coverage N       Shadow coverage threshold for rollout gate (default: 0.20)
  --require-assistant         Require assistant gate for rollout pass
  --require-shadow-data       Require shadow validation gate for rollout pass
  --enforce-gate              Enforce WiCAP rollout gate return code
  --enforce-contract          Enforce assistant contract-check
  --skip-assistant-checks     Skip assistant-side checks
  --help                      Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSIST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WICAP_ROOT="${WICAP_ROOT:-}"
ASSIST_DB="${ASSIST_DB:-${ASSIST_ROOT}/data/assistant.db}"
WITH_SCOUT=0
SKIP_BUILD=0
UI_TIMEOUT_SECONDS=180
MIN_CONN_COVERAGE="0.20"
REQUIRE_ASSISTANT=0
REQUIRE_SHADOW_DATA=0
ENFORCE_GATE=0
ENFORCE_CONTRACT=0
SKIP_ASSISTANT_CHECKS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wicap-root)
            WICAP_ROOT="${2:-}"
            shift 2
            ;;
        --assistant-db)
            ASSIST_DB="${2:-}"
            shift 2
            ;;
        --with-scout)
            WITH_SCOUT=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --ui-timeout-seconds)
            UI_TIMEOUT_SECONDS="${2:-}"
            shift 2
            ;;
        --min-conn-coverage)
            MIN_CONN_COVERAGE="${2:-}"
            shift 2
            ;;
        --require-assistant)
            REQUIRE_ASSISTANT=1
            shift
            ;;
        --require-shadow-data)
            REQUIRE_SHADOW_DATA=1
            shift
            ;;
        --enforce-gate)
            ENFORCE_GATE=1
            shift
            ;;
        --enforce-contract)
            ENFORCE_CONTRACT=1
            shift
            ;;
        --skip-assistant-checks)
            SKIP_ASSISTANT_CHECKS=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required." >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required." >&2
    exit 2
fi

resolve_wicap_root() {
    local candidate
    local candidates=()
    if [[ -n "${WICAP_ROOT:-}" ]]; then
        candidates+=("${WICAP_ROOT}")
    fi
    if [[ -n "${WICAP_REPO_ROOT:-}" ]]; then
        candidates+=("${WICAP_REPO_ROOT}")
    fi
    candidates+=(
        "${ASSIST_ROOT}/../wicap"
        "/opt/wicap"
        "/home/steve/apps/wicap"
    )
    for candidate in "${candidates[@]}"; do
        if [[ -d "${candidate}" && -f "${candidate}/docker-compose.yml" && -f "${candidate}/scripts/run_agentic_rollout_gate.py" ]]; then
            (cd "${candidate}" && pwd)
            return 0
        fi
    done
    return 1
}

WICAP_ROOT="$(resolve_wicap_root || true)"
if [[ -z "${WICAP_ROOT}" ]]; then
    echo "ERROR: unable to resolve WiCAP repo root. Use --wicap-root PATH." >&2
    exit 2
fi

services=(redis processor ui)
if [[ "${WITH_SCOUT}" -eq 1 ]]; then
    services+=(scout)
    echo "[warn] --with-scout enabled. This can interrupt SSH on single-NIC hosts."
    echo "[warn] Keep WICAP_ALLOW_MANAGEMENT_INTERFACE=false and use a dedicated capture interface."
fi

build_args=()
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    build_args+=(--build)
fi

echo "[info] assistant_root=${ASSIST_ROOT}"
echo "[info] wicap_root=${WICAP_ROOT}"
echo "[info] services=${services[*]}"

echo "[step] starting WiCAP services"
(cd "${WICAP_ROOT}" && docker compose up -d "${build_args[@]}" "${services[@]}")

echo "[step] waiting for ui health"
health_payload="$(mktemp)"
trap 'rm -f "${health_payload}"' EXIT
elapsed=0
while (( elapsed < UI_TIMEOUT_SECONDS )); do
    if curl -fsS "http://127.0.0.1:8080/health" >"${health_payload}"; then
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [[ ! -s "${health_payload}" ]]; then
    echo "ERROR: UI health did not become ready within ${UI_TIMEOUT_SECONDS}s." >&2
    (cd "${WICAP_ROOT}" && docker compose ps)
    (cd "${WICAP_ROOT}" && docker compose logs --tail 200 ui processor scout redis || true)
    exit 1
fi
python3 -m json.tool "${health_payload}"

echo "[step] running WiCAP rollout gate"
gate_cmd=(
    python3
    scripts/run_agentic_rollout_gate.py
    --json
    --assistant-repo-root "${ASSIST_ROOT}"
    --assistant-db "${ASSIST_DB}"
    --min-conn-coverage "${MIN_CONN_COVERAGE}"
)
if [[ "${REQUIRE_ASSISTANT}" -eq 1 ]]; then
    gate_cmd+=(--require-assistant)
else
    gate_cmd+=(--no-require-assistant)
fi
if [[ "${REQUIRE_SHADOW_DATA}" -eq 1 ]]; then
    gate_cmd+=(--require-shadow-data)
fi
if [[ "${ENFORCE_GATE}" -eq 1 ]]; then
    gate_cmd+=(--enforce)
fi

gate_payload="$(mktemp)"
trap 'rm -f "${health_payload}" "${gate_payload}"' EXIT
gate_rc=0
if ! (cd "${WICAP_ROOT}" && "${gate_cmd[@]}" >"${gate_payload}"); then
    gate_rc=$?
fi
python3 -m json.tool "${gate_payload}"
if [[ "${gate_rc}" -ne 0 ]]; then
    echo "ERROR: rollout gate returned rc=${gate_rc}." >&2
    exit "${gate_rc}"
fi

if [[ "${SKIP_ASSISTANT_CHECKS}" -eq 1 ]]; then
    echo "[step] skipping assistant checks"
    exit 0
fi

if [[ ! -f "${ASSIST_ROOT}/src/wicap_assist/cli.py" ]]; then
    echo "ERROR: assistant CLI not found at ${ASSIST_ROOT}/src/wicap_assist/cli.py" >&2
    exit 2
fi

echo "[step] running assistant checks"
if [[ "${ENFORCE_CONTRACT}" -eq 1 ]]; then
    (cd "${ASSIST_ROOT}" && PYTHONPATH=src python -m wicap_assist.cli --db "${ASSIST_DB}" contract-check --enforce)
else
    (cd "${ASSIST_ROOT}" && PYTHONPATH=src python -m wicap_assist.cli --db "${ASSIST_DB}" contract-check --no-enforce)
fi

assistant_rollout_payload="$(mktemp)"
trap 'rm -f "${health_payload}" "${gate_payload}" "${assistant_rollout_payload}"' EXIT
(cd "${ASSIST_ROOT}" && PYTHONPATH=src python -m wicap_assist.cli --db "${ASSIST_DB}" rollout-gates --json >"${assistant_rollout_payload}")
python3 -m json.tool "${assistant_rollout_payload}"

(cd "${ASSIST_ROOT}" && PYTHONPATH=src python -m wicap_assist.cli --db "${ASSIST_DB}" agent failover-state --json | python3 -m json.tool)
(cd "${ASSIST_ROOT}" && PYTHONPATH=src python -m wicap_assist.cli --db "${ASSIST_DB}" agent sandbox-explain --action status_check --mode observe --json | python3 -m json.tool)

echo "[pass] server rollout smoke completed."
