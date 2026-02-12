#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/comprehensive_sweep.sh [options]

Comprehensive end-to-end sweep for WiCAP + wicap-assistant.
Runs bootstrap, rollout smoke, live gate checks, autopilot verification, and state snapshots.

Options:
  --wicap-root PATH            Override WiCAP repo root (auto-detected by default)
  --assistant-db PATH          Assistant DB path (default: <assistant-root>/data/assistant.db)
  --output-dir PATH            Sweep output root (default: <assistant-root>/data/reports/sweeps)
  --autopilot-mode MODE        monitor|observe|assist|autonomous (default: autonomous)
  --operate-cycles N           Autopilot operate cycles for sweep run (default: 220)
  --ui-timeout-seconds N       Wait budget for http://127.0.0.1:8080/health (default: 180)
  --with-scout                 Start scout service during bootstrap/smoke
  --skip-build                 Skip docker compose --build steps
  --no-start-autopilot-service Do not start continuous autopilot sidecar at sweep end
  --run-certifications         Include replay/chaos certification checks
  --strict                     Fail command if any critical step fails
  --no-bootstrap               Skip bootstrap phase (assumes services already up)
  --help                       Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSIST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WICAP_ROOT="${WICAP_ROOT:-}"
ASSIST_DB="${ASSIST_DB:-${ASSIST_ROOT}/data/assistant.db}"
OUTPUT_DIR="${OUTPUT_DIR:-${ASSIST_ROOT}/data/reports/sweeps}"
AUTOPILOT_MODE="${AUTOPILOT_MODE:-autonomous}"
OPERATE_CYCLES=220
UI_TIMEOUT_SECONDS=180
WITH_SCOUT=0
SKIP_BUILD=0
START_AUTOPILOT_SERVICE=1
RUN_CERTIFICATIONS=0
STRICT=0
DO_BOOTSTRAP=1

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
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --autopilot-mode)
            AUTOPILOT_MODE="${2:-}"
            shift 2
            ;;
        --operate-cycles)
            OPERATE_CYCLES="${2:-}"
            shift 2
            ;;
        --ui-timeout-seconds)
            UI_TIMEOUT_SECONDS="${2:-}"
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
        --no-start-autopilot-service)
            START_AUTOPILOT_SERVICE=0
            shift
            ;;
        --run-certifications)
            RUN_CERTIFICATIONS=1
            shift
            ;;
        --strict)
            STRICT=1
            shift
            ;;
        --no-bootstrap)
            DO_BOOTSTRAP=0
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

case "${AUTOPILOT_MODE}" in
    monitor|observe|assist|autonomous) ;;
    *)
        echo "ERROR: invalid --autopilot-mode '${AUTOPILOT_MODE}'" >&2
        exit 2
        ;;
esac

if ! [[ "${OPERATE_CYCLES}" =~ ^[0-9]+$ ]] || [[ "${OPERATE_CYCLES}" -lt 1 ]]; then
    echo "ERROR: --operate-cycles must be an integer >= 1" >&2
    exit 2
fi
if ! [[ "${UI_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${UI_TIMEOUT_SECONDS}" -lt 1 ]]; then
    echo "ERROR: --ui-timeout-seconds must be an integer >= 1" >&2
    exit 2
fi

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
        if [[ -d "${candidate}" && -f "${candidate}/docker-compose.yml" ]]; then
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

build_args=()
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    build_args+=(--build)
fi

mkdir -p "${OUTPUT_DIR}"
SWEEP_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUTPUT_DIR}/sweep-${SWEEP_TS}"
mkdir -p "${RUN_DIR}"
STEP_FILE="${RUN_DIR}/steps.tsv"
touch "${STEP_FILE}"

echo "[info] assistant_root=${ASSIST_ROOT}"
echo "[info] wicap_root=${WICAP_ROOT}"
echo "[info] assistant_db=${ASSIST_DB}"
echo "[info] run_dir=${RUN_DIR}"
echo "[info] ui_timeout_seconds=${UI_TIMEOUT_SECONDS}"

record_step() {
    local name="$1"
    local rc="$2"
    printf '%s\t%s\n' "${name}" "${rc}" >> "${STEP_FILE}"
}

run_stream_step() {
    local name="$1"
    shift
    local log_path="${RUN_DIR}/${name}.log"
    echo "[step] ${name}"
    set +e
    "$@" 2>&1 | tee "${log_path}"
    local rc=${PIPESTATUS[0]}
    set -e
    record_step "${name}" "${rc}"
    if [[ "${rc}" -eq 0 ]]; then
        echo "[pass] ${name}"
    else
        echo "[fail] ${name} rc=${rc} (log: ${log_path})"
    fi
}

run_json_step() {
    local name="$1"
    shift
    local json_path="${RUN_DIR}/${name}.json"
    local err_path="${RUN_DIR}/${name}.err"
    echo "[step] ${name}"
    set +e
    "$@" > "${json_path}" 2> "${err_path}"
    local rc=$?
    set -e
    record_step "${name}" "${rc}"
    if [[ "${rc}" -eq 0 ]]; then
        python3 -m json.tool "${json_path}" | tee "${RUN_DIR}/${name}.pretty.log" >/dev/null
        echo "[pass] ${name}"
    else
        echo "[fail] ${name} rc=${rc} (json: ${json_path}, err: ${err_path})"
        sed -n '1,120p' "${err_path}" || true
    fi
}

if [[ "${DO_BOOTSTRAP}" -eq 1 ]]; then
    bootstrap_cmd=("${ASSIST_ROOT}/scripts/autopilot_bootstrap.sh" "--wicap-root" "${WICAP_ROOT}" "--autopilot-mode" "${AUTOPILOT_MODE}" "--core-only")
    if [[ "${WITH_SCOUT}" -eq 1 ]]; then
        bootstrap_cmd+=("--with-scout")
    fi
    if [[ "${SKIP_BUILD}" -eq 1 ]]; then
        bootstrap_cmd+=("--skip-build")
    fi
    run_stream_step "bootstrap" "${bootstrap_cmd[@]}"
else
    echo "[step] bootstrap skipped (--no-bootstrap)"
    record_step "bootstrap" "0"
fi

smoke_cmd=(
    "${ASSIST_ROOT}/scripts/server_rollout_smoke.sh"
    "--wicap-root" "${WICAP_ROOT}"
    "--assistant-db" "${ASSIST_DB}"
    "--skip-build"
)
if [[ "${WITH_SCOUT}" -eq 1 ]]; then
    smoke_cmd+=("--with-scout")
fi
if [[ "${STRICT}" -eq 1 ]]; then
    smoke_cmd+=("--enforce-gate" "--enforce-contract")
fi
run_stream_step "server_rollout_smoke" "${smoke_cmd[@]}"

core_services=(redis processor ui)
if [[ "${WITH_SCOUT}" -eq 1 ]]; then
    core_services+=(scout)
fi
core_build_args=()
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    core_build_args+=(--build)
fi
run_stream_step "core_reconcile" bash -lc "
set -euo pipefail
cd \"${WICAP_ROOT}\"
docker compose up -d ${core_build_args[*]} ${core_services[*]}
echo '[step] waiting for ui health after core reconcile'
payload=\$(mktemp)
errs=\$(mktemp)
trap 'rm -f \"\${payload}\" \"\${errs}\"' EXIT
elapsed=0
while (( elapsed < ${UI_TIMEOUT_SECONDS} )); do
    if curl -fsS 'http://127.0.0.1:8080/health' >\"\${payload}\" 2>\"\${errs}\"; then
        python3 -m json.tool \"\${payload}\"
        exit 0
    fi
    sleep 2
    elapsed=\$((elapsed + 2))
done
echo \"ERROR: core_reconcile health timeout after ${UI_TIMEOUT_SECONDS}s\" >&2
cat \"\${errs}\" >&2 || true
docker compose ps >&2 || true
exit 1
"

run_json_step "autopilot_once" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" autopilot --control-mode \"${AUTOPILOT_MODE}\" --operate-cycles \"${OPERATE_CYCLES}\" --stop-on-escalation --no-rollback-on-verify-failure --max-runs 1 --json"
run_json_step "rollout_gates_pass1" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" rollout-gates --json"
run_json_step "rollout_gates_pass2" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" rollout-gates --json"
run_stream_step "live_testing_gate" "${ASSIST_ROOT}/scripts/live_testing_gate.sh" "${ASSIST_DB}" "${RUN_DIR}" "${ASSIST_ROOT}/data/reports/rollout_gates_history.jsonl"

run_json_step "contract_check" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" contract-check --json --no-enforce"
run_json_step "failover_state" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" agent failover-state --json"
run_json_step "policy_explain" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" agent explain-policy --json"
run_json_step "sandbox_explain_assist" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" agent sandbox-explain --action status_check --mode assist --json"
run_json_step "backfill_report" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" backfill-report --json"

if [[ "${RUN_CERTIFICATIONS}" -eq 1 ]]; then
    run_json_step "replay_certify" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" agent replay-certify --profile default --json"
    run_json_step "chaos_certify" bash -lc "cd \"${ASSIST_ROOT}\" && PYTHONPATH=src python3 -m wicap_assist.cli --db \"${ASSIST_DB}\" agent chaos-certify --profile default --json"
fi

if [[ "${START_AUTOPILOT_SERVICE}" -eq 1 ]]; then
    run_stream_step "autopilot_service_start" bash -lc "cd \"${ASSIST_ROOT}\" && WICAP_HOST_REPO_ROOT=\"${WICAP_ROOT}\" WICAP_ASSIST_AUTOPILOT_MODE=\"${AUTOPILOT_MODE}\" docker compose -f compose.assistant.yml --profile autopilot up -d ${build_args[*]} wicap-assist-autopilot && docker compose -f compose.assistant.yml --profile autopilot ps wicap-assist-autopilot"
else
    echo "[step] skipping autopilot sidecar start (--no-start-autopilot-service)"
    record_step "autopilot_service_start" "0"
fi

echo "[step] snapshotting db control/mission summary"
python3 - "${ASSIST_DB}" > "${RUN_DIR}/db_snapshot.json" <<'PY'
import json
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

def one(query: str):
    row = conn.execute(query).fetchone()
    return dict(row) if row is not None else None

summary = {
    "latest_control_session": one(
        "SELECT id, mode, status, started_ts, ended_ts FROM control_sessions ORDER BY id DESC LIMIT 1"
    ),
    "latest_mission_run": one(
        "SELECT id, run_id, mode, status, ts_started, ts_ended FROM mission_runs ORDER BY id DESC LIMIT 1"
    ),
    "illegal_transition_count": int(
        conn.execute("SELECT count(*) FROM mission_steps WHERE status='illegal_transition'").fetchone()[0]
    ),
    "recent_control_events": [
        dict(row)
        for row in conn.execute(
            "SELECT ts, decision, action, status FROM control_events ORDER BY id DESC LIMIT 20"
        ).fetchall()
    ],
}
print(json.dumps(summary, sort_keys=True))
PY
python3 -m json.tool "${RUN_DIR}/db_snapshot.json" | tee "${RUN_DIR}/db_snapshot.pretty.log" >/dev/null
record_step "db_snapshot" "0"
echo "[pass] db_snapshot"

echo "[step] building sweep summary"
python3 - "${RUN_DIR}" "${STEP_FILE}" > "${RUN_DIR}/summary.json" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
step_file = pathlib.Path(sys.argv[2])
steps = []
for raw in step_file.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line:
        continue
    name, rc = line.split("\t", 1)
    steps.append({"step": name, "rc": int(rc)})

def load_json(name: str):
    path = run_dir / f"{name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

autopilot = load_json("autopilot_once")
rollout = load_json("rollout_gates_pass2")
contract = load_json("contract_check")
db_snapshot = load_json("db_snapshot")

preflight_detail = None
if isinstance(autopilot, dict):
    latest = autopilot.get("latest", {})
    if isinstance(latest, dict):
        phases = latest.get("phase_results", [])
        if isinstance(phases, list):
            for item in phases:
                if isinstance(item, dict) and str(item.get("phase", "")).strip() == "preflight":
                    preflight_detail = item.get("detail")
                    break

summary = {
    "run_dir": str(run_dir),
    "step_results": steps,
    "step_failures": [item["step"] for item in steps if int(item["rc"]) != 0],
    "autopilot_latest_status": (
        autopilot.get("latest", {}).get("status")
        if isinstance(autopilot, dict)
        else None
    ),
    "autopilot_promotion_decision": (
        autopilot.get("latest", {}).get("promotion_decision")
        if isinstance(autopilot, dict)
        else None
    ),
    "autopilot_preflight_detail": preflight_detail,
    "rollout_overall_pass": (
        rollout.get("overall_pass")
        if isinstance(rollout, dict)
        else None
    ),
    "contract_status": (
        contract.get("status")
        if isinstance(contract, dict)
        else None
    ),
    "illegal_transition_count": (
        db_snapshot.get("illegal_transition_count")
        if isinstance(db_snapshot, dict)
        else None
    ),
}
print(json.dumps(summary, sort_keys=True))
PY
python3 -m json.tool "${RUN_DIR}/summary.json"
record_step "summary" "0"

critical_fail=0
for step_name in bootstrap server_rollout_smoke core_reconcile autopilot_once rollout_gates_pass2 live_testing_gate contract_check autopilot_service_start db_snapshot summary; do
    step_rc="$(awk -F '\t' -v name="${step_name}" '$1==name {print $2}' "${STEP_FILE}" | tail -n1)"
    if [[ -n "${step_rc}" && "${step_rc}" -ne 0 ]]; then
        critical_fail=1
    fi
done

echo "[done] comprehensive sweep artifacts: ${RUN_DIR}"
if [[ "${STRICT}" -eq 1 && "${critical_fail}" -ne 0 ]]; then
    echo "ERROR: comprehensive sweep failed critical steps in strict mode." >&2
    exit 1
fi

exit 0
