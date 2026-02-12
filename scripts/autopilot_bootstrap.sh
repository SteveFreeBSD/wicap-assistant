#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/autopilot_bootstrap.sh [options]

One-command clean-boot bootstrap for WiCAP core + assistant autopilot.

Options:
  --wicap-root PATH            Override WiCAP repo root (auto-detected by default)
  --autopilot-mode MODE        monitor|observe|assist|autonomous (default: autonomous)
  --with-scout                 Start scout service alongside core services
  --skip-build                 Skip docker compose --build for both repos
  --ui-timeout-seconds N       Wait budget for http://127.0.0.1:8080/health (default: 180)
  --help                       Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSIST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WICAP_ROOT="${WICAP_ROOT:-}"
AUTOPILOT_MODE="${AUTOPILOT_MODE:-autonomous}"
WITH_SCOUT=0
SKIP_BUILD=0
UI_TIMEOUT_SECONDS=180

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wicap-root)
            WICAP_ROOT="${2:-}"
            shift 2
            ;;
        --autopilot-mode)
            AUTOPILOT_MODE="${2:-}"
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

if ! [[ "${UI_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${UI_TIMEOUT_SECONDS}" -lt 1 ]]; then
    echo "ERROR: --ui-timeout-seconds must be an integer >= 1" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required." >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required." >&2
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

services=(redis processor ui)
if [[ "${WITH_SCOUT}" -eq 1 ]]; then
    services+=(scout)
fi

echo "[info] assistant_root=${ASSIST_ROOT}"
echo "[info] wicap_root=${WICAP_ROOT}"
echo "[info] autopilot_mode=${AUTOPILOT_MODE}"
echo "[info] services=${services[*]}"

echo "[step] starting WiCAP services"
(cd "${WICAP_ROOT}" && docker compose up -d "${build_args[@]}" "${services[@]}")

echo "[step] waiting for ui health (transient connection-refused is normal during startup)"
health_payload="$(mktemp)"
health_error="$(mktemp)"
trap 'rm -f "${health_payload}" "${health_error}"' EXIT
elapsed=0
while (( elapsed < UI_TIMEOUT_SECONDS )); do
    if curl -fsS "http://127.0.0.1:8080/health" >"${health_payload}" 2>"${health_error}"; then
        echo "[info] ui health ready after ${elapsed}s"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [[ ! -s "${health_payload}" ]]; then
    last_error="$(cat "${health_error}" 2>/dev/null || true)"
    last_error="${last_error//$'\n'/ }"
    echo "ERROR: UI health did not become ready within ${UI_TIMEOUT_SECONDS}s. last_curl_error=${last_error:-none}" >&2
    (cd "${WICAP_ROOT}" && docker compose ps)
    (cd "${WICAP_ROOT}" && docker compose logs --tail 120 ui processor scout redis || true)
    exit 1
fi

python3 -m json.tool "${health_payload}"

echo "[step] starting assistant autopilot service"
(
    cd "${ASSIST_ROOT}" && \
    WICAP_HOST_REPO_ROOT="${WICAP_ROOT}" \
    WICAP_ASSIST_AUTOPILOT_MODE="${AUTOPILOT_MODE}" \
    docker compose -f compose.assistant.yml --profile autopilot up -d "${build_args[@]}" wicap-assist-autopilot
)

echo "[step] autopilot service status"
(cd "${ASSIST_ROOT}" && docker compose -f compose.assistant.yml --profile autopilot ps wicap-assist-autopilot)

echo "[pass] bootstrap complete"
echo "[next] tail logs: docker compose -f ${ASSIST_ROOT}/compose.assistant.yml --profile autopilot logs -f wicap-assist-autopilot"
