"""Policy explainability snapshot helpers for live/soak control surfaces."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

from wicap_assist.settings import wicap_repo_root
from wicap_assist.util.time import utc_now_iso

Runner = Callable[..., subprocess.CompletedProcess[str]]


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    token = str(raw).strip().lower()
    if token in {"1", "true", "yes", "on", "enabled"}:
        return True
    if token in {"0", "false", "no", "off", "disabled"}:
        return False
    return bool(default)


def _fallback_control_plane() -> dict[str, Any]:
    return {
        "runtime_plane": _bool_env("WICAP_CONTROL_RUNTIME_PLANE_ENABLED", True),
        "tool_policy_plane": _bool_env("WICAP_CONTROL_TOOL_POLICY_PLANE_ENABLED", True),
        "elevated_plane": _bool_env("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", False),
        "active_policy_profile": (
            os.environ.get("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1").strip() or "observe-v1"
        ),
        "profile_version": (
            os.environ.get("WICAP_CONTROL_ACTIVE_POLICY_PROFILE_VERSION", "1").strip() or "1"
        ),
        "cooldown_until": os.environ.get("WICAP_CONTROL_ACTION_COOLDOWN_UNTIL", "").strip() or None,
    }


def _script_candidates(repo_root: Path) -> tuple[Path, ...]:
    return (
        repo_root / "scripts" / "check_wicap_status.py",
        repo_root / "check_wicap_status.py",
    )


def _extract_intel(local_payload: dict[str, Any]) -> dict[str, Any]:
    anomaly = local_payload.get("last_anomaly_v2")
    prediction = local_payload.get("last_prediction")
    drift_state = None
    if isinstance(anomaly, dict):
        drift = anomaly.get("drift_state")
        if isinstance(drift, dict):
            drift_state = {
                "status": drift.get("status"),
                "delta": drift.get("delta"),
                "sample_count": drift.get("sample_count"),
            }
    return {
        "latest_anomaly_ts": (anomaly.get("ts") if isinstance(anomaly, dict) else None),
        "latest_prediction_ts": (prediction.get("ts") if isinstance(prediction, dict) else None),
        "latest_drift_state": drift_state,
    }


def collect_policy_explain(
    *,
    repo_root: Path | None = None,
    runner: Runner = subprocess.run,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Collect policy explainability snapshot from WiCAP runtime status surface."""
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    fallback = {
        "ts": utc_now_iso(),
        "ok": False,
        "source": "env_fallback",
        "repo_root": str(resolved_repo_root),
        "control_plane": _fallback_control_plane(),
        "intel_worker": {
            "latest_anomaly_ts": None,
            "latest_prediction_ts": None,
            "latest_drift_state": None,
        },
        "errors": [],
    }

    for script in _script_candidates(resolved_repo_root):
        if not script.exists():
            continue
        command = [sys.executable, str(script), "--local-only", "--json"]
        try:
            result = runner(
                command,
                cwd=str(resolved_repo_root),
                capture_output=True,
                text=True,
                check=False,
                timeout=max(1, int(timeout_seconds)),
            )
        except Exception as exc:  # pragma: no cover - defensive path
            fallback["errors"].append(f"{type(exc).__name__}: {exc}")
            continue
        if int(result.returncode) != 0:
            stderr = str(result.stderr or "").strip()
            fallback["errors"].append(
                f"status_script_exit_{result.returncode}: {stderr[:200] if stderr else 'no stderr'}"
            )
            continue
        raw = str(result.stdout or "").strip()
        if not raw:
            fallback["errors"].append("status_script_empty_stdout")
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            fallback["errors"].append("status_script_invalid_json")
            continue
        local = payload.get("local")
        if not isinstance(local, dict):
            fallback["errors"].append("status_script_missing_local_payload")
            continue
        control_plane = local.get("control_plane")
        if not isinstance(control_plane, dict):
            control_plane = _fallback_control_plane()
        return {
            "ts": utc_now_iso(),
            "ok": True,
            "source": "check_wicap_status_json",
            "repo_root": str(resolved_repo_root),
            "script_path": str(script),
            "command": command,
            "generated_at": payload.get("generated_at"),
            "control_plane": control_plane,
            "intel_worker": _extract_intel(local),
            "errors": [],
        }

    return fallback


def policy_explain_to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def format_policy_explain_text(payload: dict[str, Any]) -> str:
    control_plane = payload.get("control_plane", {})
    if not isinstance(control_plane, dict):
        control_plane = {}
    intel = payload.get("intel_worker", {})
    if not isinstance(intel, dict):
        intel = {}
    lines = [
        (
            "policy_explain: "
            f"ok={payload.get('ok')} source={payload.get('source')} "
            f"profile={control_plane.get('active_policy_profile')} "
            f"profile_version={control_plane.get('profile_version')}"
        ),
        (
            "planes: "
            f"runtime={control_plane.get('runtime_plane')} "
            f"tool={control_plane.get('tool_policy_plane')} "
            f"elevated={control_plane.get('elevated_plane')}"
        ),
        f"cooldown_until: {control_plane.get('cooldown_until')}",
        (
            "intel_worker: "
            f"latest_anomaly_ts={intel.get('latest_anomaly_ts')} "
            f"latest_prediction_ts={intel.get('latest_prediction_ts')}"
        ),
    ]
    drift = intel.get("latest_drift_state")
    if isinstance(drift, dict) and drift:
        lines.append(
            "intel_drift: "
            f"status={drift.get('status')} delta={drift.get('delta')} samples={drift.get('sample_count')}"
        )
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        for item in errors[:3]:
            lines.append(f"error: {item}")
    return "\n".join(lines)
