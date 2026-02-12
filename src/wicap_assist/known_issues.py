"""Deterministic known-issue routing for rollout/bootstrap failures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnownIssueRule:
    issue_id: str
    title: str
    required: tuple[str, ...]
    any_of: tuple[str, ...]
    recommended_action: str
    verification_steps: tuple[str, ...]
    risk_notes: str
    confidence: float = 0.6


_RULES: tuple[KnownIssueRule, ...] = (
    KnownIssueRule(
        issue_id="ui_internal_allowlist_block",
        title="Processor-to-UI internal auth allowlist mismatch",
        required=("ui push failed", "client not allowed"),
        any_of=("403", "/api/internal/emit"),
        recommended_action=(
            "Set `WICAP_UI_URL=http://127.0.0.1:8080` and include loopback plus LAN CIDR in "
            "`WICAP_INTERNAL_ALLOWLIST`, then recreate `ui` and `processor`."
        ),
        verification_steps=(
            "grep -E '^(WICAP_UI_URL|WICAP_INTERNAL_ALLOWLIST)=' .env",
            "docker compose up -d --force-recreate ui processor",
            "docker compose logs --tail=120 processor | grep -E 'UI push failed|UI is now ready' || true",
        ),
        risk_notes="internal UI emit path is blocked by auth allowlist; live telemetry fanout is degraded until corrected",
        confidence=0.82,
    ),
    KnownIssueRule(
        issue_id="ui_startup_unreachable",
        title="UI health endpoint unavailable during startup or bind failure",
        required=("failed to connect", "8080"),
        any_of=("/health", "couldn't connect to server", "connection refused"),
        recommended_action=(
            "Validate UI startup first (`ui` health + logs), then re-check LAN access once `/health` returns 200."
        ),
        verification_steps=(
            "docker compose ps",
            "docker compose logs --tail=120 ui",
            "curl -fsS http://127.0.0.1:8080/health",
        ),
        risk_notes="UI may still be starting or unhealthy; avoid applying network/firewall changes before local health is confirmed",
        confidence=0.68,
    ),
    KnownIssueRule(
        issue_id="assistant_compose_no_services_to_build",
        title="Assistant compose build invoked with no buildable services",
        required=("no services to build",),
        any_of=("compose.assistant.yml", "docker compose"),
        recommended_action=(
            "Use `docker compose ... up`/`run` for assistant services instead of `build` alone when compose has no build targets."
        ),
        verification_steps=(
            "docker compose -f compose.assistant.yml config --services",
            "docker compose -f compose.assistant.yml --profile observe up -d wicap-assist-live",
        ),
        risk_notes="command mismatch only; runtime is usually recoverable with the correct compose invocation",
        confidence=0.74,
    ),
    KnownIssueRule(
        issue_id="captures_directory_permission_denied",
        title="Capture directory permissions prevent WiCAP startup writes",
        required=("permission denied", "captures"),
        any_of=("could not create", "wicap_captures_dir"),
        recommended_action=(
            "Create capture/output directories and grant write access to the runtime user before starting WiCAP services."
        ),
        verification_steps=(
            "mkdir -p captures captures/bt captures/evidence/bundles",
            "chown -R \"$USER:$USER\" captures",
            "test -w captures && echo ok",
        ),
        risk_notes="capture pipeline may run partially but evidence/output writes can fail silently",
        confidence=0.72,
    ),
    KnownIssueRule(
        issue_id="wifi_management_interface_conflict",
        title="Capture interface conflicts with management Wi-Fi interface",
        required=("management interface",),
        any_of=("wlo1", "drop ssh", "capture mode"),
        recommended_action=(
            "Pin a dedicated capture adapter (`wlx...`) with explicit mode and keep management interface excluded."
        ),
        verification_steps=(
            "grep -E '^(WICAP_INTERFACE|WICAP_INTERFACE_EXCLUDE_REGEX|WICAP_ALLOW_MANAGEMENT_INTERFACE)=' .env",
            "ip route | grep '^default '",
            "docker compose logs --tail=100 scout",
        ),
        risk_notes="incorrect interface selection can drop remote management access on headless hosts",
        confidence=0.8,
    ),
)


def _normalize_text(*parts: str) -> str:
    items = [str(value or "").strip().lower() for value in parts]
    return " ".join(value for value in items if value)


def _matches_rule(text: str, rule: KnownIssueRule) -> bool:
    if not text:
        return False
    if any(token not in text for token in rule.required):
        return False
    if not rule.any_of:
        return True
    return any(token in text for token in rule.any_of)


def match_known_issue(
    *,
    signature: str,
    category: str = "",
    example: str = "",
) -> dict[str, object] | None:
    text = _normalize_text(signature, category, example)
    for rule in _RULES:
        if not _matches_rule(text, rule):
            continue
        return {
            "issue_id": rule.issue_id,
            "title": rule.title,
            "recommended_action": rule.recommended_action,
            "verification_steps": list(rule.verification_steps),
            "risk_notes": rule.risk_notes,
            "confidence": float(rule.confidence),
        }
    return None
