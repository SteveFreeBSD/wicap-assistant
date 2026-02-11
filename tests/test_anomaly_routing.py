from __future__ import annotations

import json

from wicap_assist.anomaly_routing import (
    action_to_runbook_step,
    classify_anomaly_class,
    query_feedback_calibration,
    route_for_anomaly,
)
from wicap_assist.db import connect_db


def test_classify_anomaly_class_maps_common_signatures() -> None:
    assert (
        classify_anomaly_class(
            signature="deauth_spike|global|aa:bb:cc:dd:ee:ff",
            category="network_anomaly",
        )
        == "wifi_disruption"
    )
    assert (
        classify_anomaly_class(
            signature="probe_request burst",
            category="network_anomaly",
        )
        == "probe_recon"
    )


def test_route_for_anomaly_emits_deterministic_ladders() -> None:
    route = route_for_anomaly(
        signature="deauth_spike|global|aa:bb:cc:dd:ee:ff",
        category="network_anomaly",
        attack_type="deauth_spike",
    )
    assert route["class_id"] == "wifi_disruption"
    assert route["action_ladder"][0] == "status_check"
    assert "restart_service:wicap-scout" in route["action_ladder"]
    assert route["verification_ladder"]


def test_action_to_runbook_step_maps_allowlisted_actions() -> None:
    assert action_to_runbook_step("status_check") == "python scripts/check_wicap_status.py --local-only"
    assert action_to_runbook_step("compose_up") == "docker compose up -d"
    assert action_to_runbook_step("restart_service:wicap-scout") == "docker compose restart wicap-scout"


def test_query_feedback_calibration_is_bounded(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            ("network_event_log", str(tmp_path / "captures" / "wicap_anomaly_feedback.jsonl"), 1.0, 10),
        )
        source_id = int(cur.lastrowid)
        labels = ["confirmed", "confirmed", "confirmed", "benign", "noisy"]
        for idx, label in enumerate(labels):
            extra = {
                "feedback_contract_version": "wicap.feedback.v1",
                "feedback_label": label,
                "attack_type": "deauth_spike",
            }
            cur.execute(
                """
                INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
                VALUES(?, ?, 'network_anomaly_feedback', ?, ?, ?, ?)
                """,
                (
                    source_id,
                    f"2026-02-11T16:3{idx}:00Z",
                    f"fb-{idx}",
                    f"alert-{idx}",
                    str(tmp_path / "captures" / "wicap_anomaly_feedback.jsonl"),
                    json.dumps(extra, sort_keys=True),
                ),
            )
        conn.commit()

        feedback = query_feedback_calibration(conn, attack_type="deauth_spike")
        assert feedback["status"] == "calibrated"
        assert 0.70 <= float(feedback["confidence_scale"]) <= 1.15
    finally:
        conn.close()
