from __future__ import annotations

import json
from pathlib import Path

from wicap_assist import cli
from wicap_assist.db import connect_db
from wicap_assist.ingest.network_events import ingest_network_events, scan_network_event_paths


def _write_network_events(path: Path) -> None:
    payloads = [
        {
            "event_contract_version": "wicap.event.v1",
            "ts": "2026-02-11T09:00:00Z",
            "source": "wifi",
            "category": "wids_alert",
            "signature": "deauth|lab-net",
            "severity": "high",
            "sensor_id": "sensor-1",
            "evidence_ref": {"kind": "curated_events_jsonl", "path": "/tmp/curated.jsonl", "offset": 1},
            "flow": {
                "src_ip": "10.0.0.10",
                "src_port": 5353,
                "dest_ip": "10.0.0.20",
                "dest_port": 53,
                "proto": "udp",
                "community_id": "wicap:abc",
            },
        },
        {
            "event_contract_version": "wicap.event.v1",
            "ts": "2026-02-11T09:00:01Z",
            "source": "runtime",
            "category": "flow",
            "signature": "flow|dns",
            "severity": "low",
            "sensor_id": "sensor-1",
            "evidence_ref": {"kind": "curated_events_jsonl", "path": "/tmp/curated.jsonl", "offset": 2},
            "flow": {
                "src_ip": "10.0.0.30",
                "dest_ip": "10.0.0.40",
                "proto": "tcp",
            },
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(payload) for payload in payloads) + "\n", encoding="utf-8")


def _write_anomaly_events(path: Path) -> None:
    payloads = [
        {
            "anomaly_contract_version": "wicap.anomaly.v1",
            "ts": "2026-02-11T09:00:02Z",
            "category": "anomaly_stream",
            "signature": "anomaly_stream|global|aa:bb:cc:dd:ee:ff",
            "sensor_id": "sensor-1",
            "scope": "global",
            "score": 82.4,
            "confidence": 78,
            "severity": 4,
            "is_anomaly": True,
            "baseline_ready": True,
            "baseline_maturity": 0.93,
            "baseline_sample_count": 240,
            "explanation": "deauth_rate drift",
            "feature_window": {"window_start": 1, "window_end": 2, "event_count": 10},
            "feature_vector": {"deauth_rate": 4.2},
            "evidence_event_ids": ["event-1"],
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(payload) for payload in payloads) + "\n", encoding="utf-8")


def _write_anomaly_events_v2(path: Path) -> None:
    payloads = [
        {
            "anomaly_contract_version": "wicap.anomaly.v2",
            "ts": "2026-02-11T09:00:02Z",
            "category": "anomaly_stream",
            "signature": "anomaly_stream|global|aa:bb:cc:dd:ee:ff",
            "sensor_id": "sensor-1",
            "scope": "global",
            "primary_score": 88.2,
            "score": 88.2,
            "confidence": 80,
            "severity": 4,
            "is_anomaly": True,
            "baseline_ready": True,
            "baseline_maturity": 0.95,
            "baseline_sample_count": 320,
            "drift_state": {"status": "drift", "delta": 12.1, "long_mean": 40.0, "short_mean": 52.1, "sample_count": 80},
            "score_components": {"z_rms": 2.5},
            "shadow_scores": {"mad_robust": 75.0},
            "model_votes": {"primary": True, "mad_robust": True},
            "vote_agreement": 1.0,
            "feature_window": {"window_start": 1, "window_end": 2, "event_count": 12},
            "feature_vector": {"deauth_rate": 4.6},
            "evidence_event_ids": ["event-7"],
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(payload) for payload in payloads) + "\n", encoding="utf-8")


def _write_prediction_events(path: Path, *, risk_score: float = 72.4, horizon_sec: int = 300) -> None:
    payloads = [
        {
            "prediction_contract_version": "wicap.prediction.v1",
            "ts": "2026-02-11T09:00:04Z",
            "sensor_id": "sensor-1",
            "scope": "global",
            "category": "anomaly_stream",
            "signature": "prediction|anomaly_stream|global|global|300",
            "risk_score": risk_score,
            "horizon_sec": horizon_sec,
            "top_contributors": [{"name": "deauth_rate", "weight": 0.8}],
            "confidence_band": {"low": 66.1, "high": 78.7},
            "evidence_refs": [{"kind": "event_id", "value": "event-7"}],
            "summary": "deauth_rate drifting upward",
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(payload) for payload in payloads) + "\n", encoding="utf-8")


def _write_feedback_events(path: Path) -> None:
    payloads = [
        {
            "feedback_contract_version": "wicap.feedback.v1",
            "ts": "2026-02-11T09:00:03Z",
            "source": "api_alert_feedback",
            "alert_id": "atk-42",
            "label": "confirmed",
            "attack_id": 42,
            "attack_type": "anomaly_stream",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "note": "verified",
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(payload) for payload in payloads) + "\n", encoding="utf-8")


def test_scan_network_event_paths_finds_default_contract_stream(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_network_events.jsonl"
    _write_network_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    paths = scan_network_event_paths()
    assert paths == [stream]


def test_ingest_network_events_writes_log_event_rows(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_network_events.jsonl"
    _write_network_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        files_seen, events_added = ingest_network_events(conn)
        conn.commit()
        assert int(files_seen) == 1
        assert int(events_added) == 2

        rows = conn.execute(
            "SELECT category, snippet, extra_json FROM log_events ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        categories = {str(row["category"]) for row in rows}
        assert "network_anomaly" in categories
        assert "network_flow" in categories
    finally:
        conn.close()


def test_ingest_network_events_reads_wicap_anomaly_contract_stream(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_anomaly_events.jsonl"
    _write_anomaly_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        files_seen, events_added = ingest_network_events(conn)
        conn.commit()
        assert int(files_seen) == 1
        assert int(events_added) == 1

        row = conn.execute(
            "SELECT category, snippet, extra_json FROM log_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert str(row["category"]) == "network_anomaly"
        extra = json.loads(str(row["extra_json"]))
        assert float(extra["score"]) == 82.4
        assert int(extra["confidence"]) == 78
    finally:
        conn.close()


def test_ingest_network_events_reads_wicap_anomaly_v2_contract_stream(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_anomaly_events_v2.jsonl"
    _write_anomaly_events_v2(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        files_seen, events_added = ingest_network_events(conn)
        conn.commit()
        assert int(files_seen) == 1
        assert int(events_added) == 1

        row = conn.execute(
            "SELECT category, extra_json FROM log_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert str(row["category"]) == "network_anomaly"
        extra = json.loads(str(row["extra_json"]))
        assert str(extra["anomaly_contract_version"]) == "wicap.anomaly.v2"
        assert str(extra["drift_state"]["status"]) == "drift"
        assert float(extra["primary_score"]) == 88.2

        drift_row = conn.execute(
            "SELECT status, delta, sample_count, source FROM drift_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert drift_row is not None
        assert str(drift_row["status"]) == "drift"
        assert float(drift_row["delta"]) == 12.1
        assert int(drift_row["sample_count"]) == 80
        assert str(drift_row["source"]).endswith("wicap_anomaly_events_v2.jsonl")

        shadow_row = conn.execute(
            "SELECT model_id, vote, source FROM model_shadow_metrics ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert shadow_row is not None
        assert str(shadow_row["model_id"]) == "mad_robust"
        assert int(shadow_row["vote"]) == 1
        assert str(shadow_row["source"]).endswith("wicap_anomaly_events_v2.jsonl")
    finally:
        conn.close()


def test_ingest_network_events_reads_wicap_feedback_contract_stream(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_anomaly_feedback.jsonl"
    _write_feedback_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        files_seen, events_added = ingest_network_events(conn)
        conn.commit()
        assert int(files_seen) == 1
        assert int(events_added) == 1

        row = conn.execute(
            "SELECT category, snippet, extra_json FROM log_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert str(row["category"]) == "network_anomaly_feedback"
        extra = json.loads(str(row["extra_json"]))
        assert str(extra["feedback_contract_version"]) == "wicap.feedback.v1"
        assert str(extra["feedback_label"]) == "confirmed"
    finally:
        conn.close()


def test_ingest_network_events_reads_wicap_prediction_contract_stream(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_predictions.jsonl"
    _write_prediction_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        files_seen, events_added = ingest_network_events(conn)
        conn.commit()
        assert int(files_seen) == 1
        assert int(events_added) == 1

        row = conn.execute(
            "SELECT category, extra_json FROM log_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert str(row["category"]) == "network_prediction"
        extra = json.loads(str(row["extra_json"]))
        assert str(extra["prediction_contract_version"]) == "wicap.prediction.v1"
        assert float(extra["risk_score"]) == 72.4
        assert int(extra["horizon_sec"]) == 300

        forecast_row = conn.execute(
            "SELECT horizon_sec, risk_score, source FROM forecast_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert forecast_row is not None
        assert int(forecast_row["horizon_sec"]) == 300
        assert float(forecast_row["risk_score"]) == 72.4
        assert str(forecast_row["source"]).endswith("wicap_predictions.jsonl")
    finally:
        conn.close()


def test_ingest_network_events_is_idempotent_for_unchanged_source(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_network_events.jsonl"
    _write_network_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        first_files, first_added = ingest_network_events(conn)
        conn.commit()
        second_files, second_added = ingest_network_events(conn)
        conn.commit()

        assert int(first_files) == 1
        assert int(first_added) == 2
        assert int(second_files) == 1
        assert int(second_added) == 0
    finally:
        conn.close()


def test_ingest_network_events_replaces_specialized_rows_when_source_changes(
    monkeypatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_predictions.jsonl"
    _write_prediction_events(stream, risk_score=70.0, horizon_sec=300)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    conn = connect_db(tmp_path / "assistant.db")
    try:
        ingest_network_events(conn)
        conn.commit()

        _write_prediction_events(stream, risk_score=81.5, horizon_sec=300)
        ingest_network_events(conn)
        conn.commit()

        row = conn.execute(
            "SELECT count(*) AS n, min(risk_score) AS min_score, max(risk_score) AS max_score FROM forecast_events"
        ).fetchone()
        assert row is not None
        assert int(row["n"]) == 1
        assert float(row["min_score"]) == 81.5
        assert float(row["max_score"]) == 81.5
    finally:
        conn.close()


def test_cli_ingest_scan_network_events_flag(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    stream = repo_root / "captures" / "wicap_network_events.jsonl"
    _write_network_events(stream)
    monkeypatch.setenv("WICAP_REPO_ROOT", str(repo_root))

    db_path = tmp_path / "assistant.db"
    exit_code = cli._run_ingest(
        db_path,
        scan_codex=False,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=False,
        scan_network_events=True,
    )
    assert exit_code == 0

    conn = connect_db(db_path)
    try:
        row = conn.execute("SELECT count(*) FROM log_events WHERE category LIKE 'network_%'").fetchone()
        assert row is not None
        assert int(row[0]) >= 2
    finally:
        conn.close()
