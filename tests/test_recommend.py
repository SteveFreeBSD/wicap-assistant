from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.playbooks import normalize_signature
from wicap_assist.recommend import build_recommendation, recommendation_to_json


def _seed_known_incident(conn, tmp_path: Path) -> tuple[str, str]:
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_case" / "run.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    snippet = "Error: pyodbc setinputsizes failed on sql write"
    for idx in range(3):
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (
                source_id,
                f"2026-02-10 10:00:0{idx}",
                f"log-{idx}",
                snippet,
                str(log_path),
            ),
        )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-r.jsonl", 2.0, 120),
    )
    session_source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_source_id,
            "session-recommend",
            "/home/steve/apps/wicap",
            "2026-02-10T09:55:00+00:00",
            "2026-02-10T10:05:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "deadbeef",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-r.jsonl",
        ),
    )
    session_pk = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T10:01:00+00:00",
            "out-1",
            "fixed pyodbc setinputsizes by updating sql merge path",
        ),
    )
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'commands', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T10:00:30+00:00",
            "cmd-1",
            "python scripts/check_wicap_status.py --sql-only",
        ),
    )
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'file_paths', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T10:00:40+00:00",
            "fp-1",
            "docs/playbooks/error-pyodbc-setinputsizes.md",
        ),
    )

    cur.execute(
        """
        INSERT INTO harness_scripts(script_path, role, commands_json, tools_json, env_vars_json, last_modified)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            "/home/steve/apps/wicap/tests/verifier_harness.py",
            "verifier",
            json.dumps(["python scripts/check_wicap_status.py --sql-only"], sort_keys=True),
            json.dumps(["python", "docker"], sort_keys=True),
            json.dumps(["SQL_HOST"], sort_keys=True),
            "2026-02-10T10:02:00+00:00",
        ),
    )

    conn.commit()
    return "logs_soak_case", normalize_signature(snippet)


def test_known_incident_produces_non_zero_confidence(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    incident_id, _ = _seed_known_incident(conn, tmp_path)

    payload = build_recommendation(conn, incident_id)
    assert payload["recommended_action"] != "insufficient historical evidence"
    assert float(payload["confidence"]) > 0.0
    assert payload["based_on_sessions"] == ["session-recommend"]

    conn.close()


def test_unknown_signature_returns_zero_confidence(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    payload = build_recommendation(conn, "totally-unknown-signature")

    assert payload["recommended_action"] == "insufficient historical evidence"
    assert payload["confidence"] == 0.0
    assert payload["based_on_sessions"] == []

    conn.close()


def test_network_anomaly_signature_is_considered_for_recommendation(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    log_path = tmp_path / "captures" / "wicap_network_events.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("network_event_log", str(log_path), 1.0, 10),
    )
    source_id = int(cur.lastrowid)
    snippet = "deauth|lab-net|11:22:33:44:55:66"
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'network_anomaly', ?, ?, ?, '{}')
        """,
        (
            source_id,
            "2026-02-11T09:00:00Z",
            "net-1",
            snippet,
            str(log_path),
        ),
    )
    conn.commit()

    payload = build_recommendation(conn, snippet)
    assert payload["input"] == snippet
    assert "confidence" in payload
    conn.close()


def test_recommendation_json_schema_is_stable(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _, signature = _seed_known_incident(conn, tmp_path)

    payload = build_recommendation(conn, signature)
    raw = recommendation_to_json(payload)
    parsed = json.loads(raw)

    assert list(parsed.keys()) == [
        "input",
        "recommended_action",
        "confidence",
        "based_on_sessions",
        "related_playbooks",
        "harness_tests",
        "git_context",
        "confidence_breakdown",
        "verification_priority",
        "verification_step_safety",
        "risk_notes",
        "verification_steps",
    ]
    assert isinstance(parsed["harness_tests"], list)
    assert parsed["harness_tests"]
    assert set(parsed["harness_tests"][0].keys()) == {"script", "role", "commands"}

    conn.close()


def test_confidence_is_always_within_bounds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    incident_id, signature = _seed_known_incident(conn, tmp_path)

    for target in (incident_id, signature, "unknown-signature"):
        payload = build_recommendation(conn, target)
        confidence = float(payload["confidence"])
        assert 0.0 <= confidence <= 1.0

    conn.close()


def test_confidence_breakdown_schema_contract_is_stable(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    incident_id, signature = _seed_known_incident(conn, tmp_path)

    expected_breakdown_keys = [
        "fix_success_count",
        "session_evidence_score",
        "recurrence_penalty",
        "verification_signal_score",
        "verification_outcome_score",
        "verification_outcome_pass_count",
        "verification_outcome_fail_count",
        "verification_outcome_unknown_count",
        "verification_success_score",
        "high_confidence_criteria_met",
        "confidence_cap_pct",
    ]

    known = json.loads(recommendation_to_json(build_recommendation(conn, incident_id)))
    unknown = json.loads(recommendation_to_json(build_recommendation(conn, "totally-unknown-signature")))

    for payload in (known, unknown):
        breakdown = payload["confidence_breakdown"]
        assert list(breakdown.keys()) == expected_breakdown_keys
        assert all(isinstance(value, int) for value in breakdown.values())
        assert 0 <= int(breakdown["confidence_cap_pct"]) <= 100

    conn.close()


def test_recommend_ignores_meta_outcome_chatter(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _seed_known_incident(conn, tmp_path)

    session_pk = int(conn.execute("SELECT id FROM sessions WHERE session_id = 'session-recommend'").fetchone()["id"])
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T10:06:00+00:00",
            "out-meta",
            "I’ve fixed and revalidated the tests. Next I’ll run one real wicap-assist recommend command.",
        ),
    )
    conn.commit()

    payload = build_recommendation(conn, "logs_soak_case")
    assert "revalidated the tests" not in payload["recommended_action"].lower()
    assert "Apply previously successful fix:" in payload["recommended_action"]

    conn.close()


def test_recommend_strips_leading_bullet_prefix_from_outcome(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _seed_known_incident(conn, tmp_path)

    session_pk = int(conn.execute("SELECT id FROM sessions WHERE session_id = 'session-recommend'").fetchone()["id"])
    conn.execute("DELETE FROM signals WHERE session_pk = ? AND category = 'outcomes'", (session_pk,))
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T10:06:00+00:00",
            "out-bullet",
            "- - Fixed duplicate self.batch_size in src/wicap/core/processing/persistence.py",
        ),
    )
    conn.commit()

    payload = build_recommendation(conn, "logs_soak_case")
    assert payload["recommended_action"].startswith("Apply previously successful fix: Fixed duplicate")

    conn.close()


def test_recommend_output_is_deterministic_for_same_fixture(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    incident_id, _ = _seed_known_incident(conn, tmp_path)

    first = build_recommendation(conn, incident_id)
    second = build_recommendation(conn, incident_id)

    assert first == second
    conn.close()
