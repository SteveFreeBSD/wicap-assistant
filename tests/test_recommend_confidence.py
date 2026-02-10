from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from wicap_assist.db import connect_db, insert_verification_outcome
from wicap_assist.recommend import build_recommendation, recommendation_to_json
from wicap_assist.recommend_confidence import calibrate_phase4
from wicap_assist.util.evidence import normalize_signature


def _seed_phase4_data(conn, tmp_path: Path) -> str:
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_phase4" / "run.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    snippet = "Error: pyodbc setinputsizes failed on sql write"
    for idx in range(4):
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

    for session_idx in range(3):
        cur.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            (
                "session",
                f"/home/steve/.codex/sessions/2026/02/10/rollout-phase4-{session_idx}.jsonl",
                2.0 + session_idx,
                120,
            ),
        )
        session_source_id = int(cur.lastrowid)
        session_id = f"session-phase4-{session_idx}"
        cur.execute(
            """
            INSERT INTO sessions(
                source_id, session_id, cwd, ts_first, ts_last,
                repo_url, branch, commit_hash, is_wicap, raw_path
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_source_id,
                session_id,
                "/home/steve/apps/wicap",
                "2026-02-10T09:55:00+00:00",
                f"2026-02-10T10:0{session_idx}:00+00:00",
                "https://github.com/SteveFreeBSD/wicap.git",
                "main",
                f"deadbeef{session_idx}",
                1,
                f"/home/steve/.codex/sessions/2026/02/10/rollout-phase4-{session_idx}.jsonl",
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
                f"2026-02-10T10:0{session_idx}:30+00:00",
                f"out-{session_idx}",
                "fixed pyodbc setinputsizes by updating sql merge path",
            ),
        )

        if session_idx < 2:
            command = "python scripts/check_wicap_status.py --sql-only"
        else:
            command = "pytest -q tests/test_smoke.py"

        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'commands', ?, ?, '{}')
            """,
            (
                session_pk,
                f"2026-02-10T10:0{session_idx}:10+00:00",
                f"cmd-{session_idx}",
                command,
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
            json.dumps(
                [
                    "python scripts/check_wicap_status.py --sql-only",
                    "pytest -q tests/test_smoke.py",
                ],
                sort_keys=True,
            ),
            json.dumps(["python", "pytest"], sort_keys=True),
            json.dumps(["SQL_HOST"], sort_keys=True),
            "2026-02-10T10:02:00+00:00",
        ),
    )

    conn.commit()
    return "logs_soak_phase4"


def test_confidence_breakdown_keys_exist(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_phase4_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    breakdown = payload["confidence_breakdown"]

    required = {
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
    }
    assert required.issubset(set(breakdown.keys()))
    assert isinstance(breakdown["fix_success_count"], int)
    assert isinstance(breakdown["session_evidence_score"], int)
    assert isinstance(breakdown["recurrence_penalty"], int)
    assert isinstance(breakdown["verification_signal_score"], int)
    assert isinstance(breakdown["verification_outcome_score"], int)
    assert isinstance(breakdown["verification_outcome_pass_count"], int)
    assert isinstance(breakdown["verification_outcome_fail_count"], int)
    assert isinstance(breakdown["verification_outcome_unknown_count"], int)
    assert isinstance(breakdown["verification_success_score"], int)
    assert isinstance(breakdown["high_confidence_criteria_met"], int)
    assert isinstance(breakdown["confidence_cap_pct"], int)

    conn.close()


def test_confidence_breakdown_component_consistency(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_phase4_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    breakdown = payload["confidence_breakdown"]

    assert breakdown["session_evidence_score"] == min(10, breakdown["fix_success_count"])
    assert breakdown["verification_success_score"] == max(
        0,
        breakdown["verification_signal_score"] + breakdown["verification_outcome_score"],
    )
    assert 0 <= breakdown["confidence_cap_pct"] <= 100

    conn.close()


def test_verification_priority_sorted_by_historical_success(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_phase4_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    priority = payload["verification_priority"]

    assert priority
    assert priority[0] == "python scripts/check_wicap_status.py --sql-only"
    if len(priority) > 1:
        assert priority[1] == "pytest -q tests/test_smoke.py"

    conn.close()


def test_phase4_confidence_stays_bounded(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_phase4_data(conn, tmp_path)

    payload_known = build_recommendation(conn, target)
    payload_unknown = build_recommendation(conn, "unknown-phase4-signature")

    for payload in (payload_known, payload_unknown):
        confidence = float(payload["confidence"])
        assert 0.0 <= confidence <= 1.0

    conn.close()


def _seed_hygiene_data(conn, tmp_path: Path) -> str:
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_hygiene" / "run.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    snippet = "Error: pyodbc setinputsizes failed on sql write"
    for idx in range(2):
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (
                source_id,
                f"2026-02-10 11:00:0{idx}",
                f"hyg-log-{idx}",
                snippet,
                str(log_path),
            ),
        )

    for idx in range(3):
        cur.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            (
                "session",
                f"/home/steve/.codex/sessions/2026/02/10/rollout-hygiene-rm-{idx}.jsonl",
                3.0 + idx,
                140,
            ),
        )
        src_id = int(cur.lastrowid)
        cur.execute(
            """
            INSERT INTO sessions(
                source_id, session_id, cwd, ts_first, ts_last,
                repo_url, branch, commit_hash, is_wicap, raw_path
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                src_id,
                f"session-hygiene-rm-{idx}",
                "/home/steve/apps/wicap",
                "2026-02-10T10:00:00+00:00",
                f"2026-02-10T11:0{idx}:00+00:00",
                "https://github.com/SteveFreeBSD/wicap.git",
                "main",
                f"beadfeed{idx}",
                1,
                f"/home/steve/.codex/sessions/2026/02/10/rollout-hygiene-rm-{idx}.jsonl",
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
                f"2026-02-10T11:0{idx}:30+00:00",
                f"hyg-out-rm-{idx}",
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
                f"2026-02-10T11:0{idx}:10+00:00",
                f"hyg-cmd-rm-{idx}",
                "rm -f /home/steve/apps/wicap/.soak_status.json [78139fe80f] [f386ac95ce]",
            ),
        )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-hygiene-safe.jsonl", 9.0, 140),
    )
    safe_source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            safe_source_id,
            "session-hygiene-safe",
            "/home/steve/apps/wicap",
            "2026-02-10T10:30:00+00:00",
            "2026-02-10T11:30:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "cafebabe",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-hygiene-safe.jsonl",
        ),
    )
    safe_session_pk = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (
            safe_session_pk,
            "2026-02-10T11:30:30+00:00",
            "hyg-out-safe",
            "resolved pyodbc setinputsizes issue",
        ),
    )
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'commands', ?, ?, '{}')
        """,
        (
            safe_session_pk,
            "2026-02-10T11:30:10+00:00",
            "hyg-cmd-safe",
            "python scripts/check_wicap_status.py --sql-only [deadbeefcaf0]",
        ),
    )

    conn.commit()
    return "logs_soak_hygiene"


def test_verification_steps_strip_fingerprint_tokens(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_hygiene_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    steps = payload["verification_steps"]
    assert steps
    assert all("[" not in step and "]" not in step for step in steps)

    conn.close()


def test_destructive_commands_rank_after_safe_even_if_more_frequent(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_hygiene_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    priority = payload["verification_priority"]

    assert "python scripts/check_wicap_status.py --sql-only" in priority
    assert "rm -f /home/steve/apps/wicap/.soak_status.json" in priority
    assert priority.index("python scripts/check_wicap_status.py --sql-only") < priority.index(
        "rm -f /home/steve/apps/wicap/.soak_status.json"
    )

    safety = payload["verification_step_safety"]
    safety_map = {entry["step"]: entry["safety"] for entry in safety}
    assert safety_map["python scripts/check_wicap_status.py --sql-only"] == "safe"
    assert safety_map["rm -f /home/steve/apps/wicap/.soak_status.json"] == "destructive"

    conn.close()


def test_recommend_json_schema_includes_verification_safety(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_hygiene_data(conn, tmp_path)

    payload = build_recommendation(conn, target)
    parsed = json.loads(recommendation_to_json(payload))

    assert "verification_step_safety" in parsed
    assert isinstance(parsed["verification_step_safety"], list)
    if parsed["verification_step_safety"]:
        assert set(parsed["verification_step_safety"][0].keys()) == {"step", "safety"}

    conn.close()


def _seed_high_confidence_gate_data(conn, tmp_path: Path) -> tuple[str, str]:
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_high_conf_gate" / "run.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    snippet = "Error: pyodbc setinputsizes failed on sql write path"
    for idx in range(8):
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (
                source_id,
                f"2026-02-10 12:00:{idx:02d}",
                f"high-log-{idx}",
                snippet,
                str(log_path),
            ),
        )

    for session_idx in range(9):
        cur.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            (
                "session",
                f"/home/steve/.codex/sessions/2026/02/10/rollout-high-{session_idx}.jsonl",
                3.0 + session_idx,
                160,
            ),
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
                f"session-high-{session_idx}",
                "/home/steve/apps/wicap",
                "2026-02-10T11:50:00+00:00",
                f"2026-02-10T12:{session_idx:02d}:00+00:00",
                "https://github.com/SteveFreeBSD/wicap.git",
                "main",
                f"highfeed{session_idx}",
                1,
                f"/home/steve/.codex/sessions/2026/02/10/rollout-high-{session_idx}.jsonl",
            ),
        )
        session_pk = int(cur.lastrowid)

        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'commands', ?, ?, '{}')
            """,
            (
                session_pk,
                f"2026-02-10T12:{session_idx:02d}:10+00:00",
                f"high-cmd-{session_idx}",
                "python scripts/check_wicap_status.py --sql-only",
            ),
        )
        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'outcomes', ?, ?, '{}')
            """,
            (
                session_pk,
                f"2026-02-10T12:{session_idx:02d}:20+00:00",
                f"high-out-{session_idx}",
                "fixed pyodbc setinputsizes by updating sql merge path",
            ),
        )

    conn.commit()
    return "logs_soak_high_conf_gate", normalize_signature(snippet)


def test_confidence_over_095_requires_strict_criteria(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target, signature = _seed_high_confidence_gate_data(conn, tmp_path)

    baseline = build_recommendation(conn, target)
    assert float(baseline["confidence"]) < 0.95
    assert int(baseline["confidence_breakdown"]["high_confidence_criteria_met"]) == 0

    for idx in range(3):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature=signature,
            outcome="pass",
            evidence_snippet=f"PASS strict gate run {idx}",
            ts=f"2026-02-10T12:20:{idx:02d}+00:00",
        )
    conn.commit()

    after = build_recommendation(conn, target)
    assert float(after["confidence"]) >= 0.95
    assert int(after["confidence_breakdown"]["high_confidence_criteria_met"]) == 1
    conn.close()


def test_recurrence_without_verified_success_applies_penalty() -> None:
    result = calibrate_phase4(
        related_rows=[],
        context_event_times=[
            datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 2, 10, 12, 5, tzinfo=timezone.utc),
            datetime(2026, 2, 10, 12, 10, tzinfo=timezone.utc),
        ],
        fix_outcomes=[],
        candidate_verification_steps=[],
        conn=None,
        target_signature="",
    )
    assert int(result.confidence_breakdown["recurrence_penalty"]) > 0
    assert float(result.confidence) < 0.7


def _seed_outcome_boost_data(conn, tmp_path: Path, *, recurred: bool) -> str:
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_outcome_boost" / "run.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")
    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    snippet = "Error: pyodbc write failed in persistence path"
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'error', ?, ?, ?, '{}')
        """,
        (source_id, "2026-02-10 10:00:00", "boost-log-1", snippet, str(log_path)),
    )
    if recurred:
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (source_id, "2026-02-10 10:06:00", "boost-log-2", snippet, str(log_path)),
        )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-boost.jsonl", 2.0, 120),
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
            "session-outcome-boost",
            "/home/steve/apps/wicap",
            "2026-02-10T09:50:00+00:00",
            "2026-02-10T10:07:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "facefeed",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-boost.jsonl",
        ),
    )
    session_pk = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'commands', ?, ?, '{}')
        """,
        (session_pk, "2026-02-10T10:00:10+00:00", "boost-cmd", "python scripts/check_wicap_status.py --sql-only"),
    )
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (session_pk, "2026-02-10T10:00:40+00:00", "boost-out", "fixed pyodbc persistence merge"),
    )

    conn.commit()
    return "logs_soak_outcome_boost"


def test_unknown_verification_outcomes_do_not_boost_confidence(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_outcome_boost_data(conn, tmp_path, recurred=False)

    before = build_recommendation(conn, target)
    before_score = int(before["confidence_breakdown"]["verification_success_score"])
    before_conf = float(before["confidence"])

    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="error: pyodbc write failed in persistence path",
        outcome="unknown",
        evidence_snippet="verification pending",
        ts="2026-02-10T10:02:00+00:00",
    )
    conn.commit()

    after = build_recommendation(conn, target)
    assert int(after["confidence_breakdown"]["verification_success_score"]) == before_score
    assert float(after["confidence"]) == before_conf
    conn.close()


def test_verified_success_outcome_increases_confidence(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_outcome_boost_data(conn, tmp_path, recurred=False)

    baseline = build_recommendation(conn, target)
    baseline_conf = float(baseline["confidence"])

    for idx in range(2):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature="error: pyodbc write failed in persistence path",
            outcome="pass",
            evidence_snippet=f"PASS verification {idx}",
            ts=f"2026-02-10T10:04:{idx:02d}+00:00",
        )
    conn.commit()

    boosted = build_recommendation(conn, target)
    assert float(boosted["confidence"]) > baseline_conf
    assert int(boosted["confidence_breakdown"]["verification_outcome_score"]) > 0
    conn.close()


def test_verified_failure_outcome_decreases_confidence(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_outcome_boost_data(conn, tmp_path, recurred=False)

    baseline = build_recommendation(conn, target)
    baseline_conf = float(baseline["confidence"])

    for idx in range(2):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature="error: pyodbc write failed in persistence path",
            outcome="fail",
            evidence_snippet=f"FAIL verification {idx}",
            ts=f"2026-02-10T10:04:{idx:02d}+00:00",
        )
    conn.commit()

    degraded = build_recommendation(conn, target)
    assert float(degraded["confidence"]) < baseline_conf
    assert int(degraded["confidence_breakdown"]["verification_outcome_score"]) < 0
    conn.close()


def test_verification_outcome_boost_is_capped(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_outcome_boost_data(conn, tmp_path, recurred=False)

    baseline = build_recommendation(conn, target)
    baseline_score = int(baseline["confidence_breakdown"]["verification_success_score"])

    for idx in range(10):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature="error: pyodbc write failed in persistence path",
            outcome="pass",
            evidence_snippet=f"PASS verification run {idx}",
            ts=f"2026-02-10T10:03:{idx:02d}+00:00",
        )
    conn.commit()

    boosted = build_recommendation(conn, target)
    boosted_score = int(boosted["confidence_breakdown"]["verification_success_score"])
    assert boosted_score <= baseline_score + 2
    conn.close()


def test_recurrence_penalty_blocks_positive_outcome_boost(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    target = _seed_outcome_boost_data(conn, tmp_path, recurred=True)

    baseline = build_recommendation(conn, target)
    baseline_conf = float(baseline["confidence"])
    assert int(baseline["confidence_breakdown"]["recurrence_penalty"]) > 0

    for idx in range(5):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature="error: pyodbc write failed in persistence path",
            outcome="pass",
            evidence_snippet=f"PASS post-fix verification {idx}",
            ts=f"2026-02-10T10:07:{idx:02d}+00:00",
        )
    conn.commit()

    after = build_recommendation(conn, target)
    assert float(after["confidence"]) <= baseline_conf
    conn.close()


def _insert_outcomes_for_matrix(
    conn,
    *,
    signature: str,
    outcomes: list[str],
    ts_prefix: str = "2026-02-10T10:09:",
) -> None:
    for idx, outcome in enumerate(outcomes):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature=signature,
            outcome=outcome,
            evidence_snippet=f"{outcome.upper()} matrix case {idx}",
            ts=f"{ts_prefix}{idx:02d}+00:00",
        )
    conn.commit()


def test_recurrence_verification_outcome_matrix(tmp_path: Path) -> None:
    signature = "error: pyodbc write failed in persistence path"

    # Baseline without recurrence.
    conn = connect_db(tmp_path / "matrix_baseline_non_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "baseline_non_recur", recurred=False)
    baseline_non_recur = build_recommendation(conn, target)
    baseline_non_recur_conf = float(baseline_non_recur["confidence"])
    conn.close()

    # Pass outcomes should increase confidence in non-recurrence case.
    conn = connect_db(tmp_path / "matrix_pass_non_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "pass_non_recur", recurred=False)
    _insert_outcomes_for_matrix(conn, signature=signature, outcomes=["pass", "pass"])
    pass_non_recur = build_recommendation(conn, target)
    assert float(pass_non_recur["confidence"]) > baseline_non_recur_conf
    assert int(pass_non_recur["confidence_breakdown"]["verification_outcome_score"]) > 0
    conn.close()

    # Fail outcomes should decrease confidence in non-recurrence case.
    conn = connect_db(tmp_path / "matrix_fail_non_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "fail_non_recur", recurred=False)
    _insert_outcomes_for_matrix(conn, signature=signature, outcomes=["fail", "fail"])
    fail_non_recur = build_recommendation(conn, target)
    assert float(fail_non_recur["confidence"]) < baseline_non_recur_conf
    assert int(fail_non_recur["confidence_breakdown"]["verification_outcome_score"]) < 0
    conn.close()

    # Unknown outcomes should not change confidence in non-recurrence case.
    conn = connect_db(tmp_path / "matrix_unknown_non_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "unknown_non_recur", recurred=False)
    _insert_outcomes_for_matrix(conn, signature=signature, outcomes=["unknown", "unknown"])
    unknown_non_recur = build_recommendation(conn, target)
    assert float(unknown_non_recur["confidence"]) == baseline_non_recur_conf
    assert int(unknown_non_recur["confidence_breakdown"]["verification_outcome_score"]) == 0
    conn.close()

    # Baseline with recurrence.
    conn = connect_db(tmp_path / "matrix_baseline_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "baseline_recur", recurred=True)
    baseline_recur = build_recommendation(conn, target)
    baseline_recur_conf = float(baseline_recur["confidence"])
    assert int(baseline_recur["confidence_breakdown"]["recurrence_penalty"]) > 0
    conn.close()

    # Pass outcomes are blocked from boosting when recurrence penalty is present.
    conn = connect_db(tmp_path / "matrix_pass_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "pass_recur", recurred=True)
    _insert_outcomes_for_matrix(conn, signature=signature, outcomes=["pass", "pass"])
    pass_recur = build_recommendation(conn, target)
    assert float(pass_recur["confidence"]) <= baseline_recur_conf
    assert int(pass_recur["confidence_breakdown"]["verification_outcome_score"]) == 0
    conn.close()

    # Fail outcomes with recurrence should further decrease confidence.
    conn = connect_db(tmp_path / "matrix_fail_recur.db")
    target = _seed_outcome_boost_data(conn, tmp_path / "fail_recur", recurred=True)
    _insert_outcomes_for_matrix(conn, signature=signature, outcomes=["fail", "fail"])
    fail_recur = build_recommendation(conn, target)
    assert float(fail_recur["confidence"]) < baseline_recur_conf
    assert int(fail_recur["confidence_breakdown"]["verification_outcome_score"]) < 0
    conn.close()
