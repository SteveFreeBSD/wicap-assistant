from __future__ import annotations

from pathlib import Path

from wicap_assist.cross_pattern import detect_chronic_patterns
from wicap_assist.db import connect_db
from wicap_assist.ingest.soak_logs import ingest_soak_logs, parse_soak_log_file


def _write_log(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_docker_fail_iter_info_http_200_is_not_classified_as_docker_fail(tmp_path: Path) -> None:
    log_path = tmp_path / "logs_soak_1" / "docker_fail_iter_1.log"
    _write_log(
        log_path,
        ['2026-02-10 10:00:00 INFO "POST /api/internal/emit HTTP/1.1" 200 OK'],
    )

    events = parse_soak_log_file(log_path)
    docker_fail_count = sum(1 for event in events if event.category == "docker_fail")

    assert docker_fail_count == 0


def test_docker_fail_iter_error_line_is_classified_as_docker_fail(tmp_path: Path) -> None:
    log_path = tmp_path / "logs_soak_1" / "docker_fail_iter_2.log"
    _write_log(
        log_path,
        ["2026-02-10 10:00:01 ERROR docker API request failed to connect"],
    )

    events = parse_soak_log_file(log_path)
    categories = [event.category for event in events]

    assert "docker_fail" in categories


def test_docker_fail_iter_exited_state_is_classified_as_docker_fail(tmp_path: Path) -> None:
    log_path = tmp_path / "logs_soak_1" / "docker_fail_iter_3.log"
    _write_log(
        log_path,
        ["2026-02-10 10:00:02 wicap-api Exited (1) 2 seconds ago"],
    )

    events = parse_soak_log_file(log_path)
    categories = [event.category for event in events]

    assert "docker_fail" in categories


def test_real_error_category_remains_present(tmp_path: Path) -> None:
    log_path = tmp_path / "logs_soak_1" / "run.log"
    _write_log(
        log_path,
        ["2026-02-10 10:00:03 Error: failed to connect ECONNREFUSED"],
    )

    events = parse_soak_log_file(log_path)
    categories = [event.category for event in events]

    assert "error" in categories


def test_cross_patterns_only_shows_docker_fail_when_real_markers_exist(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    info_only_log = repo_root / "logs_soak_1" / "docker_fail_iter_1.log"
    _write_log(
        info_only_log,
        ['2026-02-10 10:00:00 INFO "POST /api/internal/emit HTTP/1.1" 200 OK'],
    )

    conn = connect_db(tmp_path / "assistant.db")
    ingest_soak_logs(conn, repo_root=repo_root)
    conn.commit()

    patterns_before = detect_chronic_patterns(conn, min_occurrences=1, min_span_days=0.0, top_n=20)
    assert not any(pattern.category == "docker_fail" for pattern in patterns_before)

    fail_log = repo_root / "logs_soak_2" / "docker_fail_iter_2.log"
    _write_log(
        fail_log,
        [
            "2026-02-11 10:00:00 ERROR docker compose failed with exit code 1",
            "2026-02-11 10:00:01 wicap-api Exited (1) 1 second ago",
        ],
    )
    ingest_soak_logs(conn, repo_root=repo_root)
    conn.commit()

    patterns_after = detect_chronic_patterns(conn, min_occurrences=1, min_span_days=0.0, top_n=20)
    assert any(pattern.category == "docker_fail" for pattern in patterns_after)

    conn.close()
