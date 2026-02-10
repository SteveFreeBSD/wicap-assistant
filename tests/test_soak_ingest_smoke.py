from __future__ import annotations

from pathlib import Path
import shutil

from wicap_assist.db import connect_db
from wicap_assist.ingest.soak_logs import ingest_soak_logs


def test_soak_ingest_smoke(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    soak_dir = repo_root / "logs_soak_1700000000"
    soak_dir.mkdir(parents=True)

    fixture = Path(__file__).parent / "data" / "sample_soak.log"
    target_log = soak_dir / "run.log"
    shutil.copy2(fixture, target_log)

    conn = connect_db(tmp_path / "assistant.db")
    files_seen, events_added = ingest_soak_logs(conn, repo_root=repo_root)
    conn.commit()

    assert files_seen == 1
    assert events_added >= 1

    total = conn.execute("SELECT count(*) FROM log_events").fetchone()[0]
    errors = conn.execute("SELECT count(*) FROM log_events WHERE category = 'error'").fetchone()[0]

    assert total >= 1
    assert errors >= 1

    conn.close()


def test_soak_ingest_is_idempotent_for_unchanged_sources(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    soak_dir = repo_root / "logs_soak_1700000001"
    soak_dir.mkdir(parents=True)

    fixture = Path(__file__).parent / "data" / "sample_soak.log"
    target_log = soak_dir / "run.log"
    shutil.copy2(fixture, target_log)

    conn = connect_db(tmp_path / "assistant.db")

    files_seen_first, events_added_first = ingest_soak_logs(conn, repo_root=repo_root)
    conn.commit()
    first_total = int(conn.execute("SELECT count(*) FROM log_events").fetchone()[0])

    files_seen_second, events_added_second = ingest_soak_logs(conn, repo_root=repo_root)
    conn.commit()
    second_total = int(conn.execute("SELECT count(*) FROM log_events").fetchone()[0])

    assert files_seen_first == 1
    assert files_seen_second == 1
    assert events_added_first >= 1
    assert events_added_second == 0
    assert second_total == first_total

    conn.close()
