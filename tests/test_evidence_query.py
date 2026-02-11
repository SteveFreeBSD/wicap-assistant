from __future__ import annotations

from pathlib import Path

from wicap_assist.db import (
    connect_db,
    insert_session,
    insert_signal,
    insert_verification_outcome,
    upsert_source,
)
from wicap_assist.evidence_query import (
    query_recent_related_session,
    query_related_session_ids,
    query_verification_track_record,
)


def _seed_session(conn, db_path: Path, *, session_id: str, snippet: str, ts: str) -> None:  # type: ignore[no-untyped-def]
    source_id = upsert_source(conn, "session", str(db_path), 1.0, 10)
    session_pk, _ = insert_session(
        conn,
        source_id=source_id,
        session_id=session_id,
        cwd="/tmp/wicap",
        ts_first=ts,
        ts_last=ts,
        repo_url="https://github.com/example/wicap.git",
        branch="main",
        commit_hash="deadbeef",
        is_wicap=True,
        raw_path=str(db_path),
    )
    insert_signal(
        conn,
        session_pk=session_pk,
        ts=ts,
        category="errors",
        fingerprint=f"fp-{session_id}",
        snippet=snippet,
        extra_json={},
    )


def test_query_related_session_helpers(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        _seed_session(
            conn,
            tmp_path / "s1.jsonl",
            session_id="s1",
            snippet="Error: wicap-ui failed to connect to redis",
            ts="2026-02-11T10:00:00+00:00",
        )
        _seed_session(
            conn,
            tmp_path / "s2.jsonl",
            session_id="s2",
            snippet="Error: unrelated service timeout",
            ts="2026-02-11T09:00:00+00:00",
        )
        conn.commit()

        session_ids = query_related_session_ids(conn, "wicap ui redis", limit=10)
        assert "s1" in session_ids
        recent_id, recent_ts = query_recent_related_session(conn, "wicap redis")
        assert recent_id == "s1"
        assert isinstance(recent_ts, str)
    finally:
        conn.close()


def test_query_verification_track_record(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        source_id = upsert_source(
            conn,
            kind="antigravity_log",
            path=str(tmp_path / "ag"),
            mtime=1.0,
            size=1,
        )
        conv_pk = conn.execute(
            """
            INSERT INTO conversations(source_id, conversation_id, title, ts_first, ts_last, task_summary, artifact_type)
            VALUES(?, 'conv-1', 'title', '2026-02-11T00:00:00+00:00', '2026-02-11T00:10:00+00:00', 'task', 'walkthrough')
            """,
            (source_id,),
        ).lastrowid
        assert conv_pk is not None

        insert_verification_outcome(
            conn,
            conversation_pk=int(conv_pk),
            signature="wicap redis connection failed",
            outcome="pass",
            evidence_snippet="pass evidence",
            ts="2026-02-11T00:02:00+00:00",
        )
        insert_verification_outcome(
            conn,
            conversation_pk=int(conv_pk),
            signature="wicap redis connection failed",
            outcome="fail",
            evidence_snippet="fail evidence",
            ts="2026-02-11T00:03:00+00:00",
        )
        conn.commit()

        record = query_verification_track_record(conn, "wicap redis connection failed")
        assert record is not None
        assert int(record["passes"]) == 1
        assert int(record["fails"]) == 1
        assert bool(record["relapse_detected"]) is True
    finally:
        conn.close()
