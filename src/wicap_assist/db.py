"""SQLite storage for wicap_assist."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.util.time import utc_now_iso

DEFAULT_DB_PATH = Path("data/assistant.db")

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    mtime REAL NOT NULL,
    size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    cwd TEXT,
    ts_first TEXT,
    ts_last TEXT,
    repo_url TEXT,
    branch TEXT,
    commit_hash TEXT,
    is_wicap INTEGER NOT NULL,
    raw_path TEXT NOT NULL,
    UNIQUE(raw_path, session_id),
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_pk INTEGER NOT NULL,
    ts TEXT,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    snippet TEXT NOT NULL,
    extra_json TEXT,
    UNIQUE(session_pk, category, fingerprint),
    FOREIGN KEY(session_pk) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ingests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_ts TEXT NOT NULL,
    finished_ts TEXT,
    files_seen INTEGER NOT NULL,
    sessions_added INTEGER NOT NULL,
    signals_added INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    ts_text TEXT,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    snippet TEXT NOT NULL,
    file_path TEXT NOT NULL,
    extra_json TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS harness_scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    script_path TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    commands_json TEXT NOT NULL,
    tools_json TEXT NOT NULL,
    env_vars_json TEXT NOT NULL,
    last_modified TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    conversation_id TEXT NOT NULL UNIQUE,
    title TEXT,
    ts_first TEXT,
    ts_last TEXT,
    task_summary TEXT,
    artifact_type TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS conversation_signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_pk INTEGER NOT NULL,
    ts TEXT,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    snippet TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    extra_json TEXT,
    UNIQUE(conversation_pk, category, fingerprint),
    FOREIGN KEY(conversation_pk) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS changelog_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    release_tag TEXT NOT NULL,
    section TEXT NOT NULL,
    snippet TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verification_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_pk INTEGER,
    signature TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_snippet TEXT NOT NULL,
    ts TEXT,
    FOREIGN KEY(conversation_pk) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS soak_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_ts TEXT NOT NULL,
    ended_ts TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    runner_path TEXT NOT NULL,
    args_json TEXT NOT NULL,
    run_dir TEXT NOT NULL,
    newest_soak_dir TEXT,
    incident_path TEXT
);

CREATE TABLE IF NOT EXISTS live_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    service_status_json TEXT NOT NULL,
    top_signatures_json TEXT NOT NULL,
    recommended_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS control_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    soak_run_id INTEGER,
    ts TEXT NOT NULL,
    decision TEXT NOT NULL,
    action TEXT,
    status TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS control_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    soak_run_id INTEGER,
    started_ts TEXT NOT NULL,
    ended_ts TEXT,
    last_heartbeat_ts TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    current_phase TEXT,
    handoff_state TEXT,
    metadata_json TEXT NOT NULL,
    FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS control_session_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_session_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    phase TEXT,
    status TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_ts TEXT NOT NULL
);
"""

_MIGRATIONS: tuple[tuple[int, str, tuple[str, ...]], ...] = (
    (
        1,
        "core_index_hardening",
        (
            "CREATE INDEX IF NOT EXISTS idx_signals_category_fingerprint_session ON signals(category, fingerprint, session_pk)",
            "CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts)",
            "CREATE INDEX IF NOT EXISTS idx_log_events_category_ts_fingerprint ON log_events(category, ts_text, fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_log_events_file_path ON log_events(file_path)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_ts_last_is_wicap ON sessions(ts_last, is_wicap)",
            "CREATE INDEX IF NOT EXISTS idx_verification_outcomes_signature_ts ON verification_outcomes(signature, ts)",
            "CREATE INDEX IF NOT EXISTS idx_control_events_soak_run_ts ON control_events(soak_run_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_control_sessions_status_started ON control_sessions(status, started_ts)",
        ),
    ),
)


def connect_db(path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open SQLite DB and ensure schema exists."""
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _configure_connection_pragmas(conn)
    conn.executescript(_SCHEMA_SQL)
    _ensure_sessions_git_columns(conn)
    _ensure_control_session_columns(conn)
    _apply_migrations(conn)
    conn.commit()
    return conn


def _configure_connection_pragmas(conn: sqlite3.Connection) -> None:
    """Apply connection pragmas that improve write/read resilience."""
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        # Fallback silently (e.g., unsupported FS mode).
        pass
    try:
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.DatabaseError:
        pass


def _apply_migrations(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    applied = {int(row["version"]) for row in rows}
    for version, name, statements in _MIGRATIONS:
        if version in applied:
            continue
        for statement in statements:
            conn.execute(statement)
        conn.execute(
            "INSERT INTO schema_migrations(version, name, applied_ts) VALUES(?, ?, ?)",
            (int(version), str(name), utc_now_iso()),
        )


def _ensure_sessions_git_columns(conn: sqlite3.Connection) -> None:
    """Ensure legacy sessions tables have git metadata columns."""
    rows = conn.execute("PRAGMA table_info(sessions)").fetchall()
    columns = {str(row["name"]) for row in rows}

    if "repo_url" not in columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN repo_url TEXT")
    if "branch" not in columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN branch TEXT")
    if "commit_hash" not in columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN commit_hash TEXT")


def _ensure_control_session_columns(conn: sqlite3.Connection) -> None:
    """Ensure legacy control_sessions tables have heartbeat/handoff columns."""
    rows = conn.execute("PRAGMA table_info(control_sessions)").fetchall()
    columns = {str(row["name"]) for row in rows}

    if "last_heartbeat_ts" not in columns:
        conn.execute("ALTER TABLE control_sessions ADD COLUMN last_heartbeat_ts TEXT")
    if "handoff_state" not in columns:
        conn.execute("ALTER TABLE control_sessions ADD COLUMN handoff_state TEXT")


def upsert_source(conn: sqlite3.Connection, kind: str, path: str, mtime: float, size: int) -> int:
    """Insert or update source file metadata and return source primary key."""
    conn.execute(
        """
        INSERT INTO sources(kind, path, mtime, size)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            kind = excluded.kind,
            mtime = excluded.mtime,
            size = excluded.size
        """,
        (kind, path, mtime, size),
    )
    row = conn.execute("SELECT id FROM sources WHERE path = ?", (path,)).fetchone()
    if row is None:
        raise RuntimeError(f"Failed to fetch source id for {path}")
    return int(row["id"])


def get_source(conn: sqlite3.Connection, path: str) -> sqlite3.Row | None:
    """Fetch one source row by path."""
    return conn.execute("SELECT id, kind, mtime, size FROM sources WHERE path = ?", (path,)).fetchone()


def insert_session(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    session_id: str,
    cwd: str | None,
    ts_first: str | None,
    ts_last: str | None,
    repo_url: str | None,
    branch: str | None,
    commit_hash: str | None,
    is_wicap: bool,
    raw_path: str,
) -> tuple[int, bool]:
    """Insert session, returning (id, inserted_flag)."""
    existing = conn.execute(
        "SELECT id FROM sessions WHERE raw_path = ? AND session_id = ?",
        (raw_path, session_id),
    ).fetchone()
    if existing is not None:
        session_pk = int(existing["id"])
        conn.execute(
            """
            UPDATE sessions
            SET
                source_id = ?,
                cwd = coalesce(?, cwd),
                ts_first = coalesce(?, ts_first),
                ts_last = coalesce(?, ts_last),
                repo_url = coalesce(?, repo_url),
                branch = coalesce(?, branch),
                commit_hash = coalesce(?, commit_hash),
                is_wicap = CASE WHEN ? = 1 OR is_wicap = 1 THEN 1 ELSE 0 END
            WHERE id = ?
            """,
            (
                source_id,
                cwd,
                ts_first,
                ts_last,
                repo_url,
                branch,
                commit_hash,
                int(is_wicap),
                session_pk,
            ),
        )
        return session_pk, False

    cur = conn.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            session_id,
            cwd,
            ts_first,
            ts_last,
            repo_url,
            branch,
            commit_hash,
            int(is_wicap),
            raw_path,
        ),
    )

    if cur.rowcount and cur.lastrowid is not None:
        return int(cur.lastrowid), True
    raise RuntimeError(f"Failed to insert session row for {session_id}")


def insert_signal(
    conn: sqlite3.Connection,
    *,
    session_pk: int,
    ts: str | None,
    category: str,
    fingerprint: str,
    snippet: str,
    extra_json: dict[str, Any] | None = None,
) -> bool:
    """Insert one signal. Returns True when newly inserted."""
    payload = json.dumps(extra_json or {}, sort_keys=True)
    cur = conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_pk, category, fingerprint) DO NOTHING
        """,
        (session_pk, ts, category, fingerprint, snippet, payload),
    )
    return bool(cur.rowcount)


def delete_log_events_for_source(conn: sqlite3.Connection, source_id: int) -> None:
    """Delete prior log events for one source."""
    conn.execute("DELETE FROM log_events WHERE source_id = ?", (source_id,))


def insert_log_event(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    ts_text: str | None,
    category: str,
    fingerprint: str,
    snippet: str,
    file_path: str,
    extra_json: dict[str, Any] | None = None,
) -> bool:
    """Insert one soak log event."""
    payload = json.dumps(extra_json or {}, sort_keys=True)
    cur = conn.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (source_id, ts_text, category, fingerprint, snippet, file_path, payload),
    )
    return bool(cur.rowcount)


def upsert_harness_script(
    conn: sqlite3.Connection,
    *,
    script_path: str,
    role: str,
    commands: list[str],
    tools: list[str],
    env_vars: list[str],
    last_modified: str,
) -> None:
    """Insert or update one harness script analysis row."""
    conn.execute(
        """
        INSERT INTO harness_scripts(script_path, role, commands_json, tools_json, env_vars_json, last_modified)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(script_path) DO UPDATE SET
            role = excluded.role,
            commands_json = excluded.commands_json,
            tools_json = excluded.tools_json,
            env_vars_json = excluded.env_vars_json,
            last_modified = excluded.last_modified
        """,
        (
            script_path,
            role,
            json.dumps(commands, sort_keys=True),
            json.dumps(tools, sort_keys=True),
            json.dumps(env_vars, sort_keys=True),
            last_modified,
        ),
    )


def start_ingest(conn: sqlite3.Connection, started_ts: str) -> int:
    """Create ingest row and return ingest primary key."""
    cur = conn.execute(
        """
        INSERT INTO ingests(started_ts, finished_ts, files_seen, sessions_added, signals_added)
        VALUES(?, NULL, 0, 0, 0)
        """,
        (started_ts,),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to create ingest row")
    return int(cur.lastrowid)


def finish_ingest(
    conn: sqlite3.Connection,
    ingest_id: int,
    *,
    finished_ts: str,
    files_seen: int,
    sessions_added: int,
    signals_added: int,
) -> None:
    """Finalize ingest metrics."""
    conn.execute(
        """
        UPDATE ingests
        SET finished_ts = ?, files_seen = ?, sessions_added = ?, signals_added = ?
        WHERE id = ?
        """,
        (finished_ts, files_seen, sessions_added, signals_added, ingest_id),
    )


def search_signals(conn: sqlite3.Connection, query: str, limit: int = 200) -> list[sqlite3.Row]:
    """Search snippets and return matching joined rows."""
    q = f"%{query.lower()}%"
    rows = conn.execute(
        """
        SELECT
            s.id AS session_pk,
            s.session_id,
            s.cwd,
            s.ts_last,
            s.repo_url,
            s.branch,
            s.commit_hash,
            s.raw_path,
            sg.category,
            sg.snippet,
            sg.fingerprint,
            sg.ts
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE
            s.is_wicap = 1
            AND (
                lower(sg.snippet) LIKE ?
                OR lower(coalesce(sg.extra_json, '')) LIKE ?
            )
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        LIMIT ?
        """,
        (q, q, limit),
    ).fetchall()
    return rows


# ---------------------------------------------------------------------------
# Conversation helpers
# ---------------------------------------------------------------------------


def insert_conversation(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    conversation_id: str,
    title: str | None,
    ts_first: str | None,
    ts_last: str | None,
    task_summary: str | None,
    artifact_type: str | None,
) -> tuple[int, bool]:
    """Insert conversation, returning (id, inserted_flag)."""
    cur = conn.execute(
        """
        INSERT INTO conversations(
            source_id, conversation_id, title, ts_first, ts_last,
            task_summary, artifact_type
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(conversation_id) DO UPDATE SET
            source_id = excluded.source_id,
            title = excluded.title,
            ts_first = excluded.ts_first,
            ts_last = excluded.ts_last,
            task_summary = excluded.task_summary,
            artifact_type = excluded.artifact_type
        """,
        (source_id, conversation_id, title, ts_first, ts_last, task_summary, artifact_type),
    )

    row = conn.execute(
        "SELECT id FROM conversations WHERE conversation_id = ?",
        (conversation_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Failed to fetch conversation row for {conversation_id}")
    pk = int(row["id"])
    return pk, bool(cur.rowcount)


def delete_conversation_signals(conn: sqlite3.Connection, conversation_pk: int) -> None:
    """Delete prior conversation signals for re-ingestion."""
    conn.execute("DELETE FROM conversation_signals WHERE conversation_pk = ?", (conversation_pk,))


def insert_conversation_signal(
    conn: sqlite3.Connection,
    *,
    conversation_pk: int,
    ts: str | None,
    category: str,
    fingerprint: str,
    snippet: str,
    artifact_name: str,
    extra_json: dict[str, Any] | None = None,
) -> bool:
    """Insert one conversation signal. Returns True when newly inserted."""
    payload = json.dumps(extra_json or {}, sort_keys=True)
    cur = conn.execute(
        """
        INSERT INTO conversation_signals(
            conversation_pk, ts, category, fingerprint, snippet, artifact_name, extra_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(conversation_pk, category, fingerprint) DO NOTHING
        """,
        (conversation_pk, ts, category, fingerprint, snippet, artifact_name, payload),
    )
    return bool(cur.rowcount)


# ---------------------------------------------------------------------------
# Changelog helpers
# ---------------------------------------------------------------------------


def delete_changelog_entries_for_source(conn: sqlite3.Connection, source_id: int) -> None:
    """Delete prior changelog entries for re-ingestion."""
    conn.execute("DELETE FROM changelog_entries WHERE source_id = ?", (source_id,))


def upsert_changelog_entry(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    release_tag: str,
    section: str,
    snippet: str,
    fingerprint: str,
) -> bool:
    """Insert one changelog entry. Returns True when newly inserted."""
    cur = conn.execute(
        """
        INSERT INTO changelog_entries(source_id, release_tag, section, snippet, fingerprint)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            source_id = excluded.source_id,
            release_tag = excluded.release_tag,
            section = excluded.section,
            snippet = excluded.snippet
        """,
        (source_id, release_tag, section, snippet, fingerprint),
    )
    return bool(cur.rowcount)


# ---------------------------------------------------------------------------
# Verification outcome helpers
# ---------------------------------------------------------------------------


def insert_verification_outcome(
    conn: sqlite3.Connection,
    *,
    conversation_pk: int | None,
    signature: str,
    outcome: str,
    evidence_snippet: str,
    ts: str | None,
) -> bool:
    """Insert one verification outcome. Returns True when newly inserted."""
    raw = str(outcome).strip().lower()
    if raw in {"pass", "passed", "success", "successful", "resolved", "fixed"}:
        normalized = "pass"
    elif raw in {"fail", "failed", "failure", "broken", "still broken"}:
        normalized = "fail"
    else:
        normalized = "unknown"

    cur = conn.execute(
        """
        INSERT INTO verification_outcomes(conversation_pk, signature, outcome, evidence_snippet, ts)
        VALUES(?, ?, ?, ?, ?)
        """,
        (conversation_pk, signature, normalized, evidence_snippet, ts),
    )
    return bool(cur.rowcount)


def delete_verification_outcomes_for_conversation(conn: sqlite3.Connection, conversation_pk: int) -> None:
    """Delete prior verification outcomes for a conversation."""
    conn.execute("DELETE FROM verification_outcomes WHERE conversation_pk = ?", (conversation_pk,))


def query_outcomes_for_signature(conn: sqlite3.Connection, signature: str) -> list[sqlite3.Row]:
    """Query verification outcomes matching a signature substring."""
    q = f"%{signature.lower()}%"
    return conn.execute(
        """
        SELECT outcome, evidence_snippet, ts, conversation_pk
        FROM verification_outcomes
        WHERE lower(signature) LIKE ?
        ORDER BY ts DESC
        LIMIT 50
        """,
        (q,),
    ).fetchall()


# ---------------------------------------------------------------------------
# Soak run helpers
# ---------------------------------------------------------------------------


def insert_soak_run(
    conn: sqlite3.Connection,
    *,
    started_ts: str,
    ended_ts: str,
    exit_code: int,
    runner_path: str,
    args_json: dict[str, Any],
    run_dir: str,
    newest_soak_dir: str | None,
    incident_path: str | None,
) -> int:
    """Insert one supervised soak run row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO soak_runs(
            started_ts, ended_ts, exit_code, runner_path, args_json,
            run_dir, newest_soak_dir, incident_path
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            started_ts,
            ended_ts,
            int(exit_code),
            runner_path,
            json.dumps(args_json, sort_keys=True),
            run_dir,
            newest_soak_dir,
            incident_path,
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert soak run row")
    return int(cur.lastrowid)


def insert_live_observation(
    conn: sqlite3.Connection,
    *,
    ts: str,
    service_status_json: dict[str, Any],
    top_signatures_json: list[dict[str, Any]],
    recommended_json: list[dict[str, Any]],
) -> int:
    """Insert one live monitor observation row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO live_observations(
            ts, service_status_json, top_signatures_json, recommended_json
        )
        VALUES(?, ?, ?, ?)
        """,
        (
            ts,
            json.dumps(service_status_json, sort_keys=True),
            json.dumps(top_signatures_json, sort_keys=True),
            json.dumps(recommended_json, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert live observation row")
    return int(cur.lastrowid)


def insert_control_event(
    conn: sqlite3.Connection,
    *,
    soak_run_id: int | None,
    ts: str,
    decision: str,
    action: str | None,
    status: str,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control event row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO control_events(
            soak_run_id, ts, decision, action, status, detail_json
        )
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            soak_run_id,
            ts,
            decision,
            action,
            status,
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert control event row")
    return int(cur.lastrowid)


def insert_control_session(
    conn: sqlite3.Connection,
    *,
    soak_run_id: int | None,
    started_ts: str,
    last_heartbeat_ts: str | None = None,
    mode: str,
    status: str,
    current_phase: str | None,
    handoff_state: str | None = None,
    metadata_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control session row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO control_sessions(
            soak_run_id, started_ts, ended_ts, last_heartbeat_ts, mode, status, current_phase, handoff_state, metadata_json
        )
        VALUES(?, ?, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            soak_run_id,
            started_ts,
            last_heartbeat_ts if last_heartbeat_ts is not None else started_ts,
            mode,
            status,
            current_phase,
            handoff_state,
            json.dumps(metadata_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert control session row")
    return int(cur.lastrowid)


def update_control_session(
    conn: sqlite3.Connection,
    *,
    control_session_id: int,
    soak_run_id: int | None = None,
    ended_ts: str | None = None,
    last_heartbeat_ts: str | None = None,
    status: str | None = None,
    current_phase: str | None = None,
    handoff_state: str | None = None,
    metadata_json: dict[str, Any] | None = None,
) -> None:
    """Update one control session row with explicit fields."""
    row = conn.execute(
        """
        SELECT soak_run_id, ended_ts, last_heartbeat_ts, status, current_phase, handoff_state, metadata_json
        FROM control_sessions
        WHERE id = ?
        """,
        (control_session_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Unknown control session id: {control_session_id}")

    existing_metadata: dict[str, Any] = {}
    raw_meta = row["metadata_json"]
    if isinstance(raw_meta, str) and raw_meta.strip():
        try:
            parsed = json.loads(raw_meta)
            if isinstance(parsed, dict):
                existing_metadata = parsed
        except json.JSONDecodeError:
            existing_metadata = {}
    if metadata_json:
        existing_metadata.update(metadata_json)

    conn.execute(
        """
        UPDATE control_sessions
        SET soak_run_id = ?, ended_ts = ?, last_heartbeat_ts = ?, status = ?, current_phase = ?, handoff_state = ?, metadata_json = ?
        WHERE id = ?
        """,
        (
            row["soak_run_id"] if soak_run_id is None else soak_run_id,
            row["ended_ts"] if ended_ts is None else ended_ts,
            row["last_heartbeat_ts"] if last_heartbeat_ts is None else last_heartbeat_ts,
            row["status"] if status is None else status,
            row["current_phase"] if current_phase is None else current_phase,
            row["handoff_state"] if handoff_state is None else handoff_state,
            json.dumps(existing_metadata, sort_keys=True),
            control_session_id,
        ),
    )


def insert_control_session_event(
    conn: sqlite3.Connection,
    *,
    control_session_id: int,
    ts: str,
    phase: str | None,
    status: str,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control session phase/status event and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO control_session_events(
            control_session_id, ts, phase, status, detail_json
        )
        VALUES(?, ?, ?, ?, ?)
        """,
        (
            int(control_session_id),
            ts,
            phase,
            status,
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert control session event row")
    return int(cur.lastrowid)


def close_running_control_sessions(
    conn: sqlite3.Connection,
    *,
    ended_ts: str,
    reason: str,
    exclude_session_id: int | None = None,
) -> int:
    """Close any stale running control sessions before a new session starts."""
    rows = conn.execute(
        """
        SELECT id
        FROM control_sessions
        WHERE ended_ts IS NULL
          AND status IN ('running', 'escalated')
        """
    ).fetchall()
    count = 0
    for row in rows:
        session_id = int(row["id"])
        if exclude_session_id is not None and int(session_id) == int(exclude_session_id):
            continue
        update_control_session(
            conn,
            control_session_id=session_id,
            ended_ts=ended_ts,
            status="interrupted",
            current_phase="interrupted",
            handoff_state="interrupted",
            metadata_json={"interruption_reason": reason},
        )
        insert_control_session_event(
            conn,
            control_session_id=session_id,
            ts=ended_ts,
            phase="interrupted",
            status="interrupted",
            detail_json={"reason": reason},
        )
        count += 1
    return count
