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

CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_session_id INTEGER,
    soak_run_id INTEGER,
    ts_started TEXT NOT NULL,
    ts_ended TEXT,
    decision TEXT NOT NULL,
    action TEXT,
    status TEXT NOT NULL,
    pre_state_json TEXT NOT NULL,
    post_state_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,
    FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS episode_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    episode_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS episode_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    episode_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS decision_features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_session_id INTEGER,
    soak_run_id INTEGER,
    episode_id INTEGER,
    ts TEXT NOT NULL,
    mode TEXT NOT NULL,
    policy_profile TEXT NOT NULL,
    decision TEXT NOT NULL,
    action TEXT,
    status TEXT NOT NULL,
    feature_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,
    FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL,
    FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS forecast_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    horizon_sec INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    confidence_low REAL,
    confidence_high REAL,
    signature TEXT,
    summary TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS drift_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    delta REAL NOT NULL,
    long_mean REAL,
    short_mean REAL,
    sample_count INTEGER,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_shadow_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    decision TEXT NOT NULL,
    action TEXT,
    model_id TEXT NOT NULL,
    score REAL,
    vote INTEGER NOT NULL,
    agreement REAL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proactive_action_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    control_session_id INTEGER,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    trigger_risk_score REAL,
    horizon_sec INTEGER,
    payload_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    control_session_id INTEGER,
    soak_run_id INTEGER,
    action TEXT NOT NULL,
    mode TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    denied_by TEXT,
    reason TEXT,
    trace_id TEXT,
    policy_trace_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,
    FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS failover_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    control_session_id INTEGER,
    auth_profile TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    failure_class TEXT NOT NULL,
    cooldown_until TEXT,
    disabled_until TEXT,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS auth_profile_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile TEXT NOT NULL UNIQUE,
    attempt INTEGER NOT NULL,
    failure_class TEXT,
    cooldown_until TEXT,
    disabled_until TEXT,
    updated_ts TEXT NOT NULL,
    state_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_compactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    control_session_id INTEGER,
    compacted_rows INTEGER NOT NULL,
    summary_json TEXT NOT NULL,
    FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS mission_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    ts_started TEXT NOT NULL,
    ts_ended TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    graph_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mission_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_run_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_type TEXT NOT NULL,
    status TEXT NOT NULL,
    handoff_token TEXT,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(mission_run_id) REFERENCES mission_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    cert_type TEXT NOT NULL,
    profile TEXT NOT NULL,
    pass INTEGER NOT NULL,
    score REAL NOT NULL,
    detail_json TEXT NOT NULL
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
    (
        2,
        "episode_memory_tiers",
        (
            "CREATE TABLE IF NOT EXISTS episodes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "control_session_id INTEGER,"
            "soak_run_id INTEGER,"
            "ts_started TEXT NOT NULL,"
            "ts_ended TEXT,"
            "decision TEXT NOT NULL,"
            "action TEXT,"
            "status TEXT NOT NULL,"
            "pre_state_json TEXT NOT NULL,"
            "post_state_json TEXT NOT NULL,"
            "metadata_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,"
            "FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS episode_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "episode_id INTEGER NOT NULL,"
            "ts TEXT NOT NULL,"
            "event_type TEXT NOT NULL,"
            "payload_json TEXT NOT NULL,"
            "FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE CASCADE"
            ")",
            "CREATE TABLE IF NOT EXISTS episode_outcomes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "episode_id INTEGER NOT NULL,"
            "ts TEXT NOT NULL,"
            "outcome TEXT NOT NULL,"
            "detail_json TEXT NOT NULL,"
            "FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE CASCADE"
            ")",
            "CREATE INDEX IF NOT EXISTS idx_episodes_control_session_ts ON episodes(control_session_id, ts_started)",
            "CREATE INDEX IF NOT EXISTS idx_episodes_soak_run_ts ON episodes(soak_run_id, ts_started)",
            "CREATE INDEX IF NOT EXISTS idx_episode_events_episode_ts ON episode_events(episode_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_episode_outcomes_episode_ts ON episode_outcomes(episode_id, ts)",
        ),
    ),
    (
        3,
        "decision_feature_store",
        (
            "CREATE TABLE IF NOT EXISTS decision_features ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "control_session_id INTEGER,"
            "soak_run_id INTEGER,"
            "episode_id INTEGER,"
            "ts TEXT NOT NULL,"
            "mode TEXT NOT NULL,"
            "policy_profile TEXT NOT NULL,"
            "decision TEXT NOT NULL,"
            "action TEXT,"
            "status TEXT NOT NULL,"
            "feature_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,"
            "FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL,"
            "FOREIGN KEY(episode_id) REFERENCES episodes(id) ON DELETE SET NULL"
            ")",
            "CREATE INDEX IF NOT EXISTS idx_decision_features_session_ts ON decision_features(control_session_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_decision_features_soak_run_ts ON decision_features(soak_run_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_decision_features_episode ON decision_features(episode_id)",
            "CREATE INDEX IF NOT EXISTS idx_decision_features_action_status_ts ON decision_features(action, status, ts)",
        ),
    ),
    (
        4,
        "forecast_drift_and_proactive_tables",
        (
            "CREATE TABLE IF NOT EXISTS forecast_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "source TEXT NOT NULL,"
            "horizon_sec INTEGER NOT NULL,"
            "risk_score REAL NOT NULL,"
            "confidence_low REAL,"
            "confidence_high REAL,"
            "signature TEXT,"
            "summary TEXT,"
            "payload_json TEXT NOT NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS drift_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "source TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "delta REAL NOT NULL,"
            "long_mean REAL,"
            "short_mean REAL,"
            "sample_count INTEGER,"
            "payload_json TEXT NOT NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS model_shadow_metrics ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "source TEXT NOT NULL,"
            "decision TEXT NOT NULL,"
            "action TEXT,"
            "model_id TEXT NOT NULL,"
            "score REAL,"
            "vote INTEGER NOT NULL,"
            "agreement REAL,"
            "payload_json TEXT NOT NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS proactive_action_outcomes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "control_session_id INTEGER,"
            "action TEXT NOT NULL,"
            "decision TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "trigger_risk_score REAL,"
            "horizon_sec INTEGER,"
            "payload_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL"
            ")",
            "CREATE INDEX IF NOT EXISTS idx_forecast_events_ts_horizon ON forecast_events(ts, horizon_sec)",
            "CREATE INDEX IF NOT EXISTS idx_drift_events_ts_status ON drift_events(ts, status)",
            "CREATE INDEX IF NOT EXISTS idx_model_shadow_metrics_ts_model ON model_shadow_metrics(ts, model_id)",
            "CREATE INDEX IF NOT EXISTS idx_proactive_action_outcomes_session_ts ON proactive_action_outcomes(control_session_id, ts)",
        ),
    ),
    (
        5,
        "policy_failover_mission_certification_tables",
        (
            "CREATE TABLE IF NOT EXISTS policy_decisions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "control_session_id INTEGER,"
            "soak_run_id INTEGER,"
            "action TEXT NOT NULL,"
            "mode TEXT NOT NULL,"
            "allowed INTEGER NOT NULL,"
            "denied_by TEXT,"
            "reason TEXT,"
            "trace_id TEXT,"
            "policy_trace_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL,"
            "FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS failover_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "control_session_id INTEGER,"
            "auth_profile TEXT NOT NULL,"
            "attempt INTEGER NOT NULL,"
            "failure_class TEXT NOT NULL,"
            "cooldown_until TEXT,"
            "disabled_until TEXT,"
            "detail_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS auth_profile_state ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "profile TEXT NOT NULL UNIQUE,"
            "attempt INTEGER NOT NULL,"
            "failure_class TEXT,"
            "cooldown_until TEXT,"
            "disabled_until TEXT,"
            "updated_ts TEXT NOT NULL,"
            "state_json TEXT NOT NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS memory_compactions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "control_session_id INTEGER,"
            "compacted_rows INTEGER NOT NULL,"
            "summary_json TEXT NOT NULL,"
            "FOREIGN KEY(control_session_id) REFERENCES control_sessions(id) ON DELETE SET NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS mission_runs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "run_id TEXT NOT NULL UNIQUE,"
            "ts_started TEXT NOT NULL,"
            "ts_ended TEXT,"
            "mode TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "graph_id TEXT NOT NULL,"
            "metadata_json TEXT NOT NULL"
            ")",
            "CREATE TABLE IF NOT EXISTS mission_steps ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "mission_run_id INTEGER NOT NULL,"
            "ts TEXT NOT NULL,"
            "step_id TEXT NOT NULL,"
            "step_type TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "handoff_token TEXT,"
            "detail_json TEXT NOT NULL,"
            "FOREIGN KEY(mission_run_id) REFERENCES mission_runs(id) ON DELETE CASCADE"
            ")",
            "CREATE TABLE IF NOT EXISTS certification_runs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts TEXT NOT NULL,"
            "cert_type TEXT NOT NULL,"
            "profile TEXT NOT NULL,"
            "pass INTEGER NOT NULL,"
            "score REAL NOT NULL,"
            "detail_json TEXT NOT NULL"
            ")",
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_ts_mode_allowed ON policy_decisions(ts, mode, allowed)",
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_trace_id ON policy_decisions(trace_id)",
            "CREATE INDEX IF NOT EXISTS idx_failover_events_ts_profile ON failover_events(ts, auth_profile)",
            "CREATE INDEX IF NOT EXISTS idx_auth_profile_state_updated ON auth_profile_state(updated_ts)",
            "CREATE INDEX IF NOT EXISTS idx_memory_compactions_ts ON memory_compactions(ts)",
            "CREATE INDEX IF NOT EXISTS idx_mission_runs_started_status ON mission_runs(ts_started, status)",
            "CREATE INDEX IF NOT EXISTS idx_mission_steps_run_ts ON mission_steps(mission_run_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_certification_runs_ts_type ON certification_runs(ts, cert_type)",
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
    _ensure_model_shadow_source_column(conn)
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


def _ensure_model_shadow_source_column(conn: sqlite3.Connection) -> None:
    """Ensure legacy model_shadow_metrics tables include source column."""
    rows = conn.execute("PRAGMA table_info(model_shadow_metrics)").fetchall()
    if not rows:
        return
    columns = {str(row["name"]) for row in rows}
    if "source" not in columns:
        conn.execute("ALTER TABLE model_shadow_metrics ADD COLUMN source TEXT")
        conn.execute("UPDATE model_shadow_metrics SET source = 'legacy' WHERE source IS NULL OR trim(source) = ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_model_shadow_metrics_source_ts ON model_shadow_metrics(source, ts)"
    )


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


def insert_episode(
    conn: sqlite3.Connection,
    *,
    control_session_id: int | None,
    soak_run_id: int | None,
    ts_started: str,
    ts_ended: str | None,
    decision: str,
    action: str | None,
    status: str,
    pre_state_json: dict[str, Any] | None = None,
    post_state_json: dict[str, Any] | None = None,
    metadata_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control episode and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO episodes(
            control_session_id, soak_run_id, ts_started, ts_ended, decision, action, status,
            pre_state_json, post_state_json, metadata_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            control_session_id,
            soak_run_id,
            ts_started,
            ts_ended,
            decision,
            action,
            status,
            json.dumps(pre_state_json or {}, sort_keys=True),
            json.dumps(post_state_json or {}, sort_keys=True),
            json.dumps(metadata_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert episode row")
    return int(cur.lastrowid)


def insert_episode_event(
    conn: sqlite3.Connection,
    *,
    episode_id: int,
    ts: str,
    event_type: str,
    payload_json: dict[str, Any] | None = None,
) -> int:
    """Insert one episode event row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO episode_events(episode_id, ts, event_type, payload_json)
        VALUES(?, ?, ?, ?)
        """,
        (
            int(episode_id),
            ts,
            event_type,
            json.dumps(payload_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert episode event row")
    return int(cur.lastrowid)


def insert_episode_outcome(
    conn: sqlite3.Connection,
    *,
    episode_id: int,
    ts: str,
    outcome: str,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one episode outcome row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO episode_outcomes(episode_id, ts, outcome, detail_json)
        VALUES(?, ?, ?, ?)
        """,
        (
            int(episode_id),
            ts,
            outcome,
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert episode outcome row")
    return int(cur.lastrowid)


def insert_control_episode(
    conn: sqlite3.Connection,
    *,
    control_session_id: int | None,
    soak_run_id: int | None,
    ts: str,
    decision: str,
    action: str | None,
    status: str,
    pre_state_json: dict[str, Any] | None = None,
    post_state_json: dict[str, Any] | None = None,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control episode with linked event and outcome rows."""
    episode_id = insert_episode(
        conn,
        control_session_id=control_session_id,
        soak_run_id=soak_run_id,
        ts_started=ts,
        ts_ended=ts,
        decision=decision,
        action=action,
        status=status,
        pre_state_json=pre_state_json,
        post_state_json=post_state_json,
        metadata_json={"source": "control_event"},
    )
    payload = dict(detail_json or {})
    payload.setdefault("decision", str(decision))
    payload.setdefault("action", str(action) if action is not None else None)
    payload.setdefault("status", str(status))
    insert_episode_event(
        conn,
        episode_id=episode_id,
        ts=ts,
        event_type="control_event",
        payload_json=payload,
    )
    insert_episode_outcome(
        conn,
        episode_id=episode_id,
        ts=ts,
        outcome=str(status),
        detail_json=payload,
    )
    return int(episode_id)


def insert_control_event(
    conn: sqlite3.Connection,
    *,
    soak_run_id: int | None,
    ts: str,
    decision: str,
    action: str | None,
    status: str,
    episode_id: int | None = None,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one control event row and return primary key."""
    detail_payload = dict(detail_json or {})
    if episode_id is not None:
        detail_payload["episode_id"] = int(episode_id)
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
            json.dumps(detail_payload, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert control event row")
    return int(cur.lastrowid)


def insert_decision_feature(
    conn: sqlite3.Connection,
    *,
    control_session_id: int | None,
    soak_run_id: int | None,
    episode_id: int | None,
    ts: str,
    mode: str,
    policy_profile: str,
    decision: str,
    action: str | None,
    status: str,
    feature_json: dict[str, Any] | None = None,
) -> int:
    """Insert one decision feature row and return primary key."""
    cur = conn.execute(
        """
        INSERT INTO decision_features(
            control_session_id, soak_run_id, episode_id, ts,
            mode, policy_profile, decision, action, status, feature_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            control_session_id,
            soak_run_id,
            episode_id,
            ts,
            mode,
            policy_profile,
            decision,
            action,
            status,
            json.dumps(feature_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert decision feature row")
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


# ---------------------------------------------------------------------------
# Forecast / drift / shadow metrics helpers
# ---------------------------------------------------------------------------


def delete_forecast_events_for_source(conn: sqlite3.Connection, source: str) -> None:
    """Delete forecast events for one source path."""
    conn.execute("DELETE FROM forecast_events WHERE source = ?", (str(source),))


def delete_drift_events_for_source(conn: sqlite3.Connection, source: str) -> None:
    """Delete drift events for one source path."""
    conn.execute("DELETE FROM drift_events WHERE source = ?", (str(source),))


def delete_model_shadow_metrics_for_source(conn: sqlite3.Connection, source: str) -> None:
    """Delete model shadow metrics for one source path."""
    conn.execute("DELETE FROM model_shadow_metrics WHERE source = ?", (str(source),))


def insert_forecast_event(
    conn: sqlite3.Connection,
    *,
    ts: str,
    source: str,
    horizon_sec: int,
    risk_score: float,
    confidence_low: float | None,
    confidence_high: float | None,
    signature: str | None,
    summary: str | None,
    payload_json: dict[str, Any] | None = None,
) -> int:
    """Insert one forecast event and return row id."""
    cur = conn.execute(
        """
        INSERT INTO forecast_events(
            ts, source, horizon_sec, risk_score, confidence_low, confidence_high,
            signature, summary, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            str(source),
            int(horizon_sec),
            float(risk_score),
            float(confidence_low) if confidence_low is not None else None,
            float(confidence_high) if confidence_high is not None else None,
            str(signature).strip() if signature is not None else None,
            str(summary).strip() if summary is not None else None,
            json.dumps(payload_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert forecast event row")
    return int(cur.lastrowid)


def insert_drift_event(
    conn: sqlite3.Connection,
    *,
    ts: str,
    source: str,
    status: str,
    delta: float,
    long_mean: float | None,
    short_mean: float | None,
    sample_count: int | None,
    payload_json: dict[str, Any] | None = None,
) -> int:
    """Insert one drift event and return row id."""
    cur = conn.execute(
        """
        INSERT INTO drift_events(
            ts, source, status, delta, long_mean, short_mean, sample_count, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            str(source),
            str(status).strip() or "stable",
            float(delta),
            float(long_mean) if long_mean is not None else None,
            float(short_mean) if short_mean is not None else None,
            int(sample_count) if sample_count is not None else None,
            json.dumps(payload_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert drift event row")
    return int(cur.lastrowid)


def insert_model_shadow_metric(
    conn: sqlite3.Connection,
    *,
    ts: str,
    source: str,
    decision: str,
    action: str | None,
    model_id: str,
    score: float | None,
    vote: int | bool,
    agreement: float | None,
    payload_json: dict[str, Any] | None = None,
) -> int:
    """Insert one model shadow metric row and return row id."""
    cur = conn.execute(
        """
        INSERT INTO model_shadow_metrics(
            ts, source, decision, action, model_id, score, vote, agreement, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            str(source),
            str(decision).strip() or "unknown",
            str(action).strip() if action is not None else None,
            str(model_id).strip() or "shadow",
            float(score) if score is not None else None,
            int(bool(vote)),
            float(agreement) if agreement is not None else None,
            json.dumps(payload_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert model shadow metric row")
    return int(cur.lastrowid)


def insert_proactive_action_outcome(
    conn: sqlite3.Connection,
    *,
    ts: str,
    control_session_id: int | None,
    action: str,
    decision: str,
    status: str,
    trigger_risk_score: float | None,
    horizon_sec: int | None,
    payload_json: dict[str, Any] | None = None,
) -> int:
    """Insert one proactive action outcome row and return row id."""
    cur = conn.execute(
        """
        INSERT INTO proactive_action_outcomes(
            ts, control_session_id, action, decision, status,
            trigger_risk_score, horizon_sec, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            int(control_session_id) if control_session_id is not None else None,
            str(action).strip(),
            str(decision).strip(),
            str(status).strip(),
            float(trigger_risk_score) if trigger_risk_score is not None else None,
            int(horizon_sec) if horizon_sec is not None else None,
            json.dumps(payload_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert proactive action outcome row")
    return int(cur.lastrowid)


def summarize_recent_drift(
    conn: sqlite3.Connection,
    *,
    limit: int = 200,
) -> dict[str, Any]:
    """Summarize recent drift rows for CLI dashboards."""
    rows = conn.execute(
        """
        SELECT ts, status, delta, long_mean, short_mean, sample_count, source
        FROM drift_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, int(limit)),),
    ).fetchall()
    stable = 0
    drift = 0
    max_delta = 0.0
    latest: dict[str, Any] | None = None
    for row in rows:
        status = str(row["status"] or "").strip().lower()
        delta = float(row["delta"] or 0.0)
        max_delta = max(max_delta, abs(delta))
        if status in {"drift", "triggered"}:
            drift += 1
        else:
            stable += 1
        if latest is None:
            latest = {
                "ts": row["ts"],
                "status": row["status"],
                "delta": delta,
                "long_mean": row["long_mean"],
                "short_mean": row["short_mean"],
                "sample_count": row["sample_count"],
                "source": row["source"],
            }
    return {
        "count": int(len(rows)),
        "drift_count": int(drift),
        "stable_count": int(stable),
        "drift_rate": (float(drift) / float(len(rows))) if rows else 0.0,
        "max_abs_delta": round(float(max_delta), 6),
        "latest": latest,
    }


def insert_policy_decision(
    conn: sqlite3.Connection,
    *,
    ts: str,
    control_session_id: int | None,
    soak_run_id: int | None,
    action: str,
    mode: str,
    allowed: bool,
    denied_by: str | None,
    reason: str | None,
    trace_id: str | None,
    policy_trace_json: dict[str, Any] | None = None,
) -> int:
    """Insert one policy decision/audit row."""
    cur = conn.execute(
        """
        INSERT INTO policy_decisions(
            ts, control_session_id, soak_run_id, action, mode, allowed,
            denied_by, reason, trace_id, policy_trace_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            int(control_session_id) if control_session_id is not None else None,
            int(soak_run_id) if soak_run_id is not None else None,
            str(action).strip(),
            str(mode).strip(),
            int(bool(allowed)),
            str(denied_by).strip() if denied_by is not None else None,
            str(reason).strip() if reason is not None else None,
            str(trace_id).strip() if trace_id is not None else None,
            json.dumps(policy_trace_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert policy decision row")
    return int(cur.lastrowid)


def insert_failover_event(
    conn: sqlite3.Connection,
    *,
    ts: str,
    control_session_id: int | None,
    auth_profile: str,
    attempt: int,
    failure_class: str,
    cooldown_until: str | None,
    disabled_until: str | None,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one failover transition row."""
    cur = conn.execute(
        """
        INSERT INTO failover_events(
            ts, control_session_id, auth_profile, attempt, failure_class,
            cooldown_until, disabled_until, detail_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            int(control_session_id) if control_session_id is not None else None,
            str(auth_profile).strip(),
            int(attempt),
            str(failure_class).strip(),
            str(cooldown_until).strip() if cooldown_until is not None else None,
            str(disabled_until).strip() if disabled_until is not None else None,
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert failover event row")
    return int(cur.lastrowid)


def upsert_auth_profile_state(
    conn: sqlite3.Connection,
    *,
    profile: str,
    attempt: int,
    failure_class: str | None,
    cooldown_until: str | None,
    disabled_until: str | None,
    state_json: dict[str, Any] | None = None,
    updated_ts: str | None = None,
) -> None:
    """Insert or update persisted auth profile state."""
    conn.execute(
        """
        INSERT INTO auth_profile_state(
            profile, attempt, failure_class, cooldown_until, disabled_until, updated_ts, state_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(profile) DO UPDATE SET
            attempt = excluded.attempt,
            failure_class = excluded.failure_class,
            cooldown_until = excluded.cooldown_until,
            disabled_until = excluded.disabled_until,
            updated_ts = excluded.updated_ts,
            state_json = excluded.state_json
        """,
        (
            str(profile).strip(),
            int(attempt),
            str(failure_class).strip() if failure_class is not None else None,
            str(cooldown_until).strip() if cooldown_until is not None else None,
            str(disabled_until).strip() if disabled_until is not None else None,
            str(updated_ts or utc_now_iso()),
            json.dumps(state_json or {}, sort_keys=True),
        ),
    )


def load_auth_profile_state(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return persisted auth profile rows sorted by update time."""
    return conn.execute(
        """
        SELECT profile, attempt, failure_class, cooldown_until, disabled_until, updated_ts, state_json
        FROM auth_profile_state
        ORDER BY updated_ts DESC, profile ASC
        """
    ).fetchall()


def latest_failover_event(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """Return latest failover event row."""
    return conn.execute(
        """
        SELECT ts, control_session_id, auth_profile, attempt, failure_class, cooldown_until, disabled_until, detail_json
        FROM failover_events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()


def insert_memory_compaction(
    conn: sqlite3.Connection,
    *,
    ts: str,
    control_session_id: int | None,
    compacted_rows: int,
    summary_json: dict[str, Any] | None = None,
) -> int:
    """Insert one memory compaction record."""
    cur = conn.execute(
        """
        INSERT INTO memory_compactions(ts, control_session_id, compacted_rows, summary_json)
        VALUES(?, ?, ?, ?)
        """,
        (
            str(ts),
            int(control_session_id) if control_session_id is not None else None,
            int(compacted_rows),
            json.dumps(summary_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert memory compaction row")
    return int(cur.lastrowid)


def insert_mission_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    ts_started: str,
    mode: str,
    status: str,
    graph_id: str,
    metadata_json: dict[str, Any] | None = None,
) -> int:
    """Insert one mission run row."""
    cur = conn.execute(
        """
        INSERT INTO mission_runs(run_id, ts_started, ts_ended, mode, status, graph_id, metadata_json)
        VALUES(?, ?, NULL, ?, ?, ?, ?)
        """,
        (
            str(run_id).strip(),
            str(ts_started),
            str(mode).strip(),
            str(status).strip(),
            str(graph_id).strip(),
            json.dumps(metadata_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert mission run row")
    return int(cur.lastrowid)


def update_mission_run(
    conn: sqlite3.Connection,
    *,
    mission_run_id: int,
    status: str | None = None,
    ts_ended: str | None = None,
    metadata_json: dict[str, Any] | None = None,
) -> None:
    """Update status/timestamps for one mission run."""
    row = conn.execute(
        "SELECT status, ts_ended, metadata_json FROM mission_runs WHERE id = ?",
        (int(mission_run_id),),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Unknown mission run id: {mission_run_id}")
    existing_meta: dict[str, Any] = {}
    raw_meta = row["metadata_json"]
    if isinstance(raw_meta, str) and raw_meta.strip():
        try:
            parsed = json.loads(raw_meta)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            existing_meta = parsed
    if isinstance(metadata_json, dict):
        existing_meta.update(metadata_json)
    conn.execute(
        """
        UPDATE mission_runs
        SET status = ?, ts_ended = ?, metadata_json = ?
        WHERE id = ?
        """,
        (
            str(status).strip() if status is not None else str(row["status"]),
            str(ts_ended).strip() if ts_ended is not None else row["ts_ended"],
            json.dumps(existing_meta, sort_keys=True),
            int(mission_run_id),
        ),
    )


def insert_mission_step(
    conn: sqlite3.Connection,
    *,
    mission_run_id: int,
    ts: str,
    step_id: str,
    step_type: str,
    status: str,
    handoff_token: str | None,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one mission step row."""
    cur = conn.execute(
        """
        INSERT INTO mission_steps(
            mission_run_id, ts, step_id, step_type, status, handoff_token, detail_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(mission_run_id),
            str(ts),
            str(step_id).strip(),
            str(step_type).strip(),
            str(status).strip(),
            str(handoff_token).strip() if handoff_token is not None else None,
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert mission step row")
    return int(cur.lastrowid)


def fetch_mission_run(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row | None:
    """Fetch one mission run row by external run id."""
    return conn.execute(
        """
        SELECT id, run_id, ts_started, ts_ended, mode, status, graph_id, metadata_json
        FROM mission_runs
        WHERE run_id = ?
        """,
        (str(run_id).strip(),),
    ).fetchone()


def list_mission_steps(conn: sqlite3.Connection, mission_run_id: int) -> list[sqlite3.Row]:
    """List ordered steps for one mission run."""
    return conn.execute(
        """
        SELECT ts, step_id, step_type, status, handoff_token, detail_json
        FROM mission_steps
        WHERE mission_run_id = ?
        ORDER BY id ASC
        """,
        (int(mission_run_id),),
    ).fetchall()


def insert_certification_run(
    conn: sqlite3.Connection,
    *,
    ts: str,
    cert_type: str,
    profile: str,
    passed: bool,
    score: float,
    detail_json: dict[str, Any] | None = None,
) -> int:
    """Insert one replay/chaos certification result row."""
    cur = conn.execute(
        """
        INSERT INTO certification_runs(ts, cert_type, profile, pass, score, detail_json)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            str(ts),
            str(cert_type).strip(),
            str(profile).strip(),
            int(bool(passed)),
            float(score),
            json.dumps(detail_json or {}, sort_keys=True),
        ),
    )
    if cur.lastrowid is None:
        raise RuntimeError("Failed to insert certification run row")
    return int(cur.lastrowid)


def list_recent_certification_runs(
    conn: sqlite3.Connection,
    *,
    cert_type: str | None = None,
    profile: str | None = None,
    limit: int = 50,
) -> list[sqlite3.Row]:
    """Return recent certification runs optionally filtered by type/profile."""
    where: list[str] = []
    args: list[object] = []
    if cert_type is not None:
        where.append("cert_type = ?")
        args.append(str(cert_type).strip())
    if profile is not None:
        where.append("profile = ?")
        args.append(str(profile).strip())
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    return conn.execute(
        f"""
        SELECT ts, cert_type, profile, pass, score, detail_json
        FROM certification_runs
        {clause}
        ORDER BY id DESC
        LIMIT ?
        """,
        (*args, max(1, int(limit))),
    ).fetchall()
