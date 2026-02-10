INSERT INTO sources(id, kind, path, mtime, size) VALUES
  (1, 'soak_log', '/fixture/alpha/run.log', 1.0, 100),
  (2, 'soak_log', '/fixture/beta/run.log', 1.0, 100),
  (3, 'soak_log', '/fixture/gamma/run.log', 1.0, 100),
  (10, 'session', '/fixture/sessions/alpha-1.jsonl', 2.0, 120),
  (11, 'session', '/fixture/sessions/alpha-2.jsonl', 2.1, 120),
  (12, 'session', '/fixture/sessions/beta-1.jsonl', 2.2, 120);

INSERT INTO log_events(id, source_id, ts_text, category, fingerprint, snippet, file_path, extra_json) VALUES
  (1, 1, '2026-02-10 10:00:00', 'error', 'alpha-fp', 'Error: pyodbc timeout while writing sql batch', '/fixture/alpha/run.log', '{}'),
  (2, 1, '2026-02-10 10:07:00', 'error', 'alpha-fp', 'Error: pyodbc timeout while writing sql batch', '/fixture/alpha/run.log', '{}'),
  (3, 1, '2026-02-10 10:20:00', 'error', 'alpha-fp', 'Error: pyodbc timeout while writing sql batch', '/fixture/alpha/run.log', '{}'),
  (4, 2, '2026-02-10 11:00:00', 'error', 'beta-fp', 'Error: redis connection refused in worker', '/fixture/beta/run.log', '{}'),
  (5, 2, '2026-02-10 11:05:00', 'error', 'beta-fp', 'Error: redis connection refused in worker', '/fixture/beta/run.log', '{}'),
  (6, 3, '2026-02-10 12:00:00', 'error', 'gamma-fp', 'Error: odbc cursor execute failed with timeout', '/fixture/gamma/run.log', '{}'),
  (7, 3, '2026-02-10 12:10:00', 'error', 'gamma-fp', 'Error: odbc cursor execute failed with timeout', '/fixture/gamma/run.log', '{}');

INSERT INTO sessions(
  id, source_id, session_id, cwd, ts_first, ts_last, repo_url, branch, commit_hash, is_wicap, raw_path
) VALUES
  (
    101, 10, 'session-alpha-1', '/home/steve/apps/wicap',
    '2026-02-10T09:58:00+00:00', '2026-02-10T10:08:00+00:00',
    'https://github.com/SteveFreeBSD/wicap.git', 'main', 'alpha111', 1, '/fixture/sessions/alpha-1.jsonl'
  ),
  (
    102, 11, 'session-alpha-2', '/home/steve/apps/wicap',
    '2026-02-10T10:15:00+00:00', '2026-02-10T10:21:00+00:00',
    'https://github.com/SteveFreeBSD/wicap.git', 'main', 'alpha222', 1, '/fixture/sessions/alpha-2.jsonl'
  ),
  (
    103, 12, 'session-beta-1', '/home/steve/apps/wicap',
    '2026-02-10T10:59:00+00:00', '2026-02-10T11:03:00+00:00',
    'https://github.com/SteveFreeBSD/wicap.git', 'main', 'beta111', 1, '/fixture/sessions/beta-1.jsonl'
  );

INSERT INTO signals(id, session_pk, ts, category, fingerprint, snippet, extra_json) VALUES
  (1001, 101, '2026-02-10T10:00:10+00:00', 'commands', 'alpha-cmd-1', 'python scripts/check_wicap_status.py --sql-only', '{}'),
  (1002, 101, '2026-02-10T10:00:40+00:00', 'outcomes', 'alpha-out-1', 'fixed pyodbc timeout by adjusting sql batch flush', '{}'),
  (1003, 102, '2026-02-10T10:20:30+00:00', 'commands', 'alpha-cmd-2', 'docker logs --tail 120 wicap-processor', '{}'),
  (1004, 102, '2026-02-10T10:20:40+00:00', 'outcomes', 'alpha-out-2', 'still broken pyodbc timeout on write path', '{}'),
  (1005, 103, '2026-02-10T11:00:20+00:00', 'commands', 'beta-cmd-1', 'python scripts/check_wicap_status.py --local-only', '{}'),
  (1006, 103, '2026-02-10T11:00:40+00:00', 'outcomes', 'beta-out-1', 'resolved redis connection refused after service restart', '{}');

INSERT INTO verification_outcomes(id, conversation_pk, signature, outcome, evidence_snippet, ts) VALUES
  (2001, NULL, 'error: pyodbc timeout while writing sql batch', 'pass', 'PASS: write path verified', '2026-02-10T10:09:00+00:00'),
  (2002, NULL, 'error: pyodbc timeout while writing sql batch', 'fail', 'FAIL: timeout recurred', '2026-02-10T10:21:30+00:00'),
  (2003, NULL, 'error: pyodbc timeout while writing sql batch', 'unknown', 'pending confirmation', '2026-02-10T10:22:00+00:00'),
  (2004, NULL, 'error: redis connection refused in worker', 'pass', 'PASS: redis connectivity healthy', '2026-02-10T11:04:00+00:00'),
  (2005, NULL, 'error: odbc cursor execute failed with timeout', 'unknown', 'no final verification yet', '2026-02-10T12:11:00+00:00');
