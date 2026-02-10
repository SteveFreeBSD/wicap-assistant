from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.ingest.harness_scripts import ingest_harness_scripts


def test_ingest_harness_scripts_extracts_inventory(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")

    script = tmp_path / "soak_runner_demo.py"
    script.write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                "import time",
                "",
                "def main():",
                "    interval = int(os.getenv('SOAK_INTERVAL', '5'))",
                "    for _ in range(2):",
                "        subprocess.run(['docker', 'logs', 'wicap-ui', '--tail', '20'], check=False)",
                "        time.sleep(interval)",
                "    subprocess.run('pytest -q', shell=True, check=False)",
                "",
                "if __name__ == '__main__':",
                "    main()",
            ]
        ),
        encoding="utf-8",
    )

    files_seen, summary = ingest_harness_scripts(conn, repo_root=tmp_path)
    assert files_seen == 1
    assert summary.total_scripts == 1
    assert summary.roles.get("runner") == 1

    row = conn.execute(
        """
        SELECT script_path, role, commands_json, tools_json, env_vars_json
        FROM harness_scripts
        """
    ).fetchone()
    assert row is not None
    assert row["script_path"] == str(script)
    assert row["role"] == "runner"

    commands = json.loads(row["commands_json"])
    tools = json.loads(row["tools_json"])
    env_vars = json.loads(row["env_vars_json"])

    assert "docker logs wicap-ui --tail 20" in commands
    assert "pytest -q" in commands
    assert "docker" in tools
    assert "pytest" in tools
    assert "SOAK_INTERVAL" in env_vars

    conn.close()

