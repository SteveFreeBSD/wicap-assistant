"""Regression fixture test for calibration anti-saturation behavior."""

from __future__ import annotations

from pathlib import Path

from wicap_assist.confidence_audit import run_confidence_audit
from wicap_assist.db import connect_db
from wicap_assist.recommend import build_recommendation


_FIXTURE_SQL = Path(__file__).parent / "fixtures" / "calibration_regression_seed.sql"


def _load_fixture_db():
    conn = connect_db(":memory:")
    conn.executescript(_FIXTURE_SQL.read_text(encoding="utf-8"))
    conn.commit()
    return conn


def test_calibration_regression_fixture_blocks_saturation() -> None:
    conn = _load_fixture_db()
    targets = ["alpha", "beta", "gamma"]
    payloads = [build_recommendation(conn, target) for target in targets]

    high_conf_payloads = []
    for payload in payloads:
        breakdown = payload["confidence_breakdown"]
        assert "confidence_cap_pct" in breakdown
        assert int(breakdown["confidence_cap_pct"]) <= 100

        confidence = float(payload["confidence"])
        criteria_met = bool(int(breakdown.get("high_confidence_criteria_met", 0)))
        if confidence >= 0.95:
            high_conf_payloads.append(payload)
            assert criteria_met is True

    # Fixture intentionally has no strict-criteria case.
    assert len(high_conf_payloads) == 0
    assert sum(1 for payload in payloads if float(payload["confidence"]) >= 0.95) == 0

    # Recurrence evidence is present in fixture and should surface as penalty for alpha.
    alpha_breakdown = payloads[0]["confidence_breakdown"]
    assert int(alpha_breakdown["recurrence_penalty"]) > 0

    audit = run_confidence_audit(conn, limit=20)
    assert audit["count"] > 0
    assert int(audit["stats"]["high95_count"]) == 0

    conn.close()
