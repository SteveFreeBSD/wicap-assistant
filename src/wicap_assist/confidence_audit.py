"""Confidence calibration audit – validate score distribution."""

from __future__ import annotations

import json
from statistics import median, quantiles
from typing import Any

from wicap_assist.cross_pattern import detect_chronic_patterns
from wicap_assist.db import connect_db
from wicap_assist.recommend import build_recommendation


def run_confidence_audit(
    conn_or_path: Any,
    limit: int = 100,
) -> dict[str, Any]:
    """Run build_recommendation for top chronic patterns and analyze confidence scores."""
    if isinstance(conn_or_path, str) or hasattr(conn_or_path, "joinpath"):
        conn = connect_db(conn_or_path)
        should_close = True
    else:
        conn = conn_or_path
        should_close = False

    try:
        # Get top recurring patterns to audit
        patterns = detect_chronic_patterns(
            conn,
            min_occurrences=1,
            min_span_days=0.0,
            top_n=limit,
        )

        scores: list[float] = []
        details: list[dict[str, Any]] = []

        for p in patterns:
            # build_recommendation returns a dict with "confidence"
            rec = build_recommendation(conn, p.signature)
            score = float(rec.get("confidence", 0.0))
            scores.append(score)
            details.append({
                "signature": p.signature,
                "score": score,
                "occurrences": p.occurrence_count,
            })

        if not scores:
            return {
                "count": 0,
                "distribution": "empty",
                "stats": {},
            }

        scores.sort()
        try:
            quants = quantiles(scores, n=4)
        except ValueError:
            quants = [scores[0], scores[0], scores[0]]

        stats = {
            "min": scores[0],
            "max": scores[-1],
            "median": median(scores),
            "p25": quants[0],
            "p75": quants[2],
            "mean": sum(scores) / len(scores),
            "zero_count": scores.count(0.0),
            "one_count": scores.count(1.0),
            "high95_count": sum(1 for value in scores if value >= 0.95),
        }
        
        # Calculate percentages
        count = len(scores)
        stats["zero_pct"] = round(stats["zero_count"] / count * 100, 1)
        stats["one_pct"] = round(stats["one_count"] / count * 100, 1)
        stats["high95_pct"] = round(stats["high95_count"] / count * 100, 1)

        # Histogram (buckets of 0.1)
        hist = {f"{i/10:.1f}-{i/10+0.1:.1f}": 0 for i in range(10)}
        for s in scores:
            bucket = int(s * 10)
            if bucket >= 10: bucket = 9
            key = f"{bucket/10:.1f}-{bucket/10+0.1:.1f}"
            hist[key] += 1

        return {
            "count": count,
            "stats": stats,
            "histogram": hist,
            "samples": details[:5], # Top 5 details
        }

    finally:
        if should_close:
            conn.close()


def format_confidence_audit_text(report: dict[str, Any]) -> str:
    """Render audit report as text."""
    stats = report.get("stats", {})
    hist = report.get("histogram", {})
    count = report.get("count", 0)

    lines = ["=== Confidence Calibration Audit ===", ""]
    lines.append(f"Analyzed {count} signatures.")
    
    if count == 0:
        lines.append("No data available.")
        return "\n".join(lines)

    lines.append("")
    lines.append("Statistics:")
    lines.append(f"  Mean:   {stats.get('mean', 0):.2f}")
    lines.append(f"  Median: {stats.get('median', 0):.2f}")
    lines.append(f"  Min:    {stats.get('min', 0):.2f}")
    lines.append(f"  Max:    {stats.get('max', 0):.2f}")
    lines.append(f"  Zero (0.0): {stats.get('zero_count')} ({stats.get('zero_pct')}%)")
    lines.append(f"  One (1.0):  {stats.get('one_count')} ({stats.get('one_pct')}%)")
    lines.append(f"  High (>=0.95): {stats.get('high95_count')} ({stats.get('high95_pct')}%)")

    lines.append("")
    lines.append("Distribution:")
    for key, val in hist.items():
        bar = "#" * int(val * 50 / count) if count > 0 else ""
        lines.append(f"  {key}: {val:3d} |{bar}")

    degeneracy_warning = ""
    if stats.get("zero_pct", 0) > 80:
        degeneracy_warning = "⚠ WARNING: Degenerate distribution (mostly 0.0)"
    elif stats.get("one_pct", 0) > 80:
        degeneracy_warning = "⚠ WARNING: Degenerate distribution (mostly 1.0)"
    
    if degeneracy_warning:
        lines.append("")
        lines.append(degeneracy_warning)
    else:
        lines.append("")
        lines.append("✓ Distribution looks healthy")

    return "\n".join(lines)


def confidence_audit_to_json(report: dict[str, Any]) -> str:
    """Encode audit report as JSON."""
    return json.dumps(report, indent=2)
