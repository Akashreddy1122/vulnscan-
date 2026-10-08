"""Offline NVD 2.0 JSON importer and exact CPE cache.

Only exact, explicitly vulnerable CPE configurations are indexed. Version ranges,
negated nodes and wildcard versions are deliberately skipped to avoid false matches.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from shadowscan.core.errors import ConfigurationError

_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def prepare(conn: sqlite3.Connection) -> None:
    """Create cache table independently of the scan tables."""
    conn.execute("""CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id TEXT NOT NULL, cpe TEXT NOT NULL, score REAL NOT NULL,
        description TEXT NOT NULL, PRIMARY KEY(cve_id, cpe))""")
    conn.execute("CREATE INDEX IF NOT EXISTS cve_by_cpe ON cve_cache(cpe)")
    conn.commit()


def _matches(nodes: list[dict[str, Any]], depth: int = 0) -> Iterator[str]:
    """Walk NVD configuration trees, retaining only exact CPE matches."""
    if depth >= 16 or not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("negate") or str(node.get("operator", "OR")).upper() != "OR":
            # AND configurations require all products to be present; a lone
            # banner cannot prove that, so omit them rather than over-report.
            continue
        entries = node.get("cpeMatch", [])
        for item in entries if isinstance(entries, list) else []:
            if not isinstance(item, dict):
                continue
            cpe = item.get("criteria", "")
            if not isinstance(cpe, str):
                continue
            parts = cpe.split(":")
            if (
                item.get("vulnerable") is True
                and len(parts) == 13
                and parts[0:2] == ["cpe", "2.3"]
                and parts[5] not in {"*", "-"}
                and not any(
                    k.startswith("versionStart") or k.startswith("versionEnd")
                    for k in item
                )
            ):
                yield cpe
        yield from _matches(node.get("children", []), depth + 1)


def import_nvd(conn: sqlite3.Connection, path: str) -> int:
    """Import a bounded local NVD JSON 2.0 export transactionally."""
    source = Path(path)
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ConfigurationError("NVD file exceeds 32 MiB; split into smaller files")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ConfigurationError("Invalid NVD JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ConfigurationError("Expected an NVD 2.0 vulnerabilities array")
    if len(data["vulnerabilities"]) > 50000:
        raise ConfigurationError("NVD import limit is 50,000 records")
    prepare(conn)
    rows = []
    for record in data["vulnerabilities"]:
        if not isinstance(record, dict) or not isinstance(record.get("cve"), dict):
            continue
        cve = record["cve"]
        identifier = cve.get("id", "")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            continue
        descriptions = cve.get("descriptions", [])
        metrics = cve.get("metrics", {})
        configurations = cve.get("configurations", [])
        if (
            not isinstance(descriptions, list)
            or not isinstance(metrics, dict)
            or not isinstance(configurations, list)
        ):
            continue
        descriptions = [
            d
            for d in descriptions
            if isinstance(d, dict) and isinstance(d.get("value"), str)
        ]
        description = next(
            (d.get("value", "")[:600] for d in descriptions if d.get("lang") == "en"),
            "",
        )
        scores = [
            m["cvssData"].get("baseScore", 0)
            for group in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
            for m in (
                metrics.get(group) if isinstance(metrics.get(group), list) else []
            )
            if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)
        ]
        try:
            score = float(scores[0]) if scores else 0.0
        except (TypeError, ValueError):
            continue
        if not 0 <= score <= 10:
            continue
        for group in configurations:
            if not isinstance(group, dict):
                continue
            for cpe in _matches(group.get("nodes", [])):
                rows.append((identifier, cpe, score, description))
                if len(rows) > 100000:
                    raise ConfigurationError(
                        "NVD import limit is 100,000 exact CPE records"
                    )
    with conn:
        conn.executemany("INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?)", rows)
    return len(rows)


def lookup(conn: sqlite3.Connection, cpe: str) -> list[tuple[str, float, str]]:
    """Return exact offline CPE matches, never inferred range matches."""
    prepare(conn)
    return conn.execute(
        "SELECT cve_id, score, description FROM cve_cache WHERE cpe=?", (cpe,)
    ).fetchall()
