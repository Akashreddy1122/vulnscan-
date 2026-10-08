"""Durable scheduled jobs, executed only by an explicit --run-due command."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from shadowscan.core.errors import ConfigurationError


def parse_due(value: str) -> datetime:
    """Require an unambiguous timezone-aware ISO-8601 timestamp."""
    try:
        due = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigurationError("Use an ISO-8601 due date with timezone") from exc
    if due.tzinfo is None or due.utcoffset() is None:
        raise ConfigurationError("Schedule time must include a timezone")
    return due.astimezone(timezone.utc)


def prepare(conn: sqlite3.Connection) -> None:
    """Create a table separate from scan state and CVE cache."""
    conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY, targets TEXT NOT NULL, mode TEXT NOT NULL,
        profile TEXT NOT NULL, due TEXT, repeat_hours INTEGER,
        previous_scan TEXT)""")
    conn.commit()


def schedule(
    conn: sqlite3.Connection,
    targets: list[str],
    mode: str,
    profile: str,
    due: str,
    repeat_hours: int | None = None,
) -> str:
    """Queue a bounded job without storing credentials."""
    when = parse_due(due)
    if repeat_hours is not None and not 1 <= repeat_hours <= 8760:
        raise ConfigurationError("Repeat interval must be 1-8760 hours")
    prepare(conn)
    identifier = uuid.uuid4().hex
    with conn:
        conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?)",
            (
                identifier,
                json.dumps(targets),
                mode,
                profile,
                when.isoformat(),
                repeat_hours,
                None,
            ),
        )
    return identifier


def due_jobs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Select jobs due now in timestamp order."""
    prepare(conn)
    current = datetime.now(timezone.utc).isoformat()
    return [
        {
            "job_id": row[0],
            "targets": json.loads(row[1]),
            "mode": row[2],
            "profile": row[3],
            "due": row[4],
            "repeat_hours": row[5],
            "previous_scan": row[6],
        }
        for row in conn.execute(
            "SELECT * FROM jobs WHERE due IS NOT NULL AND due<=? ORDER BY due",
            (current,),
        )
    ]


def complete(conn: sqlite3.Connection, job: dict[str, Any], scan_id: str) -> None:
    """Advance recurring jobs past now, retaining last scan for comparison."""
    next_due = None
    if job["repeat_hours"]:
        when = parse_due(job["due"])
        now = datetime.now(timezone.utc)
        interval = timedelta(hours=job["repeat_hours"])
        while when <= now:
            when += interval
        next_due = when.isoformat()
    with conn:
        conn.execute(
            "UPDATE jobs SET due=?, previous_scan=? WHERE job_id=?",
            (next_due, scan_id, job["job_id"]),
        )
