"""Durable scheduling and explicit job execution tests."""

from datetime import datetime, timedelta, timezone

import pytest

from shadowscan.core.errors import ConfigurationError
from shadowscan.database.db_manager import Database
from shadowscan.database.scheduler import schedule, due_jobs, complete, parse_due
from shadowscan.main import execute, parser


def test_schedule_repeats_without_storing_secrets(tmp_path):
    """Recurring jobs advance and keep only targets/profile and a scan ID."""
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        with pytest.raises(ConfigurationError):
            parse_due("2026-01-01T00:00:00")
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        identifier = schedule(
            db.conn, ["example.test"], "passive", "quick", yesterday, 24
        )
        jobs = due_jobs(db.conn)
        assert len(jobs) == 1 and jobs[0]["job_id"] == identifier
        complete(db.conn, jobs[0], "scan-1")
        assert due_jobs(db.conn) == []
        assert db.conn.execute("SELECT previous_scan FROM jobs").fetchone() == (
            "scan-1",
        )
    finally:
        db.close()


@pytest.mark.asyncio
async def test_cli_schedule_and_run_due(tmp_path, monkeypatch):
    """CLI queues passive scan then executes it explicitly, without network."""
    monkeypatch.chdir(tmp_path)
    db_path = str(tmp_path / "jobs.sqlite")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    args = parser().parse_args(
        [
            "-t",
            "http://127.0.0.1:1/",
            "--authorized",
            "--passive",
            "--schedule-at",
            yesterday,
            "--db",
            db_path,
        ]
    )
    assert await execute(args) == 0
    assert (
        await execute(
            parser().parse_args(
                ["--run-due", "--authorized", "--db", db_path, "--format", "json"]
            )
        )
        == 0
    )
    db = Database(db_path)
    try:
        assert db.conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 1
        assert due_jobs(db.conn) == []
    finally:
        db.close()
