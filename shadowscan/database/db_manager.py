"""SQLite scan history and checkpoint store (no auth material persisted)."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

from shadowscan.core.models import ScanResult, Finding
from .cve_cache import prepare
from .scheduler import prepare as prepare_jobs
from shadowscan.core.errors import ConfigurationError


class Database:
    """Small SQLite repository with parameterized writes."""

    def __init__(self, path: str) -> None:
        """Initialize schema and keep database files private to the user."""
        self.path = path
        if path != ":memory:":
            if Path(path).is_symlink():
                raise ConfigurationError("Refusing a symlinked database")
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).touch(mode=0o600, exist_ok=True)
            info = Path(path).stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ConfigurationError(
                    "Database must be a regular, non-hardlinked file"
                )
            Path(path).chmod(0o600)
        self.conn = sqlite3.connect(path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS scans
            (id TEXT PRIMARY KEY, started TEXT, finished TEXT, mode TEXT,
             profile TEXT, targets TEXT, completed TEXT, errors TEXT)""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS findings
            (scan_id TEXT, target TEXT, data TEXT,
             FOREIGN KEY(scan_id) REFERENCES scans(id))""")
        self.conn.commit()
        prepare(self.conn)
        prepare_jobs(self.conn)

    def save(self, result: ScanResult) -> None:
        """Atomically save scan state for later resumption."""
        with self.conn:
            self.conn.execute(
                """INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)""",
                (
                    result.scan_id,
                    result.started,
                    result.finished,
                    result.mode,
                    result.profile,
                    json.dumps(result.targets),
                    json.dumps(result.completed),
                    json.dumps(result.errors),
                ),
            )
            self.conn.execute("DELETE FROM findings WHERE scan_id=?", (result.scan_id,))
            self.conn.executemany(
                "INSERT INTO findings VALUES (?,?,?)",
                (
                    (result.scan_id, item.url, json.dumps(item.to_dict()))
                    for item in result.findings
                ),
            )

    def load(self, scan_id: str) -> ScanResult:
        """Load a saved scan or raise an actionable error."""
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise ConfigurationError(f"Scan not found: {scan_id}")
        findings = [
            Finding(**json.loads(item[0]))
            for item in self.conn.execute(
                "SELECT data FROM findings WHERE scan_id=?", (scan_id,)
            )
        ]
        return ScanResult(
            row[0],
            row[1],
            row[3],
            row[4],
            json.loads(row[5]),
            findings,
            json.loads(row[6]),
            json.loads(row[7]),
            row[2],
        )

    def close(self) -> None:
        """Release connection."""
        self.conn.close()
