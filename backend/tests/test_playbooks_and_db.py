import os
from pathlib import Path

from malwarescan import db
from malwarescan.config import settings
from malwarescan.response import playbooks


def test_quarantine_refuses_system_paths():
    res = playbooks.quarantine_file("/etc/hosts", {}, "tester", dry_run=False)
    assert res["ok"] is False
    assert any("system-critical" in p for p in res["problems"])


def test_quarantine_dry_run_does_not_touch_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"payload-bytes")
    res = playbooks.quarantine_file(str(f), {}, "tester", dry_run=True)
    assert res["ok"] and res.get("dry_run")
    assert f.exists()


def test_quarantine_restore_roundtrip(tmp_path):
    f = tmp_path / "restore_me.bin"
    content = b"sample-content-" + os.urandom(16)
    f.write_bytes(content)
    res = playbooks.quarantine_file(str(f), {"reason": "test"}, "tester", dry_run=False)
    assert res["ok"], res
    assert not f.exists()
    qid = res["quarantine_id"]
    stored = Path(db.query_one("SELECT stored_path FROM quarantine WHERE id=?", (qid,))["stored_path"])
    assert stored.exists() and content not in stored.read_bytes()  # encrypted at rest
    back = playbooks.restore_quarantine(qid, "tester")
    assert back["ok"], back
    assert f.read_bytes() == content


def test_restore_refuses_to_overwrite(tmp_path):
    f = tmp_path / "exists.bin"
    f.write_bytes(b"a" * 30)
    res = playbooks.quarantine_file(str(f), {}, "tester", dry_run=False)
    f.write_bytes(b"new file in place")
    back = playbooks.restore_quarantine(res["quarantine_id"], "tester")
    assert back["ok"] is False
    assert f.read_bytes() == b"new file in place"


def test_kill_process_refuses_pid_1_and_self():
    assert playbooks.kill_process("1", {}, "tester", dry_run=False)["ok"] is False
    assert playbooks.kill_process(str(os.getpid()), {}, "tester", dry_run=False)["ok"] is False


def test_live_block_ip_requires_policy():
    res = playbooks.execute_playbook("block_ip", "203.0.113.66", {}, "tester", dry_run=False, confirm=True)
    assert res["ok"] is False


def test_failed_write_does_not_leave_connection_in_transaction():
    """Regression: a constraint violation must roll back so other writers are not locked out."""
    db.run_migrations()
    db.execute("INSERT INTO settings(key, value, updated_at, updated_by) VALUES('t_key','1','now','t')")
    import sqlite3
    try:
        db.execute("INSERT INTO settings(key, value, updated_at, updated_by) VALUES('t_key','2','now','t')")
    except sqlite3.IntegrityError:
        pass
    assert db.get_conn().in_transaction is False
    db.execute("UPDATE settings SET value='3' WHERE key='t_key'")  # must not be locked
    assert db.get_setting("t_key") == "3"
