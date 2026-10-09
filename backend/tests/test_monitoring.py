from malwarescan.engine.rules_loader import packs
from malwarescan.monitoring import process_monitor


def _masq():
    return [r for r in packs.process_rules if r["id"] == "proc.masquerade_name"]


def test_interpreter_in_virtualenv_is_not_flagged():
    rows = [{"pid": 1, "name": "python", "cmdline": "python -m app", "exe": "/home/dev/.venv/bin/python", "username": "dev"}]
    assert process_monitor.evaluate(_masq(), rows) == []


def test_daemon_name_from_temp_is_flagged_and_system_copy_is_not():
    rows = [
        {"pid": 2, "name": "sshd", "cmdline": "sshd", "exe": "/usr/sbin/sshd", "username": "root"},
        {"pid": 3, "name": "sshd", "cmdline": "sshd", "exe": "/tmp/x/sshd", "username": "u"},
    ]
    assert [f["row"]["pid"] for f in process_monitor.evaluate(_masq(), rows)] == [3]


def test_cryptominer_rule_matches_command_line():
    rule = [r for r in packs.process_rules if r["id"] == "proc.cryptominer"]
    rows = [{"pid": 9, "name": "kworker-x", "cmdline": "xmrig --url stratum+tcp://pool:3333", "exe": "/tmp/k", "username": "u"}]
    f = process_monitor.evaluate(rule, rows)
    assert f and f[0]["row"]["pid"] == 9
