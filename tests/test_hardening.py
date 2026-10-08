"""Regression tests for scope, output handling and sensitive transport options."""

import csv
import os
from xml.etree import ElementTree

import pytest

from shadowscan.api.server import serve
from shadowscan.core.config import load_config
from shadowscan.core.errors import ConfigurationError
from shadowscan.core.rate_limiter import RateLimiter
from shadowscan.core.scope import Scope
from shadowscan.core.session import HttpSession
from shadowscan.core.target import expand_targets
from shadowscan.core.models import Finding, ScanResult
from shadowscan.reporting.report_generator import export


def test_report_files_private_no_symlinks_or_spreadsheet_formulas(tmp_path):
    """Exports cannot overwrite symlinks and spreadsheet payloads remain inert."""
    scan = ScanResult(
        "id",
        "",
        "active",
        "quick",
        ["https://example.test"],
        [
            Finding(
                '=HYPERLINK("https://bad.invalid")',
                "low",
                "https://example.test",
                "\x00+SUM(1,1)",
                "fix",
                "headers",
                evidence="\x01unsafe",
            )
        ],
    )
    for fmt in ("csv", "html", "pdf", "json", "xml"):
        path = tmp_path / f"report.{fmt}"
        export(scan, str(path), fmt)
        if os.name == "posix":
            assert path.stat().st_mode & 0o077 == 0
    with (tmp_path / "report.csv").open() as stream:
        row = next(csv.DictReader(stream))
        assert row["title"].startswith("'=HYPERLINK")
        assert row["description"].startswith("' +SUM")
    ElementTree.parse(tmp_path / "report.xml")
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")
    with pytest.raises(ConfigurationError):
        export(scan, str(link), "json")
    assert victim.read_text() == "unchanged"


def test_unsafe_config_and_long_url_rejected_or_handled(tmp_path):
    """Authority override is prohibited; long valid URLs are not treated as files."""
    config = tmp_path / "bad.yaml"
    config.write_text("headers:\n  Host: outside.test\n")
    with pytest.raises(ConfigurationError, match="unsafe custom headers"):
        load_config(str(config))
    config.write_bytes(b"a" * (1024 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="exceeds 1 MiB"):
        load_config(str(config))
    url = "https://example.test/?q=" + "a" * 1000
    assert expand_targets([url]) == [url]


def test_plaintext_credentials_need_explicit_opt_in():
    """Basic, Bearer and user-supplied auth headers cannot silently use HTTP."""
    config = load_config()
    with pytest.raises(ConfigurationError, match="Refusing credentials"):
        HttpSession(
            config,
            Scope("http://example.test/"),
            RateLimiter(2),
            basic_auth=("user", "password"),
        )
    config["headers"] = {"Authorization": "Bearer secret"}
    with pytest.raises(ConfigurationError, match="Refusing credentials"):
        HttpSession(config, Scope("http://example.test/"), RateLimiter(2))
    config["allow_insecure_auth"] = True
    HttpSession(config, Scope("http://example.test/"), RateLimiter(2))


@pytest.mark.asyncio
async def test_api_rejects_external_plaintext_binding(tmp_path):
    """Non-loopback API exposure requires an external TLS-terminating proxy."""
    with pytest.raises(ConfigurationError, match="loopback"):
        await serve("a" * 48, str(tmp_path / "api.db"), host="0.0.0.0", port=0)
    assert not (tmp_path / "api.db").exists()


def test_reports_and_database_reject_hardlinks_and_symlinks(tmp_path):
    """Shared-inode local files cannot be truncated by an export or DB open."""
    from shadowscan.database.db_manager import Database

    victim = tmp_path / "victim.txt"
    victim.write_text("private-data")
    hardlink = tmp_path / "report.json"
    try:
        os.link(victim, hardlink)
    except (OSError, NotImplementedError):
        pytest.skip("Hardlinks unavailable on this platform")
    scan = ScanResult("id", "", "active", "quick", [])
    with pytest.raises(ConfigurationError, match="non-hardlinked"):
        export(scan, str(hardlink), "json")
    with pytest.raises(ConfigurationError, match="non-hardlinked"):
        Database(str(hardlink))
    assert victim.read_text() == "private-data"


def test_database_refuses_symlink(tmp_path):
    """DB initialization must not follow a local symlink."""
    from shadowscan.database.db_manager import Database

    victim = tmp_path / "real.db"
    victim.write_text("unchanged")
    linked = tmp_path / "linked.db"
    try:
        linked.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")
    with pytest.raises(ConfigurationError, match="symlinked database"):
        Database(str(linked))
    assert victim.read_text() == "unchanged"


def test_empty_url_userinfo_rejected():
    """An empty username still counts as URL credentials."""
    from shadowscan.core.target import normalize_target

    with pytest.raises(ConfigurationError):
        normalize_target("http://@example.test/")


def test_rotating_logs_remain_private(tmp_path):
    """Log rotation does not create world-readable copies or follow symlinks."""
    import logging
    from shadowscan.main import PrivateRotatingFileHandler

    path = tmp_path / "scan.log"
    handler = PrivateRotatingFileHandler(path, maxBytes=80, backupCount=2)
    try:
        for index in range(10):
            handler.emit(
                logging.makeLogRecord(
                    {
                        "msg": "line %d %s" % (index, "x" * 50),
                        "levelno": logging.INFO,
                        "levelname": "INFO",
                    }
                )
            )
    finally:
        handler.close()
    assert (tmp_path / "scan.log.1").exists()
    if os.name == "posix":
        assert all(
            item.stat().st_mode & 0o077 == 0 for item in tmp_path.glob("scan.log*")
        )
    linked = tmp_path / "linked.log"
    try:
        linked.symlink_to(path)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(ConfigurationError, match="symlinked log"):
        PrivateRotatingFileHandler(linked)
