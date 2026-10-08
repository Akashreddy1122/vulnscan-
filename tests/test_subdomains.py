"""DNS-only subdomain module scope tests."""
import asyncio
import socket

import pytest

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.database.db_manager import Database


@pytest.mark.asyncio
async def test_subdomains_opt_in_and_wildcard_filter(tmp_path, monkeypatch):
    """Without explicit opt-in it is inert; wildcard hosts are filtered."""
    lookups = []
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(host, port, **kwargs):
        lookups.append(host)
        ip = "192.0.2.10" if host == "www.example.test" else "198.51.100.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    db = Database(str(tmp_path / "scan.sqlite"))
    config = load_config()
    config.update(rate=100)
    try:
        plugin = select_plugins("recon", ["subdomains"])
        first = await Engine(config, db, plugin).run(["example.test"])
        assert not first.findings and not lookups
        config["enumerate_subdomains"] = True
        second = await Engine(config, db, plugin).run(["example.test"])
        assert len(second.findings) == 1
        assert "www.example.test" in second.findings[0].evidence
        assert all(host.endswith(".example.test") for host in lookups)
    finally:
        db.close()
