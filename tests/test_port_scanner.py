"""TCP connect plugin local socket test."""

import asyncio

import pytest

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.database.db_manager import Database


@pytest.mark.asyncio
async def test_port_scanner_open_port(tmp_path):
    """Only open configured ports appear in observations."""

    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = load_config()
    config.update(ports=[port], rate=100)
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        result = await Engine(config, db, select_plugins("network", ["ports"])).run(
            ["127.0.0.1"]
        )
        assert [item.title for item in result.findings] == [
            f"TCP port {port} open",
            "TCP connect scan summary",
        ]
    finally:
        db.close()
        server.close()
        await server.wait_closed()
