"""UDP inventory verified on in-process datagram services."""

import asyncio

import pytest

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.database.db_manager import Database


class Echo(asyncio.DatagramProtocol):
    """Respond to one-byte datagrams."""

    def connection_made(self, transport):
        """Store local datagram transport."""
        self.transport = transport

    def datagram_received(self, data, address):
        """Echo one response."""
        self.transport.sendto(b"ok", address)


@pytest.mark.asyncio
async def test_udp_response_inventory(tmp_path):
    """A responsive UDP port is reported without labeling silent ports open."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        Echo, local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    config = load_config()
    config.update(udp_ports=[port], rate=100, timeout=1)
    try:
        result = await Engine(config, db, select_plugins("network", ["udp_ports"])).run(
            ["127.0.0.1"]
        )
        assert [item.title for item in result.findings] == [
            f"UDP port {port} responded",
            "UDP inventory summary",
        ]
    finally:
        db.close()
        transport.close()
