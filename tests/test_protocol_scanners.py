"""Protocol checks tested against ephemeral local-only fake services."""

import asyncio

import pytest

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.database.db_manager import Database


@pytest.mark.asyncio
async def test_ssh_ftp_smtp_no_authentication(tmp_path):
    """Observe greetings and EHLO but never attempt to log in or send mail."""
    seen: dict[str, list[bytes]] = {"ssh": [], "ftp": [], "smtp": []}

    async def ssh(reader, writer):
        writer.write(b"SSH-1.99-legacy\r\n")
        await writer.drain()
        seen["ssh"].append(await reader.read(128))
        writer.close()

    async def ftp(reader, writer):
        writer.write(b"220 FTP server ready\r\n")
        await writer.drain()
        seen["ftp"].append(await reader.read(128))
        writer.close()

    async def smtp(reader, writer):
        writer.write(b"220 mail.example.test ESMTP\r\n")
        await writer.drain()
        seen["smtp"].append(await reader.readline())
        writer.write(b"250 mail.example.test\r\n")
        await writer.drain()
        seen["smtp"].append(await reader.readline())
        writer.close()

    servers = []
    for handler in (ssh, ftp, smtp):
        servers.append(await asyncio.start_server(handler, "127.0.0.1", 0))
    ports = [server.sockets[0].getsockname()[1] for server in servers]
    config = load_config()
    config.update(
        rate=100,
        timeout=2,
        ports=ports,
        service_ports=dict(zip(("ssh", "ftp", "smtp"), ports)),
    )
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        result = await Engine(
            config, db, select_plugins("network", ["ssh", "ftp", "smtp"])
        ).run(["127.0.0.1"])
        assert {f.title for f in result.findings} == {
            "Legacy SSH protocol 1",
            "Plain FTP control channel observed",
            "SMTP STARTTLS not advertised",
        }
        assert all(not chunk.strip() for chunk in seen["ssh"] + seen["ftp"])
        assert seen["smtp"] == [b"EHLO shadowscan.invalid\r\n", b"QUIT\r\n"]
    finally:
        db.close()
        for server in servers:
            server.close()
            await server.wait_closed()

@pytest.mark.asyncio
async def test_rdp_transport_negotiation_no_auth(tmp_path):
    """RDP plugin reports selected transport, never attempts account login."""
    sent = []

    async def handler(reader, writer):
        sent.append(await reader.readexactly(19))
        writer.write(bytes.fromhex("030000130ed000001234000200080001000000"))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = load_config()
    config.update(ports=[port], rate=100, service_ports={**config["service_ports"], "rdp": port})
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        result = await Engine(config, db, select_plugins("network", ["rdp"])).run(
            ["127.0.0.1"]
        )
        assert [f.title for f in result.findings] == ["RDP negotiated without NLA"]
        assert len(sent) == 1 and len(sent[0]) == 19
    finally:
        db.close()
        server.close()
        await server.wait_closed()
