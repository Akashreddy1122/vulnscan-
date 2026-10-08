"""Authenticated API integration on loopback only."""

import asyncio

import pytest
from aiohttp import ClientSession, web

from shadowscan.api.server import ScanAPI


@pytest.mark.asyncio
async def test_api_requires_token_and_explicit_authorization(tmp_path):
    """API neither scans nor reveals results to unauthenticated callers."""
    api = ScanAPI("a" * 48, str(tmp_path / "scans.sqlite"))
    runner = web.AppRunner(api.app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    address = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        async with ClientSession() as client:
            async with client.get(address + "/modules") as response:
                assert response.status == 401
            headers = {"Authorization": "Bearer " + "a" * 48}
            async with client.post(
                address + "/scans",
                headers=headers,
                json={"targets": ["http://127.0.0.1:1/"], "mode": "passive"},
            ) as response:
                assert response.status == 400
            async with client.post(
                address + "/scans",
                headers=headers,
                json={
                    "authorized": True,
                    "targets": ["http://127.0.0.1:1/"],
                    "mode": "passive",
                },
            ) as response:
                assert response.status == 202
                scan_id = (await response.json())["scan_id"]
            for _ in range(20):
                async with client.get(
                    address + "/scans/" + scan_id, headers=headers
                ) as response:
                    data = await response.json()
                    if not data["running"]:
                        break
                await asyncio.sleep(0.02)
            assert data["completed"] == ["http://127.0.0.1:1/"]
            async with client.get(address + "/scans/" + scan_id) as response:
                assert response.status == 401
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_api_cancel_preserves_resume_checkpoint(tmp_path):
    """Cancelling a slow scan persists a resumable checkpoint."""
    started = asyncio.Event()

    async def slow(request):
        started.set()
        await asyncio.sleep(0.5)
        return web.Response(text="never reached")

    target_app = web.Application()
    target_app.router.add_get("/", slow)
    target_runner = web.AppRunner(target_app)
    await target_runner.setup()
    target_site = web.TCPSite(target_runner, "127.0.0.1", 0)
    await target_site.start()
    target_port = target_site._server.sockets[0].getsockname()[1]

    api = ScanAPI("b" * 48, str(tmp_path / "scans.sqlite"))
    runner = web.AppRunner(api.app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    address = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    headers = {"Authorization": "Bearer " + "b" * 48}
    try:
        async with ClientSession() as client:
            async with client.post(
                address + "/scans",
                headers=headers,
                json={
                    "authorized": True,
                    "targets": [f"http://127.0.0.1:{target_port}/"],
                },
            ) as response:
                identifier = (await response.json())["scan_id"]
            await asyncio.wait_for(started.wait(), 2)
            async with client.delete(
                address + "/scans/" + identifier, headers=headers
            ) as response:
                assert response.status == 200
            async with client.get(
                address + "/scans/" + identifier, headers=headers
            ) as response:
                state = await response.json()
                assert state["completed"] == []
                assert not state["running"]
    finally:
        await runner.cleanup()
        await target_runner.cleanup()
