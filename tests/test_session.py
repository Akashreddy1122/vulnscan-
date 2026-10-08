"""HTTP transport authorization, proxy pacing and scope tests."""

import pytest
from aiohttp import web

from shadowscan.core.config import load_config
from shadowscan.core.errors import ScopeError
from shadowscan.core.rate_limiter import RateLimiter
from shadowscan.core.scope import Scope
from shadowscan.core.session import HttpSession


@pytest.mark.asyncio
async def test_http_proxy_rotation_and_scope():
    """Two HTTP proxies alternate while out-of-scope URLs never reach either."""
    calls = []
    runners = []
    addresses = []
    for label in ("one", "two"):

        async def handler(request, label=label):
            calls.append(label)
            return web.Response(text=label)

        app = web.Application()
        app.router.add_route("*", "/{rest:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        runners.append(runner)
        addresses.append(f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}")
    config = load_config()
    config.update(retries=0, rate=100)
    scope = Scope("http://example.test/")
    try:
        async with HttpSession(
            config, scope, RateLimiter(100), proxy_list=addresses
        ) as http:
            assert (await http.get(scope.base_url)).body == "one"
            assert (await http.get(scope.base_url)).body == "two"
            with pytest.raises(ScopeError):
                await http.get("http://outside.test/")
        assert calls == ["one", "two"]
    finally:
        for runner in runners:
            await runner.cleanup()


@pytest.mark.asyncio
async def test_user_agent_rotation_from_explicit_allowlist():
    """User-Agent override is bounded to caller-approved strings."""
    seen = []

    async def handler(request):
        seen.append(request.headers.get("User-Agent"))
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}/"
    config = load_config()
    config.update(user_agents=["ShadowScan agent A", "ShadowScan agent B"], rate=100)
    try:
        async with HttpSession(config, Scope(url), RateLimiter(100)) as http:
            for _ in range(5):
                assert (await http.get(url)).status == 200
        assert set(seen) <= set(config["user_agents"])
    finally:
        await runner.cleanup()
