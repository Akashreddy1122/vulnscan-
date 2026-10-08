"""End-to-end plugin checks against an in-process local HTTP server."""

import pytest
from aiohttp import web

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.database.db_manager import Database


@pytest.mark.asyncio
async def test_scanners_never_follow_external_redirect(tmp_path):
    """Detect scoped issues while ignoring external links and redirects."""
    calls = []

    async def handler(request):
        calls.append(request.path_qs)
        if request.query.get("next") == "https://shadowscan-test.invalid/":
            raise web.HTTPFound("https://shadowscan-test.invalid/")
        if request.query.get("q", "").endswith("'"):
            text = "sqlite3.OperationalError"
        elif request.query.get("q") == "{{713*719}}":
            text = "512647"
        elif request.query.get("q") == "{{727*733}}":
            text = "532891"
        else:
            text = request.query.get("q", "")
        return web.Response(
            text=f'<html><a href="https://outside.invalid/">outside</a>{text}</html>',
            headers={
                "Access-Control-Allow-Origin": request.headers.get("Origin", "")
                or "none",
                "Access-Control-Allow-Credentials": "true",
            },
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    config = load_config()
    config.update(rate=100, retries=0, max_pages=3)
    target = f"http://127.0.0.1:{port}/?q=hello&next=/"
    try:
        plugins = select_plugins(
            "web",
            ["headers", "cors", "sqli", "ssti", "xss", "open_redirect", "crawler"],
        )
        result = await Engine(config, db, plugins).run([target])
        titles = {f.title for f in result.findings}
        assert "Possible SQL error disclosure" in titles
        assert "Possible template expression evaluation" in titles
        assert "Unescaped HTML parameter reflection" in titles
        assert "External open redirect" in titles
        assert "Arbitrary CORS origin with credentials" in titles
        assert "Crawl inventory" in titles
        assert not result.errors
        assert len(calls) < 30
        assert db.load(result.scan_id).findings == result.findings
        calls_before = len(calls)
        await Engine(config, db, plugins).run([target], resume=db.load(result.scan_id))
        assert len(calls) == calls_before
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_passive_makes_no_http_requests(tmp_path):
    """Passive mode must not interact with the target at all."""
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        plugins = select_plugins("full", mode="passive")
        result = await Engine(load_config(), db, plugins).run(
            ["http://127.0.0.1:1/"], mode="passive"
        )
        assert result.findings == []
        assert result.errors == []
    finally:
        db.close()


@pytest.mark.asyncio
async def test_read_only_discovery_does_not_leak_secrets(tmp_path):
    """Configuration exposure is detected without saving its contents."""

    async def handler(request):
        if request.path == "/.env":
            return web.Response(text="DB_PASSWORD=do-not-save-this\n")
        if request.path == "/.git/HEAD":
            return web.Response(text="ref: refs/heads/main\n")
        if request.path == "/graphql":
            return web.json_response(
                {"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if request.path == "/openapi.json":
            return web.json_response({"openapi": "3.0.0", "paths": {"/users": {}}})
        return web.Response(status=404)

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    config = load_config()
    config.update(rate=100, retries=0)
    try:
        result = await Engine(
            config, db, select_plugins("web", ["directories", "graphql", "api"])
        ).run([f"http://127.0.0.1:{port}/"])
        titles = {item.title for item in result.findings}
        assert titles == {
            "Environment configuration exposed",
            "Git metadata exposed",
            "GraphQL schema introspection available",
            "API description exposed",
        }
        assert "do-not-save-this" not in str(result.to_dict())
        assert "do-not-save-this" not in (tmp_path / "scan.sqlite").read_bytes().decode(
            errors="ignore"
        )
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_auth_and_offline_jwt_are_not_persisted(tmp_path):
    """Basic auth stays in transport; offline JWT yields no network requests."""
    import base64
    import json
    from shadowscan.modules.web.jwt_analyzer import JWTAnalyzer

    def encode(data):
        """Encode one local test token segment."""
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    token = ".".join(
        (encode({"alg": "none"}), encode({"exp": 1, "secret": "never-save"}), "")
    )
    calls = []

    async def handler(request):
        calls.append(request.headers.get("Authorization"))
        return web.Response(text="hello", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scans.sqlite"))
    try:
        result = await Engine(
            load_config(),
            db,
            [JWTAnalyzer()],
            basic_auth=("test", "do-not-save"),
            jwt_token=token,
        ).run([f"http://127.0.0.1:{port}/"], mode="passive")
        assert len(result.findings) == 2
        assert calls == []
        assert "never-save" not in str(result.to_dict())
        assert "do-not-save" not in (tmp_path / "scans.sqlite").read_bytes().decode(
            errors="ignore"
        )
        insecure_config = load_config()
        insecure_config["allow_insecure_auth"] = True  # Explicit local test-server opt-in.
        result2 = await Engine(
            insecure_config,
            db,
            select_plugins("quick", ["headers"]),
            basic_auth=("test", "do-not-save"),
        ).run([f"http://127.0.0.1:{port}/"])
        assert calls and calls[0].startswith("Basic ")
        assert "do-not-save" not in str(result2.to_dict())
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_websocket_upgrade_no_messages(tmp_path):
    """Foreign Origin is tested on supplied path with no application frames."""

    async def ws_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get("/socket", ws_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        config = load_config()
        config.update(retries=0, timeout=2)
        result = await Engine(config, db, select_plugins("web", ["websocket"])).run(
            [f"http://127.0.0.1:{port}/socket"]
        )
        assert [item.title for item in result.findings] == [
            "WebSocket accepts synthetic cross-site Origin"
        ]
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_path_traversal_uses_only_public_control(tmp_path):
    """Traversal plugin never requests operating system files."""
    requests = []
    robots = "User-agent: *\nDisallow: /private\n"

    async def handler(request):
        requests.append(request.path_qs)
        if (
            request.path == "/robots.txt"
            or request.query.get("file") == "../../robots.txt"
        ):
            return web.Response(text=robots)
        return web.Response(text="normal page")

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        config = load_config()
        config.update(rate=100, retries=0)
        result = await Engine(config, db, select_plugins("web", ["traversal"])).run(
            [f"http://127.0.0.1:{port}/?file=welcome"]
        )
        assert [f.title for f in result.findings] == [
            "Possible same-host path traversal"
        ]
        assert not any("passwd" in path or "shadow" in path for path in requests)
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_crawler_honors_robots_and_sitemap_scope(tmp_path):
    """Robots-disallowed and external sitemap URLs must not be requested."""
    seen = []

    async def handler(request):
        seen.append(request.path)
        if request.path == "/robots.txt":
            return web.Response(text="User-agent: *\nDisallow: /private\n")
        if request.path == "/sitemap.xml":
            return web.Response(
                text=(
                    "<urlset><url><loc>http://outside.invalid/</loc></url>"
                    f"<url><loc>http://127.0.0.1:{port}/public</loc></url></urlset>"
                ),
                content_type="application/xml",
            )
        return web.Response(
            text='<a href="/private">secret</a><a href="/public">public</a>',
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        config = load_config()
        config.update(rate=100, retries=0, max_pages=5)
        result = await Engine(config, db, select_plugins("web", ["crawler"])).run(
            [f"http://127.0.0.1:{port}/"]
        )
        assert "/private" not in seen
        assert "/public" in seen
        assert not result.errors
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_targets_scan_concurrently_with_global_limit(tmp_path):
    """Separate targets overlap while shared rate cap and checkpoints remain valid."""
    import asyncio

    active = 0
    maximum = 0

    async def handler(request):
        nonlocal active, maximum
        active += 1
        maximum = max(active, maximum)
        await asyncio.sleep(0.06)
        active -= 1
        return web.Response(text="hello", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    targets = [f"http://127.0.0.1:{port}/?q={i}" for i in range(3)]
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        config = load_config()
        config.update(rate=100, retries=0, concurrency=3)
        result = await Engine(config, db, select_plugins("quick", ["headers"])).run(
            targets
        )
        assert maximum > 1
        assert set(result.completed) == set(targets)
        assert len(db.load(result.scan_id).completed) == 3
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_graphql_post_fallback_is_query_only(tmp_path):
    """POST-only endpoint receives a shallow introspection query, no mutation."""
    posted = []

    async def graphql(request):
        if request.method == "GET":
            return web.Response(status=405)
        posted.append(await request.json())
        return web.json_response(
            {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        )

    app = web.Application()
    app.router.add_route("*", "/graphql", graphql)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    config = load_config()
    config.update(rate=100)
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        result = await Engine(config, db, select_plugins("web", ["graphql"])).run(
            [f"http://127.0.0.1:{port}/"]
        )
        assert [f.title for f in result.findings] == [
            "GraphQL schema introspection available"
        ]
        assert posted == [{"query": "{__schema{queryType{name}}}"}]
    finally:
        db.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_api_trace_only_advertised_not_invoked(tmp_path):
    """Method review uses OPTIONS and does not send TRACE."""
    methods = []

    async def handler(request):
        methods.append(request.method)
        return web.Response(headers={"Allow": "GET, OPTIONS, TRACE"})

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    config = load_config()
    config.update(rate=100, retries=0)
    db = Database(str(tmp_path / "scan.sqlite"))
    try:
        result = await Engine(config, db, select_plugins("web", ["api"])).run(
            [f"http://127.0.0.1:{port}/"]
        )
        assert [f.title for f in result.findings] == ["HTTP TRACE advertised"]
        assert "TRACE" not in methods and "OPTIONS" in methods
    finally:
        db.close()
        await runner.cleanup()
