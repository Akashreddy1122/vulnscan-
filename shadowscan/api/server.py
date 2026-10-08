"""Authenticated single-scan-at-a-time API for local CI integration."""

from __future__ import annotations

import asyncio
import hmac
import logging
import uuid
from typing import Any

from aiohttp import web

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.errors import ConfigurationError
from shadowscan.core.models import ScanResult, now
from shadowscan.core.plugin_loader import PLUGINS, PROFILES, select_plugins
from shadowscan.core.target import normalize_target
from shadowscan.database.db_manager import Database

LOG = logging.getLogger(__name__)


class ScanAPI:
    """Own database and one active scan; never store credentials in scan records."""

    def __init__(self, token: str, db_path: str, config: dict | None = None) -> None:
        """Require a strong secret before binding a socket."""
        if len(token) < 32:
            raise ConfigurationError("API token must contain at least 32 characters")
        self.token = token
        self.db = Database(db_path)
        self.config = config or load_config()
        self.task: asyncio.Task | None = None
        self.active_id: str | None = None
        self.lock = asyncio.Lock()

    @web.middleware
    async def authorize(self, request: web.Request, handler: Any) -> web.StreamResponse:
        """Require bearer token on every route with timing-safe comparison."""
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + self.token):
            raise web.HTTPUnauthorized(text="Bearer token required")
        return await handler(request)

    async def modules(self, request: web.Request) -> web.Response:
        """List supported plugin names."""
        return web.json_response({"modules": list(PLUGINS), "profiles": list(PROFILES)})

    async def create(self, request: web.Request) -> web.Response:
        """Start a bounded, explicitly authorized scan of individual targets."""
        try:
            data = await request.json()
            if not isinstance(data, dict) or data.get("authorized") is not True:
                raise ValueError("Explicit authorized=true is required")
            raw = data.get("targets")
            if (
                not isinstance(raw, list)
                or not 1 <= len(raw) <= self.config["max_targets"]
            ):
                raise ValueError("targets must be a bounded list")
            if any(not isinstance(value, str) for value in raw):
                raise ValueError("targets must be strings")
            # Unlike CLI, never accept files, stdin or CIDRs via network requests.
            targets = list(dict.fromkeys(normalize_target(value) for value in raw))
            profile = data.get("profile", "quick")
            mode = data.get("mode", "active")
            if not isinstance(profile, str) or mode not in {
                "active",
                "stealth",
                "passive",
            }:
                raise ValueError("Invalid profile or mode")
            plugins = select_plugins(
                profile, mode=mode, disabled=self.config["modules_disabled"]
            )
        except (ValueError, ConfigurationError, KeyError) as exc:
            raise web.HTTPBadRequest(text=f"Invalid scan request: {exc}") from exc
        async with self.lock:
            if self.task and not self.task.done():
                raise web.HTTPConflict(text="Another scan is running")
            result = ScanResult(uuid.uuid4().hex, now(), mode, profile, targets)
            self.db.save(result)
            self.active_id = result.scan_id
            scan_config = dict(self.config)
            if mode == "stealth":
                scan_config["rate"] = min(scan_config["rate"], 0.2)
                scan_config["jitter"] = max(scan_config["jitter"], 1.0)
            engine = Engine(scan_config, self.db, plugins)
            self.task = asyncio.create_task(
                engine.run(targets, mode, profile, resume=result)
            )
            self.task.add_done_callback(
                lambda task, scan_id=result.scan_id: self._finished(task, scan_id)
            )
            return web.json_response({"scan_id": result.scan_id}, status=202)

    def _finished(self, task: asyncio.Task, scan_id: str) -> None:
        """Consume task exceptions so the server remains healthy."""
        if not task.cancelled() and task.exception():
            LOG.error("API scan failed: %s", type(task.exception()).__name__)
            if scan_id:
                try:
                    result = self.db.load(scan_id)
                    result.errors.append(
                        "Internal scan failure; resume after checking logs"
                    )
                    self.db.save(result)
                except Exception:
                    LOG.exception("Could not persist failed API scan state")

    async def result(self, request: web.Request) -> web.Response:
        """Return the last persisted checkpoint and current running status."""
        try:
            result = self.db.load(request.match_info["id"])
        except ConfigurationError as exc:
            raise web.HTTPNotFound(text="Scan not found") from exc
        data = result.to_dict()
        data["running"] = result.scan_id == self.active_id and bool(
            self.task and not self.task.done()
        )
        return web.json_response(data)

    async def cancel(self, request: web.Request) -> web.Response:
        """Stop only the current scan and preserve its last checkpoint."""
        identifier = request.match_info["id"]
        if identifier != self.active_id or not self.task or self.task.done():
            raise web.HTTPNotFound(text="Active scan not found")
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass
        return web.json_response({"scan_id": identifier, "cancelled": True})

    async def close(self, app: web.Application) -> None:
        """Cancel active scan before closing the shared SQLite connection."""
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        self.db.close()

    def app(self) -> web.Application:
        """Build an app with authenticated routes and cleanup hook."""
        app = web.Application(middlewares=[self.authorize], client_max_size=65536)
        app.router.add_get("/modules", self.modules)
        app.router.add_post("/scans", self.create)
        app.router.add_get("/scans/{id}", self.result)
        app.router.add_delete("/scans/{id}", self.cancel)
        app.on_cleanup.append(self.close)
        return app


async def serve(
    token: str, db_path: str, host: str = "127.0.0.1", port: int = 8787
) -> None:
    """Run the API until interrupted; localhost-only unless explicitly changed."""
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigurationError(
            "API must bind to loopback; use a TLS-terminating reverse proxy for remote access"
        )
    api = ScanAPI(token, db_path)
    runner = web.AppRunner(api.app())
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    try:
        await site.start()
        LOG.info("ShadowScan API listening on %s:%d", host, port)
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
