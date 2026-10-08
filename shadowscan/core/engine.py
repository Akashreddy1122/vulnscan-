"""Central scan coordinator with per-target isolation and checkpoints."""

from __future__ import annotations

import asyncio
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable

from shadowscan.database.db_manager import Database
from shadowscan.modules.base import Context, Plugin
from .models import ScanResult, now
from .rate_limiter import RateLimiter
from .scope import Scope
from .session import HttpSession

LOG = logging.getLogger(__name__)


class Engine:
    """Run selected plugins across bounded concurrent targets with shared pacing."""

    def __init__(
        self,
        config: dict,
        db: Database,
        plugins: list[Plugin],
        proxy: str | None = None,
        auth_cookie: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        bearer_token: str | None = None,
        jwt_token: str | None = None,
        digest_auth: tuple[str, str] | None = None,
        proxy_list: list[str] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> None:
        """Initialize runtime dependencies without sending network traffic."""
        self.config, self.db, self.plugins = config, db, plugins
        self.proxy, self.auth_cookie = proxy, auth_cookie
        self.basic_auth, self.bearer_token = basic_auth, bearer_token
        self.jwt_token = jwt_token
        self.digest_auth, self.proxy_list = digest_auth, proxy_list
        self.on_progress = on_progress

    async def run(
        self,
        targets: list[str],
        mode: str = "active",
        profile: str = "quick",
        resume: ScanResult | None = None,
    ) -> ScanResult:
        """Scan pending targets concurrently; checkpoint each completed target."""
        result = resume or ScanResult(uuid.uuid4().hex, now(), mode, profile, targets)
        result.finished = ""
        self.db.save(result)
        limiter = RateLimiter(self.config["rate"], self.config["jitter"])
        target_slots = asyncio.Semaphore(min(self.config["concurrency"], 8))
        checkpoint = asyncio.Lock()
        seen = {(f.module, f.title, f.url, f.parameter) for f in result.findings}

        async def one(target: str, executor: ThreadPoolExecutor) -> None:
            """Run plugins on one target, isolating failures from other targets."""
            if target in result.completed:
                return
            async with target_slots:
                scope = Scope(target)
                try:
                    if mode == "passive":
                        ctx = Context(
                            scope,
                            None,
                            self.config,
                            mode,
                            executor,
                            self.db,
                            self.jwt_token,
                        )
                        await self._run_plugins(ctx, result, seen)
                    else:
                        async with HttpSession(
                            self.config,
                            scope,
                            limiter,
                            self.proxy,
                            self.auth_cookie,
                            self.basic_auth,
                            self.bearer_token,
                            self.digest_auth,
                            self.proxy_list,
                        ) as session:
                            ctx = Context(
                                scope,
                                session,
                                self.config,
                                mode,
                                executor,
                                self.db,
                                self.jwt_token,
                            )
                            await self._run_plugins(ctx, result, seen)
                except asyncio.CancelledError:
                    async with checkpoint:
                        result.errors.append(f"{scope.hostname}: scan cancelled")
                        self.db.save(result)
                    raise
                except Exception as exc:
                    LOG.exception("Target failed: %s", scope.hostname)
                    result.errors.append(f"{scope.hostname}: {type(exc).__name__}")
                async with checkpoint:
                    result.completed.append(target)
                    self.db.save(result)
                    LOG.info(
                        "Progress: %d/%d targets",
                        len(result.completed),
                        len(result.targets),
                    )
                    if self.on_progress:
                        try:
                            self.on_progress(len(result.completed), len(result.targets))
                        except Exception:
                            LOG.debug("Progress callback failed", exc_info=True)

        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
            await asyncio.gather(*(one(t, executor) for t in result.targets))
        result.finished = now()
        self.db.save(result)
        return result

    async def _run_plugins(
        self, ctx: Context, result: ScanResult, seen: set[tuple[str, str, str, str]]
    ) -> None:
        """Isolate plugin errors and deduplicate identical observations."""
        for plugin in self.plugins:
            try:
                observations = await plugin.scan(ctx)
                for item in observations:
                    key = (item.module, item.title, item.url, item.parameter)
                    # No await between membership check and update; event-loop atomic.
                    if key not in seen:
                        result.findings.append(item)
                        seen.add(key)
                        LOG.warning(
                            "Finding: [%s] %s (%s)",
                            item.severity,
                            item.title,
                            ctx.scope.hostname,
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("Plugin %s failed on %s", plugin.name, ctx.scope.hostname)
                result.errors.append(
                    f"{ctx.scope.hostname}/{plugin.name}: {type(exc).__name__}"
                )
