"""Bounded HTTP transport with explicit scope, pacing, and no redirects."""

from __future__ import annotations

import asyncio
import itertools
import logging
import secrets
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp

from .errors import ConfigurationError
from .rate_limiter import RateLimiter
from .scope import Scope

LOG = logging.getLogger(__name__)


@dataclass
class Response:
    """Small safe-to-retain HTTP response snapshot (cookie values omitted)."""

    url: str
    status: int
    headers: dict[str, str]
    body: str
    cookies: list[dict[str, str]] = field(default_factory=list)


class HttpSession:
    """Share connection pool and cookies while enforcing limits on every request."""

    def __init__(
        self,
        config: dict,
        scope: Scope,
        limiter: RateLimiter,
        proxy: str | None = None,
        auth_cookie: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        bearer_token: str | None = None,
        digest_auth: tuple[str, str] | None = None,
        proxy_list: list[str] | None = None,
    ) -> None:
        """Validate transport options before opening the connection pool."""
        proxies = ([proxy] if proxy else []) + (proxy_list or [])
        if len(proxies) > 50:
            raise ConfigurationError("Proxy limit is 50")
        if any(
            urlsplit(value).scheme not in {"http", "https", "socks4", "socks5"}
            or not urlsplit(value).hostname
            for value in proxies
        ):
            raise ConfigurationError("Invalid HTTP(S)/SOCKS4/SOCKS5 proxy URL")
        if (
            any(urlsplit(value).scheme.startswith("socks") for value in proxies)
            and len(proxies) != 1
        ):
            raise ConfigurationError(
                "SOCKS requires one proxy; rotation supports HTTP(S) proxies only"
            )
        if sum(bool(value) for value in (basic_auth, bearer_token, digest_auth)) > 1:
            raise ConfigurationError("Choose Basic, Digest or Bearer authentication")
        configured = {key.lower() for key in config["headers"]}
        if "authorization" in configured and any(
            (basic_auth, bearer_token, digest_auth)
        ):
            raise ConfigurationError("Conflicting Authorization headers")
        if "cookie" in configured and auth_cookie:
            raise ConfigurationError("Conflicting Cookie headers")
        if any(
            any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in (
                auth_cookie or "",
                bearer_token or "",
                *(basic_auth or ()),
                *(digest_auth or ()),
            )
        ):
            raise ConfigurationError("Authentication values must not contain newlines")
        has_auth = bool(
            auth_cookie
            or basic_auth
            or bearer_token
            or digest_auth
            or any(
                key.lower() in {"authorization", "cookie", "proxy-authorization"}
                for key in config["headers"]
            )
        )
        if scope.scheme == "http" and has_auth and not config["allow_insecure_auth"]:
            raise ConfigurationError(
                "Refusing credentials over HTTP; use HTTPS or explicitly allow insecure auth"
            )
        self.config = config
        self.scope = scope
        self.limiter = limiter
        self.socks_proxy = (
            proxies[0]
            if proxies and urlsplit(proxies[0]).scheme.startswith("socks")
            else None
        )
        self.proxies = (
            itertools.cycle(proxies) if proxies and not self.socks_proxy else None
        )
        self.auth_cookie = auth_cookie
        self.basic_auth = basic_auth
        self.digest_auth = digest_auth
        self.bearer_token = bearer_token
        self.client: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> HttpSession:
        """Open a pooled session with bounded connections."""
        headers = {"User-Agent": self.config["user_agent"], **self.config["headers"]}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.basic_auth:
            headers["Authorization"] = aiohttp.encode_basic_auth(*self.basic_auth)
        connector: aiohttp.BaseConnector
        if self.socks_proxy:
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError as exc:
                raise ConfigurationError(
                    "SOCKS support requires pip install '.[socks]'"
                ) from exc
            connector = ProxyConnector.from_url(
                self.socks_proxy, limit=self.config["concurrency"]
            )
        else:
            # Pin the first DNS answer for the lifetime of this per-target
            # session, rather than re-resolving between plugin requests.
            connector = aiohttp.TCPConnector(
                limit=self.config["concurrency"], ttl_dns_cache=None
            )
        middleware = (
            (aiohttp.DigestAuthMiddleware(*self.digest_auth),)
            if self.digest_auth
            else ()
        )
        self.client = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config["timeout"]),
            connector=connector,
            middlewares=middleware,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            trust_env=False,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close all pooled sockets."""
        if self.client:
            await self.client.close()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> Response | None:
        """Make a scoped read-only request; POST is for explicit plugin probes only."""
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            raise ConfigurationError(
                "Only GET, HEAD, OPTIONS and explicit POST probes are supported"
            )
        self.scope.check(url)
        if self.client is None:
            raise RuntimeError("Session is not open")
        if data is not None and (method != "POST" or len(data) > 65536):
            raise ConfigurationError("POST payload must be at most 64 KiB")
        if headers:
            forbidden = {
                "host",
                "content-length",
                "transfer-encoding",
                "proxy-authorization",
            }
            if any(
                not isinstance(k, str)
                or not isinstance(v, str)
                or k.lower() in forbidden
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k)
                or any(ord(c) < 32 or ord(c) == 127 for c in v)
                for k, v in headers.items()
            ):
                raise ConfigurationError("Unsafe request headers")
        for attempt in range(self.config["retries"] + 1):
            await self.limiter.acquire()
            request_headers = dict(headers or {})
            if self.config["user_agents"] and "User-Agent" not in request_headers:
                request_headers["User-Agent"] = secrets.choice(
                    self.config["user_agents"]
                )
            try:
                async with self.client.request(
                    method,
                    url,
                    headers=request_headers,
                    data=data,
                    proxy=next(self.proxies) if self.proxies else None,
                    allow_redirects=False,
                ) as resp:
                    raw = await resp.content.read(self.config["max_response_bytes"] + 1)
                    if len(raw) > self.config["max_response_bytes"]:
                        LOG.warning(
                            "Response body truncated: %s", urlsplit(url).hostname
                        )
                    body = raw[: self.config["max_response_bytes"]].decode(
                        resp.charset or "utf-8", errors="replace"
                    )
                    cookies = [
                        {
                            "name": name,
                            "secure": str(cookie["secure"]),
                            "httponly": str(cookie["httponly"]),
                            "samesite": str(cookie["samesite"]),
                            "domain": str(cookie["domain"]),
                            "path": str(cookie["path"]),
                        }
                        for name, cookie in resp.cookies.items()
                    ]
                    safe_headers = {
                        key: value
                        for key, value in resp.headers.items()
                        if key.lower()
                        not in {"set-cookie", "authorization", "proxy-authenticate"}
                    }
                    return Response(
                        str(resp.url), resp.status, safe_headers, body, cookies
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError) as exc:
                LOG.debug(
                    "HTTP attempt %d failed for %s: %s",
                    attempt + 1,
                    urlsplit(url).hostname,
                    type(exc).__name__,
                )
                if attempt < self.config["retries"]:
                    await asyncio.sleep(min(0.25 * 2**attempt, 2))
        return None

    async def get(
        self, url: str, headers: dict[str, str] | None = None
    ) -> Response | None:
        """Convenience wrapper for GET."""
        return await self.request("GET", url, headers=headers)
