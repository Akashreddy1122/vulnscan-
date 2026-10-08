"""Strict per-target request scope: exact host, no external redirects."""

from __future__ import annotations

from urllib.parse import urlsplit

from .errors import ScopeError
from .target import normalize_target


class Scope:
    """Authorize only URLs matching an explicitly selected target hostname."""

    def __init__(self, target: str) -> None:
        """Store normalized host and base URL."""
        self.target = normalize_target(target)
        host = (
            f"[{self.target}]"
            if ":" in self.target and "://" not in self.target
            else self.target
        )
        self.base_url = self.target if "://" in self.target else f"https://{host}/"
        parts = urlsplit(self.base_url)
        self.hostname = parts.hostname
        self.scheme = parts.scheme
        self.port = parts.port or (443 if parts.scheme == "https" else 80)

    def check(self, url: str) -> None:
        """Reject URLs outside exact host/optional port or with credentials."""
        try:
            parts = urlsplit(url)
            if (
                parts.scheme != self.scheme
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.hostname.lower() != self.hostname
                or (parts.port or (443 if parts.scheme == "https" else 80)) != self.port
            ):
                raise ScopeError(f"Out of scope: {url}")
        except ValueError as exc:
            raise ScopeError("Malformed URL") from exc
