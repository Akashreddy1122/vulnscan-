"""Stable plugin API and shared per-target context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from shadowscan.core.models import Finding
from shadowscan.core.scope import Scope
from shadowscan.core.session import HttpSession, Response
from shadowscan.database.db_manager import Database


@dataclass
class Context:
    """Runtime context available to every scanner plugin."""

    scope: Scope
    http: HttpSession | None
    config: dict
    mode: str
    executor: object
    db: Database | None = None
    jwt_token: str | None = field(default=None, repr=False)
    _base: Response | None = field(default=None, repr=False)
    _loaded: bool = field(default=False, repr=False)

    async def base_response(self) -> Response | None:
        """Fetch the base page at most once per target."""
        if self.mode == "passive" or self.http is None:
            return None
        if not self._loaded:
            self._base = await self.http.get(self.scope.base_url)
            self._loaded = True
        return self._base


class Plugin:
    """Base class for opt-in, independent asynchronous scan modules."""

    name: ClassVar[str] = ""
    group: ClassVar[str] = ""
    active: ClassVar[bool] = False

    async def scan(self, context: Context) -> list[Finding]:
        """Return observations; subclasses must implement the scan."""
        raise NotImplementedError


def finding(
    plugin: Plugin,
    context: Context,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    *,
    evidence: str = "",
    parameter: str = "",
    confidence: str = "medium",
    cwe: str = "",
    cvss: float = 0,
    url: str | None = None,
) -> Finding:
    """Build a finding with consistent origin and metadata."""
    return Finding(
        title,
        severity,
        url or context.scope.base_url,
        description,
        remediation,
        plugin.name,
        evidence,
        parameter,
        confidence,
        cwe,
        cvss,
    )
