"""TCP connect host reachability check without privileged probes."""

import asyncio
from time import monotonic
from urllib.parse import urlsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class HostDiscovery(Plugin):
    """Establish whether explicitly supplied target responds on its web port."""

    name, group, active = "host_discovery", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Return a reachability signal, not a claim that closed hosts are down."""
        if not context.http:
            return []
        port = urlsplit(context.scope.base_url).port or (
            443 if context.scope.base_url.startswith("https://") else 80
        )
        await context.http.limiter.acquire()
        start = monotonic()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(context.scope.hostname, port),
                timeout=context.config["timeout"],
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return []
        ms = round((monotonic() - start) * 1000, 1)
        return [
            finding(
                self,
                context,
                "Host responds to TCP connect",
                "info",
                f"Web port {port} accepted a TCP connection in {ms} ms.",
                "No remediation necessary; verify service inventory.",
                evidence=f"TCP/{port} connected in {ms} ms",
                confidence="high",
            )
        ]
