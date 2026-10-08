"""DNS A/AAAA resolution for explicitly supplied hostnames only."""

import asyncio
import ipaddress
import socket

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class DNSEnumerator(Plugin):
    """Resolve target DNS records without guessing new names or hosts."""

    name, group, active = "dns", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Return A/AAAA addresses as informational observations."""
        host = context.scope.hostname
        try:
            ipaddress.ip_address(host)
            return []
        except ValueError:
            pass
        if context.http:
            await context.http.limiter.acquire()
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                timeout=context.config["timeout"],
            )
        except (OSError, asyncio.TimeoutError):
            return []
        addresses = sorted({entry[4][0] for entry in records})[:20]
        return [
            finding(
                self,
                context,
                "DNS address record",
                "info",
                f"Target resolves to {address}.",
                "Review whether this address belongs to the authorized asset inventory.",
                evidence=f"Resolved address: {address}",
                confidence="high",
            )
            for address in addresses
        ]
