"""Bounded, unauthenticated plaintext service greeting checks."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class ServiceDetector(Plugin):
    """Read greetings from configured SSH/SMTP/FTP ports without sending credentials."""

    name, group, active = "services", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Detect known protocol greetings on ports already selected by the user."""
        if not context.http:
            return []
        observations = []
        for service, prefix in (("ftp", "220"), ("ssh", "SSH-"), ("smtp", "220")):
            port = context.config["service_ports"][service]
            label = service.upper()
            if port not in context.config["ports"]:
                continue
            await context.http.limiter.acquire()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(context.scope.hostname, port),
                    timeout=context.config["timeout"],
                )
                try:
                    raw = await asyncio.wait_for(
                        reader.read(256), timeout=min(2, context.config["timeout"])
                    )
                finally:
                    writer.close()
                    await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                continue
            greeting = (
                raw.decode("ascii", "replace").splitlines()[0][:100] if raw else ""
            )
            if greeting.startswith(prefix):
                observations.append(
                    finding(
                        self,
                        context,
                        f"{label} greeting observed",
                        "info",
                        f"TCP/{port} returned a {label}-like greeting.",
                        "Review service exposure and versions against inventory.",
                        evidence=f"TCP/{port} greeting: {greeting}",
                        confidence="medium",
                    )
                )
        return observations
