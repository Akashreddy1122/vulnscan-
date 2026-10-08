"""SSH protocol version observation without authentication attempts."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class SSHScanner(Plugin):
    """Read the SSH identification line on configured TCP/22."""

    name, group, active = "ssh", "network", True

    async def scan(self, context: Context) -> list[Finding]:
        """Avoid auth method requests and return only grounded banner evidence."""
        port = context.config["service_ports"]["ssh"]
        if not context.http or port not in context.config["ports"]:
            return []
        await context.http.limiter.acquire()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(context.scope.hostname, port),
                context.config["timeout"],
            )
            try:
                banner = await asyncio.wait_for(
                    reader.readline(), min(2, context.config["timeout"])
                )
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return []
        line = banner.decode("ascii", "replace")[:100].strip()
        if not line.startswith("SSH-"):
            return []
        if line.startswith("SSH-1."):
            return [
                finding(
                    self,
                    context,
                    "Legacy SSH protocol 1",
                    "medium",
                    "The SSH identification line indicates SSH protocol 1.",
                    "Disable SSHv1; allow SSHv2 only.",
                    evidence=line,
                    confidence="high",
                    cwe="CWE-326",
                    cvss=5.3,
                )
            ]
        return [
            finding(
                self,
                context,
                "SSH service identified",
                "info",
                "SSH identification line received; cryptographic algorithms were not negotiated.",
                "Review SSH service exposure and supported algorithms separately.",
                evidence=line,
                confidence="high",
            )
        ]
