"""Plain FTP greeting detection without login or data transfer."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class FTPScanner(Plugin):
    """Read the welcome line; no anonymous/default login attempts."""

    name, group, active = "ftp", "network", True

    async def scan(self, context: Context) -> list[Finding]:
        """Identify a plaintext control channel at configured TCP/21."""
        port = context.config["service_ports"]["ftp"]
        if not context.http or port not in context.config["ports"]:
            return []
        await context.http.limiter.acquire()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(context.scope.hostname, port),
                context.config["timeout"],
            )
            try:
                line = await asyncio.wait_for(
                    reader.readline(), min(2, context.config["timeout"])
                )
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return []
        if not line.startswith(b"220"):
            return []
        return [
            finding(
                self,
                context,
                "Plain FTP control channel observed",
                "low",
                "An FTP-style plaintext greeting was received. No credentials were sent.",
                "Prefer SFTP or FTPS; disable plaintext FTP where possible.",
                evidence="FTP 220 greeting (banner omitted)",
                confidence="medium",
                cwe="CWE-319",
            )
        ]
