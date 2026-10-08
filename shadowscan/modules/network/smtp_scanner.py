"""SMTP EHLO capability observation; no mail or account enumeration."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class SMTPScanner(Plugin):
    """Test only advertised STARTTLS on configured TCP/25 or TCP/587."""

    name, group, active = "smtp", "network", True

    async def scan(self, context: Context) -> list[Finding]:
        """Send EHLO and QUIT; never VRFY, EXPN, AUTH or MAIL FROM."""
        if not context.http:
            return []
        for port in dict.fromkeys((context.config["service_ports"]["smtp"], 587)):
            if port not in context.config["ports"]:
                continue
            await context.http.limiter.acquire()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(context.scope.hostname, port),
                    context.config["timeout"],
                )
                try:
                    greeting = await asyncio.wait_for(
                        reader.readline(), min(2, context.config["timeout"])
                    )
                    if not greeting.startswith(b"220"):
                        continue
                    writer.write(b"EHLO shadowscan.invalid\r\n")
                    await writer.drain()
                    lines = []
                    for _ in range(30):
                        line = await asyncio.wait_for(
                            reader.readline(), min(2, context.config["timeout"])
                        )
                        if not line:
                            break
                        lines.append(line[:256])
                        if line.startswith(b"250 "):
                            break
                    writer.write(b"QUIT\r\n")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                continue
            if lines and not any(b"STARTTLS" in line.upper() for line in lines):
                return [
                    finding(
                        self,
                        context,
                        "SMTP STARTTLS not advertised",
                        "low",
                        f"TCP/{port} accepted EHLO but did not advertise STARTTLS.",
                        "Enable STARTTLS where appropriate and require transport security for credentials.",
                        evidence=f"EHLO capabilities on TCP/{port} lack STARTTLS",
                        confidence="medium",
                        cwe="CWE-319",
                    )
                ]
        return []
