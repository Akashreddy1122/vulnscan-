"""Bounded TCP connect-only port inventory (no raw sockets or stealth packets)."""

import asyncio
from time import monotonic

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class PortScanner(Plugin):
    """Probe explicitly configured TCP ports without service authentication."""

    name, group, active = "ports", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Report successful TCP connects and latency, never infer a vulnerability."""
        if not context.http:
            return []
        host = context.scope.hostname
        semaphore = asyncio.Semaphore(context.config["concurrency"])

        async def check(port: int) -> Finding | None:
            """Try one port with timeout and close it promptly."""
            async with semaphore:
                await context.http.limiter.acquire()
                start = monotonic()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=context.config["timeout"],
                    )
                    writer.close()
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    return None
                elapsed = (monotonic() - start) * 1000
                display_host = f"[{host}]" if ":" in host else host
                return finding(
                    self,
                    context,
                    f"TCP port {port} open",
                    "info",
                    f"TCP connection to port {port} succeeded.",
                    "Review whether this service must be publicly accessible.",
                    evidence=f"TCP connect succeeded in {elapsed:.1f} ms",
                    confidence="high",
                    url=f"tcp://{display_host}:{port}",
                )

        ports = list(dict.fromkeys(context.config["ports"]))
        output = []
        # Chunk tasks so an explicit all-ports scan does not allocate 65k futures.
        for start in range(0, len(ports), 128):
            batch = await asyncio.gather(
                *(check(port) for port in ports[start : start + 128])
            )
            output.extend(item for item in batch if item)
        output.append(
            finding(
                self,
                context,
                "TCP connect scan summary",
                "info",
                f"Checked {len(ports)} configured TCP ports; {len(output)} accepted connections."
                " No conclusion is made about unresponsive ports.",
                "Review the service inventory and scan results; do not equate no response with closed.",
                evidence=f"{len(ports)} tested, {len(output)} connected",
                confidence="high",
            )
        )
        return output
