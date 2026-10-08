"""Bounded UDP response inventory; timeouts are never called open ports."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class _Reply(asyncio.DatagramProtocol):
    """Resolve a future only after receiving a datagram or transport error."""

    def __init__(self, future: asyncio.Future[bool]) -> None:
        """Store the one-response future."""
        self.future = future

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Mark a remote UDP response without retaining its data."""
        if not self.future.done():
            self.future.set_result(True)

    def error_received(self, exc: Exception) -> None:
        """An ICMP error may indicate closed, but is not universally reliable."""
        if not self.future.done():
            self.future.set_result(False)


class UDPScanner(Plugin):
    """Send one minimal datagram to each explicitly configured UDP port."""

    name, group, active = "udp_ports", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Report responses; silently leave open|filtered ambiguity unresolved."""
        if not context.http:
            return []
        ports = context.config["udp_ports"]
        if not ports:
            return []
        loop = asyncio.get_running_loop()
        output = []
        for port in ports:
            await context.http.limiter.acquire()
            future: asyncio.Future[bool] = loop.create_future()
            try:
                transport, _protocol = await asyncio.wait_for(
                    loop.create_datagram_endpoint(
                        lambda: _Reply(future),
                        remote_addr=(context.scope.hostname, port),
                    ),
                    timeout=context.config["timeout"],
                )
                try:
                    transport.sendto(b"\x00")
                    responded = await asyncio.wait_for(
                        future, timeout=min(context.config["timeout"], 1.0)
                    )
                    if responded:
                        output.append(
                            finding(
                                self,
                                context,
                                f"UDP port {port} responded",
                                "info",
                                "A datagram response was received; the service was not identified.",
                                "Review whether this UDP service is expected.",
                                evidence=f"UDP/{port} sent one byte and received a datagram",
                                confidence="high",
                                url=context.scope.base_url,
                            )
                        )
                except asyncio.TimeoutError:
                    pass  # No reply means open|filtered|dropped; cannot distinguish.
                finally:
                    transport.close()
            except (OSError, asyncio.TimeoutError):
                continue
        output.append(
            finding(
                self,
                context,
                "UDP inventory summary",
                "info",
                f"Sent one datagram to {len(ports)} configured UDP ports; "
                f"{len(output)} responded. Silence is inconclusive.",
                "Review responsive services; do not interpret silence as closed.",
                evidence=f"{len(ports)} tested; {len(output)} responses",
                confidence="high",
            )
        )
        return output
