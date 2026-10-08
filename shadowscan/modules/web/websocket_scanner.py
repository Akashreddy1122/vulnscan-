"""Read-only WebSocket handshake with a synthetic cross-site Origin."""

import base64
import os

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class WebSocketScanner(Plugin):
    """Probe the supplied path only; never send or receive application messages."""

    name, group, active = "websocket", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Report an accepted foreign-origin upgrade as a lead, not hijacking proof."""
        if not context.http:
            return []
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        response = await context.http.get(
            context.scope.base_url,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13",
                "Origin": "https://shadowscan-test.invalid",
            },
        )
        if response and response.status == 101:
            return [
                finding(
                    self,
                    context,
                    "WebSocket accepts synthetic cross-site Origin",
                    "info",
                    "The supplied endpoint upgraded a request with a foreign Origin."
                    " Authentication and message authorization were not tested.",
                    "Validate Origin for cookie-authenticated WebSockets and authorize each message.",
                    evidence="101 Switching Protocols with synthetic .invalid Origin",
                    confidence="medium",
                    cwe="CWE-346",
                )
            ]
        return []
