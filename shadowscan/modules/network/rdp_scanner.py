"""RDP security-protocol negotiation without login or exploit traffic."""

import asyncio

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding

# Standard 19-byte TPKT/X.224 connection request advertising TLS and NLA.
_NEGOTIATE = bytes.fromhex("030000130ee000000000000100080003000000")


class RDPScanner(Plugin):
    """Observe the selected RDP transport security protocol."""

    name, group, active = "rdp", "network", True

    async def scan(self, context: Context) -> list[Finding]:
        """Send one negotiation request; never authenticate or test BlueKeep."""
        port = context.config["service_ports"]["rdp"]
        if not context.http or port not in context.config["ports"]:
            return []
        await context.http.limiter.acquire()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(context.scope.hostname, port),
                timeout=context.config["timeout"],
            )
            try:
                writer.write(_NEGOTIATE)
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.readexactly(19), timeout=context.config["timeout"]
                )
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            return []
        if response[:2] != b"\x03\x00" or response[11] not in {2, 3}:
            return []
        if response[11] == 3:
            if int.from_bytes(response[15:19], "little") == 5:
                return [
                    finding(
                        self,
                        context,
                        "RDP NLA required",
                        "info",
                        "The server requested NLA during the transport handshake.",
                        "Keep NLA enabled and restrict RDP network exposure.",
                        evidence="RDP negotiation failure code HYBRID_REQUIRED_BY_SERVER",
                        confidence="high",
                    )
                ]
            return []
        selected = int.from_bytes(response[15:19], "little")
        if selected in {0, 1}:
            return [
                finding(
                    self,
                    context,
                    "RDP negotiated without NLA",
                    "low",
                    "The transport negotiation selected legacy RDP security or TLS without NLA."
                    " This does not prove an account bypass.",
                    "Require NLA and restrict RDP to trusted clients.",
                    evidence=f"RDP selected protocol code: {selected}",
                    confidence="medium",
                    cwe="CWE-287",
                )
            ]
        return [
            finding(
                self,
                context,
                "RDP NLA transport selected",
                "info",
                "The transport handshake selected an NLA-capable protocol.",
                "Restrict RDP access and keep the host patched.",
                evidence=f"RDP selected protocol code: {selected}",
                confidence="high",
            )
        ]
