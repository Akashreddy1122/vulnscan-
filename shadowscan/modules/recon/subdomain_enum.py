"""Opt-in bounded DNS-only subdomain discovery with wildcard comparison."""

import asyncio
import ipaddress
import socket
import uuid
from importlib.resources import files

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class SubdomainEnumerator(Plugin):
    """Resolve a small local wordlist only when explicitly authorized."""

    name, group, active = "subdomains", "recon", True

    async def scan(self, context: Context) -> list[Finding]:
        """Never send HTTP traffic to discovered names or add them to scan scope."""
        if not context.config["enumerate_subdomains"] or not context.http:
            return []
        domain = context.scope.hostname
        try:
            ipaddress.ip_address(domain)
            return []
        except ValueError:
            pass
        if domain.count(".") < 1:
            return []
        loop = asyncio.get_running_loop()

        async def addresses(name: str) -> set[str]:
            """Resolve candidate with a bounded wait and global rate limit."""
            await context.http.limiter.acquire()
            try:
                result = await asyncio.wait_for(
                    loop.getaddrinfo(name, None, type=socket.SOCK_STREAM),
                    timeout=context.config["timeout"],
                )
                return {entry[4][0] for entry in result}
            except (OSError, asyncio.TimeoutError):
                return set()

        wildcard = await addresses(f"shadow-{uuid.uuid4().hex[:12]}.{domain}")
        words = (
            files("shadowscan")
            .joinpath("config/payloads/subdomain_wordlist.txt")
            .read_text()
            .splitlines()
        )
        output = []
        for word in words[:20]:
            if (
                not word
                or word.startswith("#")
                or not word.isascii()
                or not word.isalnum()
            ):
                continue
            hostname = f"{word}.{domain}"
            found = await addresses(hostname)
            if found and found != wildcard:
                output.append(
                    finding(
                        self,
                        context,
                        "Subdomain DNS record observed",
                        "info",
                        f"{hostname} resolves to an address distinct from the wildcard control.",
                        "Authorize discovered assets separately before active scanning.",
                        evidence=f"DNS name: {hostname}; addresses: {', '.join(sorted(found)[:4])}",
                        confidence="medium",
                    )
                )
        return output
