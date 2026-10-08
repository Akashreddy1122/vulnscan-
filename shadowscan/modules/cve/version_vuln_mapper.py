"""Tentative response-header version lookup against locally imported NVD CPEs."""

import re

from shadowscan.database.cve_cache import lookup
from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding

_SIGNATURES = {
    "Apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "OpenResty": ("openresty", "openresty"),
}


class CVEMapper(Plugin):
    """Report exact CPE cache candidates as unverified leads only."""

    name, group = "cve", "cve"

    async def scan(self, context: Context) -> list[Finding]:
        """Match a reported HTTP Server version; never claim confirmed exploitability."""
        if context.db is None:
            return []
        response = await context.base_response()
        if not response:
            return []
        banner = response.headers.get("Server", "")[:120]
        match = re.match(
            r"^(Apache|nginx|OpenResty)/([0-9]+(?:\.[0-9]+){1,3})\b", banner
        )
        if not match:
            return []
        vendor, product = _SIGNATURES[match[1]]
        cpe = f"cpe:2.3:a:{vendor}:{product}:{match[2]}:*:*:*:*:*:*:*"
        output = []
        for identifier, score, description in lookup(context.db.conn, cpe)[:20]:
            severity = (
                "critical"
                if score >= 9
                else "high"
                if score >= 7
                else "medium"
                if score >= 4
                else "low"
            )
            output.append(
                finding(
                    self,
                    context,
                    f"Potential {identifier} version match",
                    severity,
                    f"A reported server version matches an exact local NVD CPE. {description}",
                    "Verify installed version, patch level and affected configuration; apply vendor fixes.",
                    evidence=f"Server product/version: {match[1]}/{match[2]}; exact CPE match",
                    confidence="low",
                    cvss=score,
                )
            )
        return output
