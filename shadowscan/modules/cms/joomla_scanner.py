"""Joomla administration entry point discovery."""

from urllib.parse import urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class JoomlaScanner(Plugin):
    """Identify administration page only when Joomla markup is present."""

    name, group, active = "joomla", "cms", True

    async def scan(self, context: Context) -> list[Finding]:
        """Perform one GET on the known administrator location."""
        response = await context.base_response()
        if not response or "joomla" not in response.body.lower() or not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        url = urljoin(
            urlunsplit((parts.scheme, parts.netloc, "/", "", "")), "administrator/"
        )
        reply = await context.http.get(url)
        if reply and reply.status == 200 and "joomla" in reply.body.lower():
            return [
                finding(
                    self,
                    context,
                    "Joomla administrator page present",
                    "info",
                    "An administrator page appears reachable; authentication was not tested.",
                    "Restrict administrative access and enable MFA.",
                    evidence="Joomla administrator page signature",
                    confidence="medium",
                    url=url,
                )
            ]
        return []
