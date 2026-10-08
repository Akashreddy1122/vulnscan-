"""Drupal changelog exposure check."""

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class DrupalScanner(Plugin):
    """Read a public version document only when Drupal is already indicated."""

    name, group, active = "drupal", "cms", True

    async def scan(self, context: Context) -> list[Finding]:
        """Look for a Drupal release heading; do not infer CVEs from it."""
        response = await context.base_response()
        if (
            not response
            or not any(s in response.body.lower() for s in ("drupal", "sites/default/"))
            or not context.http
        ):
            return []
        parts = urlsplit(context.scope.base_url)
        url = urljoin(
            urlunsplit((parts.scheme, parts.netloc, "/", "", "")), "CHANGELOG.txt"
        )
        reply = await context.http.get(url)
        match = (
            re.match(r"^Drupal\s+(\d+(?:\.\d+){1,3})\b", reply.body)
            if reply and reply.status == 200
            else None
        )
        if match:
            return [
                finding(
                    self,
                    context,
                    "Drupal changelog exposes version",
                    "info",
                    "A public changelog identifies the deployed Drupal release.",
                    "Remove public changelogs and keep Drupal up to date.",
                    evidence=f"Drupal version: {match[1]}",
                    confidence="high",
                    url=url,
                )
            ]
        return []
