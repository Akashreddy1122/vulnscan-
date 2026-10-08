"""Magento deployment indicators from HTML; no user enumeration."""

import re

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class MagentoScanner(Plugin):
    """Detect exposed Magento static version directory in baseline HTML."""

    name, group = "magento", "cms"

    async def scan(self, context: Context) -> list[Finding]:
        """Inspect only an already fetched base page."""
        response = await context.base_response()
        match = re.search(r"/static/(version\d+)/", response.body) if response else None
        if match:
            return [
                finding(
                    self,
                    context,
                    "Magento static deployment identifier",
                    "info",
                    "A static asset deployment identifier is visible; it is not a software version.",
                    "No action required unless deployment metadata must be hidden.",
                    evidence="Static deployment path present",
                    confidence="high",
                )
            ]
        return []
