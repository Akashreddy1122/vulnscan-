"""Generic CMS response marker detection."""

import re

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding

_MARKERS = {
    "WordPress": r"/wp-content/|/wp-includes/|<meta[^>]+wordpress",
    "Joomla": r"/media/system/js/|<meta[^>]+joomla",
    "Drupal": r"drupal-settings-json|/sites/default/files/|<meta[^>]+drupal",
    "Magento": r"/static/version\d+/|Magento_Ui|/skin/frontend/",
}


class CMSDetector(Plugin):
    """Report framework hints from one fetched HTML document."""

    name, group = "cms", "cms"

    async def scan(self, context: Context) -> list[Finding]:
        """Use HTML patterns without enumerating names or user accounts."""
        response = await context.base_response()
        if not response:
            return []
        return [
            finding(
                self,
                context,
                f"CMS signal: {name}",
                "info",
                f"The base response contains a {name} marker. Presence is not confirmed.",
                "Maintain supported versions and apply vendor updates.",
                evidence=f"{name} HTML marker observed (content omitted)",
                confidence="medium",
            )
            for name, pattern in _MARKERS.items()
            if re.search(pattern, response.body, re.I)
        ]
