"""Conservative response-based technology signals."""

import re

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class TechnologyDetector(Plugin):
    """Observe framework hints without fetching additional resources."""

    name, group = "technology", "recon"

    async def scan(self, context: Context) -> list[Finding]:
        """Use known header and HTML markers as informational evidence."""
        response = await context.base_response()
        if not response:
            return []
        markers = {
            "WordPress": r"wp-content/|<meta[^>]+generator[^>]+wordpress",
            "Drupal": r"drupal-settings-json|/sites/default/files/",
            "Joomla": r"/media/system/js/|content=.[^>]*joomla",
            "React": r"data-reactroot|/_next/static/",
            "Vue": r"data-v-[a-f0-9]{6,}|__vue__",
        }
        output = []
        for name, pattern in markers.items():
            if re.search(pattern, response.body, re.IGNORECASE):
                output.append(
                    finding(
                        self,
                        context,
                        f"Technology signal: {name}",
                        "info",
                        f"The response contains a marker commonly associated with {name}.",
                        "Keep frameworks and dependencies updated.",
                        evidence=f"Matched known {name} HTML marker (content omitted)",
                        confidence="medium",
                    )
                )
        return output
