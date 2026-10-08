"""Example third-party plugin; install via entry point, never load arbitrary paths.

In your package's pyproject.toml:
[project.entry-points."shadowscan.plugins"]
example_observation = "your_package.plugin:ExampleObservation"

Run with --enable-third-party --modules example_observation. Only install trusted
plugins; third-party code is NOT sandboxed.
"""

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class ExampleObservation(Plugin):
    """Report an informational HTTP status observation."""

    name, group = "example_observation", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Use the scoped HTTP session and do not log response secrets."""
        response = await context.base_response()
        if not response:
            return []
        return [
            finding(
                self,
                context,
                "Example HTTP status",
                "info",
                f"The base page responded with HTTP {response.status}.",
                "No remediation needed; this is a plugin development example.",
                evidence=f"HTTP {response.status}",
                confidence="high",
            )
        ]
