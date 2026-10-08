"""Inventory query and HTML form field names without submitting forms."""

from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class _Fields(HTMLParser):
    """Collect limited form input names from baseline HTML."""

    def __init__(self) -> None:
        """Initialize field inventory."""
        super().__init__()
        self.fields: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record names, never input values."""
        if tag in {"input", "textarea", "select"}:
            name = dict(attrs).get("name")
            if name:
                self.fields.add(name[:80])


class ParameterDiscovery(Plugin):
    """Inventory parameter names visible on the supplied URL/page."""

    name, group = "parameters", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Use a pre-fetched page; never guess new parameter names."""
        names = {
            name[:80]
            for name, _ in parse_qsl(
                urlsplit(context.scope.base_url).query, keep_blank_values=True
            )
        }
        response = await context.base_response()
        if response and "html" in response.headers.get("Content-Type", "").lower():
            parser = _Fields()
            parser.feed(response.body)
            names |= parser.fields
        if not names:
            return []
        return [
            finding(
                self,
                context,
                "Parameter inventory",
                "info",
                f"Found {len(names)} query or form parameter names on the supplied page.",
                "Review sensitive parameters with authorization-aware manual testing.",
                evidence=f"Names: {', '.join(sorted(names)[:25])}",
                confidence="high",
            )
        ]
