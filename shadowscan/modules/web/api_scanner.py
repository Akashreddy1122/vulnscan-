"""Read-only API description discovery."""

import json
from urllib.parse import urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class APIScanner(Plugin):
    """Check a few conventional OpenAPI document paths."""

    name, group, active = "api", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Validate JSON shape rather than trusting status codes alone."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        output = []
        for path in ("openapi.json", "swagger.json", "v3/api-docs"):
            url = urljoin(origin, path)
            response = await context.http.get(url)
            if not response or response.status != 200:
                continue
            try:
                data = json.loads(response.body)
            except ValueError:
                continue
            if (
                isinstance(data, dict)
                and ("openapi" in data or "swagger" in data)
                and isinstance(data.get("paths"), dict)
            ):
                output.append(
                    finding(
                        self,
                        context,
                        "API description exposed",
                        "info",
                        "A publicly reachable OpenAPI description was found.",
                        "Review whether documentation should be public and enforce endpoint authorization.",
                        evidence=f"{len(data['paths'])} documented paths (names omitted)",
                        confidence="high",
                        url=url,
                    )
                )
        methods = await context.http.request("OPTIONS", context.scope.base_url)
        if methods and "TRACE" in {
            item.strip().upper() for item in methods.headers.get("Allow", "").split(",")
        }:
            output.append(
                finding(
                    self,
                    context,
                    "HTTP TRACE advertised",
                    "info",
                    "The Allow response lists TRACE; the method was not invoked.",
                    "Disable TRACE if it is not required and verify server policy.",
                    evidence="OPTIONS Allow contains TRACE",
                    confidence="medium",
                )
            )
        return output
