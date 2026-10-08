"""Read-only GraphQL introspection exposure check."""

import json
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class GraphQLScanner(Plugin):
    """Try one shallow GET introspection query on a same-host endpoint."""

    name, group, active = "graphql", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Report exposed schema entry point, not a security flaw by itself."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        url = (
            urljoin(origin, "graphql")
            + "?"
            + urlencode({"query": "{__schema{queryType{name}}}"})
        )
        response = await context.http.get(url)
        if response and response.status in {400, 405}:
            # The fixed __schema query is read-only; no mutations or batching.
            response = await context.http.request(
                "POST",
                urljoin(origin, "graphql"),
                headers={"Content-Type": "application/json"},
                data=json.dumps({"query": "{__schema{queryType{name}}}"}).encode(
                    "utf-8"
                ),
            )
        if not response or response.status != 200:
            return []
        try:
            value = json.loads(response.body)
        except ValueError:
            return []
        if (
            isinstance(value, dict)
            and isinstance(value.get("data"), dict)
            and value["data"].get("__schema")
        ):
            return [
                finding(
                    self,
                    context,
                    "GraphQL schema introspection available",
                    "info",
                    "The GraphQL endpoint responds to a shallow schema introspection query.",
                    "Review authorization on schema fields and disable introspection if required by policy.",
                    evidence="__schema.queryType returned (schema data omitted)",
                    confidence="high",
                    url=response.url,
                )
            ]
        return []
