"""WordPress read-only deployment hygiene checks."""

from urllib.parse import urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class WordPressScanner(Plugin):
    """Check XML-RPC availability when WordPress is already signaled."""

    name, group, active = "wordpress", "cms", True

    async def scan(self, context: Context) -> list[Finding]:
        """GET XML-RPC endpoint; do not submit authentication or user queries."""
        response = await context.base_response()
        if (
            not response
            or not any(
                token in response.body.lower()
                for token in ("wp-content", "wp-includes", "wordpress")
            )
            or not context.http
        ):
            return []
        parts = urlsplit(context.scope.base_url)
        root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        url = urljoin(root, "xmlrpc.php")
        reply = await context.http.get(url)
        if reply and "xml-rpc server accepts post requests only" in reply.body.lower():
            return [
                finding(
                    self,
                    context,
                    "WordPress XML-RPC endpoint enabled",
                    "info",
                    "The XML-RPC endpoint responds to a GET request. Abuse is not confirmed.",
                    "Disable XML-RPC when unused and apply rate limits to authentication.",
                    evidence="xmlrpc.php identified by standard GET response",
                    url=url,
                    confidence="high",
                )
            ]
        return []
