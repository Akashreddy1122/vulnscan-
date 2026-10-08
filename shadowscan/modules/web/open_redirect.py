"""Single-request open redirect check; redirects never followed."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding
from shadowscan.utils.payloads import load


class OpenRedirectScanner(Plugin):
    """Test existing redirect-shaped parameters with an inert .invalid hostname."""

    name, group, active = "open_redirect", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Only consider actual 3xx Location responses."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        output = []
        for i, (name, _) in enumerate(params[:10]):
            if name.lower() not in {
                "next",
                "url",
                "redirect",
                "return",
                "returnurl",
                "continue",
            }:
                continue
            for destination in load("open_redirect"):
                changed = list(params)
                changed[i] = (name, destination)
                url = urlunsplit(parts._replace(query=urlencode(changed)))
                response = await context.http.get(url)
                if (
                    response
                    and response.status in {301, 302, 303, 307, 308}
                    and response.headers.get("Location") == destination
                ):
                    output.append(
                        finding(
                            self,
                            context,
                            "External open redirect",
                            "medium",
                            "An untrusted query parameter controls an external Location header.",
                            "Allow only relative or explicitly allowlisted redirect destinations.",
                            evidence="3xx Location points to synthetic .invalid host (not followed)",
                            parameter=name,
                            confidence="high",
                            cwe="CWE-601",
                            cvss=4.7,
                            url=url,
                        )
                    )
                    break
        return output
