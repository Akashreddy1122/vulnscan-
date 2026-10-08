"""Non-executing reflection probe; never claims confirmed XSS."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding
from shadowscan.utils.payloads import load


class XSSScanner(Plugin):
    """Check query parameters for unescaped HTML-like reflection."""

    name, group, active = "xss", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Compare baseline and one harmless marker per existing parameter."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if not params:
            return []
        base = await context.base_response()
        output = []
        for index, (key, _) in enumerate(params[:10]):
            marker = "ss" + uuid4().hex[:10]
            for template in load("xss"):
                payload = template.replace("{marker}", marker)
                mutated = list(params)
                mutated[index] = (key, payload)
                url = urlunsplit(parts._replace(query=urlencode(mutated)))
                response = await context.http.get(url)
                if (
                    response
                    and payload in response.body
                    and (not base or payload not in base.body)
                ):
                    output.append(
                        finding(
                            self,
                            context,
                            "Unescaped HTML parameter reflection",
                            "low",
                            "An inert HTML marker was returned verbatim; this is not proof of executable XSS.",
                            "Contextually encode untrusted output and validate with manual testing.",
                            evidence="Non-executing marker reflected verbatim",
                            parameter=key,
                            confidence="medium",
                            cwe="CWE-79",
                            cvss=0,
                        )
                    )
                    break
        return output
