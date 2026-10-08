"""Harmless arithmetic template-expression differential probe."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding
from shadowscan.utils.payloads import load


class SSTIScanner(Plugin):
    """Look for arithmetic expression evaluation without executing commands."""

    name, group, active = "ssti", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Require two different expression results to reduce false positives."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if not params:
            return []
        output = []
        for i, (key, _) in enumerate(params[:5]):
            hits = []
            for expression, answer in (entry.split("|", 1) for entry in load("ssti")):
                changed = list(params)
                changed[i] = (key, expression)
                url = urlunsplit(parts._replace(query=urlencode(changed)))
                response = await context.http.get(url)
                hits.append(
                    bool(
                        response
                        and answer in response.body
                        and expression not in response.body
                    )
                )
            if all(hits):
                output.append(
                    finding(
                        self,
                        context,
                        "Possible template expression evaluation",
                        "medium",
                        "Two distinct arithmetic expressions appear to have been evaluated.",
                        "Avoid rendering user-controlled templates and use sandboxed templates.",
                        evidence="Two harmless arithmetic probes produced expected results",
                        parameter=key,
                        confidence="medium",
                        cwe="CWE-1336",
                        cvss=0,
                    )
                )
        return output
