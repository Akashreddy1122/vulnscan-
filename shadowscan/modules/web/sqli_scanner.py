"""Low-impact SQL error differential; no extraction, delays or stacked queries."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding
from shadowscan.utils.payloads import load

_ERRORS = re.compile(
    r"SQL syntax.*MySQL|PostgreSQL.*ERROR|SQLiteException|"
    r"sqlite3\.OperationalError|ORA-\d{5}|Unclosed quotation mark after the character string",
    re.IGNORECASE,
)


class SQLiScanner(Plugin):
    """Flag newly appearing database errors after one quote mutation."""

    name, group, active = "sqli", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Compare probe response with the same URL before mutation."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if not params:
            return []
        baseline = await context.base_response()
        if not baseline:
            return []
        previous = set(_ERRORS.findall(baseline.body))
        output = []
        for i, (name, value) in enumerate(params[:10]):
            for delimiter in load("sqli"):
                changed = list(params)
                changed[i] = (name, value + delimiter)
                url = urlunsplit(parts._replace(query=urlencode(changed)))
                response = await context.http.get(url)
                if response:
                    fresh = set(_ERRORS.findall(response.body)) - previous
                    if fresh:
                        output.append(
                            finding(
                                self,
                                context,
                                "Possible SQL error disclosure",
                                "medium",
                                "A database error appeared after a delimiter was added. Injection is not confirmed.",
                                "Use parameterized queries; manually validate the affected input.",
                                evidence=f"New error signature: {next(iter(fresh))}",
                                parameter=name,
                                confidence="low",
                                cwe="CWE-89",
                                cvss=0,
                                url=url,
                            )
                        )
                        break
        return output
