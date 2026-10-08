"""CORS response analysis using one harmless Origin header."""

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class CORSScanner(Plugin):
    """Flag dangerous origin reflection only with clear response evidence."""

    name, group, active = "cors", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Test arbitrary origin reflection and credential allowance."""
        if not context.http:
            return []
        origin = "https://shadowscan-test.invalid"
        response = await context.http.get(
            context.scope.base_url, headers={"Origin": origin}
        )
        if not response:
            return []
        headers = {k.lower(): v.strip().lower() for k, v in response.headers.items()}
        allowed = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "") == "true"
        if allowed == origin and credentials:
            return [
                finding(
                    self,
                    context,
                    "Arbitrary CORS origin with credentials",
                    "medium",
                    "A synthetic external origin was reflected and credentials were allowed.",
                    "Restrict allowed origins to a fixed, trusted list and review credential use.",
                    evidence="Synthetic Origin reflected; Access-Control-Allow-Credentials: true",
                    confidence="medium",
                    cwe="CWE-942",
                    cvss=5.3,
                )
            ]
        if allowed == origin:
            return [
                finding(
                    self,
                    context,
                    "Arbitrary CORS origin reflected",
                    "low",
                    "A synthetic external origin was reflected. Impact depends on data exposed.",
                    "Review CORS allowlist and sensitive responses.",
                    evidence="Synthetic Origin reflected",
                    confidence="medium",
                    cwe="CWE-942",
                )
            ]
        null_response = await context.http.get(
            context.scope.base_url, headers={"Origin": "null"}
        )
        if null_response:
            null_headers = {
                k.lower(): v.strip().lower() for k, v in null_response.headers.items()
            }
            if (
                null_headers.get("access-control-allow-origin") == "null"
                and null_headers.get("access-control-allow-credentials") == "true"
            ):
                return [
                    finding(
                        self,
                        context,
                        "CORS allows null Origin with credentials",
                        "medium",
                        "A null Origin can read credentialed responses in some browser contexts.",
                        "Reject null origins for sensitive credentialed endpoints.",
                        evidence="Access-Control-Allow-Origin: null and credentials: true",
                        confidence="medium",
                        cwe="CWE-942",
                        cvss=5.3,
                    )
                ]
        return []
