"""Cookie attribute review without storing cookie values."""

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class CookieAnalyzer(Plugin):
    """Review response cookie transport and browser restrictions."""

    name, group = "cookies", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Report cookie configuration signals, never secret values."""
        response = await context.base_response()
        if not response:
            return []
        output = []
        for cookie in response.cookies:
            name = cookie["name"]
            if context.scope.base_url.startswith("https://") and cookie["secure"] in {
                "",
                "False",
            }:
                output.append(
                    finding(
                        self,
                        context,
                        f"Cookie {name} lacks Secure",
                        "low",
                        "Cookie may be sent over plaintext HTTP.",
                        "Set Secure on HTTPS cookies.",
                        cwe="CWE-614",
                        cvss=3.1,
                        confidence="high",
                    )
                )
            if cookie["httponly"] in {"", "False"}:
                output.append(
                    finding(
                        self,
                        context,
                        f"Cookie {name} lacks HttpOnly",
                        "low",
                        "Client-side scripts can read this cookie.",
                        "Set HttpOnly for cookies that do not require script access.",
                        cwe="CWE-1004",
                        confidence="high",
                        cvss=2.6,
                    )
                )
            if not cookie["samesite"]:
                output.append(
                    finding(
                        self,
                        context,
                        f"Cookie {name} lacks SameSite",
                        "low",
                        "SameSite is not explicitly set.",
                        "Set SameSite=Lax or Strict when compatible.",
                        cwe="CWE-1275",
                        confidence="high",
                        cvss=2.6,
                    )
                )
            if cookie["samesite"].lower() == "none" and cookie["secure"] in {
                "",
                "False",
            }:
                output.append(
                    finding(
                        self,
                        context,
                        f"Cookie {name} has insecure SameSite=None",
                        "low",
                        "SameSite=None is used without Secure; browsers may reject it.",
                        "Set Secure with SameSite=None or choose Lax/Strict.",
                        confidence="high",
                        cwe="CWE-614",
                    )
                )
            if cookie["domain"].startswith("."):
                output.append(
                    finding(
                        self,
                        context,
                        f"Cookie {name} is scoped to subdomains",
                        "info",
                        "The cookie Domain attribute covers subdomains.",
                        "Use host-only cookies unless subdomain sharing is required.",
                        confidence="high",
                    )
                )
        return output
