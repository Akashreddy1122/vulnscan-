"""Passive analysis of security response headers on fetched pages."""

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class HeaderAnalyzer(Plugin):
    """Identify missing browser defenses without claiming exploitability."""

    name, group = "headers", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Inspect security headers on one baseline response."""
        response = await context.base_response()
        if not response:
            return []
        headers = {key.lower(): value for key, value in response.headers.items()}
        expected = {
            "content-security-policy": (
                "Content-Security-Policy",
                "Define a restrictive CSP.",
                "CWE-693",
            ),
            "x-content-type-options": (
                "X-Content-Type-Options",
                "Set X-Content-Type-Options: nosniff.",
                "CWE-693",
            ),
            "referrer-policy": (
                "Referrer-Policy",
                "Set a restrictive Referrer-Policy.",
                "CWE-200",
            ),
            "permissions-policy": (
                "Permissions-Policy",
                "Limit browser capabilities with Permissions-Policy.",
                "CWE-693",
            ),
        }
        if context.scope.base_url.startswith("https://"):
            expected["strict-transport-security"] = (
                "Strict-Transport-Security",
                "Set HSTS with a suitable max-age after reviewing HTTPS deployment.",
                "CWE-319",
            )
        output = []
        for key, (display, remedy, cwe) in expected.items():
            if key not in headers:
                output.append(
                    finding(
                        self,
                        context,
                        f"Missing {display}",
                        "low",
                        f"The response does not provide {display}.",
                        remedy,
                        evidence=f"HTTP {response.status}; header absent",
                        cwe=cwe,
                        confidence="high",
                        cvss=2.6,
                    )
                )
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get(
            "content-security-policy", ""
        ):
            output.append(
                finding(
                    self,
                    context,
                    "No framing restriction",
                    "low",
                    "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                    "Set CSP frame-ancestors or X-Frame-Options.",
                    cwe="CWE-1021",
                    confidence="high",
                    cvss=2.6,
                )
            )
        if headers.get("x-content-type-options", "").lower() not in {"", "nosniff"}:
            output.append(
                finding(
                    self,
                    context,
                    "Ineffective nosniff header",
                    "low",
                    "X-Content-Type-Options has an unexpected value.",
                    "Use the value nosniff.",
                    cwe="CWE-693",
                    evidence=headers["x-content-type-options"],
                )
            )
        csp = headers.get("content-security-policy", "").lower()
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            output.append(
                finding(
                    self,
                    context,
                    "CSP permits unsafe script behavior",
                    "low",
                    "The script policy includes unsafe-inline or unsafe-eval.",
                    "Use nonces or hashes and remove unsafe script directives where feasible.",
                    evidence="CSP includes unsafe-inline/unsafe-eval (policy omitted)",
                    cwe="CWE-693",
                    confidence="medium",
                )
            )
        hsts = headers.get("strict-transport-security", "")
        if hsts and context.scope.base_url.startswith("https://"):
            import re

            duration = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
            if not duration or int(duration[1]) < 86400:
                output.append(
                    finding(
                        self,
                        context,
                        "Weak HSTS duration",
                        "low",
                        "HSTS max-age is absent or less than one day.",
                        "Set a suitable max-age after reviewing HTTPS deployment.",
                        evidence="HSTS max-age absent or under 86400",
                        confidence="high",
                    )
                )
        if (
            response.cookies
            and "no-store" not in headers.get("cache-control", "").lower()
        ):
            output.append(
                finding(
                    self,
                    context,
                    "Cookie response lacks no-store",
                    "info",
                    "A cookie-bearing response does not explicitly prohibit caching.",
                    "Apply Cache-Control: no-store on sensitive authenticated responses.",
                    evidence="Set-Cookie present; Cache-Control no-store absent",
                    confidence="low",
                    cwe="CWE-524",
                )
            )
        for key in ("server", "x-powered-by"):
            if key in headers:
                output.append(
                    finding(
                        self,
                        context,
                        f"Technology disclosed in {key}",
                        "info",
                        "Response header reveals server technology information.",
                        "Remove detailed version information if not required.",
                        evidence=f"Header present: {key} (value omitted)",
                        confidence="high",
                        cwe="CWE-200",
                    )
                )
        return output
