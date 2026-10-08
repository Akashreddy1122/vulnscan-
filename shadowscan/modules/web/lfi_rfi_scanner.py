"""Non-sensitive traversal check using only the site's own robots.txt."""

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding
from shadowscan.utils.payloads import load


class TraversalScanner(Plugin):
    """Use a public same-host control file to avoid local secret disclosure."""

    name, group, active = "traversal", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Test file-like query parameters with bounded, non-secret path markers."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if not params:
            return []
        root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        control = await context.http.get(urljoin(root, "robots.txt"))
        baseline = await context.base_response()
        if (
            not control
            or control.status != 200
            or not baseline
            or "user-agent:" not in control.body.lower()
            or control.body in baseline.body
            or not 10 <= len(control.body) <= 4096
        ):
            return []
        output = []
        for i, (key, _) in enumerate(params[:10]):
            if key.lower() not in {
                "file",
                "path",
                "page",
                "template",
                "include",
                "document",
            }:
                continue
            changed = list(params)
            changed[i] = (key, load("lfi")[0])
            url = urlunsplit(parts._replace(query=urlencode(changed)))
            reply = await context.http.get(url)
            if (
                reply
                and reply.status == 200
                and control.body.strip() == reply.body.strip()
            ):
                output.append(
                    finding(
                        self,
                        context,
                        "Possible same-host path traversal",
                        "medium",
                        "A traversal marker retrieved the public robots.txt control body."
                        " This does not demonstrate access to sensitive files.",
                        "Canonicalize paths, restrict reads to an allowlisted directory, and verify manually.",
                        evidence="Public robots.txt body matched traversal response (content omitted)",
                        parameter=key,
                        confidence="medium",
                        cwe="CWE-22",
                        url=url,
                    )
                )
        return output
