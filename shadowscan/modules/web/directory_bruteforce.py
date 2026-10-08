"""Short read-only sensitive-file check with soft-404 comparison."""

from importlib.resources import files
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class DirectoryScanner(Plugin):
    """Look for exposed .env and Git HEAD using a bounded bundled list."""

    name, group, active = "directories", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Compare against a random missing path and never retain file contents."""
        if not context.http:
            return []
        parts = urlsplit(context.scope.base_url)
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        missing = await context.http.get(
            urljoin(origin, "shadowscan-missing-" + uuid4().hex)
        )
        words = (
            files("shadowscan")
            .joinpath("config/payloads/fuzzing_wordlist.txt")
            .read_text()
            .splitlines()
        )
        output = []
        for word in words:
            if not word or word.startswith("#"):
                continue
            url = urljoin(origin, word)
            response = await context.http.get(url)
            if not response or response.status != 200:
                continue
            if missing and missing.status == 200 and response.body == missing.body:
                continue
            if word == ".git/HEAD" and response.body.strip().startswith(
                "ref: refs/heads/"
            ):
                output.append(
                    finding(
                        self,
                        context,
                        "Git metadata exposed",
                        "medium",
                        "Git HEAD is publicly retrievable.",
                        "Block access to version control directories at the web server.",
                        evidence="GET /.git/HEAD returned a Git ref (content omitted)",
                        confidence="high",
                        cwe="CWE-552",
                        cvss=5.3,
                        url=url,
                    )
                )
            elif word == ".env" and any(
                line.startswith(
                    ("APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=")
                )
                for line in response.body.splitlines()
            ):
                output.append(
                    finding(
                        self,
                        context,
                        "Environment configuration exposed",
                        "high",
                        "A web-accessible environment file contains sensitive configuration keys.",
                        "Block access, remove the file from the web root and rotate exposed secrets.",
                        evidence="GET /.env returned recognized secret-key names (values omitted)",
                        confidence="high",
                        cwe="CWE-538",
                        cvss=7.5,
                        url=url,
                    )
                )
        return output
