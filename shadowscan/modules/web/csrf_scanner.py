"""Static form checks; no forms are submitted."""

from html.parser import HTMLParser
from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class _Forms(HTMLParser):
    """Collect form methods and hidden input names."""

    def __init__(self) -> None:
        """Prepare form list."""
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Track forms and their child hidden fields."""
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append(
                {"method": (attrs.get("method") or "get").lower(), "fields": set()}
            )
        elif (
            tag == "input" and self.forms and attrs.get("type", "").lower() == "hidden"
        ):
            self.forms[-1]["fields"].add((attrs.get("name") or "").lower())


class CSRFScanner(Plugin):
    """Identify POST forms without obvious anti-CSRF tokens as leads."""

    name, group = "csrf", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Parse only the already fetched baseline HTML."""
        response = await context.base_response()
        if (
            not response
            or "html" not in response.headers.get("Content-Type", "").lower()
        ):
            return []
        parser = _Forms()
        parser.feed(response.body)
        for form in parser.forms:
            if form["method"] == "post" and not any(
                any(word in key for word in ("csrf", "token", "nonce", "authenticity"))
                for key in form["fields"]
            ):
                return [
                    finding(
                        self,
                        context,
                        "POST form lacks visible CSRF token",
                        "info",
                        "A POST form has no recognizable hidden token. Other defenses may apply.",
                        "Review CSRF defenses and SameSite/Origin enforcement for state-changing forms.",
                        evidence="POST form found without recognizable hidden token",
                        confidence="low",
                        cwe="CWE-352",
                    )
                ]
        return []
