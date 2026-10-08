"""Static file upload entry-point discovery without uploading any content."""

from html.parser import HTMLParser

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class _Uploads(HTMLParser):
    """Detect file inputs within multipart forms."""

    def __init__(self) -> None:
        """Initialize form stack."""
        super().__init__()
        self.forms: list[dict[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Note multipart form and child file input types."""
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append(
                {
                    "multipart": "multipart/form-data"
                    in (attrs.get("enctype") or "").lower(),
                    "file": False,
                }
            )
        if (
            tag == "input"
            and self.forms
            and (attrs.get("type") or "").lower() == "file"
        ):
            self.forms[-1]["file"] = True


class FileUploadScanner(Plugin):
    """Report upload surface, not a vulnerability or bypass."""

    name, group = "file_upload", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Inspect one HTML page; do not POST a file."""
        response = await context.base_response()
        if (
            not response
            or "html" not in response.headers.get("Content-Type", "").lower()
        ):
            return []
        parser = _Uploads()
        parser.feed(response.body)
        count = sum(1 for form in parser.forms if form["file"])
        if not count:
            return []
        return [
            finding(
                self,
                context,
                "File upload form observed",
                "info",
                f"Found {count} form(s) containing a file input; no files were uploaded.",
                "Verify file size, type, authorization and storage controls manually.",
                evidence=f"File input forms: {count}",
                confidence="high",
            )
        ]
