"""Bounded same-host link inventory respecting robots and sitemap references."""

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urldefrag, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

from shadowscan.core.errors import ScopeError
from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class _Links(HTMLParser):
    """Parse anchor href attributes from HTML."""

    def __init__(self) -> None:
        """Initialize link collection."""
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect explicit links, ignoring scripts and forms."""
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


class Crawler(Plugin):
    """Inventory limited HTML pages, obeying robots.txt and exact-host scope."""

    name, group, active = "crawler", "web", True

    async def scan(self, context: Context) -> list[Finding]:
        """Breadth-first traverse bounded by max_pages and max_depth."""
        if not context.http:
            return []
        root = context.scope.base_url
        parts = urlsplit(root)
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        robots = RobotFileParser()
        policy = await context.http.get(urljoin(origin, "robots.txt"))
        if policy and policy.status == 200:
            robots.parse(policy.body.splitlines()[:5000])
        else:
            robots.parse([])
        queue = deque([(root, 0)])
        seen: set[str] = set()
        sitemap = await context.http.get(urljoin(origin, "sitemap.xml"))
        if (
            sitemap
            and sitemap.status == 200
            and "xml" in sitemap.headers.get("Content-Type", "").lower()
        ):
            try:
                document = fromstring(sitemap.body)
                for element in document.iter():
                    if (
                        element.tag.rsplit("}", 1)[-1].lower() != "loc"
                        or not element.text
                    ):
                        continue
                    candidate = urldefrag(element.text.strip())[0]
                    try:
                        context.scope.check(candidate)
                    except ScopeError:
                        continue
                    if len(queue) < context.config["max_pages"] and robots.can_fetch(
                        context.config["user_agent"], candidate
                    ):
                        queue.append((candidate, 1))
            except (ValueError, ParseError, DefusedXmlException):
                pass
        while queue and len(seen) < context.config["max_pages"]:
            url, depth = queue.popleft()
            if url in seen or not robots.can_fetch(context.config["user_agent"], url):
                continue
            seen.add(url)
            response = await context.http.get(url)
            if (
                not response
                or "html" not in response.headers.get("Content-Type", "").lower()
            ):
                continue
            parser = _Links()
            parser.feed(response.body)
            if depth >= context.config["max_depth"]:
                continue
            for link in parser.links:
                candidate = urldefrag(urljoin(url, link))[0]
                if urlsplit(candidate).scheme not in {"http", "https"}:
                    continue
                try:
                    context.scope.check(candidate)
                except ScopeError:
                    continue
                if (
                    candidate not in seen
                    and robots.can_fetch(context.config["user_agent"], candidate)
                    and len(queue) + len(seen) < context.config["max_pages"]
                ):
                    queue.append((candidate, depth + 1))
        return [
            finding(
                self,
                context,
                "Crawl inventory",
                "info",
                f"Visited {len(seen)} same-host URLs up to depth {context.config['max_depth']}.",
                "Review discovered pages and parameters in an authorized manual assessment.",
                evidence=f"Pages visited: {len(seen)}",
                confidence="high",
            )
        ]
