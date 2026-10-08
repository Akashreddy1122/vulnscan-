"""Report escaping and basic format round-trips."""

import csv
import json
from xml.etree import ElementTree

from shadowscan.core.models import Finding, ScanResult
from shadowscan.reporting.report_generator import export


def test_exports_escape_html_and_roundtrip(tmp_path):
    """Findings are correctly escaped in HTML and structured in other formats."""
    result = ScanResult(
        "test-id",
        "start",
        "active",
        "quick",
        ["example.test"],
        [
            Finding(
                "<script>alert(1)</script>",
                "low",
                "http://example.test/",
                "detail",
                "fix",
                "headers",
            )
        ],
        ["example.test"],
        [],
        "end",
    )
    for extension in ("html", "json", "xml", "csv"):
        export(result, str(tmp_path / f"report.{extension}"), extension)
    assert "&lt;script&gt;" in (tmp_path / "report.html").read_text()
    assert "<script>alert(1)</script>" not in (tmp_path / "report.html").read_text()
    assert (
        json.loads((tmp_path / "report.json").read_text())["findings"][0]["severity"]
        == "low"
    )
    assert ElementTree.parse(tmp_path / "report.xml").getroot().tag == "scan"
    with (tmp_path / "report.csv").open() as stream:
        assert next(csv.DictReader(stream))["module"] == "headers"


def test_delta_detects_new_resolved_and_unchanged():
    """Compare stable identity rather than response wording."""
    from shadowscan.reporting.delta import compare

    def item(name):
        return Finding(name, "low", "https://example.test/", "detail", "fix", "headers")

    old = ScanResult("old", "", "active", "quick", [], [item("same"), item("fixed")])
    new = ScanResult("new", "", "active", "quick", [], [item("same"), item("added")])
    diff = compare(old, new)
    assert [f["title"] for f in diff["new"]] == ["added"]
    assert [f["title"] for f in diff["resolved"]] == ["fixed"]
    assert diff["unchanged_count"] == 1
