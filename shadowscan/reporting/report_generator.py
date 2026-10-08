"""Self-contained, escaped report exporters with private file creation."""

from __future__ import annotations

import csv
import html
import io
import json
import os
import stat
from collections import Counter
from pathlib import Path
from typing import BinaryIO
from xml.etree.ElementTree import Element, ElementTree, SubElement

from shadowscan.core.errors import ConfigurationError
from shadowscan.core.models import ScanResult


def _csv_cell(value: object) -> str:
    """Prevent spreadsheet formula evaluation, including whitespace-prefixed cells."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(
        ("\t", "\r", "\n")
    ):
        return "'" + text
    return text


def _xml_text(value: object) -> str:
    """Remove code points forbidden by XML 1.0 before serialization."""
    text = ", ".join(value) if isinstance(value, list) else str(value)
    return "".join(
        c
        for c in text
        if ord(c) in (9, 10, 13)
        or 32 <= ord(c) <= 0xD7FF
        or 0xE000 <= ord(c) <= 0xFFFD
        or 0x10000 <= ord(c) <= 0x10FFFF
    )


def export(result: ScanResult, path: str, format_name: str) -> None:
    """Write a report through a private, non-symlink file descriptor."""
    if format_name not in {"json", "html", "csv", "xml", "pdf"}:
        raise ConfigurationError("Unsupported report format")
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise ConfigurationError("Refusing to overwrite a symlinked report")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(dest, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ConfigurationError("Report must be a regular, non-hardlinked file")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            if format_name == "json":
                stream.write(json.dumps(result.to_dict(), indent=2).encode("utf-8"))
            elif format_name == "html":
                stream.write(_html(result).encode("utf-8"))
            elif format_name == "csv":
                text = io.TextIOWrapper(
                    stream, encoding="utf-8", newline="", write_through=True
                )
                try:
                    fields = (
                        "severity",
                        "title",
                        "module",
                        "url",
                        "parameter",
                        "confidence",
                        "cvss",
                        "cwe",
                        "description",
                        "remediation",
                        "evidence",
                    )
                    writer = csv.DictWriter(
                        text, fieldnames=fields, extrasaction="ignore"
                    )
                    writer.writeheader()
                    for item in result.findings:
                        writer.writerow(
                            {
                                key: _csv_cell(value)
                                for key, value in item.to_dict().items()
                            }
                        )
                    text.flush()
                finally:
                    text.detach()
            elif format_name == "xml":
                root = Element(
                    "scan",
                    {
                        "id": _xml_text(result.scan_id),
                        "started": _xml_text(result.started),
                        "finished": _xml_text(result.finished),
                        "mode": _xml_text(result.mode),
                    },
                )
                for item in result.findings:
                    node = SubElement(root, "finding")
                    for key, value in item.to_dict().items():
                        SubElement(node, key).text = _xml_text(value)
                ElementTree(root).write(stream, encoding="utf-8", xml_declaration=True)
            else:
                _pdf(result, stream)
    finally:
        if fd != -1:
            os.close(fd)


def _html(result: ScanResult) -> str:
    """Generate a local-only HTML report with safely escaped content."""

    def esc(value: object) -> str:
        """Escape report fields before interpolating into HTML."""
        return html.escape(str(value), quote=True)

    counts = Counter(item.severity for item in result.findings)
    maximum = max(counts.values(), default=1)
    bars = "".join(
        f'<div class="bar {esc(level)}" style="width:{max(10, 95 * counts[level] // maximum)}%">'
        f"{esc(level.title())}: {counts[level]}</div>"
        for level in ("critical", "high", "medium", "low", "info")
    )
    scored = [
        item.cvss for item in result.findings if item.confidence == "high" and item.cvss
    ]
    highest = max(scored, default=0)
    rows = "".join(
        f'<tr data-level="{esc(item.severity)}"><td><span class="badge {esc(item.severity)}">'
        f"{esc(item.severity.title())}</span></td><td>{esc(item.title)}</td><td>{esc(item.module)}</td>"
        f"<td>{esc(item.url)}</td><td>{esc(item.parameter)}</td><td>{esc(item.confidence)}</td>"
        f"<td>{esc(item.cvss)}</td><td>{esc(item.cwe)}</td>"
        f"<td><details><summary>Details</summary><p>{esc(item.description)}</p>"
        f"<p><b>Evidence:</b> {esc(item.evidence)}</p>"
        f"<p><b>Remediation:</b> {esc(item.remediation)}</p></details></td></tr>"
        for item in result.findings
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>ShadowScan {esc(result.scan_id)}</title><style>
body{{font:15px system-ui,sans-serif;background:#101827;color:#e7effc;margin:2em auto;max-width:1300px}}
h1{{color:#7dd3fc}} section{{background:#1c293b;padding:1.2em;margin:1em 0;border-radius:10px}}
table{{width:100%;border-collapse:collapse;word-break:break-word}}th,td{{padding:.7em;border-bottom:1px solid #43536a;text-align:left}}
.badge,.bar{{display:inline-block;padding:.3em .6em;border-radius:5px}}.bar{{display:block;margin:.4em 0;box-sizing:border-box}}th.sortable{{cursor:pointer}}
.critical{{background:#8b1834}}.high{{background:#a43833}}.medium{{background:#99560d}}.low{{background:#285687}}.info{{background:#3e526c}}
select{{padding:.5em;background:#24344b;color:white}}details p{{max-width:40em}}small{{color:#b6c6df}}
</style></head><body><h1>ShadowScan assessment</h1>
<section><h2>Executive summary</h2><p>{len(result.findings)} observations across {len(result.targets)} target(s). Highest scored high-confidence observation: {highest}/10 (not an overall risk score).</p>
<p>Scan {esc(result.scan_id)} · {esc(result.mode)} / {esc(result.profile)} · {esc(result.started)} to {esc(result.finished)}</p>
{bars}<small>Observations may be leads, not confirmed vulnerabilities. Review confidence and evidence.</small></section>
<section><h2>Findings</h2><label>Severity <select id="filter"><option value="all">All</option>
{"".join(f'<option value="{level}">{level.title()}</option>' for level in ("critical", "high", "medium", "low", "info"))}
</select></label><table><thead><tr><th class="sortable">Severity</th><th class="sortable">Title</th><th class="sortable">Module</th><th class="sortable">Endpoint</th><th class="sortable">Parameter</th><th class="sortable">Confidence</th><th class="sortable">CVSS</th><th class="sortable">CWE</th><th>Evidence and guidance</th></tr></thead>
<tbody>{rows}</tbody></table></section>
<section><h2>Scope and errors</h2><p>{", ".join(esc(t) for t in result.targets)}</p>
{"".join(f"<p>{esc(err)}</p>" for err in result.errors)}</section>
<script>document.getElementById('filter').addEventListener('change',e=>{{document.querySelectorAll('tbody tr').forEach(row=>{{row.hidden=e.target.value!=='all'&&row.dataset.level!==e.target.value}})}});
document.querySelectorAll('th.sortable').forEach((th,index)=>{{let asc=true;th.addEventListener('click',()=>{{const body=document.querySelector('tbody');const rows=[...body.rows];rows.sort((a,b)=>{{const x=a.cells[index].textContent.trim(),y=b.cells[index].textContent.trim();return (index===6?Number(x)-Number(y):x.localeCompare(y))*(asc?1:-1)}});rows.forEach(row=>body.appendChild(row));asc=!asc}})}});</script>
</body></html>"""


def _pdf(result: ScanResult, stream: BinaryIO) -> None:
    """Create an optional compact text-first PDF via ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen.canvas import Canvas
    except ImportError as exc:
        raise ConfigurationError("PDF support requires pip install '.[pdf]'") from exc
    canvas = Canvas(stream, pagesize=A4)
    width, height = A4
    page = 1
    y = height - 55

    def line(text: str) -> None:
        """Wrap plain text and paginate within the page."""
        nonlocal page, y
        while text:
            chunk, text = text[:95], text[95:]
            if y < 55:
                canvas.drawString(40, 30, f"Page {page}")
                canvas.showPage()
                page += 1
                y = height - 55
            canvas.drawString(
                40, y, chunk.encode("latin-1", errors="replace").decode("latin-1")
            )
            y -= 15

    line("ShadowScan assessment")
    line(f"Scan ID: {result.scan_id} | Mode: {result.mode} | Profile: {result.profile}")
    line(f"Started: {result.started} | Finished: {result.finished}")
    line(f"Findings: {len(result.findings)} | Targets: {len(result.targets)}")
    for item in result.findings:
        y -= 8
        for text in (
            f"[{item.severity.upper()}] {item.title} ({item.module})",
            item.url,
            f"Confidence: {item.confidence} | CWE: {item.cwe} | CVSS: {item.cvss}",
            item.description,
            f"Evidence: {item.evidence}",
            f"Remediation: {item.remediation}",
        ):
            line(text)
    canvas.drawString(40, 30, f"Page {page}")
    canvas.save()
