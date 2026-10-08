"""Typed scan records shared by plugins, storage and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now() -> str:
    """Return an ISO UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """One observation; confidence distinguishes signals from verified issues."""

    title: str
    severity: str
    url: str
    description: str
    remediation: str
    module: str
    evidence: str = ""
    parameter: str = ""
    confidence: str = "low"
    cwe: str = ""
    cvss: float = 0.0
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate output before it reaches storage or reports."""
        if self.severity not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError("Invalid severity")
        if self.confidence not in {"low", "medium", "high"}:
            raise ValueError("Invalid confidence")
        if not 0 <= self.cvss <= 10:
            raise ValueError("Invalid CVSS score")
        self.evidence = self.evidence[:2000]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding."""
        return asdict(self)


@dataclass
class ScanResult:
    """A scan with per-target progress and recorded errors."""

    scan_id: str
    started: str
    mode: str
    profile: str
    targets: list[str]
    findings: list[Finding] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    finished: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for export or persistence."""
        return asdict(self)
