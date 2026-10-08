"""Compare two persisted scans by stable finding identity."""

from __future__ import annotations

from typing import Any

from shadowscan.core.models import Finding, ScanResult


def compare(old: ScanResult, new: ScanResult) -> dict[str, Any]:
    """Identify new and resolved observations, avoiding unstable evidence text."""

    def key(item: Finding) -> tuple[str, str, str, str]:
        """Use endpoint/parameter plus plugin and title as the stable identifier."""
        return item.module, item.title, item.url, item.parameter

    before = {key(item): item for item in old.findings}
    after = {key(item): item for item in new.findings}
    return {
        "previous": old.scan_id,
        "current": new.scan_id,
        "new": [after[k].to_dict() for k in sorted(after.keys() - before.keys())],
        "resolved": [before[k].to_dict() for k in sorted(before.keys() - after.keys())],
        "unchanged_count": len(before.keys() & after.keys()),
    }
