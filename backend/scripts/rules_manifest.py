#!/usr/bin/env python3
"""Generate engine/rules/manifest.json (SHA256 per rule file + version)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from malwarescan.engine.rules_loader import compute_manifest  # noqa: E402

if __name__ == "__main__":
    m = compute_manifest()
    print(f"manifest version {m['version']} — {len(m['files'])} files hashed")
