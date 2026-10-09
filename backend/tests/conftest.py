"""Test configuration: isolated data directory, no background workers."""
import os
import sys
import tempfile
from pathlib import Path

_DATA = tempfile.mkdtemp(prefix="ms-test-")
os.environ.setdefault("MALWARESCAN_DATA", _DATA)
os.environ.setdefault("MALWARESCAN_LOCAL_MONITORING", "false")
os.environ.setdefault("MALWARESCAN_ADMIN_PASSWORD", "TestAdmin!12345")
os.environ.setdefault("MALWARESCAN_PBKDF2_ITERATIONS", "20000")  # fast tests only

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
