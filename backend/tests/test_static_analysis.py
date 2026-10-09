import os

from malwarescan.api.scans import sanitize_filename
from malwarescan.engine import static_analysis as sa


def test_identify_shebang_and_elf():
    mime, detail, *_ = sa.identify_type(b"#!/bin/sh\necho hi\n")
    assert mime == "text/x-script" and "sh" in detail
    mime2, *_ = sa.identify_type(b"\x7fELF" + b"\x00" * 60)
    assert "ELF" in mime2


def test_random_bytes_have_high_entropy():
    assert sa.shannon_entropy(os.urandom(65536)) > 7.5
    assert sa.shannon_entropy(b"aaaa") == 0.0


def test_suspicious_patterns_detected():
    rep = sa.analyze(b"vssadmin delete shadows /all /quiet", "x.txt")
    assert rep.suspicious_weight >= 12


def test_filename_sanitization_strips_paths_and_unsafe_chars():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert "/" not in sanitize_filename("a/b\\c.exe")
    assert sanitize_filename("") == "upload.bin"
    assert len(sanitize_filename("x" * 500)) <= 180


def test_malformed_pe_is_flagged_not_crashing():
    rep = sa.analyze(b"MZ" + os.urandom(2000), "bad.exe")
    assert rep.is_pe
    assert any(f["key"] == "pe.malformed" for f in rep.factors)
