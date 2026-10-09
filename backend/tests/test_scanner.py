from malwarescan.engine import scanner

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_is_detected():
    r = scanner.scan_bytes(EICAR, "eicar.com")
    assert r.verdict == "malicious"
    assert r.severity == "info"  # test file: definitive but harmless
    assert any(d.get("rule") == "EICAR_Test_File" for d in r.detections)


def test_benign_text_is_clean():
    r = scanner.scan_bytes(b"Quarterly notes. Nothing unusual here.\n" * 40, "notes.txt")
    assert r.verdict == "clean"
    assert r.score < 20


def test_webshell_shape_is_malicious_with_mitre():
    data = b"<?php system($_GET['c']); eval(base64_decode($_POST['x'])); passthru($_REQUEST['y']); ?>"
    r = scanner.scan_bytes(data, "upload.php")
    assert r.verdict in ("malicious", "suspicious")
    assert r.score >= 40
    assert any(t["id"] == "T1505.003" for t in r.mitre)


def test_explanation_and_factors_present():
    r = scanner.scan_bytes(b"powershell -EncodedCommand SQBFAFgA", "x.ps1")
    assert r.explanation
    assert all({"key", "weight", "description"} <= set(f) for f in r.factors)


def test_scores_are_bounded():
    r = scanner.scan_bytes(EICAR * 3, "eicar.com")
    assert 0 <= r.score <= 100
