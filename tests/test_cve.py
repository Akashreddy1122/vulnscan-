"""Offline NVD exact-CPE integration tests."""

import json

import pytest
from aiohttp import web

from shadowscan.database.db_manager import Database
from shadowscan.database.cve_cache import import_nvd, lookup
from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.plugin_loader import select_plugins


@pytest.mark.asyncio
async def test_import_and_exact_version_match(tmp_path):
    """Only explicit exact version matches produce unverified findings."""
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-9999",
                    "descriptions": [{"lang": "en", "value": "Example issue"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"vulnerable": True, "criteria": cpe},
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "2.0",
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    file = tmp_path / "nvd.json"
    file.write_text(json.dumps(data))
    db = Database(str(tmp_path / "scan.sqlite"))
    assert import_nvd(db.conn, str(file)) == 1
    assert lookup(db.conn, cpe)[0][0] == "CVE-2021-9999"

    async def handler(request):
        return web.Response(text="hello", headers={"Server": "Apache/2.4.49"})

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        result = await Engine(
            load_config(), db, select_plugins("standard", ["cve"])
        ).run([f"http://127.0.0.1:{port}/"])
        assert [f.title for f in result.findings] == [
            "Potential CVE-2021-9999 version match"
        ]
        assert result.findings[0].confidence == "low"
    finally:
        db.close()
        await runner.cleanup()


def test_nvd_import_skips_bad_records(tmp_path):
    """Malformed records cannot crash import or fabricate matches."""
    file = tmp_path / "invalid-records.json"
    file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    None,
                    {"cve": {"id": "CVE-2024-1234", "metrics": None}},
                    {"cve": {"id": 23}},
                ]
            }
        )
    )
    db = Database(":memory:")
    try:
        assert import_nvd(db.conn, str(file)) == 0
    finally:
        db.close()
