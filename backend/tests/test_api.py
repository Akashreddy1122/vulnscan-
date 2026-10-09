import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from malwarescan.main import create_app
    app = create_app()
    with TestClient(app) as c:
        yield c


def _login(client, user="admin", pw="TestAdmin!12345"):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_health_and_docs(client):
    assert client.get("/api/health").json()["database"] == "ok"
    assert client.get("/api/openapi.json").status_code == 200


def test_protected_routes_require_token(client):
    assert client.get("/api/dashboard/overview").status_code == 401


def test_admin_bootstrap_and_me(client):
    h = _login(client)
    me = client.get("/api/auth/me", headers=h).json()
    assert me["user"]["role"] == "admin" and me["permissions"] == ["*"]


def test_viewer_cannot_upload_or_administer(client):
    h = _login(client)
    client.post("/api/auth/register", json={"username": "pytest_viewer", "email": "pv@example.com",
                                            "password": "ViewerPass!1"})
    vh = _login(client, "pytest_viewer", "ViewerPass!1")
    assert client.post("/api/scans/upload", headers=vh, files={"file": ("a.txt", b"x")}).status_code == 403
    assert client.get("/api/admin/users", headers=vh).status_code == 403
    assert client.get("/api/alerts", headers=vh).status_code == 200


def test_upload_scan_and_result(client):
    h = _login(client)
    r = client.post("/api/scans/upload", headers=h, files={"file": ("../evil name.txt", b"hello world" * 10)})
    assert r.status_code == 200
    assert r.json()["filename"] == "evil name.txt"  # traversal stripped


def test_empty_upload_rejected(client):
    h = _login(client)
    assert client.post("/api/scans/upload", headers=h, files={"file": ("e.bin", b"")}).status_code == 400


def test_unknown_playbook_and_dangerous_without_confirm(client):
    h = _login(client)
    r = client.post("/api/response/execute", headers=h,
                    json={"playbook": "kill_process", "target": "1", "dry_run": False, "confirm": False})
    assert r.json()["ok"] is False and r.json().get("requires_confirmation")


def test_auth_brute_force_is_rate_limited(client, monkeypatch):
    from malwarescan.config import settings
    from malwarescan.security import rate_limiter
    rate_limiter._hits.clear()
    monkeypatch.setattr(settings, "rate_limit_auth", 3)
    codes = [client.post("/api/auth/login", json={"username": "nobody", "password": "whatever123"}).status_code
             for _ in range(5)]
    assert 429 in codes
    rate_limiter._hits.clear()


def test_session_checks_are_not_counted_as_login_attempts(client, monkeypatch):
    from malwarescan.config import settings
    from malwarescan.security import rate_limiter
    rate_limiter._hits.clear()
    monkeypatch.setattr(settings, "rate_limit_auth", 2)
    h = _login(client)
    codes = [client.get("/api/auth/me", headers=h).status_code for _ in range(6)]
    assert 429 not in codes
    rate_limiter._hits.clear()


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
