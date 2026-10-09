import time

import pytest

from malwarescan.security import (RateLimiter, create_token, decode_token, hash_password,
                                  role_has_permission, verify_password)


def test_password_hash_roundtrip_and_rejects_wrong():
    h = hash_password("correct horse")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong horse", h)
    assert h.startswith("pbkdf2_sha256$")


def test_short_password_rejected():
    with pytest.raises(ValueError):
        hash_password("short")


def test_token_roundtrip_and_tamper_detection():
    t = create_token(7, "alice", "analyst")
    claims = decode_token(t)
    assert claims["sub"] == "7" and claims["role"] == "analyst"
    with pytest.raises(Exception):
        decode_token(t[:-2] + ("AA" if not t.endswith("AA") else "BB"))


@pytest.mark.parametrize("role,perm,expected", [
    ("admin", "anything:at_all", True),
    ("analyst", "scan:write", True),
    ("analyst", "response:execute", False),
    ("responder", "response:execute", True),
    ("viewer", "scan:write", False),
    ("viewer", "scan:read", True),
    ("nonexistent", "scan:read", False),
])
def test_rbac_matrix(role, perm, expected):
    assert role_has_permission(role, perm) is expected


def test_rate_limiter_window():
    rl = RateLimiter()
    results = [rl.allow("k", 3, window_seconds=60)[0] for _ in range(4)]
    assert results == [True, True, True, False]
    assert rl.allow("other", 3)[0] is True
