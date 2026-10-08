"""Input and scope boundary tests."""

import pytest

from shadowscan.core.errors import ConfigurationError, ScopeError
from shadowscan.core.scope import Scope
from shadowscan.core.target import expand_targets


def test_target_expansion_and_limit():
    """Small ranges work and large CIDRs fail without allocation."""
    assert expand_targets(["192.0.2.1-3"]) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    with pytest.raises(ConfigurationError):
        expand_targets(["10.0.0.0/8"])
    with pytest.raises(ConfigurationError):
        expand_targets(["192.0.2.5-3"])


def test_scope_rejects_external_and_credentials():
    """Explicit URL host and port are immutable."""
    scope = Scope("http://example.test:8090/start")
    scope.check("http://example.test:8090/elsewhere")
    for url in (
        "http://evil.test:8090/",
        "http://example.test:8091/",
        "http://user:password@example.test:8090/",
        "file:///etc/passwd",
    ):
        with pytest.raises(ScopeError):
            scope.check(url)


def test_scope_keeps_default_port_and_ipv6():
    """A same-host different port must not be silently included."""
    scope = Scope("https://example.test/")
    with pytest.raises(ScopeError):
        scope.check("https://example.test:8443/")
    with pytest.raises(ScopeError):
        scope.check("http://example.test:443/")
    assert Scope("::1").base_url == "https://[::1]/"


def test_recursive_target_file_is_bounded(tmp_path):
    """A list that contains itself cannot loop forever."""
    path = tmp_path / "targets.txt"
    path.write_text(str(path))
    with pytest.raises(ConfigurationError, match="recursive target file"):
        expand_targets([str(path)], max_targets=2)
