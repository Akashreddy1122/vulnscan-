"""Built-in and explicit third-party plugin selection."""

import pytest

from shadowscan.core.errors import ConfigurationError
from shadowscan.core.plugin_loader import select_plugins
from shadowscan.modules.base import Plugin


def test_plugin_registry_filters_passive_and_unknown():
    """Passive mode excludes active plugins; unknown names fail clearly."""
    assert (
        select_plugins("web", ["headers", "xss"], mode="passive")[0].name == "headers"
    )
    assert len(select_plugins("web", ["headers", "xss"], mode="passive")) == 1
    with pytest.raises(ConfigurationError):
        select_plugins("quick", ["not-a-plugin"])


def test_external_plugin_is_explicit(monkeypatch):
    """Third-party entry points are never loaded unless opted in."""
    from shadowscan.core import external_plugins

    class Sample(Plugin):
        name, group = "sample", "web"

    class Entry:
        name = "sample"

        def load(self):
            return Sample

    monkeypatch.setattr(external_plugins, "entry_points", lambda **kwargs: [Entry()])
    with pytest.raises(ConfigurationError):
        select_plugins("quick", ["sample"])
    assert select_plugins("quick", ["sample"], external=True)[0].name == "sample"
