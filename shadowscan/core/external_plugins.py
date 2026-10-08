"""Opt-in loader for trusted setuptools entry-point plugins."""

from importlib.metadata import entry_points

from shadowscan.core.errors import ConfigurationError
from shadowscan.modules.base import Plugin


def discover(builtin_names: set[str]) -> dict[str, type[Plugin]]:
    """Load installed plugins only when the caller explicitly opts in.

    Entry points execute arbitrary Python at load time: install only trusted packages.
    Third-party plugins are NOT sandboxed and may bypass core scope protections.
    """
    found: dict[str, type[Plugin]] = {}
    for entry in entry_points(group="shadowscan.plugins"):
        try:
            plugin = entry.load()
        except Exception as exc:
            raise ConfigurationError(
                f"Cannot load third-party plugin {entry.name}"
            ) from exc
        if (
            not isinstance(plugin, type)
            or not issubclass(plugin, Plugin)
            or plugin is Plugin
            or not plugin.name
            or not plugin.group
            or entry.name != plugin.name
            or plugin.name in builtin_names
            or plugin.name in found
        ):
            raise ConfigurationError(
                f"Invalid or conflicting third-party plugin: {entry.name}"
            )
        found[plugin.name] = plugin
    return found
