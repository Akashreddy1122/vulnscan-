"""Explicit scanner error categories."""


class ShadowScanError(Exception):
    """Base error for recoverable scanner failures."""


class ConfigurationError(ShadowScanError):
    """Invalid configuration or arguments."""


class ScopeError(ShadowScanError):
    """Target or request outside authorized scope."""


class ScanError(ShadowScanError):
    """Scanning could not complete."""
