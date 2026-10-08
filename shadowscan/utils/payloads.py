"""Bounded, packaged non-executing probe marker loader."""

from importlib.resources import files


_ALLOWED = {"sqli", "xss", "ssti", "open_redirect", "lfi"}


def load(name: str) -> list[str]:
    """Load a small built-in list; never open arbitrary filesystem paths."""
    if name not in _ALLOWED:
        raise ValueError("Unknown payload group")
    text = (
        files("shadowscan").joinpath(f"config/payloads/{name}_payloads.txt").read_text()
    )
    if len(text) > 4096:
        raise ValueError("Payload list exceeds 4 KiB")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ][:16]
