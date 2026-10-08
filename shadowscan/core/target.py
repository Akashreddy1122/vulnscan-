"""Bounded expansion of explicit target inputs."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .errors import ConfigurationError

_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$")


def normalize_target(value: str) -> str:
    """Accept only HTTP(S) URLs, IPs and syntactically valid hostnames."""
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ConfigurationError("Empty target or whitespace/control character")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port == 0
            ):
                raise ValueError("Unsupported URL")
            _validate_host(parsed.hostname)
            return value.split("#", 1)[0]
        except ValueError as exc:
            raise ConfigurationError(f"Invalid URL: {value}") from exc
    _validate_host(value)
    return value.lower()


def _validate_host(host: str) -> None:
    """Reject malformed numeric hosts and invalid domain labels."""
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if host.replace(".", "").isdigit() or not _DOMAIN.fullmatch(host):
        raise ConfigurationError(f"Invalid hostname: {host}")


def expand_targets(inputs: list[str], max_targets: int = 256) -> list[str]:
    """Expand explicit files, stdin, IPv4 short ranges and CIDR with a hard cap."""
    pending = list(inputs)
    result: list[str] = []
    processed = 0
    while pending:
        processed += 1
        if processed > max_targets * 8:
            raise ConfigurationError("Too many target entries or recursive target file")
        item = pending.pop(0).strip()
        if not item or item.startswith("#"):
            continue
        if len(item) > 4096:
            raise ConfigurationError("Target entry too long")
        if item == "-":
            text = sys.stdin.read(1048577)
            if len(text) > 1048576:
                raise ConfigurationError("Stdin target list exceeds 1 MiB")
            pending = text.splitlines() + pending
            continue
        # URL paths/queries can exceed filesystem component limits; do not
        # interpret URLs as local filenames.
        if "://" not in item:
            try:
                is_file = Path(item).is_file()
            except OSError:
                is_file = False
            if is_file:
                path = Path(item)
                if path.stat().st_size > 1048576:
                    raise ConfigurationError("Target file exceeds 1 MiB")
                pending = path.read_text(encoding="utf-8").splitlines() + pending
                continue
        match = _RANGE.fullmatch(item)
        if match:
            first = ipaddress.IPv4Address(match.group(1))
            last = ipaddress.IPv4Address(
                str(first).rsplit(".", 1)[0] + "." + match.group(2)
            )
            if last < first:
                raise ConfigurationError("Reversed IP range")
            count = int(last) - int(first) + 1
            if count > max_targets or len(result) + count > max_targets:
                raise ConfigurationError("Target limit exceeded")
            result.extend(
                str(ipaddress.IPv4Address(i)) for i in range(int(first), int(last) + 1)
            )
        elif "/" in item and "://" not in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigurationError(f"Invalid CIDR: {item}") from exc
            if (
                net.num_addresses > max_targets
                or len(result) + net.num_addresses > max_targets
            ):
                raise ConfigurationError("Target limit exceeded")
            result.extend(str(ip) for ip in net.hosts())
        else:
            result.append(normalize_target(item))
        if len(result) > max_targets or len(pending) > max_targets * 4:
            raise ConfigurationError("Target limit exceeded")
    if not result:
        raise ConfigurationError("No targets supplied")
    return list(dict.fromkeys(result))
