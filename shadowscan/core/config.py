"""Configuration loader with explicit validation and no code evaluation."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationError


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load defaults, then overlay a YAML/JSON mapping if supplied."""
    defaults = yaml.safe_load(
        files("shadowscan").joinpath("config/default_config.yaml").read_text()
    )
    if path:
        try:
            source = Path(path)
            if source.stat().st_size > 1024 * 1024:
                raise ConfigurationError("Config file exceeds 1 MiB")
            text = source.read_text(encoding="utf-8")
            extra = (
                json.loads(text)
                if path.lower().endswith(".json")
                else yaml.safe_load(text)
            )
        except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
            raise ConfigurationError(f"Cannot read config: {exc}") from exc
        if not isinstance(extra, dict):
            raise ConfigurationError("Config must be a mapping")
        if not all(isinstance(key, str) for key in extra):
            raise ConfigurationError("Config keys must be strings")
        unknown = set(extra) - set(defaults)
        if unknown:
            raise ConfigurationError(
                f"Unknown config keys: {', '.join(sorted(unknown))}"
            )
        defaults.update(extra)
    for key, low, high in (
        ("concurrency", 1, 200),
        ("threads", 1, 200),
        ("max_targets", 1, 4096),
        ("max_pages", 1, 500),
        ("max_depth", 0, 20),
        ("max_response_bytes", 1024, 4194304),
        ("retries", 0, 5),
    ):
        value = defaults[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise ConfigurationError(f"{key} must be between {low} and {high}")
    for key, low, high in (
        ("timeout", 0.1, 120),
        ("rate", 0.1, 100),
        ("jitter", 0, 60),
    ):
        value = defaults[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not low <= value <= high
        ):
            raise ConfigurationError(f"{key} must be between {low} and {high}")
    if not isinstance(defaults["headers"], dict) or not all(
        isinstance(k, str) and isinstance(v, str)
        for k, v in defaults["headers"].items()
    ):
        raise ConfigurationError("headers must contain string keys and values")
    if (
        not isinstance(defaults["ports"], list)
        or len(defaults["ports"]) > 1024
        or not all(type(p) is int and 1 <= p <= 65535 for p in defaults["ports"])
    ):
        raise ConfigurationError("ports must contain at most 1024 valid port numbers")
    if (
        not isinstance(defaults["udp_ports"], list)
        or len(defaults["udp_ports"]) > 64
        or not all(type(p) is int and 1 <= p <= 65535 for p in defaults["udp_ports"])
    ):
        raise ConfigurationError("udp_ports must contain at most 64 valid port numbers")
    if not isinstance(defaults["modules_disabled"], list) or not all(
        isinstance(name, str) for name in defaults["modules_disabled"]
    ):
        raise ConfigurationError("modules_disabled must be a list of module names")
    if not isinstance(defaults["user_agent"], str) or any(
        char in defaults["user_agent"] for char in "\r\n"
    ):
        raise ConfigurationError("Invalid user_agent")
    forbidden = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-authorization",
        "upgrade",
    }
    token = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    if (
        len(defaults["headers"]) > 50
        or sum(len(key) + len(value) for key, value in defaults["headers"].items())
        > 16384
        or any(
            not token.fullmatch(key)
            or key.lower() in forbidden
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for key, value in defaults["headers"].items()
        )
    ):
        raise ConfigurationError("Invalid or unsafe custom headers")
    agents = defaults["user_agents"]
    if (
        not isinstance(agents, list)
        or len(agents) > 20
        or not all(
            isinstance(ua, str)
            and 0 < len(ua) <= 256
            and "\r" not in ua
            and "\n" not in ua
            for ua in agents
        )
    ):
        raise ConfigurationError(
            "user_agents must contain up to 20 valid user-agent strings"
        )
    if type(defaults["enumerate_subdomains"]) is not bool:
        raise ConfigurationError("enumerate_subdomains must be true or false")
    if type(defaults["allow_insecure_auth"]) is not bool:
        raise ConfigurationError("allow_insecure_auth must be true or false")
    if not isinstance(defaults["mode"], str) or defaults["mode"] not in {
        "passive",
        "active",
        "aggressive",
        "stealth",
    }:
        raise ConfigurationError("Invalid scan mode")
    if not isinstance(defaults["profile"], str) or defaults["profile"] not in {
        "quick",
        "standard",
        "full",
        "web",
        "network",
        "recon",
    }:
        raise ConfigurationError("Invalid scan profile")
    services = defaults["service_ports"]
    if (
        not isinstance(services, dict)
        or set(services) != {"ssh", "ftp", "smtp", "rdp"}
        or not all(
            type(port) is int and 1 <= port <= 65535 for port in services.values()
        )
    ):
        raise ConfigurationError(
            "service_ports must map ssh, ftp, smtp and rdp to valid ports"
        )
    return defaults
