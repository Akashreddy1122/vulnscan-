"""Offline, non-validating JWT metadata inspection; never persists tokens."""

import base64
import binascii
import json
import time

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


def _segment(value: str) -> dict:
    """Decode one bounded JWT segment; reject non-object JSON."""
    if len(value) > 8192:
        raise ValueError("JWT segment is too large")
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("JWT segment is not a JSON object")
    return obj


class JWTAnalyzer(Plugin):
    """Analyze explicit locally supplied JWT without verifying signature or guessing keys."""

    name, group = "jwt", "web"

    async def scan(self, context: Context) -> list[Finding]:
        """Report only header algorithm and expiration status, never claim acceptance."""
        token = context.jwt_token
        if not token:
            return []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("JWT must have three segments")
            header, payload = _segment(parts[0]), _segment(parts[1])
        except (ValueError, UnicodeError, binascii.Error):
            return [
                finding(
                    self,
                    context,
                    "Malformed supplied JWT",
                    "info",
                    "The supplied token is not a parseable compact JWT.",
                    "Confirm token format; do not share JWTs in reports.",
                    confidence="high",
                )
            ]
        output = []
        alg = header.get("alg", "")
        if alg == "none":
            output.append(
                finding(
                    self,
                    context,
                    "Supplied JWT uses none algorithm",
                    "info",
                    "The locally supplied token declares no signature algorithm; server acceptance is not tested.",
                    "Ensure the server only accepts an explicit set of signed algorithms.",
                    evidence="JWT header alg=none (token omitted)",
                    confidence="high",
                    cwe="CWE-347",
                )
            )
        exp = payload.get("exp")
        if (
            isinstance(exp, (int, float))
            and not isinstance(exp, bool)
            and exp < time.time()
        ):
            output.append(
                finding(
                    self,
                    context,
                    "Supplied JWT is expired",
                    "info",
                    "The local token exp timestamp is in the past; server handling is not tested.",
                    "Reject expired tokens at every authenticated endpoint.",
                    evidence="exp claim precedes current time (value omitted)",
                    confidence="high",
                )
            )
        elif exp is None:
            output.append(
                finding(
                    self,
                    context,
                    "Supplied JWT lacks exp claim",
                    "info",
                    "No expiration claim is present in the locally decoded token.",
                    "Issue short-lived tokens and validate expiry on the server.",
                    evidence="exp claim absent",
                    confidence="high",
                )
            )
        return output
