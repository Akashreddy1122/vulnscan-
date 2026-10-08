"""TLS certificate and negotiated cipher review, with opt-in legacy probes."""

import asyncio
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class TLSAnalyzer(Plugin):
    """Verify the normal handshake; probe legacy protocol support in aggressive mode."""

    name, group, active = "tls", "network", True

    async def scan(self, context: Context) -> list[Finding]:
        """Run bounded blocking TLS handshakes in the configured executor."""
        parts = urlsplit(context.scope.base_url)
        if parts.scheme != "https":
            return []
        host, port = parts.hostname, parts.port or 443
        loop = asyncio.get_running_loop()
        timeout = context.config["timeout"]
        output: list[Finding] = []

        def handshake() -> tuple[str, dict, str]:
            """Verify chain and hostname using system CA store."""
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ssl.create_default_context().wrap_socket(
                    sock, server_hostname=host
                ) as secure:
                    return (
                        secure.version() or "unknown",
                        secure.getpeercert(),
                        secure.cipher()[0],
                    )

        try:
            if context.http:
                await context.http.limiter.acquire()
            version, cert, cipher = await asyncio.wait_for(
                loop.run_in_executor(context.executor, handshake), timeout=timeout + 1
            )
        except ssl.SSLCertVerificationError as exc:
            output.append(
                finding(
                    self,
                    context,
                    "TLS certificate verification failed",
                    "medium",
                    "The certificate chain or hostname could not be verified.",
                    "Install a valid certificate issued for this hostname by a trusted CA.",
                    evidence=f"Verification code: {exc.verify_code}",
                    confidence="high",
                    cwe="CWE-295",
                    cvss=5.3,
                )
            )
            version, cert, cipher = "", {}, ""
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            version, cert, cipher = "", {}, ""
        if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            output.append(
                finding(
                    self,
                    context,
                    "Legacy TLS negotiated",
                    "medium",
                    f"The verified connection negotiated {version}.",
                    "Disable legacy protocols; prefer TLS 1.2 and 1.3.",
                    evidence=f"Negotiated protocol: {version}",
                    confidence="high",
                    cwe="CWE-326",
                    cvss=5.3,
                )
            )
        if any(weak in cipher.upper() for weak in ("RC4", "3DES", "NULL", "EXPORT")):
            output.append(
                finding(
                    self,
                    context,
                    "Weak TLS cipher negotiated",
                    "medium",
                    "The verified TLS connection negotiated a weak cipher suite.",
                    "Disable weak ciphers and prefer AEAD suites.",
                    evidence=f"Cipher: {cipher}",
                    confidence="high",
                    cwe="CWE-327",
                )
            )
        if version == "TLSv1.2" and not any(
            kex in cipher.upper() for kex in ("ECDHE", "DHE")
        ):
            output.append(
                finding(
                    self,
                    context,
                    "No forward secrecy in negotiated TLS suite",
                    "low",
                    "The negotiated TLS 1.2 suite does not indicate ephemeral key exchange.",
                    "Prefer ECDHE/DHE cipher suites or TLS 1.3.",
                    evidence=f"Cipher: {cipher}",
                    confidence="medium",
                    cwe="CWE-326",
                )
            )
        expiry = cert.get("notAfter")
        if expiry:
            end = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc)
            if (end - datetime.now(timezone.utc)).days < 30:
                output.append(
                    finding(
                        self,
                        context,
                        "TLS certificate expires soon",
                        "low",
                        "Verified certificate expires within 30 days.",
                        "Renew the certificate before it expires.",
                        evidence=f"Expiry: {end.date().isoformat()}",
                        confidence="high",
                        cwe="CWE-295",
                    )
                )
        if context.mode == "aggressive":
            for legacy in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                await context.http.limiter.acquire()

                def probe(version: ssl.TLSVersion = legacy) -> bool:
                    """Test protocol acceptance only; ignore cert trust for this probe."""
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        client.check_hostname = False
                        client.verify_mode = ssl.CERT_NONE
                        client.minimum_version = version
                        client.maximum_version = version
                        try:
                            client.set_ciphers("DEFAULT:@SECLEVEL=0")
                        except ssl.SSLError:
                            pass
                    try:
                        with socket.create_connection(
                            (host, port), timeout=timeout
                        ) as sock:
                            with client.wrap_socket(
                                sock, server_hostname=host
                            ) as secure:
                                return secure.version() is not None
                    except (OSError, ssl.SSLError):
                        return False

                try:
                    supported = await asyncio.wait_for(
                        loop.run_in_executor(context.executor, probe),
                        timeout=timeout + 1,
                    )
                except (OSError, ssl.SSLError, asyncio.TimeoutError):
                    supported = False
                if supported:
                    output.append(
                        finding(
                            self,
                            context,
                            f"Legacy {legacy.name} supported",
                            "medium",
                            "A version-constrained handshake succeeded without sending credentials.",
                            "Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.",
                            evidence=f"Version-constrained handshake: {legacy.name}",
                            confidence="high",
                            cwe="CWE-326",
                            cvss=5.3,
                        )
                    )
        return output
