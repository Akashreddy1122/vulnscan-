"""Header-based CDN and WAF signal detection (not bypass testing)."""

from shadowscan.modules.base import Context, Plugin, finding
from shadowscan.core.models import Finding


class WAFDetector(Plugin):
    """Observe common infrastructure headers without active fingerprint probes."""

    name, group = "waf", "recon"

    async def scan(self, context: Context) -> list[Finding]:
        """Classify conservative header patterns as informational hints."""
        response = await context.base_response()
        if not response:
            return []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        signals = {
            "Cloudflare": "cf-ray" in headers,
            "AWS CloudFront": "x-amz-cf-id" in headers,
            "Akamai": any(k.startswith("x-akamai") for k in headers),
        }
        return [
            finding(
                self,
                context,
                f"Edge/WAF signal: {vendor}",
                "info",
                "The response contains a header associated with an edge provider; a WAF is not confirmed.",
                "No action required; verify edge security policy separately.",
                evidence=f"Provider-associated header present: {vendor}",
                confidence="medium",
            )
            for vendor, observed in signals.items()
            if observed
        ]
