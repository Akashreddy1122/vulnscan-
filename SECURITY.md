# ShadowScan security guidance

ShadowScan is for authorized assessments only. Never scan a third-party asset without permission. The tool makes network requests, may reveal sensitive service details, and must be run with conservative rate limits on fragile services.

## Trust boundaries

- The built-in HTTP transport enforces an exact scheme, hostname, and effective port. It does not follow redirects or accept authority/framing header overrides. Raw network modules scan only configured ports. Opt-in DNS subdomain enumeration does not authorize subsequent HTTP scans of discovered names.
- Authentication data belongs in environment variables where possible. Plain HTTP credentials are blocked unless the operator explicitly opts in. A user-configured proxy and trusted third-party plugins are **outside** the built-in transport trust boundary.
- API access is restricted to loopback and bearer-authenticated routes. Use a separate TLS-terminating reverse proxy and access controls if remote API access is required.
- Target URLs, evidence, logs, reports, and SQLite data can be sensitive. Keep them in private directories, rotate exposed credentials, and delete outputs when no longer needed. Avoid placing secrets in URL query strings.

## Reporting an issue

Please report suspected security issues privately to the repository owner (for example, using GitHub's private vulnerability reporting if enabled) rather than posting working exploits in a public issue. Include the affected version, reproduction steps using a local test target, and impact. Do not test against systems you do not control.

Dependency and test results represent a point in time. Neither passing tests nor an advisory scan can prove the absence of vulnerabilities.
