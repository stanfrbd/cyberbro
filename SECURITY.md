# Security Policy

## Deployment and access control

Cyberbro is a lightweight IOC enrichment application and **does not implement built-in authentication or authorization**. This is intentional; native authentication is not currently planned.

Treat any instance reachable by other users or systems as potentially sensitive: accessible endpoints may allow analyses to be started, investigation history and results to be read, and configured third-party API quotas to be consumed.

**Do not expose Cyberbro directly to the public Internet or other untrusted networks without external access controls.** Protect all routes, including API, history, results, and exports, using a trusted authentication-enabled reverse proxy, an identity-aware access proxy (such as Cloudflare Access), or a VPN. Apply firewall restrictions or IP allowlisting where appropriate. A WAF is an additional defense, **not a substitute for authentication**.

See the [README](README.md#security-and-access-control) for more information.

## Reporting a vulnerability

Please report security vulnerabilities privately through [GitHub's private vulnerability reporting](https://github.com/stanfrbd/cyberbro/security/advisories/new), if available.

If private reporting is unavailable, [open an issue](https://github.com/stanfrbd/cyberbro/issues/new) without including exploit details, credentials, or sensitive data, so an appropriate disclosure channel can be arranged.

Security reports are appreciated and will be reviewed as maintainer availability permits. Not all reported concerns imply a change to the project's intentionally limited scope.
