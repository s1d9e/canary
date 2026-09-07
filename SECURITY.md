# Canary — Security Policy

Canary is a defensive threat-intelligence aggregation platform. The security of Canary itself matters because it ingests untrusted attacker-derived data.

## Data Handling

- Canary treats all incoming event payloads as **untrusted data**. Field values are stored as strings and never executed, evaluated, or interpolated into shell commands.
- The web dashboard escapes all rendered output (no reflected XSS). Do not disable escaping.
- The ingestion API binds to `127.0.0.1` by default. Exposing it on a public interface is at your own risk — consider an API token or a reverse proxy.

## Reporting a Vulnerability

If you find a security issue in Canary (injection, XSS, RCE, info leak, etc.), please **do not open a public issue**. Report it responsibly via [GitHub Issues](https://github.com/s1d9e/canary/issues) with the label `security`, or open a private advisory.

## Scope

The following are NOT vulnerabilities:
- Weaknesses that only manifest when running with deliberately unsafe configurations the user chose to enable.
- Unauthorized collection from third-party networks (that is a deployment decision, not a defect in Canary).
