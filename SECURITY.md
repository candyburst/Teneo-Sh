# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities via GitHub Issues.**

If you discover a vulnerability, please open a [GitHub Security Advisory](../../security/advisories/new) or email the maintainers privately. Include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You can expect an acknowledgement within **48 hours** and a status update within **7 days**.

Please do not publicly disclose the issue until a fix has been released.

## Scope

This project applies 13 hardening layers to Ubuntu systems. Security-relevant findings include but are not limited to:

- Privilege escalation via the script itself
- Credential exposure or insecure storage
- Bypasses to any hardening layer
- Unsafe handling of user-supplied input (proxy URLs, account names, etc.)
