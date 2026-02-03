# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Report a Vulnerability

**Do not use public GitHub issues for security vulnerabilities.**

Report via [GitHub Security Advisory](../../security/advisories/new) or email sunnamed434 (at) proton dot me.

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

Response time: 72 hours. Please don't disclose publicly until we release a fix.

## What We Care About

- Authentication/OAuth vulnerabilities
- Credential exposure (tokens, keys)
- Path traversal or access control bypasses
- Command injection
- Docker/container security issues

Out of scope: physical access, social engineering, third-party dependency vulnerabilities, misconfigured deployments.

## Security Best Practices

When deploying YARMCP:

1. Use HTTPS
2. Rotate credentials regularly
3. Restrict network access
4. Keep YARMCP updated
5. Monitor logs for suspicious activity

---

**Note**: This policy covers YARMCP itself, not repositories it accesses.
