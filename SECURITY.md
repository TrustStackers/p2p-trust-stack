# Security Policy

## Reporting a vulnerability

This library implements cryptographic primitives, DID rotation, an encrypted
keystore, and a peer-to-peer protocol. We take security reports seriously.

**Please do not open a public GitHub issue for a vulnerability.**

Instead, report it privately:

- **GitHub Security Advisories:** use the "Report a vulnerability" button on the
  Security tab of the repository (preferred).
- **Email:** security@truststackers.com

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof of concept
- Affected versions
- Any proposed fix

## Process

1. We acknowledge receipt within 5 business days.
2. We triage and confirm the issue.
3. We coordinate a fix and a release, and credit the reporter (with consent).

## Disclosure

We prefer coordinated disclosure. We will work with you to determine an
appropriate public disclosure timeline.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x (latest) | ✅ |
| < 0.2.0 | ❌ |

## Cryptographic notice

This project is pre-1.0 and has not undergone a third-party security audit.
Do not rely on it for production security until an audit has been completed.

## Export notice

This project includes cryptographic functionality and is subject to export
control laws, including the U.S. Export Administration Regulations. Published
source code generally qualifies for the "publicly available" exception; users
are responsible for their own compliance.
