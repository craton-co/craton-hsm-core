# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Craton HSM, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/craton-co/craton-hsm-core/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- Affected versions
- Any potential impact assessment

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix or mitigation**: depends on severity, targeting 30 days for critical issues

### What happens next

1. We will confirm receipt and begin investigation
2. We will work with you to understand the scope and impact
3. We will develop and test a fix
4. We will coordinate disclosure timing with you
5. We will credit you in the advisory (unless you prefer anonymity)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | Yes (0.9.1 includes critical security fixes) |
| 0.8.x   | Yes       |
| < 0.8   | No        |

## Security Design

Craton HSM's security architecture is documented in:

- [Security Model](docs/security-model.md) — threat model, key protection, side-channel resistance
- [Security Policy (FIPS)](docs/security-policy.md) — FIPS 140-3 security policy with CSP table
- [Security Review Checklist](docs/security-review-checklist.md) — pre-audit self-assessment

## Scope

The following are in scope for security reports:

- Memory safety issues in unsafe blocks (FFI boundary)
- Key material leaks (in logs, error messages, debug output, core dumps)
- Authentication bypass (PIN verification, session state machine)
- Cryptographic implementation flaws
- Side-channel vulnerabilities (timing, cache)
- Denial of service via crafted PKCS#11 calls
- Audit log integrity bypass

The following are out of scope:

- Vulnerabilities in upstream dependencies (report to the upstream project)
- Issues requiring physical access to the host machine (Level 1 software module)
- Social engineering attacks
