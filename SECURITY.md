# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: <security@codepros.dev>

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if you have one)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow responsible disclosure practices
- Security advisories will be published after fixes are available
- Credit will be given to reporters (unless anonymity is requested)

## Security Measures

This project implements:

- **Memory Safety**: Zig's compile-time memory safety checks
- **Safety-Checked Builds**: Debug/ReleaseSafe builds are exercised in CI
  alongside ReleaseFast/ReleaseSmall; randomness comes from the process
  CSPRNG (`std.Io` `random`, never silently uninitialized); untrusted
  envelope parsing is bounds-checked with fuzz coverage
- **Dependency Scanning**: Automated security scanning in CI
- **Secret Detection**: Gitleaks scanning for leaked credentials

### Hardening Notes

- **Identifier constraints**: key-derivation identifiers (`tenant`,
  `schema`, `field`) must be non-empty and must not contain `:` or `/` —
  violations are rejected with `Error.InvalidIdentifier` so derivation
  contexts and cache keys stay injective
- **Master-key format**: `EnvKeyProvider` accepts exactly 32 raw bytes or
  exactly 64 hex characters; any other length is rejected (no silent
  truncation of key material)
- **FEK rotation**: FEKs use random 96-bit AEAD nonces — rotate via
  `KeyManager.rotateFEK` well before 2^32 encryptions per key (plan for
  ~2^28); see `docs/KEY_HIERARCHY.md` for the full guidance

## Security Best Practices

When using this library:

1. Keep dependencies updated
2. Review security advisories regularly
3. Report any suspicious behavior
4. Follow secure coding guidelines

## Contact

For non-security issues, see [SUPPORT.md](SUPPORT.md).
