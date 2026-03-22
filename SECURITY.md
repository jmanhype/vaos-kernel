# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in vaos-kernel, please report it responsibly:

- Email: straughter@vaos.sh
- Do NOT open a public GitHub issue for security vulnerabilities

## Scope

vaos-kernel uses HS256 (symmetric HMAC) for JWT signing. This is appropriate for single-issuer deployments. For multi-service deployments, migration to EdDSA (Ed25519) asymmetric signing is recommended. See the paper for details.

## Supported Versions

| Version | Supported |
|---------|-----------|
| master  | ✅        |
