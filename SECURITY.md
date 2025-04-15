# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in DePIN SDK, please follow these steps:

1. **Do not disclose the vulnerability publicly**
2. Email [security@example.com](mailto:security@example.com) with details about the vulnerability
3. Include steps to reproduce the vulnerability if possible
4. We will acknowledge receipt of your report within 48 hours
5. We will provide an estimated timeline for a fix
6. Once the vulnerability is fixed, we will notify you and publicly acknowledge your contribution (unless you prefer to remain anonymous)

## Security Principles

DePIN SDK follows these security principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Components only have access to what they strictly need
3. **Container Isolation**: Strong security boundaries between components
4. **Cryptographic Agility**: Ability to upgrade cryptographic algorithms
5. **Post-Quantum Security**: First-class support for post-quantum algorithms
6. **Regular Security Audits**: Ongoing review of code and architecture

## Post-Quantum Security

DePIN SDK provides post-quantum security through:

- Kyber for key encapsulation
- Dilithium, Falcon, and SPHINCS+ for signatures
- Lattice-based vector commitments for Verkle trees

For more details on our post-quantum strategy, see `docs/security/post_quantum.md`.
