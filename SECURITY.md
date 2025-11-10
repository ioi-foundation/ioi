# 🔐 IOI SDK Security Policy

The IOI SDK is a foundational framework for decentralized intelligence networks.  
Security, determinism, and verifiable correctness are treated as first-class design goals.

---

## 🧩 Supported Versions

| Version | Supported | Notes |
|----------|------------|-------|
| **0.1.x** | ✅ Actively maintained | Receives ongoing security patches |
| **Pre-0.1.0** | ❌ Unsupported | Early development snapshots, not maintained |

Only maintained branches receive coordinated patches.  
Older tags remain available for audit reference but are **not patched retroactively**.

---

## 📣 Reporting a Vulnerability

If you discover a vulnerability in the IOI SDK, please follow responsible disclosure procedures:

1. **Do not disclose publicly.**  
   Contact the IOI Security Team directly.
2. **Email:** [security@ioi.network](mailto:security@ioi.network)  
   Include a clear description, proof-of-concept if possible, and affected components.
3. **Acknowledgement:** You’ll receive confirmation of receipt within **48 hours**.
4. **Triage:** The team will assess severity and determine patch priority.
5. **Fix Window:** Critical vulnerabilities are patched within **7–14 days**, depending on complexity.
6. **Public Disclosure:** Once remediated, a formal advisory (`docs/security/IOI-SEC-YYYY-###.md`) is published.
7. **Attribution:** Reporters may choose to be publicly acknowledged or remain anonymous.

For encrypted communication, use the IOI Security Team’s PGP key available at  
[https://ioi.network/pgp.txt](https://ioi.network/pgp.txt).

---

## 🧱 Security Architecture Principles

1. **Defense in Depth** — layered protection across consensus, networking, and services.  
2. **Least Privilege** — each module operates with minimal authority.  
3. **Container Isolation** — Orchestration, Workload, and Guardian nodes run in sandboxed environments.  
4. **Deterministic State Machines** — consensus-critical logic is strictly reproducible across nodes.  
5. **Cryptographic Agility** — algorithms and suites are upgradeable via governance without chain resets.  
6. **Post-Quantum Readiness** — hybrid PQC primitives baked into transport and consensus layers.  
7. **Transparent Disclosure** — all resolved vulnerabilities are documented under `docs/security/`.

---

## 🧬 Post-Quantum Security

The IOI SDK implements hybrid post-quantum cryptography for both transport and consensus layers.

| Category | Algorithm | Purpose |
|-----------|------------|----------|
| **Key Encapsulation** | Kyber | Secure session establishment |
| **Signatures** | Dilithium • Falcon • SPHINCS+ | Consensus blocks and identity proofs |
| **Commitments / Trees** | Lattice-based commitments | Verkle and sparse Merkle structures |

Further details are available in [`docs/security/post_quantum.md`](./docs/security/post_quantum.md).

---

## 🧾 Advisory Documentation

Security advisories are maintained under the `docs/security/` directory:

| File | Purpose |
|------|----------|
| `docs/security/template.md` | Canonical template for all new advisories |
| `docs/security/IOI-SEC-YYYY-###.md` | Individual vulnerability reports and remediation details |
| `docs/security/post_quantum.md` | PQC architecture and cryptographic roadmap |

Example:
- [`docs/security/IOI-SEC-2025-001.md`](./docs/security/IOI-SEC-2025-001.md) — Critical Replay Vulnerability in Misbehavior Reporting

---

## 🪪 Disclosure Workflow Summary

| Stage | Visibility | Description |
|--------|-------------|--------------|
| **Private Report** | Confidential | Researcher submits vulnerability via email |
| **Under Review** | Internal | Issue triaged, patch drafted and tested |
| **Coordinated Fix** | Internal | Patch merged across maintained branches |
| **Public Advisory** | Public | Advisory published under `docs/security/` |
| **Acknowledgement** | Public | Credits or anonymous note added to advisory |

---

**Thank you for helping secure the IOI SDK and the Internet of Intelligence.**  
Together we uphold transparency, verifiability, and resilience across decentralized systems.

_Last updated: 2025-11-10_
