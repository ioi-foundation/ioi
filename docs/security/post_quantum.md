# 🧬 IOI Kernel — Post-Quantum Security Architecture

The IOI Kernel is designed to be secure in a post-quantum computing era. This document outlines the framework’s cryptographic strategy, its hybrid key exchange for transport security, and the on-chain governance mechanisms for migrating cryptographic primitives.

_Last updated: 2025-11-10_

---

## 1. Overview

The IOI Kernel employs a **hybrid classical + post-quantum** security model, focusing on providing forward secrecy for network communications and cryptographic agility for on-chain identity and consensus.

**Goals**

*   Ensure forward secrecy for network transport against future "harvest now, decrypt later" attacks.
*   Maintain interoperability with existing Ed25519-based ecosystems (e.g., Cosmos / IBC) while allowing migration to PQ signatures.
*   Enable seamless algorithm migration for validator identities via on-chain governance through the `IdentityHub` service.
*   Provide a modular foundation to support future PQ-secure state commitment schemes.

---

## 2. Cryptographic Primitives

The SDK integrates a set of classical and post-quantum algorithms from the `dcrypt` library, exposed through the `ioi-crypto` crate.

| Category                | Algorithms                                                                 | Usage                                                                                    |
| ----------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Key Encapsulation (KEM)** | **`ECDH (NIST Curves)` + `Kyber`**                                         | Hybrid key exchange for secure mTLS channels between validator components.               |
| **Signatures**          | **`Ed25519` (default)**, **`Dilithium2`**, `Falcon`, `SPHINCS+` (Planned) | Validator identities, block headers, transaction signing.                                |
| **Hash / XOF**          | **SHA-256**, **Blake3Xof**                                                 | State tree hashing, commitment hashing, `evidence_id` generation.                        |
| **Commitments / Trees** | Hash-based (IAVL, SMT), KZG-based (Verkle), Lattice-based (SIS - Proof-of-Concept) | Current state commitment backends.                                                       |
| **Randomness**          | OS entropy (`rand::rngs::OsRng`)                                           | Cryptographic key generation.                                                            |

On-chain logic references these algorithms via the `SignatureSuite` enum for runtime configurability and future extension.

---

## 3. Hybrid Handshake Model for Transport Security

All mTLS connections between validator components (e.g., Orchestration↔Workload) are secured with a post-quantum hybrid key exchange, implemented in `ioi-crypto`'s `hybrid_kem_tls` module.

This model, which occurs immediately after the standard TLS 1.3 handshake, provides **forward secrecy** against quantum adversaries.

1.  **Classical TLS Handshake:** A standard TLS 1.3 session is established, providing classical security and authentication using Ed25519 certificates.
2.  **Post-Handshake Hybrid Key Exchange:**
    *   The client generates a hybrid `Ecdh-Kyber` public key and sends it to the server.
    *   The server receives the public key, performs a hybrid `Ecdh-Kyber` encapsulation to generate two shared secrets (one classical, one post-quantum), and sends the resulting ciphertext back to the client.
    *   The client decapsulates the ciphertext to derive the same two shared secrets.
3.  **Session Key Derivation:**
    Both parties combine the classical and post-quantum shared secrets by hashing them with a secret derived from the TLS session using the TLS Exporter functionality. This binds the hybrid exchange to the authenticated TLS channel. The final session key is derived using an HKDF-like construction with HMAC-SHA256.

    > **Security Note:** The underlying `dcrypt` library correctly uses HKDF-SHA256 to combine the two secrets, ensuring the final key is secure as long as at least one of the component schemes remains unbroken. This is verified by the `test_hybrid_secret_changes_if_either_component_changes` contract test.

4.  **AEAD-Wrapped Channel:** All subsequent application data is encrypted using an AEAD wrapper (`ChaCha20Poly1305`) keyed with this derived application key.

This ensures that the channel's confidentiality is secure as long as **at least one** of the KEMs (ECDH or Kyber) remains unbroken.

---

## 4. Consensus & Identity Layer

The IOI Kernel supports cryptographic agility for validator identities through the **`IdentityHub`** service. This enables a seamless, on-chain migration from classical to post-quantum signatures without requiring a hard fork.

The process is as follows:
1.  **Initial State:** A validator's on-chain identity is initially represented by an `Ed25519` key.
2.  **Key Rotation:** The validator submits a `rotate_key` transaction containing a `RotationProof`. This proof is signed by both the old `Ed25519` key and the new `Dilithium2` key over a deterministic challenge.
3.  **Grace Period:** The `IdentityHub` stages the new `Dilithium2` key. For a configured number of blocks (the grace period), the chain accepts transactions signed by **either** the old or new key.
4.  **Activation:** After the grace period, the `IdentityHub` promotes the `Dilithium2` key, making it the **sole active key**. The `Ed25519` key is retired and can no longer be used to sign transactions for that account.

Block headers are signed with the validator's currently active consensus key, whatever its suite may be. This allows the network to migrate to post-quantum signatures validator by validator.

---

## 5. State Commitments

The SDK currently supports multiple state backends, with varying levels of post-quantum readiness:

*   **IAVL & Sparse Merkle Trees:** Use SHA-256 for hashing, which is considered quantum-resistant for the foreseeable future.
*   **Verkle Trees:** Use the **KZG** polynomial commitment scheme, which is based on pairings over elliptic curves and is **not** quantum-resistant. The Verkle tree's reliance on KZG is its primary vulnerability to quantum adversaries.
*   **Lattice-Based Commitments:** A `LatticeCommitmentScheme` based on the **Short Integer Solution (SIS)** problem exists in the codebase as a proof-of-concept. This primitive is quantum-resistant but is not yet integrated with a production-ready state tree.

The roadmap includes a critical phase to replace KZG with a quantum-resistant alternative, likely a lattice-based polynomial commitment scheme, to make the Verkle tree fully PQ-secure.

---

## 6. Governance-Controlled Agility

Cryptographic policies are managed on-chain and can be updated via the `governance` service. Key examples include:
*   The `IdentityHub`'s configuration, which specifies the `allowed_target_suites` for key rotation. A governance proposal could add `Dilithium3`, `FALCON`, or `SPHINCS+` to this list in the future.
*   The core protocol can be upgraded forklessly via the `SwapModule` system transaction, allowing for the replacement of services with new versions that may use different cryptographic schemes.

---

## 7. Roadmap & Current Status

| Phase              | Objective                                                                                                                                                                                                                                                                          | Status          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| **Phase 1 (2025)** | Implement hybrid `Ed25519` + `Dilithium2` identities via `IdentityHub`.                                                                                                                                                                                                               | ✅ **Complete** |
| **Phase 2 (2025)** | Implement PQ-secure handshake for all container mTLS channels using `ECDH` + `Kyber`.                                                                                                                                                                                                | ✅ **Complete** |
| **Phase 3 (2026)** | **Expand Signature Scheme Support:** Integrate additional NIST-standardized PQC signature schemes, `FALCON` (lattice-based) and `SPHINCS+` (hash-based), into the `IdentityHub` to offer users diverse security and performance trade-offs.                                             | Planned         |
| **Phase 4 (2026-2027)**| **Quantum-Resistant State Commitments:** Replace the Verkle tree's non-quantum-safe KZG commitment scheme with a quantum-resistant alternative, such as a lattice-based polynomial commitment scheme. This will make the Verkle tree backend fully PQ-secure. | Planned         |
| **Phase 5 (2028+)**| Research and implement pure PQ consensus mechanisms.                                                                                                                                                                                                                                   | Research Stage  |

---

## 8. References

*   [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
*   [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
*   [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
*   [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

---

**Maintained by:** IOI Core Security & Cryptography Team
**Contact:** [security@ioi.network](mailto:security@ioi.network)