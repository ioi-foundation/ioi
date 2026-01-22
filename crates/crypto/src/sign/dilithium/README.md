# ML-DSA (Dilithium) Signatures

This module implements **ML-DSA (Module-Lattice-Based Digital Signature Algorithm)**, formerly known as CRYSTALS-Dilithium. It is the primary NIST-standardized Post-Quantum signature scheme used by the IOI Kernel.

While `Ed25519` is used for high-speed local operations, `ML-DSA` is required for **Long-Term Identity** and **Consensus Finality**, ensuring the blockchain's history cannot be forged by future quantum adversaries.

## Security Levels

We support the three NIST-defined parameter sets, mapping them to the IOI `SecurityLevel` enum:

| IOI Level | NIST Name | Classical Security | Signature Size | Public Key Size | Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Level 2** | **ML-DSA-44** | ~128-bit | 2,420 bytes | 1,312 bytes | Standard User Transactions |
| **Level 3** | **ML-DSA-65** | ~192-bit | 3,293 bytes | 1,952 bytes | Validator Consensus Keys |
| **Level 5** | **ML-DSA-87** | ~256-bit | 4,595 bytes | 2,592 bytes | Root Governance / Guardians |

## Implementation Details

*   **Lattice Hardness:** Security relies on the hardness of the Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems.
*   **Deterministic Signing:** Unlike early lattice schemes, our implementation uses deterministic nonce generation (derived from the message and private key) to prevent catastrophic failure from RNG reuse.
*   **Performance:** Verification is extremely fast (faster than ECDSA), making it ideal for validating block headers on light clients. However, keys and signatures are significantly larger than Elliptic Curve equivalents, requiring optimized storage layouts in the `NodeStore`.