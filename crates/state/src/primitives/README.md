# Cryptographic Commitments

This module defines the mathematical primitives used to fingerprint data within the IOI Kernel. The choice of commitment scheme determines the security properties and proof capabilities of the state tree.

The IOI Kernel is **Agile**: the commitment scheme is a generic parameter, allowing the chain to upgrade its cryptography (e.g., for Quantum Resistance) without rewriting the consensus logic.

## Supported Schemes

### 1. Hash (`hash/`)
*   **Algorithm:** SHA-256 / SHA-512.
*   **Use Case:** Standard Merkle Trees (IAVL, Jellyfish).
*   **Pros:** Fast, quantum-resistant (hash-based), standard.
*   **Cons:** Linearly growing proofs.

### 2. KZG (`kzg/`)
*   **Algorithm:** Kate-Zaverucha-Goldberg Polynomial Commitments (BLS12-381).
*   **Use Case:** **Verkle Trees**.
*   **Pros:** **Constant-sized proofs**. A proof for 1,000 keys is the same size as a proof for 1 key. This is critical for scaling stateless clients.
*   **Cons:** Requires a Trusted Setup (SRS), computationally expensive (elliptic curve pairings), not quantum-safe.

### 3. Lattice (`lattice/`)
*   **Algorithm:** Module-LWE / SIS (Kyber/Dilithium based).
*   **Use Case:** **Post-Quantum Verkle Trees**.
*   **Pros:** Quantum-safe, supports homomorphic operations.
*   **Cons:** Large key/proof sizes compared to KZG. This is an experimental feature for future-proofing the network.

### 4. Pedersen (`pedersen/`)
*   **Algorithm:** Vector Commitments on Elliptic Curves (k256).
*   **Use Case:** Privacy-preserving accumulators (e.g., ZK-Rollups).
*   **Pros:** Homomorphic (Sum of Commitments = Commitment of Sums).