# Common Validator Components: The Guardian

This module implements the **Guardian**, the hardware-anchored root of trust for the IOI Kernel.

## The Guardian Container (`guardian.rs`)

The Guardian is a security enclave. It creates a boundary around the node's identity to prevent key exfiltration and equivocation.

### 1. Secure Key Storage (`IOI-GKEY`)
Keys are never stored in plaintext. The `load_encrypted_file` and `save_encrypted_file` functions enforce a custom encryption format:
*   **KDF:** Argon2id (resistance against GPU cracking).
*   **Encryption:** XChaCha20Poly1305 (Authenticated Encryption).
*   **At-Rest:** Keys are only decrypted in memory during the signing operation and are zeroized immediately after usage.

### 2. Binary Integrity
Upon startup, the Guardian performs a self-check and a sibling-check:
*   It computes the SHA-256 hash of the running `orchestration` and `workload` binaries.
*   It compares these hashes against the `approved_hashes` in `guardian.toml`.
*   **Locking:** It holds open file handles to these binaries to prevent them from being swapped out or modified by an attacker while the node is running (utilizing OS-level `ETXTBSY` protections on Linux).

### 3. Oracle-Anchored Signing
To prevent **Equivocation** (signing two different blocks at the same height) in the A-DMFT consensus:
*   The Guardian maintains a local, monotonic counter and a hash chain (Trace).
*   **Signature Payload:** `Hash(BlockHeader) || Counter || Trace`.
*   This binds every signature to a unique point in the node's history. If a node tries to "forget" it signed a block and sign a conflicting one, the counter sequence would break or diverge, providing cryptographic proof of fraud.

### 4. Secure Egress
Used for "Bring Your Own Key" AI services.
*   The Workload requests an HTTP call (e.g., to OpenAI).
*   The Guardian looks up the encrypted API key in its vault.
*   The Guardian performs the TLS handshake and injects the key directly into the HTTP headers.
*   The Workload receives the response but *never sees the key*.