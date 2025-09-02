# Production-Grade IAVL State Backend

This module provides a production-grade, secure, and interoperable IAVL (Immutable AVL) tree implementation. It follows principles inspired by the Inter-Chain Standard for Merkle Proofs (ICS-23) to ensure that proofs are compact, deterministic, and verifiable by third parties with minimal trust.

The on-chain root hash serves as an irrefutable commitment to the state, and off-chain proofs can be verified against this commitment in logarithmic time.

## Canonical Hashing Rules

The integrity of the state machine relies on a byte-exact, deterministic hashing specification. Any deviation will cause consensus failures.

-   **Hash Function**: **SHA-256** (32-byte digest).
-   **Integer Encodings**: All integers (`version`, `size`, `height`, and length prefixes) are encoded using fixed-width, **little-endian** byte order.
-   **Child Hashes**: Left and right child hashes are always 32 bytes. A missing child is represented by a **32-byte zero hash** (`[0u8; 32]`).

### Leaf Node Hash

A leaf node's hash is computed as:
`SHA256( 0x00 || version || height || size || len(key) || key || len(value) || value )`

-   `0x00`: A single-byte domain tag for leaf nodes.
-   `version`: `u64` (8 bytes)
-   `height`: `i32` (4 bytes, always 0 for leaves)
-   `size`: `u64` (8 bytes, always 1 for leaves)
-   `len(key)` / `len(value)`: `u32` (4 bytes)

### Inner Node Hash

An inner (or branch) node's hash is computed as:
`SHA256( 0x01 || version || height || size || len(key) || key || left_hash || right_hash )`

-   `0x01`: A single-byte domain tag for inner nodes.
-   `version`, `height`, `size`, `len(key)`: Same encoding as leaves.
-   `left_hash`, `right_hash`: 32-byte child hashes.

## Proof Structure

The `IavlProof` is a unified enum capable of proving both existence and non-existence of a key.

### Existence Proof

An `ExistenceProof` proves that a `(key, value)` pair is present in the tree that commits to a specific root hash. It contains:

-   The `key` and `value` being proven.
-   A `LeafOp` with the minimal metadata (`version`) needed to reconstruct the leaf hash.
-   A `path` of `InnerOp`s, one for each node from the leaf's parent to the root. Each `InnerOp` contains all metadata (`version`, `height`, `size`, `split_key`) and the sibling hash required to reconstruct the parent hash at that level.

### Non-Existence Proof

A `NonExistenceProof` proves that a `key` is not present in the tree. It does this by providing existence proofs for the key's immediate lexicographical neighbors (predecessor and successor). A verifier can use these neighbors to confirm there is no space between them for the missing key.

## Verification

Verification is performed by a pure, stateless function:
`verify_iavl_proof_bytes(root, key, expected_value, proof_bytes)`

-   It takes a trusted `root` hash.
-   `expected_value` is `Some(value)` for an existence check and `None` for a non-existence check.
-   The function deserializes `proof_bytes` and uses the canonical hashing rules to deterministically reconstruct a candidate root hash.
-   The proof is valid if and only if the reconstructed hash matches the trusted `root` hash.

## Migration Guide

To upgrade from the previous mock verifier to this production implementation:

1.  **Replace `verify_proof`**: The body of the `verify_proof` function in the `StateCommitment` implementation for `IAVLTree` should be replaced with a call to the new `proof::verify_iavl_proof_bytes` function.
2.  **Update `create_proof`**: The `create_proof` function should be updated to use the new `build_existence_proof` and `build_non_existence_proof` helpers and serialize the resulting `IavlProof` enum.
3.  **Update `IAVLNode::compute_hash`**: Ensure the internal hashing logic of `IAVLNode` matches the canonical specification documented above. The provided `mod.rs` file already contains this change.

This upgrade ensures the tree's internal state commitments and external proofs are fully aligned and verifiable.