# Canonical IAVL Leaf Hashing Profile (ICS-23 Compliant)

This document is the **single source of truth** for the byte-for-byte canonical representation of IAVL tree leaf nodes within the IOI Kernel. A deterministic hashing profile is critical for consensus, as all nodes must compute identical state root hashes. It is also essential for interoperability, as external verifiers (like IBC relayers) must know the exact preimage to verify Merkle proofs.

## IOI IAVL Leaf Profile

To ensure interoperability with the broader Cosmos ecosystem, the IOI Kernel's IAVL implementation aligns with the common profile used by the Cosmos SDK. This involves pre-hashing the value before including it in the final leaf preimage.

The [`LeafOp` parameters](https://github.com/cosmos/ics23/blob/main/go/ics23.go) for an ICS-23 proof are as follows:

| Parameter       | Value            | Description                                                                 |
| --------------- | ---------------- | --------------------------------------------------------------------------- |
| `hash`          | `Sha256`         | The final operation applied to the entire leaf preimage.                      |
| `prehash_key`   | `NoHash`         | The key is not hashed before being length-prefixed.                         |
| **`prehash_value`** | **`Sha256`**     | **The raw value is first hashed with SHA-256 to get a 32-byte digest.**         |
| `length`        | `VarProto`       | The key and (pre-hashed) value are length-prefixed using Protobuf varints.  |
| `prefix`        | `0x00`           | A single `0x00` byte prepended to the preimage to signify a leaf node.      |

### Detailed Preimage Construction

The final hash of a leaf node, which becomes its identifier in the tree, is calculated as follows:

**`Leaf Hash = SHA-256( Leaf Prefix || Key Preimage || Value Preimage )`**

Where:
1.  **`Leaf Prefix`**: A single byte: `0x00`.
2.  **`Key Preimage`**: The raw key, prefixed with its length as a Protobuf `varint`.
    *   `prost::encode_length_delimiter(key.len()) || key`
3.  **`Value Preimage`**: The **SHA-256 hash** of the raw value, prefixed with its length (which is always `32`) as a Protobuf `varint`.
    *   `prost::encode_length_delimiter(32) || SHA-256(raw_value)`

#### Concrete Example

*   `key`: `"foo"` (bytes `0x666f6f`)
*   `raw_value`: `"bar"` (bytes `0x626172`)

1.  **Prefix**:
    *   `0x00`
2.  **Key Preimage**:
    *   `key.len()` is 3. `VarProto(3)` is `0x03`.
    *   Preimage: `0x03666f6f`
3.  **Value Preimage**:
    *   `SHA-256("bar")` -> `0xfcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9`
    *   Length of this hash is 32. `VarProto(32)` is `0x20`.
    *   Preimage: `0x20fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9`

4.  **Final Concatenated Preimage to be Hashed**:
    ```
    0x00 || 0x03666f6f || 0x20fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
    ```
    The `SHA-256` of this byte string produces the final leaf hash.