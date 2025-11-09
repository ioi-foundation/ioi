### **Universal Interoperability (IBC)**

The IOI SDK implements the Inter-Blockchain Communication (IBC) protocol to enable trustless communication with other IBC-enabled chains, including those in the Cosmos ecosystem. Interoperability is facilitated through a dedicated **HTTP Gateway** that exposes a stable, JSON-RPC-based API for relayers and off-chain tools.

#### **HTTP Gateway API**

The gateway provides endpoints for querying chain state, retrieving cryptographic proofs, and submitting IBC messages.

**Endpoint: `POST /v1/ibc/query`**

This is the primary endpoint for querying key-value pairs from the chain's IBC state store. It is used by relayers to fetch client states, consensus states, connection ends, channel ends, and packet commitments/acknowledgements.

**Request Body (JSON):**

```json
{
  "path": "clients/07-tendermint-0/clientType",
  "height": "12345",
  "latest": false,
  "proof_format": "ics23"
}
```

*   `path` (string, required): The ICS-24 storage path for the desired key (e.g., `clients/{client_id}/clientState`). The `ibc/` store prefix should be omitted.
*   `height` (string, optional): The specific block height to query. This is mutually exclusive with `latest`.
*   `latest` (boolean, optional): If `true`, queries the state at the last committed block height. Defaults to `false`. Exactly one of `height` or `latest` must be specified.
*   `proof_format` (string, optional): Specifies the desired format for the returned cryptographic proof. **Defaults to `"ics23"`.**
    *   `"ics23"`: Returns the proof as a Protobuf-encoded `ibc.core.commitment.v1.MerkleProof`. This is the standard format for modern IBC relayers.
    *   `"proofops"`: Returns the proof wrapped in a Protobuf-encoded `tendermint.crypto.ProofOps` structure for compatibility with older Cosmos SDK versions.
    *   `"native"`: Returns the raw, SCALE-encoded `IavlProof` from the underlying state machine. This is an efficient format for internal tooling but is **not** IBC-compliant.

**Success Response (JSON):**

```json
{
  "value_pb": "YmFzZTY0...",
  "proof_pb": "CgYIARJY...",
  "height": "12345",
  "proof_format": "ics23"
}
```

*   `value_pb` (**string**, Base64): The Protobuf-encoded value stored at the specified path. For example, for a client state, this will be the bytes of a `google.protobuf.Any` wrapping an `ibc.lightclients.tendermint.v1.ClientState`. For absence proofs, this field will be `null`.
*   `proof_pb` (**string**, Base64): The Protobuf-encoded cryptographic proof in the requested format.
*   `height` (**string**): The block height at which the proof and value were generated.
*   `proof_format` (**string**): Echoes the format of the returned `proof_pb` (`"ics23"`, `"proofops"`, or `"native"`).

**Endpoint: `POST /v1/ibc/root`**

Retrieves the application's Merkle root hash (app hash) for a given height.

**Request Body (JSON):**

```json
{
  "height": "12345",
  "latest": false
}
```

**Success Response (JSON):**

```json
{
  "root_pb": "eJ7r+zG5vU3BqbtNC/60ocR/UEzL6ZUL7l3K2IZhR+U=",
  "height": "12345"
}
```

**Endpoint: `POST /v1/ibc/submit`**

Submits a transaction containing one or more IBC messages to the chain's mempool.

**Request Body (JSON):**

```json
{
  "msgs_pb": "YmFzZTY0..."
}
```

*   `msgs_pb` (string, Base64): The Protobuf-encoded bytes of a `cosmos.tx.v1beta1.TxBody` message. The `messages` field within `TxBody` should contain a list of IBC messages, each wrapped in a `google.protobuf.Any`.

**Success Response (JSON):**

```json
{
  "tx_hash": "a1b2c3d4..."
}
```

*   `tx_hash` (string, hex): The SHA-256 hash of the submitted transaction, which can be used to track its inclusion in a block.