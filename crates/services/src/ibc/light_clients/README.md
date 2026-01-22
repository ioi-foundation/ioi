# IOI IBC Light Clients

This module contains the concrete implementations of **Light Clients** (Verifiers) for the IOI Kernel's Inter-Blockchain Communication (IBC) stack.

These components are responsible for cryptographically verifying the consensus headers and state proofs of counterparty blockchains. They implement the `ioi_api::ibc::LightClient` trait.

## Supported Architectures

The IOI Kernel supports a **Hybrid Client Architecture**, combining native performance with dynamic upgradeability.

### 1. Tendermint (Native)
*   **Source**: `tendermint.rs`
*   **Standard**: ICS-07
*   **Description**: A native Rust implementation of the Tendermint light client.
*   **Use Case**: High-performance bridging to Cosmos SDK chains (e.g., Cosmos Hub, Osmosis).
*   **Verification**: Validates Ed25519 signatures, voting power, and header continuity.

### 2. Wasm / ICS-08 (Dynamic)
*   **Source**: `wasm.rs`
*   **Standard**: ICS-08 (Wasm Client)
*   **Description**: A generic host that runs light client logic compiled to WebAssembly (WASM).
*   **Mechanism**:
    *   It uses the `wasmtime` runtime with the Component Model.
    *   Verifier artifacts are stored on-chain in the `upgrade` namespace.
    *   The `VerifierRegistry` loads these artifacts dynamically at runtime.
*   **Use Case**: Bridging to new chains (e.g., Near, Polkadot, new L2s) **without** requiring a hard fork of the IOI Kernel.

### 3. Ethereum ZK (Zero-Knowledge)
*   **Source**: `ethereum_zk.rs` (Requires `ethereum-zk` feature)
*   **Description**: A SNARK-based light client for the Ethereum Beacon Chain.
*   **Mechanism**:
    *   Delegates proof verification to the `zk-driver-succinct` crate.
    *   Verifies SP1 (RISC-V ZKVM) or Groth16 proofs proving the validity of Beacon Chain sync committee updates and execution layer state roots.
*   **Use Case**: Trust-minimized, low-cost bridging to Ethereum Mainnet and EVM L2s.

## Architecture

Clients are managed by the `VerifierRegistry` (`../core/registry.rs`). The registry resolves a client request to a concrete implementation based on the `client_type` identifier:

1.  **Native Check**: Is there a hardcoded rust implementation? (e.g., `07-tendermint`).
2.  **Cache Check**: Is there a compiled WASM module in memory?
3.  **Dynamic Load**: Does the on-chain state contain a registered WASM artifact for this client type?

### The `LightClient` Trait

All implementations must satisfy the `LightClient` trait defined in `ioi_api`:

```rust
#[async_trait]
pub trait LightClient: Send + Sync {
    /// The unique identifier for the chain/client type.
    fn chain_id(&self) -> &str;

    /// Verifies a consensus header updates the client state.
    async fn verify_header(
        &self,
        header: &Header,
        finality: &Finality,
        ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError>;

    /// Verifies a Merkle proof of state inclusion against a trusted header.
    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &Header,
        ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError>;

    // ...
}
```

## Error Handling

Common errors are defined in `errors.rs` and mapped to the standard `CoreError` type. This includes:
*   `ClientStateNotFound`
*   `ConsensusStateNotFound`
*   Cryptographic verification failures (signature mismatch, root mismatch).