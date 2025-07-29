# DePIN SDK

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/depin-sdk/rust.yml?branch=main)](https://github.com/your-org/depin-sdk/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**The Framework for Sovereign Web4 Blockchains.**

The DePIN SDK is a next-generation blockchain framework, written entirely in Rust, designed to build high-performance, sovereign, and secure decentralized networks. It evolves beyond the Web3 paradigm of "read, write, own" to enable **Web4**: chains that can also **understand** user intent through a native, distributed AI semantic layer.

Our mission is to provide the tools to build chains that are not just decentralized ledgers, but intelligent, autonomous partners in achieving complex goals.

---

### Core Features

*   🧠 **Web4 Semantic Layer**: A native, distributed AI infrastructure that allows blockchains to interpret natural language, understand user intent, and execute complex semantic operations.
*   🛡️ **Post-Quantum Security**: A pragmatic, forward-thinking cryptographic architecture that is quantum-resistant from day one, featuring hybrid KEMs for transport security and a clear, non-disruptive migration path for on-chain signatures.
*   ⛓️ **True Sovereignty & Forkless Upgrades**: Chains achieve sovereignty through compile-time module scaffolding, creating dependency-free binaries. A powerful runtime upgrade manager allows for hot-swapping any core service—including governance—without network halts.
*   🦀 **Modular, Rust-Native Architecture**: Built from the ground up in Rust for maximum safety, performance, and modularity. Every component, from consensus to the VM, is a pluggable service behind a standard trait.
*   🏛️ **Triple-Container Validator Model**: A defense-in-depth architecture that isolates responsibilities into a **Guardian Container** (security), **Orchestration Container** (consensus/networking), and **Workload Container** (VM/transaction execution).
*   🌐 **Consensus-Agnostic Security**: A robust security model that provides strong guarantees through cryptography, reputation, and quarantine mechanisms, without relying solely on economic slashing. This makes the SDK adaptable to Proof-of-Stake, Proof-of-Work, Proof-of-Authority, and custom consensus models.

### Architectural Overview

The DePIN SDK is designed with an SDK-first methodology. The core components are provided as a set of composable Rust crates, allowing developers to build custom, sovereign chains tailored to their specific use case. The foundation of this design is the **Triple-Container Architecture**, which ensures a strict separation of concerns and enhances security.

For a deep dive into the architecture, please see the [**Architectural Documentation**](./docs).

### Current Status

> **Note**: The project is currently in an active development phase. The `main` branch contains a functional prototype that demonstrates the core architectural principles.
>
> Phase 3 of our implementation plan is complete. This means:
> *   The full **Triple-Container Architecture** is scaffolded.
> *   Validators load their configuration from `.toml` files.
> *   Nodes can discover each other via P2P networking and persist their state.
>
> The current focus is on **Phase 4**, which involves implementing the real consensus and transaction processing logic inside the containers. **The software is not yet mainnet-ready.**

---

### Getting Started

You can build and run a local, multi-node test network right now to validate the core networking and persistence features.

#### Prerequisites

*   **Rust**: Ensure you have the latest stable version of Rust installed via `rustup`.
*   **Build Tools**: A C compiler, such as GCC or Clang, is required.

#### 1. Clone the Repository

```bash
git clone https://github.com/your-org/depin-sdk.git
cd depin-sdk
```

#### 2. Create Configuration Files

The validator requires configuration files for its containers. Create a `config` directory in the project root with the following minimal setup:

```bash
# Create the directory
mkdir -p config

# Create guardian.toml
echo 'signature_policy = "FollowChain"' > config/guardian.toml

# Create orchestration.toml
echo 'consensus_type = "ProofOfStake"' > config/orchestration.toml

# Create workload.toml
echo 'enabled_vms = ["WASM"]' > config/workload.toml
```

#### 3. Run the Testnet

The following steps will guide you through running a single node and then a multi-node network. The `cargo run` command will compile the necessary binary (`mvsc`) for you.

#### **Phase 1: Single Node Validation**

**Test 1.1: Clean Start & Block Production**

This test ensures the node can start from a genesis state and begin producing blocks.

```bash
# 1. Clean up any previous state
rm -f state.json

# 2. Run the node binary
cargo run --release --features="depin-sdk-chain/mvsc-bin" --bin mvsc
```

**Test 1.2: State Persistence & Loading**

This test verifies that the node correctly persists its state to a file and can resume from it after a restart.

```bash
# 1. Run the node for a few blocks, then stop with Ctrl+C

# 2. Inspect the state file to see the saved data
cat state.json

# 3. Restart the node
cargo run --release --features="depin-sdk-chain/mvsc-bin" --bin mvsc
```
You should see it resume from the last block height logged before you stopped it.

---

### **Phase 2: Multi-Node Network Test**

This test confirms that two nodes can connect over the network and that blocks produced by one are gossiped to the other. You will need two terminals or a terminal multiplexer like `tmux`.

1.  **Clean up (in both terminals):**
    ```bash
    rm -f state_node1.json state_node2.json
    ```
2.  **Run Node 1 (in the first terminal):**
    ```bash
    cargo run --release --features="depin-sdk-chain/mvsc-bin" --bin mvsc -- --state-file state_node1.json
    ```
3.  **Wait for and copy the `New listen address`** from Node 1's output. It will look something like `/ip4/127.0.0.1/tcp/34677`.

4.  **Run Node 2 (in the second terminal, using the copied address):**
    ```bash
    # Replace the --peer address with the one you copied from Node 1
    cargo run --release --features="depin-sdk-chain/mvsc-bin" --bin mvsc -- --state-file state_node2.json --peer /ip4/127.0.0.1/tcp/34677
    ```

You should now see connection messages in both terminals. As Node 1 produces new blocks, you will see log messages in Node 2 indicating it has received the block gossip, confirming your P2P layer is functional.

---

### Project Structure

The SDK is organized into a workspace of several key crates:

*   `crates/core`: Defines the core traits and interfaces for all components (e.g., `CommitmentScheme`, `ValidatorModel`, `TransactionModel`).
*   `crates/validator`: Implements the Triple-Container Architecture for both `StandardValidator` and `HybridValidator` models.
*   `crates/chain`: Contains the `SovereignAppChain` implementation and the `mvsc` binary that hosts the validator.
*   `crates/commitment_schemes`: Implementations of various cryptographic commitment schemes (Merkle, KZG, etc.).
*   `crates/state_trees`: Implementations of different state storage models (Verkle, IAVL+, file-based).
*   `crates/transaction_models`: Implementations for UTXO, Account, and Hybrid transaction models.
*   `crates/services`: Implementations of standard, pluggable services like Governance and the Semantic Layer.
*   `crates/crypto`: Low-level cryptographic primitives, including post-quantum algorithms.

### Roadmap

Our high-level roadmap is focused on incrementally building out the features defined in our architecture.

*   ✅ **Phase 3: Integrate Real Architecture** - *Complete*
*   ➡️ **Phase 4: Activate Core Validator Logic** - *In Progress*
    *   Relocate P2P networking and block production into the `OrchestrationContainer`.
    *   Implement real transaction execution in the `WorkloadContainer`.
*   ▶️ **Phase 5: Mainnet Hardening & Advanced Features**
    *   Implement the Post-Quantum Cryptography migration path and Identity Hub.
    *   Flesh out the Hybrid Validator model and tiered economics.
    *   Integrate the optional Policy Stack for formal rule enforcement.
*   ▶️ **Phase 6: Ecosystem Expansion & Evolution**
    *   Develop the DePIN Forge IDE and multi-language SDKs.
    *   Implement IBC and Ethereum compatibility modules.
    *   Integrate production-ready distributed AI models.

### Contributing

We welcome contributions from the community! If you're interested in helping build the future of Web4, please read our [**Contributing Guide**](./CONTRIBUTING.md) to get started.

All participants are expected to follow our [**Code of Conduct**](./CODE_OF_CONDUCT.md).

### License

This project is licensed under either of

*   Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
*   MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.