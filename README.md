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

> **Note**: The project is currently in an active development phase. The `main` branch contains a functional prototype that demonstrates the core architectural principles, including P2P networking, state persistence, and a modular, compile-time selectable consensus mechanism.
>
> **The software is not yet mainnet-ready.**

---

### Getting Started

You can build and run a local, multi-node test network to validate the core networking, persistence, and consensus features.

#### Prerequisites

*   **Rust**: Ensure you have the latest stable version of Rust installed via `rustup`.
*   **Build Tools**: A C compiler, such as GCC or Clang, is required.

#### 1. Clone the Repository

```bash
git clone https://github.com/your-org/depin-sdk.git
cd depin-sdk
```

#### 2. Create Configuration Files

The validator requires configuration files. Create a `config` directory in the project root:

```bash
# Create the directory
mkdir -p config

# Create a minimal orchestration.toml. The content can be simple for now.
# Note: The RPC address is now configured inside the node binary itself.
echo 'consensus_type = "ProofOfAuthority"' > config/orchestration.toml

# Create a minimal guardian.toml
echo 'signature_policy = "FollowChain"' > config/guardian.toml
```

#### 3. Build the Node Binary

First, compile the project in release mode. This creates the `node` binary we'll use for testing.

**Crucially, you must now choose a consensus engine at compile time using a feature flag.** This ensures the final binary is lean and optimized for a specific purpose.

**Option A: Build with Round Robin BFT Consensus**

This engine is suitable for networks where all validators are known and trusted, and it includes logic for fault tolerance (view changes) if a leader goes offline.

```bash
cargo build --release -p depin-sdk-binaries --features consensus-round-robin
```

**Option B: Build with Proof of Authority (PoA) Consensus**

This is a simpler engine that relies on a fixed, on-chain list of authorities. It does not include fault tolerance logic beyond simple leader rotation.

```bash
cargo build --release -p depin-sdk-binaries --features consensus-poa
```

**Option C: Build with Proof of Stake (PoS) Consensus**

This engine selects block producers based on their staked token amount, providing a decentralized and permissionless security model.

```bash
cargo build --release -p depin-sdk-binaries --features consensus-pos
```

The compiled binary will be located at `target/release/node`.

#### 4. Local Testnet Workflow

This workflow will guide you through running a two-node network using the **Round Robin BFT** engine, as it demonstrates the fault-tolerance features. You will need two terminals.

**Step 1: Full Reset (Optional)**

To start from a clean slate, you can remove all previous state and identity files. This single command resets everything for both nodes.

```bash
rm -f state_node*.json state_node*.json.identity.key
```

**Step 2: Run Node 1 (Terminal 1)**

This node will start as the genesis node.

```bash
target/release/node --state-file state_node1.json
```

It will create `state_node1.json` for its chain state and `state_node1.json.identity.key` for its permanent network identity. Note the listening address it prints, which will look like `/ip4/127.0.0.1/tcp/34677`.

**Step 3: Run Node 2 (Terminal 2)**

Use the listening address from Node 1 to connect.

```bash
# Replace the --peer address with the one you copied from Node 1
target/release/node --state-file state_node2.json --peer /ip4/127.0.0.1/tcp/34677
```

Node 2 will create its own unique state and identity files. You will see it connect to Node 1 and sync the blocks that Node 1 already produced. The two nodes will now alternate leadership and produce blocks.

**Step 4: Test State Persistence & Fault Tolerance**

1.  Stop **Node 2** (`Ctrl+C`).
2.  Observe Terminal 1. Node 1 will continue producing blocks. If it was Node 2's turn to be leader, Node 1 will correctly time out, propose a "view change", and take over leadership to ensure the chain doesn't halt.
3.  Stop **Node 1** (`Ctrl+C`).
4.  Restart **Node 1**:
    ```bash
    target/release/node --state-file state_node1.json
    ```
    Observe that it loads its state and identity, resuming from the correct block height. It will now be stalled, as it needs a quorum of 2 validators to produce blocks.

5.  Restart **Node 2** (using the new listening address from Node 1):
    ```bash
    target/release/node --state-file state_node2.json --peer <new_address_from_node1>
    ```
    Observe that Node 2 reconnects, syncs any blocks it missed, and the network resumes block production.

This workflow validates that node identities are persistent, state is correctly saved and loaded, and the consensus mechanism is tolerant to nodes stopping and restarting.

---

### Development & Testing

This project includes a suite of tests to ensure correctness and stability.

#### Running Unit & Integration Tests

To run the standard unit and integration tests for all crates in the workspace, use the following command:

```bash
cargo test --workspace
```

#### Running End-to-End (E2E) Tests

The repository includes long-running end-to-end tests that simulate a live multi-node network to verify complex lifecycles like governance and staking. These tests are ignored by default to keep the standard test runs fast.

To run the E2E tests, use the `--ignored` flag:

```bash
cargo test -p depin-sdk-binaries -- --ignored
```

This will execute tests such as:
*   `test_governance_authority_change_lifecycle`: Simulates a governance-driven change to the Proof-of-Authority validator set.
*   `test_staking_lifecycle`: Simulates a change in the Proof-of-Stake validator set based on staking and unstaking transactions.

These tests will compile the necessary node binaries with the appropriate consensus features before running.

---

### Project Structure

The SDK is organized into a workspace of several key crates:

*   `crates/core`: Defines the core traits and interfaces for all components (e.g., `CommitmentScheme`, `ValidatorModel`, `TransactionModel`).
*   `crates/binaries`: Contains the main executable targets, such as the `node` binary. This crate is the composition root for the application.
*   `crates/validator`: Implements the Triple-Container Architecture for both `StandardValidator` and `HybridValidator` models.
*   `crates/chain`: Contains the `SovereignAppChain` implementation, which defines the state machine logic.
*   `crates/sync`: Implements the `BlockSync` trait for P2P networking and block synchronization.
*   `crates/consensus`: Implements the `ConsensusEngine` trait for leader election and fault tolerance.
*   `crates/commitment_schemes`: Implementations of various cryptographic commitment schemes (Merkle, KZG, etc.).
*   `crates/state_trees`: Implementations of different state storage models (Verkle, IAVL+, file-based).
*   `crates/transaction_models`: Implementations for UTXO, Account, and Hybrid transaction models.
*   `crates/services`: Implementations of standard, pluggable services like Governance and the Semantic Layer.
*   `crates/crypto`: Low-level cryptographic primitives, including post-quantum algorithms.

### Roadmap

Our high-level roadmap is focused on incrementally building out the features defined in our architecture.

*   ✅ **Phase 3: Integrate Real Architecture & P2P Networking** - *Complete*
*   ➡️ **Phase 4: Activate Core Validator Logic** - *In Progress*
    *   Refine consensus and sync state machines and error handling.
    *   Implement real transaction execution and mempool logic.
*   ▶️ **Phase 5: Mainnet Hardening & Advanced Features**
    *   Implement the Post-Quantum Cryptography migration path and Identity Hub.
    *   Flesh out the Hybrid Validator model and tiered economics.
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