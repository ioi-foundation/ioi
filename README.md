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
>
> **Implementation Status: Phase 3 - Integrated Architecture**
> *   ✅ **Core Traits & Types**: `depin-sdk-core` provides a stable foundation for traits.
> *   ✅ **Modular Crates**: Logic is decoupled into specialized crates (`chain`, `consensus`, `network`, etc.).
> *   ✅ **Node & Forge Separation**: The `node` crate acts as the production binary, while the `forge` crate provides a developer toolkit and houses all E2E tests.
> *   ✅ **P2P Networking**: `libp2p` integration is functional for peer discovery, block gossip, and state sync requests.
> *   ✅ **Consensus Engines**: Compile-time selectable consensus engines (PoA, PoS, Round Robin) are implemented and validated via E2E tests.
> *   ✅ **State Persistence**: A file-based state tree (`FileStateTree`) provides durable state for nodes.
>
> The next phase focuses on activating the core validator logic, including robust mempool management and transaction execution.

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
mkdir -p examples/config

# Create a minimal orchestration.toml. The RPC address is now configured here.
echo 'consensus_type = "ProofOfAuthority"' > examples/config/orchestration.toml
echo 'rpc_listen_address = "127.0.0.1:9944"' >> examples/config/orchestration.toml

# Create a minimal guardian.toml
echo 'signature_policy = "FollowChain"' > examples/config/guardian.toml
```

#### 3. Build the Node Binary

First, compile the project in release mode. This creates the `node` binary we'll use for testing.

**Crucially, you must now choose a consensus engine at compile time using a feature flag.** This ensures the final binary is lean and optimized for a specific purpose.

**Option A: Build with Round Robin BFT Consensus**

This engine is suitable for networks where all validators are known and trusted, and it includes logic for fault tolerance (view changes) if a leader goes offline.

```bash
cargo build --release -p depin-sdk-node --features consensus-round-robin,vm-wasm
```

**Option B: Build with Proof of Authority (PoA) Consensus**

This is a simpler engine that relies on a fixed, on-chain list of authorities. It does not include fault tolerance logic beyond simple leader rotation.

```bash
cargo build --release -p depin-sdk-node --features consensus-poa,vm-wasm
```

**Option C: Build with Proof of Stake (PoS) Consensus**

This engine selects block producers based on their staked token amount, providing a decentralized and permissionless security model.

```bash
cargo build --release -p depin-sdk-node --features consensus-pos,vm-wasm
```

The compiled binary will be located at `target/release/node`.

#### 4. Local Testnet Workflow

This workflow will guide you through running a two-node network. You will need two terminals.

**Step 1: Full Reset (Optional)**

To start from a clean slate, you can remove all previous state and identity files.

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

Node 2 will create its own unique state and identity files. You will see it connect to Node 1 and sync the blocks that Node 1 already produced.

---

### Development & Testing

The project includes a comprehensive suite of tests to ensure correctness and stability. The new `forge` crate is central to this workflow.

#### 1. Quick Check (Fastest)

For rapid feedback while developing, run `cargo check`. It analyzes the code for errors without compiling dependencies or running tests.

```bash
cargo check --workspace
```

#### 2. Standard Tests

To run all unit and integration tests across the entire workspace (excluding the slow end-to-end tests), use the standard test command. This is ideal for pre-commit checks.

```bash
cargo test --workspace
```

#### 3. Full E2E Test Suite

The repository includes long-running end-to-end (E2E) tests that simulate a live multi-node network. **These tests now live in the `forge` crate** and are ignored by default.

To run the **entire E2E test suite**, use this single command:

```bash
cargo test -p depin-sdk-forge -- --ignored
```

To run a **specific E2E test** (e.g., the staking lifecycle test):

```bash
cargo test -p depin-sdk-forge --test staking_e2e -- --ignored --nocapture
```

These commands will execute critical E2E scenarios, including:
*   `test_governance_authority_change_lifecycle`: Simulates a governance-driven change to the Proof-of-Authority validator set.
*   `test_staking_lifecycle`: Simulates a change in the Proof-of-Stake validator set based on `Stake` and `Unstake` transactions.

These tests automatically compile the necessary `node` binaries with the appropriate consensus features before running.

---

### Project Structure

The SDK is organized into a workspace of several key crates:

*   `crates/core`: Defines the core traits and interfaces for all components.
*   `crates/node`: Contains the main executable for the production validator. This crate is the composition root for the application.
*   `crates/forge`: A developer toolkit that provides a CLI and a library with helpers for E2E testing. It is the primary consumer of the SDK's public APIs.
*   `crates/contract`: The `no_std` SDK for writing smart contracts that compile to WASM.
*   `crates/validator`: Implements the Triple-Container Architecture for validator models.
*   `crates/chain`: Contains the `Chain` implementation, which defines the state machine logic.
*   ... and other specialized implementation crates.

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
    *   Develop the `forge` CLI and multi-language SDKs.
    *   Implement IBC and Ethereum compatibility modules.
    *   Integrate production-ready distributed AI models.

### Contributing

We welcome contributions from the community! If you're interested in helping build the future of Web4, please read our [**Contributing Guide**](./CONTRIBUTING.md) to get started.

All participants are expected to follow our [**Code of Conduct**](./CODE_OF_CONDUCT.md).

### License

This project is licensed under either of

*   Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
at your option.