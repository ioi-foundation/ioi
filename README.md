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
> **Implementation Status: Phase 3 - API Boundary Refactoring**
> *   ✅ **Clear API Boundary**: The core logic has been split into `depin-sdk-api` (stable traits) and `depin-sdk-core` (concrete data types), creating a compiler-enforced boundary.
> *   ✅ **Modular Crates**: Logic is decoupled into specialized crates (`chain`, `consensus`, `network`, etc.).
> *   ✅ **Node & Forge Separation**: The `node` crate acts as the production binary, while the `forge` crate provides a developer toolkit and houses all E2E tests.
> *   ✅ **P2P Networking**: `libp2p` integration is functional for peer discovery, block gossip, and state sync requests.
> *   ✅ **Consensus Engines**: Compile-time selectable consensus engines (PoA, PoS, Round Robin) are implemented and validated via E2E tests.
> *   ✅ **State Persistence**: A file-based state tree (`FileStateTree`) provides durable state for nodes.
>
> The next phase focuses on activating the core validator logic, including robust mempool management and transaction execution.

---

### Running a Manual Testnet

While the automated E2E tests in the `forge` crate are the recommended way to test changes, you can still run a manual multi-node network for experimentation.

#### Prerequisites

*   **Rust**: Ensure you have the latest stable version of Rust installed via `rustup`.
*   **Build Tools**: A C compiler, such as GCC or Clang, is required.
*   **(Optional) Docker**: Required if you wish to run tests using the Docker backend.

#### 1. Clone the Repository

```bash
git clone https://github.com/your-org/depin-sdk.git
cd depin-sdk
```

#### 2. Build the Node Binary

First, compile the node binary in release mode. You must choose a consensus engine at compile time using a feature flag.

```bash
# Example: Build with Proof of Authority
cargo build --release -p depin-sdk-node --features "build-bins,consensus-poa,vm-wasm"

# Example: Build with Proof of Stake
# cargo build --release -p depin-sdk-node --features "build-bins,consensus-pos,vm-wasm"
```

The compiled binary will be located at `target/release/depin-sdk-node`.

#### 3. Run a Multi-Node Network

This workflow uses two terminals to run a two-node network.

**Step 1: Full Reset (Optional)**

To start from a clean slate, you can remove previous state and identity files.

```bash
rm -f state_node*.json state_node*.json.identity.key
```

**Step 2: Run Node 1 (Terminal 1)**

This node will start as the genesis node. It will create state and identity files and print its listening address.

```bash
./target/release/depin-sdk-node orchestration \
    --config-dir ./crates/validator/config/templates \
    --state-file state_node1.json \
    --genesis-file ./crates/validator/config/templates/genesis.json
```

Note the listening address it prints, which will look like `/ip4/127.0.0.1/tcp/34677`.

**Step 3: Run Node 2 (Terminal 2)**

Use the listening address from Node 1 as a bootnode to connect.

```bash
# Replace the --bootnode address with the one you copied from Node 1
./target/release/depin-sdk-node orchestration \
    --config-dir ./crates/validator/config/templates \
    --state-file state_node2.json \
    --genesis-file ./crates/validator/config/templates/genesis.json \
    --listen-address /ip4/0.0.0.0/tcp/0 \
    --bootnode /ip4/127.0.0.1/tcp/34677
```

Node 2 will create its own unique state and identity files. You will see it connect to Node 1 and sync the blocks that Node 1 already produced.

---

### Development & Testing

The project includes a comprehensive suite of tests managed by the **`forge`** crate. This is the **recommended workflow** for all testing.

#### 1. Quick Check (Fastest)

For rapid feedback while developing, run `cargo check`. It analyzes the code for errors without compiling dependencies or running tests.

```bash
cargo check --workspace```

#### 2. Unit & Integration Tests

To run all unit and integration tests across the workspace (excluding the slower E2E tests), use the standard test command. This is ideal for pre-commit checks.

```bash
cargo test --workspace
```

#### 3. Full End-to-End (E2E) Test Suite

The `forge` crate contains the full E2E test suite, which programmatically builds and orchestrates multi-node clusters to simulate live network conditions.

**Key Feature**: The test harness **automatically builds all required artifacts** (node binaries, WASM contracts) with the correct features before the tests run.

**Run the Entire E2E Suite:**

This single command will execute all E2E tests. By default, it runs nodes as local processes for speed.

```bash
cargo test -p depin-sdk-forge -- --test-threads=1
```

**Run a Specific E2E Test File:**

To focus on a specific scenario, you can run a single test file. The `-- --nocapture` flag is recommended to see the detailed log output from the nodes.

```bash
# Run the staking and leader rotation test
cargo test -p depin-sdk-forge --test staking_e2e -- --nocapture

# Run the smart contract deployment and execution test
cargo test -p depin-sdk-forge --test contract_e2e -- --nocapture

# Run the governance and proposal tallying test
cargo test -p depin-sdk-forge --test governance_e2e -- --nocapture
```

**Running Tests with Docker:**

The test harness can also run nodes in Docker containers for a more isolated environment.

```bash
# 1. Clean up containers and networks
docker rm -f guardian orchestration workload
docker network prune -f

# 2. IMPORTANT: Remove the old image
docker rmi depin-sdk-node:e2e

# 3. Rebuild the image with the latest binaries
docker build -t depin-sdk-node:e2e -f crates/node/Dockerfile .

# 4. Run the test
cargo test -p depin-sdk-forge --test container_e2e -- --nocapture
```

---

### Project Structure

The SDK is organized into a workspace of several key crates:

*   `crates/api`: Defines the stable, public traits and interfaces for all components. This is the primary crate for plugin and implementation developers.
*   `crates/types`: Contains shared, concrete data structures (e.g., `Block`, `ChainTransaction`) and error types.
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

This project is licensed under

*   Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) http://www.apache.org/licenses/LICENSE-2.0)