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

> **Note**: The project is currently in a rapid, prototyping phase. The `main` branch contains a functional implementation of the polymorphic framework.
>
> **The software is not yet mainnet-ready.**
>
> **Implementation Status: Phase 4 - Polymorphic Framework & Core Logic**
> *   ✅ **Polymorphic Consensus:** The `orchestration` binary now dynamically loads its consensus engine (PoA, PoS) based on its configuration file.
> *   ✅ **Polymorphic State Management:** The `workload` binary acts as a factory, instantiating its state tree and commitment scheme (e.g., `FileStateTree<HashCommitmentScheme>`) based on its configuration file.
> *   ✅ **Feature-Gated Components:** Compile-time features (`consensus-pos`, `tree-file`, etc.) are used to include only the necessary backend implementations, producing lean, specialized binaries.
> *   ✅ **Dynamic Test Harness:** The `forge` crate's `TestClusterBuilder` can now declaratively build and launch clusters with different architectures (PoA on File vs. PoS on HashMap, etc.).
> *   ✅ **Comprehensive E2E Validation:** The core polymorphic capabilities are validated by an E2E test that runs two architecturally distinct chains concurrently, proving the success of the refactor.
>
> The project has successfully established its core polymorphic architecture. The next phase will focus on hardening this foundation, refining the transaction lifecycle, and implementing more advanced features.

---

### Running a Manual Testnet

**Note:** The recommended method for testing is the automated E2E suite in the `forge` crate. The following instructions are for manual experimentation and demonstrate the new configuration-based workflow.

#### Prerequisites

*   **Rust**: Ensure you have the latest stable version of Rust installed via `rustup`.
*   **Build Tools**: A C compiler, such as GCC or Clang.

#### 1. Build the Node Binaries

Compile the node binaries in release mode. You must enable the features for the components you wish to use.

```bash
# Example: Build with PoA consensus and the File state tree
cargo build -p depin-sdk-node --release --no-default-features \
    --features "build-bins,consensus-poa,vm-wasm,tree-file,primitive-hash"
```

The compiled binaries (`orchestration`, `workload`) will be in `target/release/`.

#### 2. Configure and Run a Two-Node Network

This workflow requires four terminals to run a two-node network (one `orchestration` and one `workload` process per node).

**Step 1: Create Shared Configs and Genesis**

Create the following three files in your project root.

1.  **`genesis.json`** (Replace with your actual authority PeerIDs)
    ```json
    {
      "genesis_state": {
        "system::authorities": [
          [2, ...], 
          [2, ...]
        ]
      }
    }
    ```

2.  **`workload.toml`**
    ```toml
    enabled_vms = ["WASM"]
    state_tree = "File"
    commitment_scheme = "Hash"
    genesis_file = "genesis.json"
    state_file = "state.json" 
    ```

3.  **`orchestration.toml`**
    ```toml
    consensus_type = "ProofOfAuthority"
    rpc_listen_address = "127.0.0.1:9944"
    initial_sync_timeout_secs = 5
    ```

**Step 2: Run Node 1**

*   **Terminal 1 (Workload 1):**
    ```bash
    WORKLOAD_IPC_ADDR=127.0.0.1:8555 ./target/release/workload --config ./workload.toml
    ```
*   **Terminal 2 (Orchestration 1):**
    ```bash
    WORKLOAD_IPC_ADDR=127.0.0.1:8555 ./target/release/orchestration \
        --config ./orchestration.toml \
        --identity-key-file ./node1.key \
        --listen-address /ip4/127.0.0.1/tcp/0
    ```
    Note the listening address it prints, e.g., `/ip4/127.0.0.1/tcp/51234`.

**Step 3: Run Node 2**

*   **Terminal 3 (Workload 2):** Use a different IPC address.
    ```bash
    WORKLOAD_IPC_ADDR=127.0.0.1:8556 ./target/release/workload --config ./workload.toml
    ```
*   **Terminal 4 (Orchestration 2):** Use the address from Node 1 as a bootnode.
    ```bash
    # Replace the --bootnode address with the one from Terminal 2
    WORKLOAD_IPC_ADDR=127.0.0.1:8556 ./target/release/orchestration \
        --config ./orchestration.toml \
        --identity-key-file ./node2.key \
        --listen-address /ip4/0.0.0.0/tcp/0 \
        --bootnode /ip4/127.0.0.1/tcp/51234
    ```

---

### Development & Testing

The project's testing workflow is centered around the **`forge`** crate, which provides a powerful, declarative E2E testing harness. This is the **recommended workflow** for all testing.

#### 1. Quick Check (Fastest)

For rapid feedback while developing, run `cargo check`.

```bash
cargo check --workspace
```

#### 2. Unit & Integration Tests

To run all fast tests across the workspace (excluding E2E tests), use:

```bash
cargo test --workspace
```

#### 3. Full End-to-End (E2E) Test Suite

The `forge` crate contains the E2E test suite. The key change is that **you must now specify which features to test via the `--features` flag.**

**Key Feature**: The test harness **automatically builds all required artifacts** (node binaries, WASM contracts) with the correct features before the tests run.

**Run a Specific E2E Test (New Workflow):**

You must provide the features that the test file requires. The `-- --nocapture` flag is recommended to see detailed log output from the nodes.


---

#### 1. `staking_e2e.rs`

*   **New Command:**
    ```bash
    cargo test -p depin-sdk-forge --release \
    --features "consensus-pos,vm-wasm,tree-file,primitive-hash" \
    --test staking_e2e -- --nocapture
    ```

---

#### 2. `contract_e2e.rs`

*   **New Command:**
    ```bash
    cargo test -p depin-sdk-forge --release \
    --features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
    --test contract_e2e -- --nocapture
    ```

---

#### 3. `governance_e2e.rs`

*   **New Command:**
    ```bash
    cargo test -p depin-sdk-forge --release \
    --features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
    --test governance_e2e -- --nocapture    
```

---

#### 4. `module_upgrade_e2e.rs`

*   **New Command:**
    ```bash
    cargo test -p depin-sdk-forge --release \
    --features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
    --test module_upgrade_e2e -- --nocapture
    ```

---

#### 5. `semantic_consensus_e2e.rs`

*   **New Commands:**
    ```bash

    # For semantic_consensus_e2e
cargo test -p depin-sdk-forge --release \
--features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
--test semantic_consensus_e2e -- --nocapture
    ```

#### 6. `oracle_e2e.rs`

*   **New Commands:**
    ```bash
    # For oracle_e2e
cargo test -p depin-sdk-forge --release --features "consensus-pos,vm-wasm,tree-file,primitive-hash" --test oracle_e2e -- --nocapture --test-threads=1
    ```


#### Running Tests with Docker:

#### The test harness can also run nodes in Docker containers for a more isolated environment.

```bash
# 1. Clean up containers and networks
docker rm -f guardian orchestration workload
docker network prune -f

# 2. IMPORTANT: Remove the old image
docker rmi depin-sdk-node:e2e

# 3. Rebuild the image with the correct features for the test
#    Note the new --build-arg flag!
docker build \
  --build-arg FEATURES="build-bins,consensus-poa,vm-wasm,tree-file,primitive-hash" \
  -t depin-sdk-node:e2e \
  -f crates/node/Dockerfile .

# 4. Run the test (this command remains the same)
cargo test -p depin-sdk-forge --release \
  --features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
  --test container_e2e -- --nocapture
    ```

**Run All E2E Tests:**

To run the entire suite, you must enable all features that the tests depend on.

```bash
cargo test -p depin-sdk-forge --release \
    --features "consensus-poa,consensus-pos,vm-wasm,tree-file,tree-hashmap,primitive-hash" \
    -- --nocapture --test-threads=1
```

---

### Project Structure

The SDK is organized into a workspace of several key crates:

*   `crates/api`: Defines the stable, public traits and interfaces for all components.
*   `crates/types`: Contains shared, concrete data structures (e.g., `Block`, `ChainTransaction`) and configuration structs.
*   `crates/node`: Contains the main executables (`orchestration`, `workload`, `guardian`). This crate is the composition root for the application.
*   `crates/forge`: A developer toolkit providing a library with helpers for E2E testing. It is the primary consumer of the SDK's public APIs.
*   `crates/contract`: The `no_std` SDK for writing smart contracts that compile to WASM.
*   `crates/validator`: Implements the Triple-Container Architecture for validator models.
*   `crates/chain`: Contains the `Chain` implementation, which defines the state machine logic.
*   ... and other specialized implementation crates (`consensus`, `network`, `commitment`, etc.).

### Roadmap

Our high-level roadmap is focused on incrementally building out the features defined in our architecture.

*   ✅ **Phase 4: Polymorphic Framework & Core Logic** - *Complete*
*   ➡️ **Phase 5: Mainnet Hardening & Advanced Features** - *In Progress*
    *   Implement robust mempool, transaction validation, and state proof logic.
    *   Flesh out the Post-Quantum Cryptography migration path and Identity Hub.
    *   Develop the Hybrid Validator model and tiered economics.
*   ▶️ **Phase 6: Ecosystem Expansion & Evolution**
    *   Develop the `forge` CLI and multi-language SDKs.
    *   Implement IBC and Ethereum compatibility modules.
    *   Integrate production-ready distributed AI models for the Semantic Layer.

### Contributing

We welcome contributions from the community! If you're interested in helping build the future of Web4, please read our [**Contributing Guide**](./CONTRIBUTING.md) to get started.

All participants are expected to follow our [**Code of Conduct**](./CODE_OF_CONDUCT.md).

### License

This project is licensed under either of:

*   Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
*   MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)