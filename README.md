# IOI SDK

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/ioi/rust.yml?branch=main)](https://github.com/your-org/ioi/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**The Framework for Sovereign Web4 Blockchains**

The IOI SDK is a next-generation blockchain framework written entirely in Rust, designed to build high-performance, sovereign, and secure decentralized networks. It evolves beyond the Web3 paradigm of "read, write, own" to enable **Web4**: chains that can also **understand** user intent through a native, distributed AI agentic layer.

> 🎯 **Mission**: Provide the tools to build chains that are not just decentralized ledgers, but intelligent, autonomous partners in achieving complex goals.

## Table of Contents

- [Core Features](#core-features)
- [Architectural Overview](#architectural-overview)
- [Current Status](#current-status)
- [Quick Start](#quick-start)
- [Running a Manual Testnet](#running-a-manual-testnet)
- [Development & Testing](#development--testing)
- [Logging and Debugging](#logging-and-debugging)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Core Features

### 🧠 Web4 Agentic Layer
A validator native, distributed AI infrastructure that allows blockchains to interpret natural language, understand user intent, and execute complex agentic operations.

### 🛡️ Post-Quantum Security
A pragmatic, forward-thinking cryptographic architecture that is quantum-resistant from day one, featuring hybrid KEMs for transport security and a clear, non-disruptive migration path for on-chain signatures.

### ⛓️ True Sovereignty & Forkless Upgrades
Chains achieve sovereignty through compile-time module scaffolding, creating dependency-free binaries. A powerful runtime upgrade manager allows for hot-swapping any core service—including governance—without network halts.

### 🦀 Modular, Rust-Native Architecture
Built from the ground up in Rust for maximum safety, performance, and modularity. Every component, from consensus to the VM, is a pluggable service behind a standard trait.

### 🏛️ Triple-Container Validator Model
A defense-in-depth architecture that isolates responsibilities into:
- **Guardian Container** (security)
- **Orchestration Container** (consensus/networking)
- **Workload Container** (VM/transaction execution)

### 🌐 Consensus-Agnostic Security
A robust security model that provides strong guarantees through cryptography, reputation, and quarantine mechanisms, without relying solely on economic slashing. Adaptable to Proof-of-Stake, Proof-of-Work, Proof-of-Authority, and custom consensus models.

## Architectural Overview

The IOI SDK follows an SDK-first methodology. Core components are provided as composable Rust crates, allowing developers to build custom, sovereign chains tailored to their specific use case. The foundation is the **Triple-Container Architecture**, ensuring strict separation of concerns and enhanced security.

📖 **For detailed architecture information, see the [Architectural Documentation](./docs)**

## Current Status

> ⚠️ **Important**: The project is in an active development phase. The `main` branch contains a functional, end-to-end implementation of the polymorphic framework.
>
> **The software is not yet mainnet-ready.**

### Implementation Status: Phase 4 - Foundational Implementation

| Component | Status | Description |
|-----------|--------|-------------|
| ✅ Polymorphic Consensus | Complete | `orchestration` binary correctly dispatches to PoA and PoS engines based on config. |
| ✅ Polymorphic State | Complete | `workload` binary acts as a factory for state trees (IAVL, SMT, Verkle) and commitment schemes. |
| ✅ IPC-Based Validator | Complete | The triple-container model communicates securely via mTLS + PQC KEM. |
| ✅ Modular Services | Complete | Core services (Identity, Governance, Oracle) are functional and upgradable via on-chain governance. |
| ✅ E2E Test Harness | Complete | `forge` crate successfully builds and validates multi-node clusters with diverse configurations. |

**Next Phase**: Mainnet hardening, performance optimization, and expanding the service ecosystem.

## Quick Start

### Prerequisites

- **Rust**: Latest stable version via `rustup`
- **Build Tools**: C compiler (GCC or Clang), `protobuf-compiler`, `pkg-config`, `libssl-dev`

### Build Example

```bash
# Build with PoS consensus, IAVL state tree, and IBC support
cargo build -p ioi-node --release --no-default-features \
    --features "validator-bins,consensus-pos,vm-wasm,state-iavl,commitment-hash,ibc-deps"
```

Compiled binaries (`orchestration`, `workload`) will be in `target/release/`.

## Running a Manual Testnet

> 💡 **Recommended**: Use the automated E2E suite in the `forge` crate for testing. Manual setup is for experimentation.

### Step 0: Generate Certificates

Validator containers communicate over secure mTLS channels. Generate the necessary certificates first.

```bash
# This command will create a `certs` directory in your current location
CERTS_DIR=./certs ./target/release/guardian --config-dir . --agentic-model-path /dev/null
# You only need to run it once. Ignore the output after the certs are created.
# Press Ctrl+C to exit.
```

### Step 1: Create Configuration Files

Create these files in your project root. This example sets up a single Proof-of-Authority validator.

**`genesis.json`** (For a single validator)
```json
{
  "genesis_state": {
    "b64:aWRlbnRpdHk6OmNyZWRzOjpiNjg5M2FhN2FhMWU3Y2EzYjZkZTllZTA2ODU4MDQ0MzI1N2ZmMzU0YmMzYjJmMWU2NDFhNzFhMjY2Yzk5MjZl": "b64:BQAAAAABAAACAAAG0qO5kS06i2hJ+m/gU5Jc8yR+i+Z8jVlT1uC169LJAQAAAAAAAAAA",
    "b64:aWRlbnRpdHk6OmtleV9yZWNvcmQ6OmI2ODkzYWE3YWExZTdjYTNiNmRlOWVlMDY4NTgwNDQzMjU3ZmYzNTRiYzNiMmYxZTY0MWE3MWEyNjZjOTkyNmU=": "b64:AAAG0qO5kS06i2hJ+m/gU5Jc8yR+i+Z8jVlT1uC169LJAQAAAAAAAAA=",
    "b64:aWRlbnRpdHk6OnB1YmtleTo6YjY4OTNhYTdhYTFlN2NhM2I2ZGU5ZWUwNjg1ODA0NDMyNTdmZjM1NGJjM2IyZjFlNjQxYTcxYTI2NmM5OTI2ZQ==": "b64:CAESIMf0pY2q39pGzRkQDIaVoh2Bztx3C9zFjYqP/sS9xZ5X",
    "system::validators::current": "b64:AgQAAAAAAAABAAAAAAAAAAEAAAAAABiNqO5kS06i2hJ+m/gU5Jc8yR+i+Z8jVlT1uC169LJAQAAAAAAAACAAACAAAYjajqZUtOotoSfpv4FOSXPMkforifI1ZU9bgtevSyQEAAAAAAAAAA"
  }
}
```

**`workload.toml`**:
```toml
runtimes = ["WASM"]
state_tree = "IAVL"
commitment_scheme = "Hash"
consensus_type = "ProofOfAuthority"
genesis_file = "genesis.json"
state_file = "state.db"
epoch_size = 100
```

**`orchestration.toml`**:
```toml
chain_id = 1
consensus_type = "ProofOfAuthority"
rpc_listen_address = "127.0.0.1:9944"
initial_sync_timeout_secs = 5
```

### Step 2: Launch a Single Node

You'll need **2 terminals** for a single-node network:

**Terminal 1 (Workload):**
```bash
CERTS_DIR=./certs IPC_SERVER_ADDR=127.0.0.1:8555 \
./target/release/workload --config ./workload.toml
```

**Terminal 2 (Orchestration):**
```bash
# This command generates `node1.key` on first run.
CERTS_DIR=./certs WORKLOAD_IPC_ADDR=127.0.0.1:8555 \
./target/release/orchestration \
    --config ./orchestration.toml \
    --identity-key-file ./node1.key \
    --listen-address /ip4/127.0.0.1/tcp/9000
```
> 📝 For a multi-node setup, adjust ports and use the `--bootnode` flag as shown in the E2E tests.

## Development & Testing

Testing centers around the **`forge`** crate, providing powerful declarative E2E testing.

### 1. Quick Check (Fastest)
```bash
cargo check --workspace
```

### 2. Unit & Integration Tests
```bash
cargo test --workspace
```

### 3. End-to-End Test Suite

> 🔧 **Key Change**: You must specify features via the `--features` flag. The test harness automatically builds the required node binaries with those features.

#### Core E2E Tests

| Test | Command |
|------|---------|
| **Staking** | `cargo test -p ioi-forge --release --features "consensus-pos,vm-wasm,state-iavl,commitment-hash" --test staking_e2e -- --nocapture` |
| **Contract** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test contract_e2e -- --nocapture` |
| **PQC Migration** | `cargo test -p ioi-forge --release --features "consensus-pos,vm-wasm,state-iavl,commitment-hash" --test pqc_migration_e2e -- --nocapture` |
| **Governance** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test governance_e2e -- --nocapture` |
| **Module Upgrade** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test module_upgrade_e2e -- --nocapture` |
| **Service Architecture** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test service_architecture_e2e -- --nocapture` |
| **Agentic Consensus** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test agentic_consensus_e2e -- --nocapture --test-threads=1` |
| **Oracle** | `cargo test -p ioi-forge --release --features "consensus-pos,vm-wasm,state-iavl,commitment-hash" --test oracle_e2e -- --nocapture` |
| **Deterministic Timestamps** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test t_timestamp_coherence -- --nocapture` |

#### Penalty Mechanism Tests

| Test | Command |
|------|---------|
| **PoS Slashing** | `cargo test -p ioi-forge --release --features "consensus-pos,vm-wasm,state-iavl,commitment-hash" --test penalty_pos_e2e -- --nocapture --test-threads=1` |
| **PoA Quarantine** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" --test penalty_poa_e2e -- --nocapture --test-threads=1` |

#### State Tree Backend Tests

| Backend | Command |
|---------|---------|
| **IAVL Tree** | `cargo test -p ioi-forge --test state_iavl_e2e --no-default-features -F "consensus-poa,vm-wasm,state-iavl,commitment-hash" -- --nocapture` |
| **Sparse Merkle** | `cargo test -p ioi-forge --test state_sparse_merkle_e2e --no-default-features -F "consensus-poa,vm-wasm,state-sparse-merkle,commitment-hash" -- --nocapture` |
| **Verkle Tree** | `cargo test -p ioi-forge --test state_verkle_e2e --no-default-features -F "consensus-poa,vm-wasm,state-verkle,commitment-kzg" -- --nocapture` |

#### Specialized & Infrastructure Tests

| Test | Command |
|------|---------|
| **IBC Gateway Metrics** | `GATEWAY_CHAIN_ID=localnet-1 cargo run -p ioi-node && curl -s localhost:9100/metrics | grep ioi_ibc_gateway_` |
| **Interopability** | `cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash,ibc-deps" --test ibc_e2e -- --nocapture` |
| **Update IBC Golden Files** | `UPDATE_GOLDENS=1 cargo test -p ioi-forge --release --features "consensus-poa,vm-wasm,state-iavl,commitment-hash,ibc-deps" --test ibc_golden_e2e -- --nocapture` |
| **IBC Relayer E2E** | `RUST_LOG=trace RUST_BACKTRACE=1 cargo test -p ioi-forge --release  --features "consensus-poa,vm-wasm,state-iavl,commitment-hash,ibc-deps"  --test ibc_relayer_e2e -- --nocapture 2>&1 | tee /tmp/e2e.log` |
| **Proof Verification** | `cargo test -p ioi-forge --test proof_verification_e2e --features "consensus-poa,vm-wasm,state-iavl,commitment-hash,malicious-bin" -- --nocapture` |
| **Network Sync** | `cargo test --package ioi-forge --test sync_e2e --features "consensus-poa,vm-wasm,state-iavl" -- --nocapture --test-threads=1` |
| **Infrastructure (+Metrics)** | `RUST_LOG=trace,ioi_client::workload_client=trace,ioi_client::security=trace,ioi_client::workload_client::actor=trace \
cargo test -p ioi-forge --test infra_e2e --features "consensus-poa,vm-wasm,state-iavl" -- --nocapture --test-threads=1` |

### Docker Testing

For an isolated testing environment:

```bash
# 1. Clean up
docker rm -f guardian orchestration workload
docker network prune -f

# 2. Remove old image
docker rmi ioi-node:e2e

# 3. Rebuild with correct features
docker build \
  --build-arg FEATURES="validator-bins,consensus-poa,vm-wasm,state-iavl,commitment-hash" \
  -t ioi-node:e2e \
  -f crates/node/Dockerfile .

# 4. Run test
cargo test -p ioi-forge --release \
  --features "consensus-poa,vm-wasm,state-iavl,commitment-hash" \
  --test container_e2e -- --nocapture
```


## Logging and Debugging

The SDK uses the `tracing` framework to produce structured JSON logs. This modern approach is more powerful than traditional text-based logging, allowing for rich, queryable output that can be analyzed with tools like `jq`.

### The New Workflow: Capture First, Filter Later

Instead of pre-filtering logs with complex `RUST_LOG` strings, the recommended workflow is to capture detailed logs and then use post-processing tools to analyze them.

1.  **Run your test and capture all `info`-level logs:**

    ```bash
    RUST_LOG=info cargo test -p ioi-forge --test <your_test_name> -- --nocapture | tee test_run.log
    ```

2.  **Analyze the log file with `jq`:**
    `jq` is a command-line JSON processor. You can use it to slice, filter, and transform the log data.

    **Example Log Entry:**
    ```json
    {
        "timestamp": "2025-09-24T04:08:47.515838Z",
        "level": "INFO",
        "fields": {
            "message": "[PoS Decide H=1] DECISION: We are not the leader. Will WaitForBlock.",
            "log.target": "ioi_consensus::proof_of_stake",
            "log.module_path": "ioi_consensus::proof_of_stake",
            "log.file": "/workspaces/ioi/crates/consensus/src/proof_of_stake.rs",
            "log.line": 251
        },
        "target": "ioi_consensus::proof_of_stake"
    }
    ```

### Common Logging Recipes with `jq`

Here are some useful commands for debugging different parts of the system using the captured `test_run.log` file.

#### High-Level Overview
See only the high-level events from the orchestration, consensus, and chain modules.

```bash
# Filter by the 'target' field
cat test_run.log | jq 'select(.target | contains("orchestration") or contains("consensus") or contains("chain"))'
```

#### Tracing a Specific Block
Show all log entries related to the production or processing of block #3.

```bash
# Filter by the 'fields.height' value
cat test_run.log | jq 'select(.fields.height == 3)'
```

#### Isolate Consensus Decisions
View only the final decision made by the consensus engine in each tick.

```bash
# Filter by the 'fields.event' value
cat test_run.log | jq 'select(.fields.event == "decision")'
```

#### Verbose Debugging (When Needed)
While `RUST_LOG=info` is a good default, you can temporarily enable more verbose logging for a specific module if needed. This is useful for deep-diving into state tree or consensus issues without being flooded by noise from other modules.

```bash
# Enable trace-level logging ONLY for the IAVL tree and consensus logic
RUST_LOG=info,ioi_state::tree::iavl=trace,ioi_validator::standard::orchestration::consensus=trace \
cargo test ... -- --nocapture | tee deep_debug.log
```

You can then use `jq` on `deep_debug.log` to analyze the highly detailed output from just those modules.

### Enabling Full Panic Backtraces

For diagnosing crashes, it's useful to get a full stack trace.

```bash
RUST_BACKTRACE=1 cargo test ...
```

## Project Structure

```
crates/
├── api/              # Public traits and interfaces
├── types/            # Shared data structures and configs
├── node/             # Main executables (orchestration, workload, guardian)
├── forge/            # E2E testing harness and developer toolkit
├── contract/         # no_std SDK for WASM smart contracts
├── validator/        # Triple-Container Architecture implementation
├── chain/            # Chain state machine logic
└── ...              # Specialized implementation crates
```

### Key Crates

- **`api`**: Stable, public traits and interfaces
- **`types`**: Concrete data structures (`Block`, `ChainTransaction`) and configs
- **`node`**: Main executables and composition root
- **`forge`**: Developer toolkit and E2E testing library
- **`contract`**: Smart contract SDK for WASM compilation
- **`validator`**: Triple-Container Architecture
- **`chain`**: State machine implementation

## Roadmap

### ✅ Phase 4: Foundational Implementation
*Complete* - Established polymorphic architecture, IPC-based validator model, and comprehensive E2E validation with the `forge` crate.

### ➡️ Phase 5: Mainnet Hardening & Advanced Features
*In Progress*
- Robust mempool and transaction validation.
- State proof logic implementation and verification.
- Post-Quantum Cryptography migration path demonstrated.
- Identity Hub and on-chain Governance services implemented.
- Hybrid Validator model and tiered economics.

### ▶️ Phase 6: Ecosystem Expansion & Evolution
*Planned*
- `forge` CLI and multi-language SDKs
- IBC and Ethereum compatibility modules
- Production-ready distributed AI for agentic Layer

## Contributing

We welcome community contributions! 🎉

- 📖 Read our [Contributing Guide](./CONTRIBUTING.md)
- 📋 Follow our [Code of Conduct](./CODE_OF_CONDUCT.md)
- 🐛 Report issues on GitHub
- 💡 Propose new features via discussions

## License

The IOI SDK is released under a **hybrid open-source model** designed to balance transparency, community adoption, and protection against direct framework cloning.

### 🧩 Licensing Overview

| Layer                                         | Scope                                                                        | License                                                                                     |
| --------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| **Core Cryptography & Primitives**            | Foundational crates (`crypto`, `commitment`, `homomorphic`, `types`)         | **Apache License 2.0** — fully open source and freely reusable.                             |
| **Framework & Validator Orchestration Layer** | Core SDK crates (`api`, `chain`, `validator`, `node`, `network`, `services`) | **IOI Business Source License 1.1 (BBSL)** — source-available with limited use restriction. |
| **Developer & Testing Tools**                 | Tooling crates (`forge`, `contract`)                                         | **Apache License 2.0** — open for integration, testing, and research.                       |

### ⚖️ Summary of Terms

* The **BBSL** grants broad rights to use, modify, and deploy the IOI SDK for any purpose, **including**:

  * Building and launching **sovereign Layer-1 or Layer-2 blockchains**.
  * Developing **agentic**, **DePIN**, **AI**, or **application-specific** chains.
  * Running validators, governance systems, or distributed AI networks.
* The **only restriction** is that the IOI SDK **may not be used to create or distribute a competing blockchain development framework or SDK** whose primary purpose is to enable third parties to build blockchains or validator frameworks in direct competition with IOI.
* All restrictions automatically terminate, and the license converts to **Apache 2.0**, on **November 6, 2029**.
* All cryptographic and protocol crates are **already Apache 2.0 today** and can be freely reused or audited.

### 🔐 Legal Text

* **Business Source License:** [`LICENSE-BBSL`](./LICENSE-BBSL)
* **Apache 2.0 License:** [`LICENSE-APACHE`](http://www.apache.org/licenses/LICENSE-2.0)
* © 2025 IOI Foundation. All rights reserved.


---

*Building the future of Web4* 🚀