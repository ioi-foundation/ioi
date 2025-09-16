# DePIN SDK

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/depin-sdk/rust.yml?branch=main)](https://github.com/your-org/depin-sdk/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**The Framework for Sovereign Web4 Blockchains**

The DePIN SDK is a next-generation blockchain framework written entirely in Rust, designed to build high-performance, sovereign, and secure decentralized networks. It evolves beyond the Web3 paradigm of "read, write, own" to enable **Web4**: chains that can also **understand** user intent through a native, distributed AI agentic layer.

> 🎯 **Mission**: Provide the tools to build chains that are not just decentralized ledgers, but intelligent, autonomous partners in achieving complex goals.

## Table of Contents

- [Core Features](#core-features)
- [Architectural Overview](#architectural-overview)
- [Current Status](#current-status)
- [Quick Start](#quick-start)
- [Running a Manual Testnet](#running-a-manual-testnet)
- [Development & Testing](#development--testing)
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

The DePIN SDK follows an SDK-first methodology. Core components are provided as composable Rust crates, allowing developers to build custom, sovereign chains tailored to their specific use case. The foundation is the **Triple-Container Architecture**, ensuring strict separation of concerns and enhanced security.

📖 **For detailed architecture information, see the [Architectural Documentation](./docs)**

## Current Status

> ⚠️ **Important**: The project is currently in rapid prototyping phase. The `main` branch contains a functional implementation of the polymorphic framework.
>
> **The software is not yet mainnet-ready.**

### Implementation Status: Phase 4 - Polymorphic Framework & Core Logic

| Component | Status | Description |
|-----------|--------|-------------|
| ✅ Polymorphic Consensus | Complete | `orchestration` binary dynamically loads consensus engines (PoA, PoS) |
| ✅ Polymorphic State Management | Complete | `workload` binary acts as factory for state trees and commitment schemes |
| ✅ Feature-Gated Components | Complete | Compile-time features produce lean, specialized binaries |
| ✅ Dynamic Test Harness | Complete | `forge` crate builds clusters with different architectures |
| ✅ Comprehensive E2E Validation | Complete | Core polymorphic capabilities validated by concurrent chain tests |

**Next Phase**: Hardening foundation, refining transaction lifecycle, implementing advanced features.

## Quick Start

### Prerequisites

- **Rust**: Latest stable version via `rustup`
- **Build Tools**: C compiler (GCC or Clang)

### Build Example

```bash
# Build with PoA consensus and File state tree
cargo build -p depin-sdk-node --release --no-default-features \
    --features "build-bins,consensus-poa,vm-wasm,tree-file,primitive-hash"
```

Compiled binaries (`orchestration`, `workload`) will be in `target/release/`.

## Running a Manual Testnet

> 💡 **Recommended**: Use the automated E2E suite in the `forge` crate for testing. Manual setup is for experimentation.

### Step 1: Create Configuration Files

Create these files in your project root:

**`genesis.json`** (Replace with actual authority PeerIDs):
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

**`workload.toml`**:
```toml
enabled_vms = ["WASM"]
state_tree = "File"
commitment_scheme = "Hash"
consensus_type = "ProofOfAuthority"
genesis_file = "genesis.json"
state_file = "state.json" 
```

**`orchestration.toml`**:
```toml
consensus_type = "ProofOfAuthority"
rpc_listen_address = "127.0.0.1:9944"
initial_sync_timeout_secs = 5
```

### Step 2: Launch Two-Node Network

You'll need **4 terminals** for a two-node network:

#### Node 1
**Terminal 1 (Workload 1):**
```bash
WORKLOAD_IPC_ADDR=127.0.0.1:8555 ./target/release/workload --config ./workload.toml
```

**Terminal 2 (Orchestration 1):**
```bash
WORKLOAD_IPC_ADDR=127.0.0.1:8555 ./target/release/orchestration \
    --config ./orchestration.toml \
    --identity-key-file ./node1.key \
    --listen-address /ip4/127.0.0.1/tcp/0
```
> 📝 Note the listening address it prints (e.g., `/ip4/127.0.0.1/tcp/51234`)

#### Node 2
**Terminal 3 (Workload 2):**
```bash
WORKLOAD_IPC_ADDR=127.0.0.1:8556 ./target/release/workload --config ./workload.toml
```

**Terminal 4 (Orchestration 2):**
```bash
# Replace bootnode address with output from Terminal 2
WORKLOAD_IPC_ADDR=127.0.0.1:8556 ./target/release/orchestration \
    --config ./orchestration.toml \
    --identity-key-file ./node2.key \
    --listen-address /ip4/0.0.0.0/tcp/0 \
    --bootnode /ip4/127.0.0.1/tcp/51234
```

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

> 🔧 **Key Change**: You must specify features via `--features` flag. The harness automatically builds required artifacts.

Of course. Adding a new test to the documentation is a great way to ensure it's easy for others to run. I've added the "Polymorphism" test to the "Individual E2E Tests" section.

Here is the updated testing section for your `README.md`:

#### Individual E2E Tests

| Test | Command |
|------|---------|
| **Staking** | `cargo test -p depin-sdk-forge --release --features "consensus-pos,vm-wasm,tree-iavl,primitive-hash" --test staking_e2e -- --nocapture` |
| **Contract** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-iavl,primitive-hash" --test contract_e2e -- --nocapture` |
| **PQC Migration** | `cargo test -p depin-sdk-forge --release --features "consensus-pos,vm-wasm,tree-iavl,primitive-hash" --test pqc_migration_e2e -- --nocapture` |
| **Governance** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-file,primitive-hash" --test governance_e2e -- --nocapture` |
| **Module Upgrade** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-file,primitive-hash" --test module_upgrade_e2e -- --nocapture` |
| **Agentic Consensus** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-file,primitive-hash" --test agentic_consensus_e2e -- --nocapture` |
| **Oracle** | `cargo test -p depin-sdk-forge --release --features "consensus-pos,vm-wasm,tree-file,primitive-hash" --test oracle_e2e -- --nocapture --test-threads=1` |
| **Interoperability** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-file,primitive-hash" --test interop_e2e -- --nocapture` |

#### with logging ex:
RUST_LOG=info,depin_sdk_chain=debug,depin_sdk_validator=debug,depin_sdk_commitment=debug,depin_sdk_consensus=debug cargo test -p depin-sdk-forge --release --features="consensus-pos,vm-wasm,tree-iavl,primitive-hash" --test staking_e2e -- --nocapture

or

ORCH_BLOCK_INTERVAL_SECS=1 RUST_BACKTRACE=1 \
RUST_LOG=info,depin_sdk_validator=info,depin_sdk_validator::standard::orchestration=debug,depin_sdk_validator::standard::orchestration::consensus=debug,depin_sdk_network::libp2p=info,depin_sdk_commitment::tree::iavl=debug \
cargo test -p depin-sdk-forge --release --features="consensus-pos,vm-wasm,tree-iavl,primitive-hash,strict_iavl" --test staking_e2e -- --nocapture

#### Penalty Mechanism Tests

| Test | Command |
|------|---------|
| **PoS Slashing** | `cargo test -p depin-sdk-forge --release --features "consensus-pos,vm-wasm,tree-file,primitive-hash" --test penalty_pos_e2e -- --nocapture --test-threads=1` |
| **PoA Quarantine** | `cargo test -p depin-sdk-forge --release --features "consensus-poa,vm-wasm,tree-file,primitive-hash" --test penalty_poa_e2e -- --nocapture --test-threads=1` |

#### State Tree Backend Tests

| Backend | Command |
|---------|---------|
| **IAVL Tree** | `cargo test -p depin-sdk-forge --test state_iavl_e2e --no-default-features -F "consensus-poa,vm-wasm,tree-iavl,primitive-hash" -- --nocapture` |
| **Sparse Merkle** | `cargo test -p depin-sdk-forge --test state_sparse_merkle_e2e --no-default-features -F "consensus-poa,vm-wasm,tree-sparse-merkle,primitive-hash" -- --nocapture` |
| **Verkle Tree** | `cargo test -p depin-sdk-forge --test state_verkle_e2e --no-default-features -F "consensus-poa,vm-wasm,tree-verkle,primitive-kzg" -- --nocapture` |

### Docker Testing

For isolated testing environment:

```bash
# 1. Clean up
docker rm -f guardian orchestration workload
docker network prune -f

# 2. Remove old image
docker rmi depin-sdk-node:e2e

# 3. Rebuild with correct features
docker build \
  --build-arg FEATURES="validator-bins,consensus-poa,vm-wasm,tree-file,primitive-hash" \
  -t depin-sdk-node:e2e \
  -f crates/node/Dockerfile .

# 4. Run test
cargo test -p depin-sdk-forge --release \
  --features "consensus-poa,vm-wasm,tree-file,primitive-hash" \
  --test container_e2e -- --nocapture
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

### ✅ Phase 4: Polymorphic Framework & Core Logic
*Complete* - Established polymorphic architecture and validation

### ➡️ Phase 5: Mainnet Hardening & Advanced Features
*In Progress*
- Robust mempool and transaction validation
- State proof logic implementation
- Post-Quantum Cryptography migration path
- Identity Hub development
- Hybrid Validator model and tiered economics

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

This project is dual-licensed under:

- **Apache License 2.0** ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT License** ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

---

*Building the future of Web4* 🚀