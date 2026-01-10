# IOI: Internet of Intelligence

![Status](https://img.shields.io/badge/status-pre--alpha-orange)
![License](https://img.shields.io/badge/license-BBSL-blue)
![Architecture](https://img.shields.io/badge/architecture-runtime--first-green)

**IOI is the Operating System for Agency.**

It is a runtime-first protocol that democratizes **Web4: The capacity to Act.** While Web3 democratized value, IOI provides the verifiable infrastructure for software agents to interpret intent, orchestrate resources, and execute economic actions across the open economy.

IOI transforms probabilistic AI inference into **Deterministic Agentic Finality**. By treating the blockchain not as the CPU for cognition, but as the "High Court" for enforcement, IOI creates a global marketplace where autonomous systems can be trusted with value, rights, and liability.

---

## 📚 Table of Contents

- [Core Concepts](#-core-concepts)
- [Architecture](#-architecture)
    - [The Triadic Kernel](#the-triadic-kernel)
    - [Fractal Topology](#fractal-topology)
- [Repository Structure](#-repository-structure)
- [Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Building from Source](#building-from-source)
    - [Running a Local Devnet](#running-a-local-devnet)
- [Developing Agents](#-developing-agents)
- [Cryptography & Security](#-cryptography--security)
- [License](#-license)

---

## 💡 Core Concepts

The IOI protocol solves the **"Sandboxing Paradox"**—where agents are either safe but useless (trapped in a browser) or useful but dangerous (running as root scripts).

1.  **Agency Firewall:** A deterministic policy engine that intercepts agent I/O (`net::fetch`, `fs::write`, `wallet::sign`), enforcing user-defined constraints before execution.
2.  **Verification Ladder:** A spectrum of trust. Agents execute locally for free (**Rung 0**), execute optimistically in sessions (**Rung 1**), and escalate to on-chain ZK proofs or arbitration only when high-value settlement is required (**Rung 3/4**).
3.  **Labor Gas:** The currency of the network. Unlike blockspace gas, Labor Gas pays for *inference*, *readiness*, and *liability insurance*.
4.  **Sovereign Context Substrate (SCS):** Privacy-preserving context injection. Agents work against encrypted slices of user data, ensuring the full corpus never leaves the device.

---

## 🏗 Architecture

### The Triadic Kernel
Every node in the IOI network (User, Provider, or Validator) runs the **Triadic Kernel**, a user-space hypervisor composed of three isolated processes:

1.  **Guardian (`crates/node/src/bin/guardian.rs`):**
    *   Hardware-anchored root of trust (TEE/TPM).
    *   Holds identity keys and enforces **Non-Equivocation** via monotonic counters.
    *   Signs the audit log of all actions.
2.  **Orchestrator (`crates/node/src/bin/orchestration.rs`):**
    *   The control plane and **Agency Firewall**.
    *   Manages the memeory pool, networking, and policy enforcement.
    *   Routes intents to local hardware or the Burst Network.
3.  **Workload (`crates/node/src/bin/workload.rs`):**
    *   The ephemeral sandbox where "Alien Intelligence" (AI Models/Scripts) runs.
    *   Communicates via Shared Memory (Zero-Copy) for high throughput.

### Fractal Topology
IOI is **Edge-In**, not Server-Out.
*   **Mode 0 (Local):** Runs on your laptop (`ioi-local`). Zero latency, full privacy.
*   **Mode 1 (Session):** Burst to a Provider via p2p state channels for heavy compute (e.g., H100 GPU).
*   **Mode 2 (Global):** The Mainnet. Used only for settlement, bonding, and dispute resolution.

---

## 📂 Repository Structure

The codebase is organized as a Rust workspace with an Agent SDK in Python.

### Core Protocol (`crates/`)
| Crate | Description |
| :--- | :--- |
| **`api`** | Core traits (`ChainStateMachine`, `CommitmentScheme`, `TransactionModel`) and interfaces. |
| **`cli`** | The `ioi` developer toolchain. Handles scaffolding, testing, and devnets. |
| **`consensus`** | Implements **A-DMFT** (Adaptive Deterministic Mirror Fault Tolerance). |
| **`crypto`** | Post-Quantum primitives (ML-DSA, Kyber), BLS12-381, and Ed25519. |
| **`execution`** | The execution environment, including **Block-STM**-style parallel execution (`mv_memory`). |
| **`ibc-host`** | Universal Interoperability implementation (ICS-23, ICS-24, ICS-26). |
| **`ipc`** | Inter-Process Communication using **gRPC** (Control) and **rkyv** (Shared Memory Data Plane). |
| **`networking`** | Libp2p stack for block sync, gossipsub, and request-response. |
| **`node`** | Entry points for the binaries (`orchestration`, `workload`, `guardian`, `ioi-local`). |
| **`services`** | Native WASM modules: `Governance`, `IdentityHub`, `ProviderRegistry`, `IBC`. |
| **`state`** | Pluggable state trees: **IAVL**, **Jellyfish**, **Verkle**, **SparseMerkle**, and **mHNSW**. |
| **`storage`** | Persistent storage layer based on **redb** with WAL support. |
| **`tx`** | Transaction models (`UnifiedTransactionModel`, `SettlementModel`). |
| **`validator`** | Container architecture logic (Standard vs. Hybrid validators). |
| **`vm/wasm`** | Wasmtime-based runtime for smart contracts and services. |
| **`zk-driver-succinct`** | Drivers for verifying SP1 / Succinct zero-knowledge proofs. |

### SDKs
| Path | Description |
| :--- | :--- |
| **`agent-sdk/python`** | Python bindings for building agents that interface with the IOI Kernel. |

---

## 🚀 Getting Started

### Prerequisites
*   **Rust:** Stable 1.78+ (`rustup update stable`)
*   **Protobuf Compiler:** `protoc` (required for `tonic-build`)
*   **System Deps:** `pkg-config`, `libssl-dev`, `build-essential`

### Building from Source

Build the CLI tool, which includes the embedded node runner:

```bash
cargo build --release -p ioi-cli
```

### Running a Local Devnet

The easiest way to develop on IOI is using the CLI to spawn a local cluster. This sets up a Genesis block, keys, and runs the Triadic Kernel locally.

```bash
# Run a single-node devnet with Proof of Authority and IAVL state
./target/release/cli node --validators 1 --consensus poa --tree iavl
```

You should see logs indicating the **Orchestrator**, **Workload**, and **Guardian** containers starting up and peering via mTLS.

---

## 🤖 Developing Agents

IOI agents are "Trace-First". You define logic, and the system auto-generates the security policy.

1.  **Scaffold a Project:**
    ```bash
    ./target/release/cli init my-agent
    ```

2.  **Define Logic (Python SDK):**
    ```python
    from ioi import tool, Agent

    @tool("net::fetch")
    def get_price(ticker: str):
        # Implementation...
        pass
    
    agent = Agent("trader")
    ```

3.  **Ghost Mode (Trace Generation):**
    Run the agent in "Ghost Mode" to capture its behavior without enforcement. The kernel records all I/O to generate a Manifest.
    ```bash
    # (Future feature in CLI)
    ioi-cli ghost run my_agent.py
    ```

4. **Helpful test commands**

    ```bash
    IOI_GUARDIAN_KEY_PASS="local-mode" cargo run --bin ioi-local --features="validator-bins state-iavl consensus-admft"
    ```

    2.  **Restart the Node:**
    ```bash
    LISTEN_ADDRESS="/ip4/0.0.0.0/tcp/9000" \
    ORCHESTRATION_RPC_LISTEN_ADDRESS="0.0.0.0:9000" \
    IOI_GUARDIAN_KEY_PASS="local-mode" \
    cargo run --bin ioi-local --features="validator-bins state-iavl consensus-admft"
    ```
3.  **Run the Agent Script:**
    ```bash
    export PYTHONPATH=$PYTHONPATH:$(pwd)/agent-sdk/python/src
    python3 examples/test_agent.py
    ```
    ```bash
    cargo test -p ioi-cli --test infra_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```

    ```bash
    cargo test --package ioi-cli --test sync_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test scrubber_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```

    ```bash
    cargo test --package ioi-cli --test workload_control_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```

    ```bash
    cargo test --package ioi-cli --test agentic_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_trace_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```

    ```bash
    cargo test --package ioi-cli --test agent_budget_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_hybrid_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_pause_resume_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_resilience_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_scrub_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```
    ```bash
    cargo test --package ioi-cli --test agent_swarm_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1
    ```

---

## 🔐 Cryptography & Security

IOI is designed for **Industrial Assurance**.

*   **Post-Quantum Native:** The protocol uses NIST-standardized **ML-KEM (Kyber)** for transport encryption and **ML-DSA (Dilithium)** for signatures by default.
*   **Hybrid KEM:** We utilize a hybrid key exchange (ECDH + Kyber) to protect against "Harvest Now, Decrypt Later" attacks while maintaining classical security guarantees.
*   **Non-Equivocation:** The **Guardian** module uses local hardware (or a remote signing oracle) to enforce monotonic counters on all consensus messages, making safety violations ($n > 2f$) attributable and slashable.

---

## 📄 License

This project is licensed under the **BBSL** (Business Source License) as defined in the `LICENSE-BBSL` file.
*   Free for non-production and development use.
*   Production use requires a license (or converts to Open Source after a set period).

*Copyright © 2025 IOI Foundation.*