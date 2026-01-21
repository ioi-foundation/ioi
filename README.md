# IOI: Internet of Intelligence

![Status](https://img.shields.io/badge/status-alpha-yellow)
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
    - [Running the Full Stack (Kernel + UI)](#running-the-full-stack-kernel--ui)
- [The "Human-in-the-Loop" Workflow](#-the-human-in-the-loop-workflow)
- [Developing Agents](#-developing-agents)
    - [Test Suite](#test-suite)
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
    *   Manages the mempool, networking, and policy enforcement.
    *   Routes intents to local hardware or the Burst Network.
3.  **Workload (`crates/node/src/bin/workload.rs`):**
    *   The ephemeral sandbox where "Alien Intelligence" (AI Models/Scripts) runs.
    *   Communicates via Shared Memory (Zero-Copy) for high throughput.

---

## 📂 Repository Structure

The codebase is organized as a Rust workspace with an Agent SDK in Python.

| Crate | Description |
| :--- | :--- |
| **`api`** | Core traits (`ChainStateMachine`, `CommitmentScheme`) and interfaces. |
| **`cli`** | The `ioi` developer toolchain. Handles scaffolding, testing, and devnets. |
| **`consensus`** | Implements **A-DMFT** (Adaptive Deterministic Mirror Fault Tolerance). |
| **`crypto`** | Post-Quantum primitives (ML-DSA, Kyber), BLS12-381, and Ed25519. |
| **`execution`** | The execution environment, including **Block-STM**-style parallel execution (`mv_memory`). |
| **`ibc-host`** | Universal Interoperability implementation (ICS-23, ICS-24, ICS-26). |
| **`ipc`** | Inter-Process Communication using **gRPC** (Control) and **rkyv** (Shared Memory Data Plane). |
| **`drivers`** | Native hardware drivers (GUI, Browser, MCP) for agent interaction. |
| **`node`** | Entry points for the binaries (`ioi-local`, `guardian`, `workload`). |
| **`services`** | Native WASM modules: `Governance`, `IdentityHub`, `ProviderRegistry`, `IBC`. |
| **`state`** | Pluggable state trees: **IAVL**, **Jellyfish**, **Verkle**, **mHNSW**. |
| **`storage`** | Persistent storage layer based on **redb** with WAL support. |
| **`validator`** | Container architecture logic (Standard vs. Hybrid validators). |
| **`vm/wasm`** | Wasmtime-based runtime for smart contracts and services. |

---

## 🚀 Getting Started

### Prerequisites
*   **Rust:** Stable 1.78+ (`rustup update stable`)
*   **Protobuf Compiler:** `protoc` (required for `tonic-build`)
*   **Node.js/NPM:** Required for the Autopilot UI.
*   **System Deps:** `pkg-config`, `libssl-dev`, `build-essential`

### Running the Full Stack (Kernel + UI)

#### 1. Start the IOI Kernel (Local Mode)
In a **terminal**, first build and initialize the local node to generate identity keys and genesis state:

```bash
cargo run --bin ioi-local --features="validator-bins state-iavl consensus-admft"
```

Once the node starts and prints the logs, **stop it (Ctrl+C)**.

To enable real AI inference (required for complex agent demos), inject your API key and run the compiled binary directly:

```bash
export OPENAI_API_KEY=sk-proj-...
./target/debug/ioi-local
```
*Wait for:* `ORCHESTRATION_RPC_LISTENING_ON_0.0.0.0:9000`

#### 2. Start the Autopilot UI
In a **second terminal**, start the desktop frontend.

```bash
cd apps/autopilot
npm install
npm run tauri dev
```
*Action:* Press `Ctrl+Space` (or `Cmd+Space` on macOS) to open the spotlight bar.

---

## 🛡️ The "Human-in-the-Loop" Workflow

IOI introduces the **Agency Firewall**, allowing users to safely delegate tasks to agents. Here is the lifecycle of a protected action:

1.  **Intent:** User types `"Write a file to ./ioi-data/test.txt"` in Autopilot.
2.  **Inference:** The Kernel's AI resolves this intent to a tool call: `filesystem__write_file`.
3.  **Interception:** The Firewall detects that `fs::write` is a restricted capability. It halts execution and returns `REQUIRE_APPROVAL`.
4.  **Gate Window:** The Autopilot UI catches this event and pops up a "Policy Gate" window.
5.  **Approval:** The user clicks "Approve". The UI signs a cryptographic `ApprovalToken` using the local identity.
6.  **Resumption:** The token is submitted to the Kernel via `resume@v1`.
7.  **Execution:** The Kernel verifies the token, unblocks the action, and the MCP Server executes the file write.

---

## 🤖 Developing Agents

IOI agents are "Trace-First". You define logic, and the system auto-generates the security policy.

### Test Suite
Run specific end-to-end tests to verify kernel components:

```bash
# Core Infrastructure
cargo test -p ioi-cli --test infra_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

# Agentic Capabilities (Budget, Policy, Scrubbing)
cargo test -p ioi-cli --test agent_budget_e2e --features "consensus-admft,vm-wasm,state-iavl"
cargo test -p ioi-cli --test agent_scrub_e2e --features "consensus-admft,vm-wasm,state-iavl"
cargo test -p ioi-cli --test agent_rag_and_policy_e2e --features "consensus-admft,vm-wasm,state-iavl"

# Model Context Protocol (MCP) Integration
cargo test -p ioi-cli --test agent_mcp_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

# Full Swarm Logic
cargo test -p ioi-cli --test agent_swarm_e2e --features "consensus-admft,vm-wasm,state-iavl"
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

*Copyright © 2026 IOI Foundation.*