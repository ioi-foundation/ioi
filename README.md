# IOI: Internet of Intelligence

![Status](https://img.shields.io/badge/status-alpha-yellow)
![License](https://img.shields.io/badge/license-BBSL-blue)
![Architecture](https://img.shields.io/badge/architecture-runtime--first-green)

**The Operating System for Agency.** 

A Web4 infrastructure framework enabling "Read-Write-Own-Act" by bridging probabilistic AI with deterministic blockchain settlement.

IOI is a **fractal runtime**: it runs locally on user devices to provide free, private desktop automation (Mode 0), and scales to a global validator network for high-stakes financial settlement (Mode 2), without changing the underlying agent code.

---

## 🏗 The Architecture

IOI solves the "Trust Gap" in AI—users can't trust agents with wallets, and agents can't trust each other with data. We solve this by wrapping the AI model in a **Secure Hypervisor** that enforces policy before an agent can touch the network, filesystem, or wallet.

### The Stack
*   **The Brain (Workload):** Executes AI logic (Wasm/Python) and manages vector memory.
*   **The Hands (Drivers):** Native bindings for Mouse/Keyboard, Browsers (CDP), and MCP servers.
*   **The Conscience (Firewall):** A deterministic policy engine that blocks dangerous actions *before* execution.
*   **The Judge (Consensus):** A-DMFT consensus engine for settling disputes and enforcing liability bonds.

---

## 📂 Repository Structure

The codebase is organized as a Rust workspace with an Agent SDK in Python. This monorepo contains the entire stack, from the kernel to the frontend.

| Crate | Description |
| :--- | :--- |
| **`api`** | Core traits (`ChainStateMachine`, `CommitmentScheme`) and interfaces. |
| **`cli`** | The `ioi` developer toolchain. Handles scaffolding, testing, and devnets. |
| **`consensus`** | Implements **A-DMFT** (Adaptive Deterministic Mirror Fault Tolerance). |
| **`crypto`** | Post-Quantum primitives (ML-DSA, Kyber), BLS12-381, and Ed25519. |
| **`execution`** | The execution environment, including **Block-STM**-style parallel execution (`mv_memory`). |
| **`ibc-host`** | Universal Interoperability implementation (ICS-23, ICS-24, ICS-26). |
| **`ipc`** | Inter-Process Communication using **gRPC** (Control) and **rkyv** (Shared Memory Data Plane). |
| **`drivers`** | Native hardware drivers (GUI, Browser, Terminal, MCP) for agent interaction. |
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
cargo run --bin ioi-local --features "local-mode" 
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
cargo test -p ioi-cli --test infra_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1

RUST_LOG=info,consensus=info cargo test -p ioi-cli --test admft_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

RUST_LOG=info,consensus=info cargo test -p ioi-cli --test protocol_apex_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

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
*   **Core Interfaces (`ioi-api`, `ioi-types`):** MIT / Apache 2.0 (Permissive).
*   **Kernel Engine (`ioi-consensus`, `ioi-validator`):** Business Source License (BSL) 1.1. Free for non-commercial and development use. Converts to Open Source after 3 years.