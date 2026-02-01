# IOI: Internet of Intelligence

![Status](https://img.shields.io/badge/status-alpha-yellow)
![License](https://img.shields.io/badge/license-BBSL-blue)
![Consensus](https://img.shields.io/badge/consensus-Lazarus_Fault_Tolerance-purple)
![Cryptography](https://img.shields.io/badge/crypto-Post--Quantum-green)

**The Operating System for Agency.**

IOI is a Web4 infrastructure framework that bridges **probabilistic AI inference** with **deterministic blockchain settlement**. It is the reference implementation of the **Lazarus Fault Tolerance** protocol.

IOI is a **fractal runtime**: it runs locally on user devices to provide free, private desktop automation (**Mode 0**), and scales to a global validator network for high-stakes financial settlement (**Mode 2**), without changing the underlying agent code.

---

## 🏗 The Architecture

IOI solves the "Trust Gap" in AI: users cannot trust agents with wallets, and agents cannot trust each other with data. We solve this by wrapping the AI model in a **Secure Hypervisor** that enforces policy before an agent can touch the network, filesystem, or wallet.

### System Topology
The node is composed of three isolated containers to enforce security boundaries:

```mermaid
graph TD
    User[User / Autopilot UI] <--> O[Orchestrator]
    
    subgraph "Trust Boundary"
        O <== gRPC ==> W[Workload Container]
        O <== mTLS ==> G[Guardian TEE]
    end

    W -- "Data Plane (Shmem)" --> O
    G -- "Signing Oracle" --> O
```

1.  **Orchestrator (The Nervous System):** Handles P2P networking, mempool, and consensus ordering. It never sees the raw data or model weights.
2.  **Workload (The Brain):** Executes AI logic (Wasm/Python), manages vector memory (SCS), and runs the VM.
3.  **Guardian (The Conscience):** A hardware-anchored (SGX/Nitro) sidecar that holds keys and enforces non-equivocation.

---

## ⚡ Key Innovations

### 1. Lazarus Fault Tolerance (A-DMFT)
A bimodal consensus engine that breaks the classical 33% BFT threshold.
*   **Normal Mode:** Uses hardware-anchored non-equivocation to achieve safety with **51% majority**.
*   **Panic Mode:** If a hardware compromise is detected (Proof of Divergence), the network executes a "Kill Switch" and transitions to a probabilistic mesh (A-PMFT) to maintain liveness.

### 2. Sovereign Context Substrate (SCS)
A verifiable, append-only file format (`.scs`) for agent memory. It uses **mHNSW** (Merkelized Hierarchical Navigable Small World) graphs to allow agents to prove they retrieved the correct memory without hallucination.

### 3. The Agency Firewall
A deterministic policy engine sitting between the LLM and the OS. It intercepts tool calls (e.g., `fs::write`, `wallet::sign`) and checks them against a user-defined policy (`policy.toml`) before execution.

---

## 📂 Repository Structure

The codebase is organized as a Rust workspace.

### Core Kernel
| Crate | Description |
| :--- | :--- |
| **`node`** | Entry points for the binaries (`ioi-local`, `guardian`, `workload`). |
| **`consensus`** | Implementation of **A-DMFT** (Engine A), **A-PMFT** (Engine B), and the Kill Switch. |
| **`validator`** | Container orchestration, reactor loops, and the main event bus. |
| **`api`** | Core traits (`ChainStateMachine`, `CommitmentScheme`) defining the component interfaces. |

### Execution & State
| Crate | Description |
| :--- | :--- |
| **`execution`** | The state transition machine, including **Block-STM**-style parallel execution (`mv_memory`). |
| **`state`** | Pluggable state trees: **IAVL**, **Jellyfish**, **Verkle** (KZG), and **mHNSW**. |
| **`storage`** | Persistent storage layer based on **redb** with Write-Ahead Log (WAL) support. |
| **`scs`** | The Sovereign Context Substrate logic and vector indexing. |
| **`vm/wasm`** | Wasmtime-based runtime for smart contracts and services. |

### Interfaces & Drivers
| Crate | Description |
| :--- | :--- |
| **`drivers`** | Native hardware bindings: **GUI** (mouse/keyboard), **Browser** (CDP), **Terminal**, and **MCP**. |
| **`services`** | Native WASM modules: `Governance`, `IdentityHub`, `ProviderRegistry`, `IBC`, `DesktopAgent`. |
| **`ibc-host`** | Universal Interoperability implementation (ICS-23, ICS-24, ICS-26). |
| **`cli`** | The developer toolchain. Handles scaffolding, testing, and devnets. |

---

## 🚀 Getting Started

### Prerequisites
*   **Rust:** Stable 1.78+ (`rustup update stable`)
*   **Protobuf:** `protoc` (required for `tonic-build`)
*   **Node.js/NPM:** Required for the Autopilot UI.
*   **System Deps:** `pkg-config`, `libssl-dev`, `build-essential`

### 🛠 Running the Developer Stack (Mode 0)

Mode 0 runs the full stack locally for agent development.

#### 1. Start the IOI Kernel
In a terminal, build and initialize the local node. This generates your identity keys and genesis state in `./ioi-data`.

```bash
# First run (initializes genesis and keys)
cargo run --bin ioi-local --features "local-mode" 
```

To enable real AI inference (required for complex agent demos), export your key and run the compiled binary:

```bash
export OPENAI_API_KEY=sk-proj-...
./target/debug/ioi-local
```
*Wait for log:* `ORCHESTRATION_RPC_LISTENING_ON_0.0.0.0:9000`

#### 2. Start the Autopilot UI
In a **second terminal**, start the desktop frontend.

```bash
cd apps/autopilot
npm install
npm run tauri dev
```
*Action:* Press `Ctrl+Space` (or `Cmd+Space` on macOS) to open the spotlight bar.

---

## 🧪 Testing & Verification

IOI employs a "Trace-First" development methodology. You can verify the kernel components using the CLI test suite.

```bash
# 1. Infrastructure E2E: Verifies P2P sync and block production
cargo test -p ioi-cli --test infra_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture --test-threads=1

# 2. Lazarus Protocol: Verifies 2-Chain Commit Rule & Safety Guard
RUST_LOG=info,consensus=info cargo test -p ioi-cli --test admft_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

# 3. Phase Transition: Verifies Kill Switch and A-PMFT Handover
RUST_LOG=info,consensus=info cargo test -p ioi-cli --test protocol_apex_e2e --features "consensus-admft,vm-wasm,state-iavl" -- --nocapture

# 4. Agentic Security: Verifies PII Scrubbing and Policy Gates
cargo test -p ioi-cli --test agent_scrub_e2e --features "consensus-admft,vm-wasm,state-iavl"
```

---

## 🔐 Cryptography

IOI is designed for **Industrial Assurance** and long-term security.

*   **Post-Quantum Native:** The protocol uses NIST-standardized **ML-KEM (Kyber)** for transport encryption and **ML-DSA (Dilithium)** for signatures by default.
*   **Hybrid KEM:** We utilize a hybrid key exchange (ECDH + Kyber) to protect against "Harvest Now, Decrypt Later" attacks while maintaining classical security guarantees.
*   **Non-Equivocation:** The **Guardian** module uses local hardware (or a remote signing oracle) to enforce monotonic counters on all consensus messages, making safety violations ($n > 2f$) attributable and slashable.

---

## 📄 License

*   **Core Interfaces (`ioi-api`, `ioi-types`):** MIT / Apache 2.0 (Permissive).
*   **Kernel Engine (`ioi-consensus`, `ioi-validator`):** Business Source License (BSL) 1.1. Free for non-commercial and development use. Converts to Open Source after 3 years.