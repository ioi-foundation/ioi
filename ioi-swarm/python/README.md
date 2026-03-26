# 🤖 IOI Swarm SDK (`ioi-swarm`)

**The Official Python Framework for the Internet of Intelligence (IOI) Protocol.**

`ioi-swarm` is a high-performance library for building **sovereign, autonomous agents** that run on the Internet of Intelligence. Unlike standard agent frameworks, IOI agents are tied into the IOI runtime and memory substrate so that observations, decisions, and actions can be tracked, constrained, and receipted.

[![PyPI version](https://badge.fury.io/py/ioi-swarm.svg)](https://pypi.org/project/ioi-swarm/)
[![License: BBSL](https://img.shields.io/badge/License-BBSL-blue.svg)](https://github.com/ioi-foundation/ioi/blob/master/LICENSE-BBSL)

---

## 🚀 Key Features

*   **`ioi-memory` runtime integration:** Local-first checkpoints, archival recall, and runtime-governed memory for agent sessions.
*   **Distributed Inference Mesh (DIM):** Seamlessly burst agent reasoning to a decentralized network of GPU providers.
*   **Verifiable Agency:** Every tool call generates a cryptographic receipt, providing an immutable audit trail of agent behavior.
*   **Ghost Mode:** Record agent traces locally to synthesize security policies for the IOI Semantic Firewall.
*   **Post-Quantum Secure:** Built-in support for hybrid classical/PQ cryptographic identities.

## 📦 Installation

```bash
pip install ioi-swarm
```

*Note: Requires a running [IOI Node](https://github.com/ioi-foundation/ioi) (`ioi-local`) for full verification and settlement capabilities.*

## 🛠 Quickstart

```python
from ioi_swarm import Agent, tool, ActionTarget

# 1. Initialize your Sovereign Agent
agent = Agent(name="Autopilot", policy_id="finance-restricted")

# 2. Define a Verifiable Tool
@tool(name="get_balance", target=ActionTarget.FS_READ)
def check_vault_balance(vault_id: str):
    """Checks the balance of a specific on-chain vault."""
    # Logic intercepted by the IOI Kernel for policy enforcement
    return 100.0

# 3. Register and Run
agent.register_tool(check_vault_balance)
agent.run("Check my vault balance and alert me if it's below 50")
```

## 🧠 The Triad of Agency

IOI agents operate within a strict architectural boundary:

1.  **Drivers:** Native hardware capabilities (Eyes & Hands).
2.  **Tools:** Extensible WASM-based instruments (Utility).
3.  **Skills:** Procedural memory stored in runtime archival memory (Know-How).

## 📄 Documentation

For full protocol specifications, whitepaper details, and advanced swarming patterns, visit [docs.ioi.network](https://docs.ioi.network).

## 🛡 Security

The `ioi-swarm` SDK is designed to be "Secure by Default." All outbound requests are gated by the **IOI Agency Firewall**, which performs real-time PII scrubbing and intent validation.

---

© 2026 IOI Foundation. Built for the Internet of Intelligence.
