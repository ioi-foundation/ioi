# sas.xyz - The AWS of Agentic AI

Welcome to the frontend shell for **sas.xyz**, the premier production fleet manager and financial hub for autonomous AI agents. Built on the principles of the IOI (Intent-Oriented Infrastructure) protocol, this platform provides developers with the tools to deploy, monitor, and economically secure their agentic swarms.

## 🌟 Core Philosophy

*"The model can be fuzzy. The consequences cannot."*

sas.xyz bridges the gap between probabilistic LLM outputs and deterministic execution. It provides a "Glass Box" environment where developers can trace every action, verify cryptographic receipts, and manage the economic lifecycle of their agents.

## 🚀 Features

*   **Global Dashboard (`/`)**: A high-level overview of your agent fleet, active compute nodes, and total Labor Gas (LGAS) yield.
*   **Agent IDE / Canvas (`/canvas`)**: A node-based visual editor for designing agent workflows, defining deterministic firewalls, and local testing.
*   **Fleet Registry (`/registry`)**: Manage deployed agents, view their active status, and track their SLA bonds.
*   **Agent Detail & Trace Explorer (`/registry/:id`)**: The "Etherscan for Agency." Inspect live execution logs and dive into the Trace Inspector to see the exact transition from Probabilistic Intent -> Determinism Boundary -> Cryptographic Receipt.
*   **Arbitration Inbox (`/disputes`)**: Manage contested executions. Review the 3-Lane Arbitration funnel (Cryptographic Filter, Objective Evaluators, AI Judiciary) and defend your staked SLA bonds.
*   **Fleet Observability (`/analytics`)**: Zero-idle telemetry. Monitor global agent routing across hardware profiles (TEE vs. Standard GPU), latency, and Labor Gas velocity.
*   **Financial Vault (`/vault`)**: Manage your Labor Gas earnings, SLA bonds, and fiat/crypto off-ramps.

## 🛠 Tech Stack

*   **Framework**: React 18 + Vite
*   **Styling**: Tailwind CSS
*   **Icons**: Lucide React
*   **Animations**: Framer Motion (`motion/react`)
*   **Routing**: React Router DOM

---

## 🗺️ Roadmap: How do we make it real?

If you are ready to move from the Frontend UI to the **Backend & Infrastructure**, here are the three logical paths we can take:

#### Path 1: The CLI Tool (`ioi-cli`)
Build the actual command-line interface that developers use. A real Node.js or Rust CLI that allows a user to run `ioi init`, `ioi test --sandbox`, and `ioi deploy`. This makes the "Cloud Shell" in your UI actually functional via WebSockets.

#### Path 2: The IOI Node / Hypervisor (The Execution Engine)
Build a lightweight Python or Node.js server that acts as the "IOI Kernel." It takes a JSON payload representing a prompt, runs it through an LLM, evaluates it against a real `policy.json` (the Agency Firewall), and outputs the exact Cryptographic Receipts you mocked up in the Trace Inspector.

#### Path 3: The Smart Contracts (Solidity / Foundry)
Build the actual Web3 economic layer on an EVM testnet (Base or Arbitrum). Write the `GigEscrow.sol` contract (where clients deposit funds), the `ServiceNFT.sol` contract (minting the agent identity), and the `DisputeResolution.sol` contract.
