# aiagent.xyz

**Composable autonomous supply for the IOI network.**

`aiagent.xyz` is the supply-side marketplace and packaging layer for the [IOI Network](https://ioi.network). It is where builders discover, publish, compose, license, and run verifiable autonomous capabilities, including agents, workflows, swarms, operator packs, service modules, and embodied runtimes.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

## 🏗 Architecture

This repository contains the **supply-side interface** for the IOI protocol. It is the place where autonomous components are packaged and traded before the most mature offerings are promoted into `sas.xyz` as finished, outcome-based services.

*   **Framework:** React + Vite
*   **Styling:** Tailwind CSS (Utility-first, High-density)
*   **Routing:** React Router v6
*   **State:** Local React State (Mocked for Prototype)

### Rule of Abstraction

Use this rule across the ecosystem:

*   If the buyer is choosing **how it works**, it belongs closer to **aiagent.xyz**.
*   If the buyer is choosing **what result they want**, it belongs closer to **sas.xyz**.

That keeps the boundary based on abstraction level rather than company size or deal size.

### Key Modules

| Module | Route | Description |
| :--- | :--- | :--- |
| **Explore** | `/` | Browse and filter packaged autonomous capabilities by execution shape. |
| **Workflows / Services** | `/?format=Workflow` / `/?format=Service Module` | Navigate reusable workflows and packaged service modules. |
| **Freelance** | `/freelance` | The "Request for Agent" (RFA) job board. |
| **Publish** | `/sell` | Package a new agent, workflow, operator pack, or service module. |
| **Foundry** | `/post-job` | Create new test-driven bounties for net-new capabilities. |
| **Command Center** | `/dashboard` | Manage active deployments, earnings, and listings. |
| **Identity** | `/profile/:id` | Reputation and verification badges for developers. |

### Listing Taxonomy

`aiagent.xyz` classifies the market by execution shape:

*   Agents
*   Workflows
*   Swarms
*   Operator Packs
*   Service Modules
*   Embodied Runtimes

The goal is to let builders package composables without forcing every listing to pretend it is already a full enterprise service.

### Commercial Models

Supply-side pricing belongs here:

*   metered execution
*   license
*   rev share
*   lease
*   settlement-based compensation

When a listing matures into a governed, buyer-facing service with SLAs and outcome contracts, it can be promoted into `sas.xyz`.

## 🚀 Getting Started

### Prerequisites

*   Node.js 18+
*   npm or yarn

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ioi-foundation/aiagent-xyz.git
cd aiagent-xyz

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

The application will be available at `http://localhost:5173`.

## 📦 Build for Production

```bash
npm run build
```

The output will be in the `dist` folder, ready for deployment to Vercel, Netlify, or IPFS.

## 🔌 Protocol Integration (Mocked)

Currently, this frontend operates in **Prototype Mode**.
*   **Auth:** Simulates Wallet Connect via `WalletModal`.
*   **Data:** Uses static JSON mocks for Agents and Jobs.
*   **Execution:** Simulates "Deployment" via `ConsoleModal`.

**Future Integrations:**
*   **IOI SDK:** For real wallet signatures and `AuthToken` generation.
*   **The Graph / Indexer:** For fetching live Agent Manifests from the chain.
*   **IPFS Gateway:** For resolving agent icons and descriptions.

## 🚀 Promotion Path

Strong listings on `aiagent.xyz` should not dead-end in the marketplace. The intended maturity ladder is:

1.  Agent
2.  Workflow
3.  Operator Pack
4.  Service Module
5.  Managed Service
6.  Enterprise SaS Offering

`aiagent.xyz` supplies the verified components. `sas.xyz` assembles those components into outcome-based services with SLAs, governance, escalation, and reporting.

## 🎨 Design System

The UI follows the **"Trader Workstation"** aesthetic:
*   **High Density:** Data-rich tables and grids.
*   **Utility First:** Fast filtering, keyboard shortcuts.
*   **Trust Signals:** Prominent verification badges and bond amounts.
*   **Palette:** Slate (Backgrounds) + Blue (Primary) + Green/Red (Financial indicators).

## 🤝 Contributing

1.  Fork the repo
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
