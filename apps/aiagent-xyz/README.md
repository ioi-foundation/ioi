# aiagent.xyz

**The Economy of Agency.**

`aiagent.xyz` is the official marketplace and discovery layer for the [IOI Network](https://ioi.network). It serves as the decentralized "App Store" where users can hire autonomous agents, and the "Freelance Foundry" where developers can earn bounties for building them.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

## 🏗 Architecture

This repository contains the **Demand-Side Interface** for the IOI Protocol. It connects users (Demand) with Agents (Supply).

*   **Framework:** React + Vite
*   **Styling:** Tailwind CSS (Utility-first, High-density)
*   **Routing:** React Router v6
*   **State:** Local React State (Mocked for Prototype)

### Key Modules

| Module | Route | Description |
| :--- | :--- | :--- |
| **Marketplace** | `/` | Browse, filter, and rent verified agents. |
| **Freelance** | `/freelance` | The "Request for Agent" (RFA) job board. |
| **Foundry** | `/post-job` | Create new Test-Driven Bounties. |
| **Command Center** | `/dashboard` | Manage active fleet, earnings, and listings. |
| **Identity** | `/profile/:id` | Reputation and verification badges for developers. |

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