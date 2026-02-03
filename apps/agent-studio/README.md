# Agent Studio

The official web-based IDE for designing, testing, and managing IOI Agents. 

**Agent Studio** provides a zero-setup environment for developers to visually compose agent graphs, configure governance policies, and simulate execution logic directly in the browser.

## 🌟 Overview

Agent Studio is built on the portable `@ioi/agent-ide` core. It allows you to:

*   **Visually Compose** complex agent workflows using a node-based canvas.
*   **Configure Policies** like budget caps and network allowlists ("Logic vs. Law").
*   **Simulate Execution** with instant feedback loops.
*   **Manage Fleets** of remote agent containers.
*   **Browse & Fork** templates from the Marketplace.

Unlike the desktop **Autopilot** runtime which executes agents locally on your machine, Agent Studio is designed for **Cloud & Remote Management**.

## 🚀 Getting Started

### Prerequisites
Run from the monorepo root:

```bash
npm install
```

### Start Development Server

```bash
# From root
npm run dev:web
```

Open [http://localhost:5173](http://localhost:5173) to view the IDE.

## 🛠 Architecture

The application implements the **Runtime Adapter Pattern** to run the IDE in a browser environment.

*   **Core:** `@ioi/agent-ide` (Shared Logic)
*   **Adapter:** `WebMockRuntime` 
    *   *Storage:* Uses `localStorage` for project persistence.
    *   *Execution:* Simulates node processing latency and events.
    *   *Fleet:* Mocks connection to cloud providers (e.g. Akash, AWS).

## 📦 Deployment

Agent Studio is a static Single Page Application (SPA). It can be deployed to Vercel, Netlify, or any static host.

```bash
# Build for production
npm run build
```

Artifacts are output to `dist/`.