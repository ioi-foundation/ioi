# Agent Chat

The workspace shell for shaping, staging, and handing off IOI agents.

**Agent Chat** gives operators and builders a zero-setup workspace shell for
graph composition, runtime catalog staging, connector posture review, and
persisted handoff before work moves into the desktop runtime.

## Overview

Agent Chat is built on the portable `@ioi/agent-ide` core. It lets you:

- Visually compose complex agent workflows using a node-based canvas.
- Stage runtime packs into the workspace from the runtime catalog.
- Review connector posture and exercise integration actions before handoff.
- Inspect fleet state before handing work to the desktop shell.
- Persist workspace state so the shell keeps handoff context intact.

Unlike the desktop **Autopilot** runtime, which owns live execution, Agent
Chat is the browser shell for shaping work and carrying it forward into
desktop handoff.

## Getting Started

Run from the monorepo root:

```bash
npm install
```

Start the development server:

```bash
npm run dev:web
```

Open [http://localhost:5173](http://localhost:5173) to view Agent Chat.

## Architecture

The application uses the same portable `@ioi/agent-ide` shell with a browser
workspace runtime adapter.

- Core: `@ioi/agent-ide`
- Adapter: `BrowserWorkspaceRuntime`
  - Storage: persists project state, staged catalog entries, and workspace agents in `localStorage`
  - Execution: provides workspace execution feedback for graph and node runs
  - Catalog: stages runtime catalog packs into the workspace
  - Fleet and connectors: exposes current posture so the shell remains useful before desktop handoff

## Deployment

Agent Chat is a static single-page application and can be deployed to any
static host.

```bash
npm run build
```

Artifacts are output to `dist/`.
