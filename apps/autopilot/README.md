# Autopilot Workbench

Autopilot Workbench is the canonical Electron/VS Code fork for IOI-governed
autonomous systems. It is the IDE-grade operator console over the IOI daemon,
not the runtime authority itself.

The daemon owns execution, policy, approvals, model mounting, connector calls,
secrets, receipts, replay, and workspace mutation. The Workbench projects state,
sends typed requests, and gives the operator first-class surfaces for Agent
Studio, Models, Workflow Composer, runs, policy, receipts, and evidence.

## Architecture

```
Autopilot Workbench
│
├── Electron/VS Code fork
│   ├── canonical app shell
│   ├── Activity Bar surfaces
│   ├── editor tabs, webviews, commands, menus, keybindings
│   └── native shell affordances and daemon supervision
│
├── ioi-workbench
│   ├── Agent Studio
│   ├── Autopilot Models
│   ├── Workflow Composer
│   ├── policy, runs, receipts, replay, and evidence projections
│   └── daemon request bridge
│
└── IOI daemon
    ├── runtime authority and durable execution boundary
    ├── model artifact/catalog/backend/endpoint/route authority
    ├── workflow execution, patch apply, policy, approvals, receipts, replay
    └── connector calls, secrets, and workspace mutation
```

## Runtime Boundary

Canonical framing:

```text
IOI daemon = hypervisor/control plane for autonomous execution
Autopilot Workbench = IDE-grade operator console
Electron/VS Code fork = canonical app shell
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

Tauri/OpenVSCode embedding is legacy extraction inventory. Do not add new
runtime, shell, or validation work to the retired Tauri path.

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) (v20+ LTS recommended)
- Packaged Electron/VS Code app at `ide/builds/VSCode-linux-x64`, or set
  `AUTOPILOT_VSCODE_PACKAGED_ROOT`
- Optional VS Code source checkout at `ide/vscode` for fork development

### Setup

```bash
# Install dependencies
npm install

# Run the Electron/VS Code fork in development.
# This also starts a supervised IOI daemon sidecar and projects discovered
# local LM Studio/Ollama model artifacts into Autopilot Models.
npm run dev:desktop

# Validate the direct Workspace shell and retain a GUI receipt bundle
npm run probe:desktop:workspace
```

`npm run dev:desktop` launches the canonical Electron/VS Code fork through
`scripts/launch-autopilot-ide-fork.mjs`. If `IOI_DAEMON_ENDPOINT` is not already
set, the launcher syncs the current `ioi-workbench` extension into the packaged
fork, starts an IOI daemon sidecar, grants the workbench a scoped daemon token,
asks the daemon to discover local model providers, mounts discovered local
models as daemon endpoints, and passes the daemon endpoint/token to
`ioi-workbench`. Set `AUTOPILOT_SKIP_EXTENSION_SYNC=1` to skip extension sync,
`AUTOPILOT_SKIP_DAEMON=1` to opt out of daemon startup, or
`AUTOPILOT_SKIP_MODEL_AUTODISCOVERY=1` to start the daemon without local model
discovery. The `ide/vscode` source checkout is optional for this launch path;
the required runtime artifact is the packaged Electron app at
`ide/builds/VSCode-linux-x64` or `AUTOPILOT_VSCODE_PACKAGED_ROOT`.

### Project Structure

```
apps/autopilot/
├── openvscode-extension/ioi-workbench/  # built-in Workbench extension/API layer
├── scripts/                             # launchers, probes, validation harnesses
├── package.json                         # Autopilot scripts
└── README.md

ide/
├── builds/VSCode-linux-x64/             # packaged runnable Electron app
└── vscode/                              # optional VS Code fork source checkout

packages/
├── runtime-daemon/                      # IOI daemon authority boundary
└── agent-ide/                           # Workflow Composer and agent-IDE surfaces
```

## Key Features

### IDE-First Workbench
- Agent Studio for agent/workflow intent.
- Autopilot Models for daemon-owned local model discovery, load, unload, route,
  server, log, receipt, and replay state.
- Workflow Composer for IDE-native graph composition, readiness, timeline,
  model binding, approvals, and evidence.

### Daemon-Owned Authority
- The Workbench must not directly execute durable runtime work.
- Extension-host and webview code are projection/request surfaces.
- All consequential actions resolve through daemon/domain APIs.

### Validation
- `npm run dev:desktop` launches the canonical Electron/VS Code fork with a
  supervised daemon sidecar by default.
- GUI probes and goal scripts should target the Electron/VS Code fork path and
  retain screenshots, logs, receipts, and proof JSON.

## License

MIT
