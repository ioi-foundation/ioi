# Hypervisor App

Hypervisor App is the native operator cockpit for IOI-governed autonomous
systems. It is a first-class client over Hypervisor Core and the IOI daemon,
not the runtime authority itself and not a single-IDE product.

The daemon owns execution, policy, approvals, model mounting, connector calls,
secrets, receipts, replay, and workspace mutation. Hypervisor App projects
state, sends typed requests, and gives the operator first-class surfaces for
Sessions, Workbench, Automations, Insights, Agents, Models, Privacy,
provider/environment views, Foundry, Authority, Receipts, and Settings.

## Architecture

```
Hypervisor App
│
├── Hypervisor shell
│   ├── Home, Sessions, Projects, and New Session
│   ├── application surfaces: Workbench, Automations, Agents, Models, Foundry
│   ├── provider/environment views: local, cloud, DePIN, storage, and nodes
│   ├── governance surfaces: Privacy, Authority, Receipts, Settings
│   └── inspectors for changes, ports/services, tasks, terminal, logs, and receipts
│
├── Workbench adapter hosts
│   ├── packaged Electron/VS Code host for the current development path
│   ├── OpenVSCode, VS Code, Cursor, Windsurf, JetBrains, browser IDE, and terminal targets
│   └── daemon request bridge and adapter capability boundary
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
Hypervisor App = native client over Hypervisor Core
Hypervisor Workbench = code/systems surface inside Hypervisor App/Web
Editor hosts = adapter targets, not product identity or runtime truth
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

Tauri/OpenVSCode embedding is legacy extraction inventory. The active product
path should not revive Tauri or present OpenVSCode, VS Code, or any other editor
as the parent product.

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) (v20+ LTS recommended)
- Packaged Electron/VS Code app at
  `workbench-adapters/builds/VSCode-linux-x64`, or set
  `HYPERVISOR_WORKBENCH_VSCODE_PACKAGED_ROOT`.
- Optional VS Code source checkout at `workbench-adapters/vscode` for adapter
  development.

### Setup

```bash
# Install dependencies
npm install

# Run the current Workbench editor host in development.
# This also starts a supervised IOI daemon sidecar and projects discovered
# local LM Studio/Ollama model artifacts into Models.
npm run dev:hypervisor-app

# Validate the direct Workspace shell and retain a GUI receipt bundle
npm run probe:hypervisor-app:workspace

# Build the Hypervisor Workbench package
npm run build:workbench
```

`npm run dev:hypervisor-app` currently launches the packaged Electron/VS Code
Workbench adapter host through
`scripts/launch-hypervisor-workbench-adapter-host.mjs`. The launcher role is
editor-host launch, not Hypervisor product identity. If `IOI_DAEMON_ENDPOINT`
is not already set, the launcher syncs the current `ioi-workbench` extension
into the packaged host, starts an IOI daemon sidecar, grants the workbench a
scoped daemon token, asks the daemon to discover local model providers, mounts
discovered local models as daemon endpoints, and passes the daemon
endpoint/token to `ioi-workbench`. Set
`HYPERVISOR_SKIP_EXTENSION_SYNC=1` to skip extension sync,
`HYPERVISOR_SKIP_DAEMON=1` to opt out of daemon startup, or
`HYPERVISOR_SKIP_MODEL_AUTODISCOVERY=1` to start the daemon without local model
discovery. The `workbench-adapters/vscode` source checkout is optional for this
launch path; the required editor-host artifact is the packaged Electron app at
`workbench-adapters/builds/VSCode-linux-x64` or
`HYPERVISOR_WORKBENCH_VSCODE_PACKAGED_ROOT`. The old root `ide/` artifact path
is retired.

### Project Structure

```
apps/hypervisor/
├── scripts/                             # launchers, probes, validation harnesses
├── package.json                         # Hypervisor App scripts
└── README.md

workbench-adapters/
├── README.md                            # adapter-host ownership notes
├── ioi-workbench/                       # built-in code editor adapter extension
├── shell.manifest.json                  # adapter-host manifest
├── builds/VSCode-linux-x64/             # ignored packaged runnable Electron app
└── vscode/                              # ignored optional VS Code source checkout

packages/
├── runtime-daemon/                      # IOI daemon authority boundary
└── hypervisor-workbench/                # Workbench and workflow-composer package
```

## Key Features

### Hypervisor Surfaces
- Sessions for live governed runs, approvals, blockers, receipts, and replay.
- Workbench for code/systems work through editor, terminal, browser, and VM adapters.
- Automations for workflow composition, templates, schedules, and reusable runs.
- Models for daemon-owned local model discovery, load, unload, route, server,
  log, receipt, and replay state.
- Authority, Privacy, provider/environment views, Foundry, and Receipts over
  the same daemon/Core contracts.

### Daemon-Owned Authority
- Hypervisor App and Workbench must not directly execute durable runtime work.
- Editor hosts, extension-host code, and webviews are projection/request surfaces.
- All consequential actions resolve through daemon/domain APIs.

### Validation
- `npm run dev:hypervisor-app` launches the current packaged editor host with a
  supervised daemon sidecar by default.
- GUI probes and goal scripts should target Hypervisor App surfaces and may use
  the packaged editor host as one Workbench adapter target while retaining
  screenshots, logs, receipts, and proof JSON.

## License

MIT
