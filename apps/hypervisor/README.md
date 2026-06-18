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
├── Code editor adapter hosts
│   ├── packaged Electron/VS Code host for the current development path
│   ├── editor, browser IDE, terminal, VM, and hosted workspace targets
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

Legacy native/embedded editor experiments are extraction inventory. The active
product path should not present any editor host as the parent product.

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) (v20+ LTS recommended)
- Packaged Electron/VS Code app at
  `code-editor-adapters/builds/VSCode-linux-x64`, or set
  `HYPERVISOR_CODE_EDITOR_VSCODE_PACKAGED_ROOT`.
- Optional VS Code source checkout at `code-editor-adapters/vscode` for adapter
  development.

### Setup

```bash
# Install dependencies
npm install

# Run the current Workbench code-editor adapter host in development.
npm run dev:hypervisor-app

# Build the Hypervisor Workbench package
npm run build:workbench
```

`npm run dev:hypervisor-app` currently launches the packaged Electron/VS Code
Code editor adapter host through
`scripts/launch-hypervisor-code-editor-adapter-host.mjs`. The launcher role is
editor-host launch, not Hypervisor product identity. Hypervisor App/Core owns
daemon access, model mounting, session authority, and receipts; the editor-host
launcher does not start daemon sidecars, mount models, or pass daemon tokens to
the extension. The launcher only syncs the current `ioi-code-editor-adapter`
extension into the packaged host. Set `HYPERVISOR_SKIP_EXTENSION_SYNC=1` to skip
extension sync. The `code-editor-adapters/vscode` source checkout is optional for this
launch path; the required editor-host artifact is the packaged Electron app at
`code-editor-adapters/builds/VSCode-linux-x64` or
`HYPERVISOR_CODE_EDITOR_VSCODE_PACKAGED_ROOT`. The old root `ide/` artifact path
is retired.

### Project Structure

```
apps/hypervisor/
├── scripts/                             # launchers, probes, validation harnesses
├── package.json                         # Hypervisor App scripts
└── README.md

code-editor-adapters/
├── README.md                            # adapter-host ownership notes
├── ioi-code-editor-adapter/                       # built-in code editor adapter extension
├── code-editor-adapter-host.manifest.json           # code-editor adapter-host manifest
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
  the packaged editor host as one code editor adapter target while retaining
  screenshots, logs, receipts, and proof JSON.

## License

MIT
