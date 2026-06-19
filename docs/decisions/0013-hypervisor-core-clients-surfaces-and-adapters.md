# ADR 0013: Define Hypervisor Core, Clients, Surfaces, And Adapter Targets

- Status: Accepted
- Date: 2026-06-16
- Owners: Hypervisor / daemon runtime / Workbench / provider integrations / wallet.network / Agentgres

Note: ADR 0014 refines this decision by making Hypervisor an IDE-of-IDEs and
by folding Fleet terminology into sessions, providers, environments, and
session-estate views.

## Context

The earlier desktop direction treated the product as an IDE-first app and used
the Electron/VS Code fork as the canonical shell after retiring Tauri. That was
the right intermediate correction away from a split Tauri path, but it is too
narrow for the end-state product.

Hypervisor now has to support native desktop, web, headless, remote workspaces,
many editor/viewer targets, external agent harnesses, provider infrastructure,
models, agents, workflow composition, Fleet, Foundry, cTEE/private workspaces,
receipts, and authority. A single IDE shell cannot be the product identity or
runtime truth.

## Decision

Hypervisor adopts this canonical product/runtime taxonomy:

```text
Hypervisor Core
  shared product/runtime substrate whose execution owner is the Hypervisor
  Daemon.

Hypervisor App
  native desktop client over Hypervisor Core.

Hypervisor Web
  browser/team/remote client over Hypervisor Core.

Hypervisor CLI/headless
  terminal, scripting, CI, node-ops, and headless client over Hypervisor Core.
  TUI is an optional presentation of this client, not a separate first-class
  product lane.

Hypervisor Workbench / Foundry / Fleet
  application surfaces over Hypervisor Core, not separate apps with separate
  runtime truth.

Adapter targets
  editors, terminals, browsers, VMs, containers, local OS surfaces, provider
  nodes, and external harnesses mediated by session connection profiles.
```

The Workbench code/systems surface may use VS Code-family adapters, Cursor,
Windsurf, JetBrains, browser IDEs, terminal/tmux views, and other editor/viewer
targets. Those targets are mediated adapter targets, not the parent product.

External coding or agent harnesses such as Codex, Claude Code, Grok Build,
OpenHands, Aider, DeepSeek TUI-like runtimes, shell/tmux loops, CI agents, and
hosted coding agents are Agent Harness Adapters. They may propose work through
Hypervisor Core and the Hypervisor Daemon, but they do not become Hypervisor
clients or runtime truth.

The daemon remains the execution owner. Agentgres owns admitted operational
truth. wallet.network owns authority, secrets, leases, approvals,
declassification, spend, revocation, and step-up. Storage backends hold bytes.
IOI L1 settles only selected public/economic/cross-domain commitments.

## Consequences

- Retired Tauri code and native desktop Rust paths must not be recreated as an active
  product path.
- The old root `ide/` artifact path is retired; adapter-host metadata and local
  editor build conventions live under `code-editor-adapters/`.
- Documentation must not use "Hypervisor IDE" as the live parent product.
  `Hypervisor Workbench` is the code/systems/workspace surface.
- Electron/VS Code is one current Code editor adapter-host implementation, not
  the product identity.
- Hypervisor App, Hypervisor Web, CLI/headless, SDK, ADK, Workbench, Foundry,
  Fleet, external harness adapters, and provider integrations must share daemon
  and domain contracts.
- Application surfaces may compose and inspect work, but consequential actions
  still route through daemon policy, wallet.network authority, Agentgres
  admission, receipts, replay, and verification.
- Remote/provider sessions must declare local-only, provider-trust, TEE, or
  cTEE/private-workspace posture before protected state is mounted or
  projected.

## Anti-Patterns

Do not model:

```text
Hypervisor = IDE
Hypervisor = VS Code fork
Hypervisor App = Core owner
Hypervisor Web = separate runtime
CLI/TUI = separate runtime
Tauri = compatibility path to preserve
root ide/ = active product source
Workbench = runtime truth
Foundry = direct self-mutation path
Fleet = execution authority
external agent harness = Hypervisor client
editor preference string = adapter contract
```

Correct:

```text
Hypervisor = shared governed autonomous-work substrate
Hypervisor Core = shared client/surface/session/adapter contracts
Hypervisor Daemon = execution owner
App/Web/CLI-headless = first-class clients
Workbench/Foundry/Fleet = application surfaces
adapter targets = mediated execution/view/control targets
wallet.network = authority
Agentgres = admitted truth
```

## Supersedes

- ADR 0007's "IDE-first Autopilot" product framing.
- ADR 0009's "Electron/VS Code fork as canonical app shell" framing.

Those ADRs remain useful implementation history for why Tauri was retired and
why first-class Code editor adapter integration matters.

## Canonical References

- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/components/hypervisor/fleet.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/vocabulary.md`
