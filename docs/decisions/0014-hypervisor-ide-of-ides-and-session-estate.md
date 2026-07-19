# ADR 0014: Make Hypervisor An IDE-Of-IDEs And Session Estate

- Status: Accepted
- Date: 2026-06-17
- Owners: Hypervisor / Workbench / provider integrations / daemon runtime / wallet.network / Agentgres
- Refined by: ADR 0016, which keeps the IDE-of-IDEs and execution boundaries
  while renaming Workbench to Developer Workspace and broadening the product
  estate from Sessions to typed Work projections.

## Context

ADR 0013 established the correct broad taxonomy: Hypervisor Core is the shared
substrate, Hypervisor App/Web/CLI-headless are clients, Workbench and Foundry
are application surfaces, adapter targets are mediated through Core, and the
Hypervisor Daemon remains the execution owner.

That decision still left two product-shape risks:

```text
1. Hypervisor could still be implemented as a single IDE shell with extra tabs.
2. Infrastructure estate management could still harden into a separate Fleet
   product or posture layer.
```

Both are the wrong end shape.

The product needs to manage code editors, terminal views, browser workspaces,
remote VMs, local workspaces, provider nodes, hosted workers, model surfaces,
workflow canvases, autonomous agents, and privacy/authority posture through one
governed substrate. No single editor, file tree, terminal, cloud console, or
provider dashboard should become the product identity.

Likewise, provider and infrastructure management is not a separate app users
should have to learn. It is part of managing sessions, projects, environments,
and the cross-session estate.

## Decision

Hypervisor is an **IDE-of-IDEs**:

```text
Hypervisor is not one IDE.
Hypervisor is the governed substrate that can host, connect, select, mediate,
and receipt many editor, terminal, browser, VM, worker, and node targets.
```

The parent product is:

```text
Hypervisor
  shared governed autonomous-work substrate.
```

The first-class clients are:

```text
Hypervisor App
Hypervisor Web
Hypervisor CLI/headless
```

The application surfaces include:

```text
Workbench
Foundry
Agents
Models
Privacy / cTEE
Authority
Receipts / Audit
Insights
Automations / Workflows
provider and environment views
```

The mediated targets include:

```text
editor targets
terminal targets
browser targets
VM / container / microVM targets
local OS targets
provider nodes
HypervisorOS nodes
external agent harnesses
```

Editor and harness integrations are adapter targets, not product identity. A
workspace can choose an adapter target per session or project, and Hypervisor
may embed, open, connect to, or supervise that target through an
`AdapterConnectionProfile`. The adapter target never becomes runtime truth.

Provider and infrastructure estate management is abstracted into **sessions and
session estate**, not a separate Fleet product.

The canonical unit is:

```text
HypervisorSession
  a governed live, idle, archived, blocked, or restorable unit of autonomous
  work.
```

Session estate is viewed through:

```text
Projects
Sessions
Environments
Providers
Nodes
Storage
Costs
Health
Archive / Restore
Access leases
Services
Tasks
Ports
Logs
SCM auth
```

Those views are Hypervisor views over daemon/Core objects. They are not a
separate Fleet runtime, app, authority plane, storage authority, or source of
truth.

## Ownership Boundary

```text
Hypervisor App/Web/CLI-headless
  Clients over Core.

Hypervisor Core
  Shared client/surface/session/adapter contracts.

Hypervisor Daemon
  Execution owner and policy/effect boundary.

Workbench
  Code/systems surface that selects and mediates editor/terminal/browser
  targets.

Provider/environment views
  Cross-session estate views over sessions, environments, providers, costs,
  health, storage, access, and restore posture.

wallet.network
  Authority, approvals, secrets, capability leases, spend, SCM credential
  release, access leases, declassification, and revocation.

Agentgres
  Admitted operational truth, receipts, state roots, artifact refs, archive
  refs, replay/import metadata, and restore validity.

Storage backends
  Payload and archive bytes only.
```

## Consequences

- Product copy and implementation docs must not describe Hypervisor as a
  singular IDE product.
- The code/systems experience belongs to Workbench, but Workbench is one
  surface over Hypervisor Core.
- Editor selection belongs to adapter connection profiles and project/session
  preferences, not to product identity.
- External agent harnesses are mediated harness adapters. They may propose work
  and exercise leased capabilities, but they do not own runtime truth.
- Provider and infrastructure posture appears through session, project,
  provider, and environment views.
- The term `Fleet` is deprecated for live product architecture. Existing code
  paths using that name are implementation debt and should be renamed to
  provider/environment/session-estate language when touched.
- Session estate actions that affect authority, privacy, cost, access, replay,
  or restore must route through daemon policy, wallet.network authority,
  Agentgres receipts, and restore/import semantics.
- Encrypted blobs may be necessary restore material, but they are never restore
  truth by themselves.

## Anti-Patterns

Do not model:

```text
Hypervisor = one IDE
Workbench = parent product
editor target = product identity
editor preference = adapter contract
external harness = Hypervisor client
terminal harness = runtime truth
Fleet = separate app
Fleet = posture layer
Fleet = provider authority
provider dashboard = restore truth
encrypted provider volume = restore truth
```

Correct:

```text
Hypervisor = IDE-of-IDEs plus governed session estate
Workbench = code/systems surface
Adapter target = mediated workspace target
Session = unit of governed work
Provider/environment views = session-estate projections
Daemon = execution owner
wallet.network = authority
Agentgres = admitted truth
Storage backends = bytes
```

## Supersedes / Refines

This ADR refines ADR 0013.

It supersedes the part of ADR 0013 that treated Fleet as a live application
surface. It preserves ADR 0013's Core/client/surface/adapter taxonomy, daemon
execution boundary, Workbench surface, and adapter-target model.

## Canonical References

- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/components/hypervisor/providers-and-environments.md`
- `docs/architecture/components/hypervisor/fleet.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/vocabulary.md`
