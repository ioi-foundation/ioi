# ADR 0008: Adopt IOI Authority Gateway As The Sidecar Adoption Wedge

- Status: Accepted
- Date: 2026-05-20
- Owners: daemon runtime / Hypervisor / connectors-tools / wallet.network / policy

## Context

Hypervisor Workbench is the canonical full operator console for IOI-governed
autonomous systems, but the market will not standardize on one agent UI. Users
will keep using Cursor, VS Code, JetBrains, Codex, Claude Code, OpenHands-like
tools, hosted agent products, browser automations, MCP tools, and whatever comes
next.

IOI should not force every user to switch surfaces before they can benefit from
alignment-secure execution. The stronger adoption wedge is:

> **Keep your IDE. Keep your model. Put consequential execution behind IOI.**

## Decision

IOI Authority Gateway is the canonical sidecar/compatibility profile for routing
proposed actions from existing IDEs, CLI agents, hosted agents, MCP tools,
shell/Git surfaces, browser adapters, API gateways, credential brokers, and
CI/CD gates through the IOI daemon.

Hypervisor Workbench remains the native full code/systems experience over
Hypervisor Core. IOI Authority Gateway is not a separate runtime and not merely
a VS Code extension identity. "Hypervisor Guard" may be used as
developer-facing packaging for the adapter bundle, but the canonical
architecture term is IOI Authority Gateway.

The operating doctrine is:

> **Models reason. IOI authorizes action.**

Adapters submit action requests, previews, observations, and approval decisions.
The daemon owns policy, authority scopes, effect execution, receipts, replay,
settlement hooks, secrets, and durable runtime state.

## Consequences

- IOI can support users who keep existing IDEs, models, and agent tools while
  still moving consequential actions behind a deterministic authority boundary.
- VS Code-family integrations can use extensions, terminals, workspace watchers,
  MCP gateways, and command wrappers where available.
- CLI agents can run as guest workloads behind shell wrappers, tool proxies, and
  daemon action-request APIs.
- Hosted agent systems can integrate through API gateways, GitHub Apps, webhook
  mediation, CI/CD policy gates, receipt ingestion, and wallet.network delegated
  credentials where possible.
- The sidecar creates an installed base for aiagent.xyz workers, sas.xyz
  outcomes, wallet.network authority, and IOI settlement without cannibalizing
  the native Hypervisor Workbench.
- Adapter documentation must be precise about what it can mediate. Closed or
  opaque tools may expose only partial control points.

## Non-Goals

- Do not represent IOI as merely a VS Code security plugin.
- Do not move daemon authority into an IDE extension, shell wrapper, webview,
  MCP server, API proxy, Git hook, browser adapter, hosted-agent gateway, CI/CD
  gate, SDK helper, or Hypervisor UI surface.
- Do not claim full interception of opaque third-party runtimes when only shell,
  file, Git, MCP, API, browser, credential, webhook, or CI/CD control points are
  available.
- Do not make Authority Gateway a competing product substrate beside Hypervisor
  Workbench. It is the compatibility profile over the same daemon substrate.

## Canonical Framing

```text
IOI daemon = deterministic execution boundary
Hypervisor Workbench = native code/systems operator surface
IOI Authority Gateway = compatibility sidecar/adapters
Workers/models/tools/connectors = guest workloads/capabilities
wallet.network = authority/secrets/payment
IOI mainnet = settlement/reputation/dispute/proof anchoring
```
