# Start Here

Status: entry-point shim.
Canonical owner: [`_meta/start-here.md`](./_meta/start-here.md).
Supersedes: references that expected a top-level `docs/architecture/START_HERE.md`.
Superseded by: none.
Last alignment pass: 2026-06-17.

Start with [`_meta/start-here.md`](./_meta/start-here.md).

That file owns the five-minute stack model, role-based reading paths, common
boundary mistakes, and links to the source-of-truth map, vocabulary, and
implementation matrix.

Fast entry routes now live there as well:

```text
Hypervisor cockpit / IOI reference shell
  -> components/hypervisor/core-clients-surfaces.md

External coding tools and heterogeneous harnesses
  -> components/hypervisor/core-clients-surfaces.md
  -> components/daemon-runtime/default-harness-profile.md

Wallet authority, approvals, agent credentials, exchange, or trade
  -> components/wallet-network/doctrine.md
  -> components/wallet-network/product-exchange-risk.md

Private rented/cloud compute and cTEE/model-weight posture
  -> components/daemon-runtime/private-workspace-ctee.md
  -> components/hypervisor/providers-and-environments.md

Agentgres refs, storage backends, restore, or artifact repair
  -> components/agentgres/artifact-ref-plane.md
  -> components/storage-backends/doctrine.md

aiagent managed workers or sas service outcomes
  -> domains/aiagent/worker-marketplace.md
  -> domains/sas/service-marketplace.md

Physical/embodied work
  -> foundations/physical-action-safety.md

Provider integrations across local, cloud, DePIN, storage, or HypervisorOS
  -> components/hypervisor/providers-and-environments.md

Stockfish-style coding, multi-agent search, or benchmarked outcome races
  -> components/hypervisor/outcome-rooms.md
```

Current Hypervisor product-surface addition:

> **Hypervisor Core is the shared product/runtime substrate whose execution owner
> is the Hypervisor Daemon. Hypervisor App, Hypervisor Web, and CLI/headless are
> first-class clients over Core; TUI is an optional CLI presentation. Hypervisor
> Workbench, Automations, and Foundry are application surfaces over the same
> Core. Automations owns the durable workflow/service/mission surface, while
> Canvas is a visual editor/projection inside Automations, Workbench, or
> Foundry. Outcome Rooms are governed collaborative missions for
> multi-agent/multi-session search toward one measurable outcome. Sessions are
> the primary unit. Providers, environments, services, tasks, ports, logs,
> archive refs, restore refs, and infrastructure posture are default Hypervisor
> session/project/provider views, not a separate Fleet surface. Editor
> integrations and external agent harnesses such as VS Code, Cursor, Windsurf,
> JetBrains, Codex, Claude Code, Grok Build, browser IDEs, terminals, VMs,
> local OS surfaces, and HypervisorOS nodes are adapter targets, not
> Hypervisor's product identity.**

Current Wallet addition:

> **wallet.network is the authority wallet and cockpit for autonomous finance. Wallet
> Exchange is source-agnostic: route sources such as decentralized.exchange,
> direct pools, routers, solvers, and quote APIs produce candidates, but
> wallet.network owns exchange authority, risk disclosure, approval, signing or
> denial, revocation, protection actions, and receipts. Wallet Trade is
> advanced and high-risk: perps, margin, leverage, prediction markets, event
> contracts, and position lifecycle require exact TradeIntent or
> PredictionIntent approval, risk labels, and position or prediction receipts.**

Current Wallet/provider integration addition:

> **decentralized.exchange is a route-intelligence engine for liquidity and
> decentralized.trade is a venue/market-intelligence engine for exposure,
> including event markets. Hypervisor has direct provider integrations for cloud
> compute, storage, GPUs, confidential compute, DePIN, local machines, and customer
> infrastructure. Candidates propose; wallet.network authorizes; Hypervisor
> executes or deploys; venues and providers perform; Agentgres records; IOI L1
> settles by trigger.**

Current aiagent broad-labor addition:

> **aiagent.xyz is the discovery, procurement, installation, initialization, and
> routing layer for ontology-bound digital and embodied workers. The marketplace
> indexes WorkerPackages and ManagedWorkerInstances through
> DigitalWorkerOntology, VerticalOntologyPacks, IntegrationSurfaces, lifecycle
> policy, receipts, benchmarks, authority requirements, runtime posture, and
> safety posture instead of hardcoded vertical directories.**
