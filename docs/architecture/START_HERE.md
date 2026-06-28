# Start Here

Status: entry-point shim.
Canonical owner: [`_meta/start-here.md`](./_meta/start-here.md).
Supersedes: references that expected a top-level `docs/architecture/START_HERE.md`.
Superseded by: none.
Last alignment pass: 2026-06-23.

Start with [`_meta/start-here.md`](./_meta/start-here.md).

That file owns the five-minute stack model, role-based reading paths, common
boundary mistakes, and links to the source-of-truth map, vocabulary, and
implementation matrix.

For the current cross-owner architecture digest, read
[`_meta/current-canon-defaults.md`](./_meta/current-canon-defaults.md). For the
edit-first owner of any subject, read
[`_meta/source-of-truth-map.md`](./_meta/source-of-truth-map.md).

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
  -> components/daemon-runtime/embodied-runtime.md

Ecosystem assurance, certification, compliance, liability, or audit exports
  -> foundations/ecosystem-assurance-certification-liability.md

Provider integrations across local, cloud, DePIN, storage, or HypervisorOS
  -> components/hypervisor/providers-and-environments.md

Pricing boundaries, Work Credits, marketplace fees, token/BME timing, or
  whether a substrate should monetize
  -> foundations/economic-flywheel-and-pricing-boundaries.md

ioi.ai multi-model goal pursuit, Stockfish-style coding search, or
goal-appropriate collaborative outcomes
  -> domains/ioi-ai/collaborative-outcome-pattern.md

Model gardens, tuning, evals, datasets, endpoints, training, package promotion,
or ontology-aware worker building
  -> components/hypervisor/foundry.md
```

Current Hypervisor product-shell addition:

> **Hypervisor Core is the shared runtime/control substrate whose execution owner
> is the Hypervisor Daemon. Hypervisor App, Hypervisor Web, and CLI/headless are
> first-class clients over Core; TUI is an optional CLI presentation. The default
> shell is Home, Projects, Automations, Applications, and Sessions: Home starts
> or resumes work, Projects organize persistent software/system work,
> Automations own durable workflows/services, Applications expose specialized
> surfaces, and Sessions show live and historical execution. Workbench,
> Automations, and Foundry are application surfaces over the same Core. ioi.ai
> is the intent-to-outcome surface; when a goal calls for it, ioi.ai can
> coordinate multiple models, harnesses, workers, connectors, sessions, branches,
> and verifier lanes over Hypervisor. Foundry is the model, worker, eval,
> dataset, simulation-training, endpoint, registry, and ontology-aware
> package-building surface. Providers, environments, services, tasks, ports,
> logs, archive refs, restore refs, and infrastructure posture are default
> Hypervisor session/project/provider views. Editor integrations and external
> agent harnesses such as VS Code, Cursor, Windsurf, JetBrains, Codex, Claude
> Code, Grok Build, browser IDEs, terminals, VMs, local OS surfaces, and
> HypervisorOS nodes are adapter targets, not Hypervisor's product identity.
> Hypervisor Core coordinates authority gateways but does not replace
> wallet.network authority or Agentgres truth.**

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
> infrastructure. Candidates propose; authority providers and local/domain
> governance authorize as required, with wallet.network mandatory for portable
> delegated authority and high-risk external effects; Hypervisor executes or
> deploys; venues and providers perform; Agentgres records; IOI L1 settles by
> trigger.**

Current aiagent broad-labor addition:

> **aiagent.xyz is the discovery, procurement, installation, initialization, and
> routing layer for ontology-bound digital and embodied workers. The marketplace
> indexes WorkerPackages and ManagedWorkerInstances through
> DigitalWorkerOntology, VerticalOntologyPacks, IntegrationSurfaces, lifecycle
> policy, ManagedWorkerOnboardingPlans, ContactDeliveryChannels, receipts,
> benchmarks, authority requirements, runtime posture, and safety posture instead
> of hardcoded vertical directories.**
