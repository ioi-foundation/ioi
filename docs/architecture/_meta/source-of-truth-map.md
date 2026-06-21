# Architecture Source Of Truth Map

Status: canonical documentation ownership map.
Canonical owner: this file for where architecture subjects should be edited first.
Supersedes: informal subject ownership scattered across plans/specs.
Superseded by: none.
Last alignment pass: 2026-06-21.

## Purpose

This map prevents split-brain architecture documentation. When a subject appears
in multiple plans, specs, evidence bundles, or implementation guides, edit the
canonical architecture file first and let supporting docs reference it.
Internal master guides are private execution scaffolding, not doctrine. They may
carry raw comparisons, sensitive sequencing, and transitional language; any
durable architectural decision they produce must be distilled into the canonical
owner below or into an accepted ADR before other docs or code treat it as canon.

New readers should start with [`../START_HERE.md`](../START_HERE.md), which
points to the canonical [`start-here.md`](./start-here.md). Builders who already
know the stack can use [`implementation-matrix.md`](./implementation-matrix.md)
to map each concept to its durable form, owner doc, code anchor, and conformance
hook.

Conflict rule:

1. Prefer `docs/architecture/` over plans, specs, ignored local master guides,
   and evidence when architecture direction conflicts.
2. If two architecture files disagree, prefer the newer aligned direction.
   Current canonical defaults:
   - `prim:*` means primitive execution capability;
   - `scope:*` means wallet/provider authority scope;
   - daemon/public runtime APIs own execution semantics;
   - Hypervisor Daemon runtime nodes are the hypervisor/control plane for
     autonomous execution;
   - Workflow Compositor owns high-level directed workflow/service shape:
     graph, dependencies, step contracts, review points, delivery contracts,
     and reusable templates;
   - HarnessProfiles are daemon-executed or daemon-mediated step-resolution
     profiles/adapters; they must produce common boundary objects and cannot
     own execution truth;
   - the Default Harness Profile is IOI's reference scaffold/fallback
     HarnessProfile for loop-native scoped step resolution; it is not a peer
     runtime, not the only admissible harness, not a meta-harness, and not the
     owner of high-level workflow composition;
   - persistent workspace intelligence such as skills, Agent Wiki /
     `ioi-memory`, wiki facts, learned tool affordances, and durable
     behavior-affecting context is workspace/project/domain state that should
     survive model/harness swaps when workspace identity, compatibility,
     provenance, policy, and authority allow;
   - the Hypervisor Daemon is the deterministic execution substrate for
     portable, verifiable autonomous systems;
   - HypervisorOS is the bare-metal node profile where the Hypervisor Daemon is
     the node root; it improves control, integrity, containment, measurement,
     reproducibility, and policy enforcement, but it is not a peer runtime and
     does not replace cTEE no-plaintext-custody;
   - Hypervisor manages sessions, environments, providers, and cross-session
     infrastructure posture directly through the Applications catalog, the
     singular Open Application slot, session detail, project settings, provider
     settings, org/admin views, and operator console panels; provider posture
     is not a separate product or truth layer;
   - Hypervisor Core is the shared runtime/control substrate whose execution
     owner is the Hypervisor Daemon; it is not a peer runtime beside the daemon,
     not a replacement for wallet.network, and not a replacement for Agentgres;
   - Hypervisor App, Hypervisor Web, and Hypervisor CLI/headless are
     first-class clients over Hypervisor Core; TUI is an optional presentation
     of the CLI/headless client, not a separate first-class client lane;
   - Hypervisor's default shell is Home, Projects, Automations, Applications,
     and Sessions; Applications is a query-first catalog rather than permanent
     rail expansion, `Open Application` is a singular active surface slot, and
     specialized platform and vertical surfaces should resolve through the
     Applications catalog, Open Application, or contextual views unless product
     testing proves a new top-level category is needed;
   - Hypervisor product direction is an open operating environment for
     autonomous systems, organized by a lifecycle lens of Build, Run/Scale,
     Govern, Observe/Verify, Optimize, and Package/Trade behind the stable
     shell;
   - Hypervisor Workbench, Automations, Foundry, Agents / Workers, Models,
     Connectors / Tools / MCP, Data / Knowledge, Ontology, Authority / Govern,
     Receipts / Replay, Operate / Monitoring, Providers / Environments,
     Privacy / cTEE, Change Plane, Marketplace, Patterns / Examples / Training, and
     Domain Apps are application surfaces over Hypervisor Core, not
     runtime-truth owners; favorites, recommended apps, promoted apps, pinned
     apps, and organization shortcuts are catalog, Home, project/session, or
     user preference affordances, not canonical shell categories;
   - Hypervisor application surfaces should register stable identity, owner doc,
     object families, allowed placements, launch modes, project/session
     compatibility, daemon/API dependencies, authority/privacy posture,
     receipts/replay/eval/package obligations, and install/favorite/recommended
     metadata before becoming durable first-class inventory;
   - Patterns / Examples / Training is the role-guided recipe surface for
     turning learning tracks, solution diagrams, example apps, starter
     automations, data recipes, ontology packs, eval packs, and package
     templates into governed sessions, automations, Foundry jobs, domain apps,
     receipts, replay, promotion proposals, and marketplace paths;
   - Agents are configurable, buildable product objects over Hypervisor Core;
     Workers remain the accountable protocol package/manifest boundary.
     Product controls such as Agent, Mode, Model, Reasoning, Speed, Harness,
     Tools / Connectors, Memory, Authority, Budget, Evals, and
     Receipts / Replay compile into daemon records, wallet authority, model
     routing, HarnessProfile selection, Agentgres operations, and receipts;
   - Models is the product-facing surface label; ModelRoute remains the
     implementation/runtime object for provider, custody, fallback, spend,
     privacy, eligibility, and invocation policy;
   - Hypervisor's Agent Operating Plane is daemon-owned: configured agent
     records, agent/session admission, work queues, work items, work runs,
     turn control, conversation streams, subagent delegation, runner
     reconciliation, usage accounting, and exec/security telemetry are
     runtime contracts, not client-local state;
   - Hypervisor Automations is the durable workflow, trigger, schedule,
     API/service, approval-flow, queue, and background-mission surface over the
     Workflow Compositor; it is not a peer runtime and does not own
     wallet.network authority or Agentgres truth;
   - ioi.ai is the intent-to-outcome surface and may coordinate multiple models,
     harnesses, workers, connectors, sessions, verifier paths, and attempt
     strategies over Hypervisor when a goal calls for it;
   - Hypervisor Foundry owns the model/worker/eval/dataset/registry/endpoint/
     training/package build surface, including ontology-aware capability
     packaging and promotion proposals;
   - Data / Knowledge and Ontology are first-party Hypervisor surfaces over the
     semantic data plane; Foundry consumes them for training, evaluation,
     simulation, worker/package generation, and capability improvement, but does
     not own semantic truth;
   - Connectors / Tools / MCP is a first-party Hypervisor surface over the
     authority-aware registry; MCP servers, external agent tools, and
     workflow-as-tool subgraphs must compile to RuntimeToolContract, primitive
     capabilities, authority scopes, policy decisions, and receipt obligations;
   - wallet.network is the autonomous-work authority wallet and gateway for
     identity, auth factors, guardian surfaces, key shards, provider credential
     bindings, delegated authority, leases, approvals, secrets, spend, data-use
     permission, declassification, revocation, policy simulation inputs,
     gateway decisions, risk labels, and authority receipts;
   - Hypervisor Workbench is the live code/systems surface term;
   - editor integrations such as VS Code, Cursor, Windsurf, JetBrains, browser
     IDEs, terminals, VMs, local OS surfaces, and HypervisorOS nodes are
     adapter targets, not Hypervisor's product identity;
   - external CLI or hosted agent harnesses such as Codex, Claude Code, Grok
     Build, OpenHands, Aider, shell/tmux agents, CI agents, and hosted coding
     agents are Agent Harness Adapters; they submit proposed work through
     Hypervisor Core and the daemon and do not become Hypervisor clients or
     runtime truth;
   - host-terminal harness sessions become daemon-admitted only after recipe
     admission, harness binding admission, launch, spawn, readiness, terminal
     attach, and transcript projection refs are all bound; a Hypervisor client
     PTY is transport, not runtime truth;
   - Hypervisor is the flagship product substrate for building, deploying, and
     governing autonomous systems through daemon/runtime contracts;
   - Hypervisor product UX direction belongs in the canonical owner docs; any
     private sprint, research, or product-reference scaffold must be translated
     into ownership, authority, state, receipt, privacy, and adapter contracts
     before it becomes doctrine;
   - ioi.ai Goal Chat is an intent and coordination surface: it may ask,
     invoke, inspect, summarize, and draft Hypervisor work, but durable
     workflows/services must hand off to Hypervisor Automations and execution
     must pass through the Hypervisor Daemon;
   - IOI Authority Gateway is the daemon sidecar/compatibility profile for
     existing IDE, CLI, browser, hosted-agent, and MCP/tool ecosystems; it is
     not a separate runtime;
   - Agentgres is operation-backed domain truth with a Postgres bridge;
   - Agent Wiki / `ioi-memory` is the adjacent context-memory plane for what
     agents can know, retrieve, and remember; Agentgres admits and proves
     durable memory mutations when they become canonical, shared, portable,
     replayable, policy-relevant, routing-relevant, training-relevant, or
     restore-relevant;
   - Agentgres artifact refs own payload meaning, lifecycle, policy,
     authority, receipts, replay/import metadata, archive/restore validity, and
     state-root validity;
   - private user/app state follows the same split as private agent state:
     Agentgres owns canonical refs and meaning, storage backends hold encrypted
     bytes, wallet.network controls viewing/decryption/mutation authority, and
     IOI L1 receives only selected public/economic/cross-domain commitments;
   - wallet.network is the authority wallet and user-facing cockpit for
     autonomous agents and autonomous finance: it owns auth-factor posture,
     guardian and key-shard posture, provider credential binding posture,
     agent/session authority, exchange authority, trade authority, risk
     disclosure, approval, signing/denial, revocation, protection actions, and
     wallet receipts, while agents, routes, venues, connectors, and provider
     adapters only produce requests or candidates;
   - `decentralized.exchange` is a preferred first-party route-intelligence
     engine for asset conversion, not a mandatory exchange UI, exchange
     backend, authority layer, liquidity owner, execution owner, or trust root;
   - `decentralized.trade` is a preferred first-party venue, market, and
     exposure-intelligence engine, not a mandatory trading UI, broker,
     custodian, user position owner, authority layer, venue execution owner, or
     trust root;
   - Hypervisor has direct provider integrations for cloud compute, storage,
     GPUs, confidential compute, DePIN, local machines, customer cloud,
     enterprise infrastructure, decentralized storage, and user-specified
     provider routes;
   - aiagent.xyz is the discovery, procurement, installation, initialization,
     and routing layer for ontology-bound digital and embodied workers; it
     indexes workers through `DigitalWorkerOntology`, `VerticalOntologyPack`,
     `IntegrationSurface`, `ManagedWorkerInstance`, managed-instance lifecycle,
     receipts, benchmarks, authority, runtime posture, and safety posture instead of hardcoded
     vertical directories;
   - decentralized.exchange/trade produce route candidates; wallet.network
     authorizes;
     Hypervisor deploys or executes; venues and providers perform; Agentgres
     records; IOI L1 settles by trigger;
   - storage backends such as Filecoin/CAS, S3, local disk, and object stores
     hold payload bytes only; missing, invalid, stale, or unavailable payloads
     become Agentgres `ArtifactAvailabilityIncident` records plus repair
     receipts when they affect admitted work;
   - Private Workspace backed by cTEE is the daemon-owned workspace/execution
     profile for persistent rented GPU Hypervisor Nodes that must keep protected
     plaintext off provider-controlled nodes by default;
   - Candidate-Lattice Private Decoding is the default protected-agency strategy
     for Private Workspace backed by cTEE: rented nodes generate candidates,
     sealed/private heads select or deny;
   - IOI kernel is the L0 substrate;
   - IOI L1 is the public settlement, registry, dispute, and governance root;
   - autonomous systems can execute anywhere; IOI settles what matters;
   - AIIP moves delegated autonomous work, authority leases, receipts,
     settlement intents, disputes, reputation queries, and handoffs across
     bounded execution domains;
   - AIIP uses the same semantic protocol for local Hypervisor microharness
     routing and external autonomous-system handoffs, while transport and
     settlement mode vary by profile;
   - governed autonomous-system chains are system-local execution chains with
     policy, modules, proposals, receipts, state roots, and governed upgrades;
   - a Hypervisor Node is a local settlement, orchestration, authority, state,
     replay, routing, and interop domain for many governed autonomous-system
     chains;
   - Hypervisor App, Hypervisor Web, CLI/headless, Workbench, Automations,
     Foundry, other application surfaces, and Providers / Environments views
     are not the Hypervisor Node; they are clients, application surfaces, or
     projections, while the node is the local settlement domain composed around
     Hypervisor Daemon, Agentgres, wallet.network authority paths, local
     registries, receipts, and replay;
   - Hypervisor Nodes settle autonomous work locally; IOI L1 settles machine
     labor globally;
   - IOI topology is edge-in and fractal;
   - verifiable bounded agency is IOI's execution-boundary alignment thesis:
     workers may reason or propose probabilistically, but consequential effects
     cross reality only through bounded authority, policy, receipts, and
     verification;
   - Smarter-agent runtime loop is the bounded cognition discipline for
     model pass, action proposal, gate, execution, observation, receipt, and
     re-entry; it is mediated by Hypervisor Daemon/Core and never owns
     execution authority by itself;
   - `physical_action` is a high-risk effect class, not a generic tool-call
     variant; actuator-affecting work must bind to Physical Action Safety
     objects such as `PhysicalActionPolicy`, `SafetyEnvelope`,
     `EmergencyStopAuthority`, `SensorEvidenceReceipt`, and
     `ActuatorCommandReceipt` before execution;
   - workers, models, tools, connectors, browsers, shells, and computer-use
     providers are guest workloads/capabilities leased through daemon
     authority;
   - policy, receipts, replay, approvals, authority scopes, and settlement hooks
     are the shared trust/audit substrate;
   - clients are projections or operators, not private runtime truth;
   - Providers / Environments views in Hypervisor App, Hypervisor Web,
     CLI/headless projections, and console.ioi.ai are projections and control
     lenses over daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
     substrate; they are not separate apps with separate runtime truth;
   - CLI/headless, SDK, and ADK are separate surfaces: CLI/headless is the
     operator/scripting/CI client, TUI is an optional presentation of it, SDK is
     the low-level protocol/client library, and ADK is the autonomous-system
     builder framework;
   - IDE/CLI/browser/hosted-agent adapters mediate through available control
     points only and must not claim total interception of opaque tools;
   - models and agents may reason or propose; the daemon authorizes anything
     that crosses the deterministic execution boundary;
   - Hypervisor's primary build artifact is an Autonomous System Package;
   - Autonomous System Package lifecycle is compose -> bind -> simulate ->
     authorize -> run -> verify -> inspect receipts -> package -> deploy ->
     promote -> improve;
   - Worker is the protocol actor;
   - Model is a cognition backend;
   - MoW is labor routing;
   - Worker Training is the supply-creation lifecycle;
   - TrainingBatchPlan, RawBatchArchive, QualityGateReport,
     ModelCapacityProfile, and TrainingCostLedger are first-class Foundry and
     Agentgres objects when batch-level training mechanics matter;
   - Domain Ontologies and Data Recipes are the semantic data plane, surfaced
     in Hypervisor through Data / Knowledge and Ontology applications or
     contextual views;
   - DistilledOntologyDataset is the compact high-signal data substrate for
     efficient specialist training and evaluation when useful;
   - adaptive work graph is execution strategy only.
3. Record resolved contradictions only when the decision history is needed for
   future maintainers; do not keep obsolete variants as parallel doctrine.

## Subject Ownership

| Subject | Canonical Owner | Low-Level Reference | Supporting Context |
| --- | --- | --- | --- |
| First-read architecture path | [`start-here.md`](./start-here.md), [`../START_HERE.md`](../START_HERE.md) | [`source-of-truth-map.md`](./source-of-truth-map.md), [`implementation-matrix.md`](./implementation-matrix.md), [`vocabulary.md`](./vocabulary.md) | role-based onboarding paths; top-level shim avoids broken references |
| Architecture whitepaper synthesis and publishing source | [`whitepaper.tex`](../whitepaper.tex) | all component owner docs in this map | current long-form architecture synthesis; it summarizes the canon but does not override subject owners. If a drift is found, update either the whitepaper or this owner map explicitly |
| Concept implementation status and durable form | [`implementation-matrix.md`](./implementation-matrix.md) | subject owner docs listed per row | code anchors, conformance hooks, promotion guidance |
| Hypervisor kernel substrate unification migration, Step/Module ABI, route-family owner map, Rust core extraction target, JS facade retirement, and terminal conformance command contract | [`hypervisor-kernel-substrate-unification-master-guide.md`](./hypervisor-kernel-substrate-unification-master-guide.md) | [`hypervisor-kernel-substrate-migration-matrix.md`](./hypervisor-kernel-substrate-migration-matrix.md), [`implementation-matrix.md`](./implementation-matrix.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | `hypervisor-conformance`, Rust core module targets, and route-family cleanup conditions |
| Canon readability and enterability workplan | [`canon-readability-audit.md`](./canon-readability-audit.md) | [`start-here.md`](./start-here.md), [`implementation-matrix.md`](./implementation-matrix.md) | cleanup backlog and terminology watchlist |
| Web4 category and IOI stack | [`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | architectural-improvements plans |
| decentralized.* domain pack, decentralized.exchange, decentralized.trade, route/venue-intelligence engine boundaries, prediction markets/event contracts, trade/provider non-ownership, and proposal/authority/execution/truth/settlement split | [`domains/decentralized/README.md`](../domains/decentralized/README.md) | [`exchange.md`](../domains/decentralized/exchange.md), [`trade.md`](../domains/decentralized/trade.md), [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md), [`hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | Wallet is the cockpit; decentralized.exchange is a route-intelligence engine for liquidity; decentralized.trade is a venue/market-intelligence engine for exposure including prediction markets/event contracts; Hypervisor integrates directly with compute/storage/GPU/confidential/DePIN/local/customer providers; candidates propose, Wallet authorizes, Hypervisor executes/deploys, venues/providers perform, Agentgres records, IOI settles by trigger |
| AIIP, bounded execution domains, work interop, and cross-system handoffs | [`aiip.md`](../foundations/aiip.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | autonomous-system settlement layer synthesis, IBC comparison notes, marketplace interop docs |
| Physical action safety, embodied workers, robot fleets, actuator commands, human supervision, emergency stop, sensor evidence, physical-action receipts, and incidents | [`physical-action-safety.md`](../foundations/physical-action-safety.md) | [`aiip.md`](../foundations/aiip.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | `physical_action` is not a generic tool call; robot fleets and actuator APIs must bind safety envelopes, supervision, e-stop authority, sensor evidence, actuator receipts, and incident state before execution |
| Governed autonomous-system chains, Hypervisor Nodes, and machine-economy stack | [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | Hypervisor Node, local settlement, interop, and machine-economy strategy docs |
| Verifiable bounded agency and execution-boundary alignment | [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md) | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | bounded-agency thesis, conformance contracts, investor/product framing |
| Mixture of Workers and worker routing | [`mixture-of-workers.md`](../foundations/mixture-of-workers.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | aiagent/sas routing docs |
| Worker Training lifecycle and training profiles | [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | Hypervisor Foundry, aiagent categories, sas worker-training contracts |
| Domain Ontologies and Data Recipes | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | Data / Knowledge and Ontology Hypervisor surfaces, Hypervisor Foundry capability improvement, Worker Training, connector mappings, distilled ontology datasets, evaluation datasets, ontology-aware projections |
| IOI L1, L0/L1 boundary, and settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`ioi-l1-smart-contract-interfaces.md`](../foundations/ioi-l1-contract-interfaces.md) | sas/aiagent marketplace docs |
| Kernel/domain architecture and edge-in topology | [`domain-kernels.md`](../foundations/domain-kernels.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime package boundaries |
| Autonomous System Package lifecycle | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | Hypervisor lifecycle clarity master guide, autonomous systems shape audit, workflow compositor docs |
| Agentgres canonical state and Postgres bridge | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md) | detailed Agentgres reference module inside canonical owner, evidence/architectural-improvements-broad |
| Agentgres artifact refs, payload refs, evidence bundles, delivery bundles, archive refs, availability incidents, repair receipts, and restore/import validity | [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | storage backend docs, delivery/evidence docs; `ArtifactAvailabilityIncident` and `ArtifactRepairReceipt` govern backend failure without making storage backends authority layers |
| Private user/app state refs, encrypted profile metadata, app preferences, service intake state, workspace snapshots, and non-public app payloads | [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md) | App surfaces may resolve authorized views; IOI L1 stores only selected public/economic commitments |
| Agent Wiki, `ioi-memory`, persistent workspace intelligence, workspace/project/domain skills, learned tool affordances, and context-memory admission boundary | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | ADR 0001, roadmap memory notes, Hypervisor product context. Persistent intelligence is not owned by the selected model or harness and should be portable across swaps under compatibility, provenance, policy, and authority. |
| HarnessProfile, Default Harness Profile reference scaffold/fallback, loop-native step resolution, context topology, and output ownership | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`intent-resolution.md`](../../conformance/hypervisor-core/intent-resolution.md), [`effect-execution.md`](../../conformance/hypervisor-core/effect-execution.md), [`harness-profile-adapter.md`](../../conformance/hypervisor-core/harness-profile-adapter.md) | runtime harness code, default-harness projection/shadow/gated/live activation, external harness adapters, service module step resolution |
| HypervisorOS, bare-metal Hypervisor nodes, measured boot, daemon-rooted node control, `NodeEnforcementProfile`, executable/egress/datawall enforcement events, node measurement receipts, and HypervisorOS conformance | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | bare-metal node image plans, measured boot plans, provider/DePIN node integrity docs, enforcement/datawall/egress receipt docs |
| Hypervisor Core, Hypervisor App, Hypervisor Web, Hypervisor CLI/headless, optional TUI presentation, Hypervisor Home, Hypervisor Projects, Hypervisor Automations, Hypervisor Applications, Hypervisor Sessions, Hypervisor Workbench, Hypervisor Foundry, Patterns / Examples / Training, first-class clients, application surfaces, Missions, `HypervisorAutomationSpec`, `HypervisorAutomationRun`, `HypervisorWorkQueue`, `HypervisorWorkItem`, `HypervisorWorkRun`, `HypervisorWorkRunConversationProjection`, `HypervisorWorkRunIntegrationStatus`, `HypervisorWorkRunReviewState`, `AgentOperatingPlane`, `AgentRecord`, `AgentExecution`, `TurnControlInput`, `ModelConfiguration`, `ReasoningEffort`, `ServiceTier`, change/rollout/recall/remediation surface projections, adapter targets, `AdapterConnectionProfile`, editor targets, Agent Harness Adapters, `HypervisorHarnessSelectionOption`, `HypervisorSessionModelConfiguration`, `HarnessSessionBinding`, `HarnessSessionBindingAdmission`, `HarnessSessionLaunch`, `HarnessSessionSpawn`, `HarnessSessionReadiness`, `HarnessSessionTerminalAttach`, `HarnessTerminalTranscriptProjection`, `terminal_transcript` receipt evidence, `HarnessAdapterReceipt`, `HarnessContainerLanePlan`, `HarnessContainerLaneReceipt`, `HypervisorEnvironmentClass`, `HypervisorEnvironmentOpsProfile`, `AgentHarnessEnvironmentOpsProfile`, `HypervisorEnvironmentLifecycleState`, `HypervisorEnvironmentActivitySignal`, `HypervisorSessionAccessLease`, `SessionAccessToken`, `HypervisorEnvironmentService`, `HypervisorEnvironmentTask`, `HypervisorEnvironmentPort`, `HypervisorScmAuthRequirement`, `PortExposurePolicy`, `BrowserOpenPolicy`, `SupportBundlePolicy`, and client/surface/session/environment taxonomy | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`foundry.md`](../components/hypervisor/foundry.md), [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md) | Hypervisor is the open operating environment for autonomous systems. Home starts/resumes work; Projects organize persistent software/system work; Automations own durable workflows/services; Applications expose specialized vertical/platform surfaces; Sessions show live and historical execution. The lifecycle lens is Build, Run/Scale, Govern, Observe/Verify, Optimize, and Package/Trade behind the stable shell. Hypervisor App/Web/CLI-headless clients, optional TUI presentation, Workbench/Automations/Foundry and other application surfaces, role-guided patterns/examples/training, New Session governance, delegated agent-work queues/items/runs/review and conversation projections, ioi.ai collaborative outcome projections over Hypervisor, Providers / Environments and change/rollout/remediation views, VS Code/Cursor/Windsurf/JetBrains/browser IDE/terminal/VM/HypervisorOS adapter targets, Codex/Claude Code/Grok Build/OpenHands/Aider/CI harness adapters, first-session local model configurations, harness session bindings/admissions/launch/spawn/readiness/terminal-attach contracts, terminal transcript projections with client PTY read/poll/closure observations and closed transcript receipt-evidence refs as evidence, Codex OSS local Ollama/Qwen host-dev launch and admitted client-PTY attach contract, Docker/Podman container lane plans and receipts, session preferences, harness/model/privacy/authority selection, environment class/lifecycle/service/agent-service/task/port/SCM-auth objects, short-lived access/log/support leases and derived tokens, shared Core contracts |
| Hypervisor Foundry, model catalog, model registry, model routes, model mounts, tuning, training, evaluation, datasets, feature views, experiments, pipelines, endpoints, batch inference, metadata, monitoring, simulation training, robotics training worlds, package promotion, ontology-aware capability building, `FoundryProject`, `FoundryJobRequest`, and `FoundryScorecard` | [`foundry.md`](../components/hypervisor/foundry.md) | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md), [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md), [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md), [`physical-action-safety.md`](../foundations/physical-action-safety.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | Foundry is the platform-style build/eval/model/worker/simulation surface and capability improvement loop. It turns sessions, receipts, traces, corrections, failures, datasets, evals, and simulations into gated promotion or rollback proposals. It may use ontology-bound datasets, LiDAR/point-clouds, Gaussian splats, simulator worlds, and projections, but does not own runtime execution, wallet authority, Agentgres truth, ioi.ai coordination, semantic truth, or physical actuator authority. |
| ioi.ai collaborative outcome pattern, multi-model goal pursuit, multi-path software search, goal-appropriate attempt comparison, shared evidence projections, `IoiAiGoal`, `IoiAiOutcomePlan`, and `IoiAiAttemptSummary` | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md), [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md), [`foundry.md`](../components/hypervisor/foundry.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | ioi.ai is the first-party intent-to-outcome UX. It may coordinate multiple models/harnesses/connectors/sessions when useful; Automations owns durable mission/workflow/service specs; sessions isolate attempts; harness adapters propose; daemon gates and executes; Foundry evaluates/mines lessons or handles build jobs; Workbench inspects; Agentgres records; wallet.network authorizes; IOI L1 settles by trigger |
| Hypervisor Providers / Environments management, direct provider integrations, Akash compute/GPU lane, Filecoin storage/retrieval lane, CloudRoute, CloudCandidate, HypervisorChangePlane, HypervisorTargetState, HypervisorObservedState, HypervisorEnvironmentInstallation, DeployedWhereIndex, HypervisorChangePlan, ChangePlanGate, ReleaseChannel, MaintenanceWindow, SuppressionWindow, CanaryRun, AdjudicationReceipt, RecallPolicy, RecallReceipt, RemediationPlan, SupplyChainManifestRef, SBOMRef, VulnerabilityFinding, PatchSlaPolicy, `WorkspacePersistenceProfile`, `EnvironmentWarmupProfile`, `HypervisorDevelopmentEnvironmentRecipe`, `HypervisorEnvironmentRecipeResolution`, `HypervisorEnvironmentLifecycleObservation`, `HypervisorEnvironmentStopPolicy`, `HypervisorEnvironmentSnapshot`, `HypervisorEnvironmentBackup`, `HypervisorEnvironmentClass`, `HypervisorEnvironmentOpsProfile`, `HypervisorEnvironmentLifecycleState`, `HypervisorEnvironmentActivitySignal`, `HypervisorSessionAccessLease`, `HypervisorEnvironmentService`, `HypervisorEnvironmentTask`, `HypervisorEnvironmentPort`, `HypervisorScmAuthRequirement`, `HypervisorWorkQueue`, `HypervisorWorkItem`, `HypervisorWorkRun`, `HypervisorWorkRunConversationProjection`, `HypervisorWorkRunIntegrationStatus`, `HypervisorWorkRunReviewState`, VMs, containers, microVMs, WASM workloads, images, volumes, networks, snapshots, backups, restore, GPU pools, DePIN/cloud/local/bare-metal provider posture, storage posture, cTEE posture, placement, cost, health, receipts, replay projections, migration cockpit, Hypervisor App/Web provider views, CLI/headless provider projections, and console.ioi.ai Providers / Environments views | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md) | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md), [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | Providers / Environments as Applications catalog entry, Open Application, session detail, project settings, provider settings, org/admin, and operator-console views; VMware/Proxmox/KubeVirt/Nutanix/Kubernetes/bare-metal migration cockpit, direct provider connectors, DePIN/cloud GPU manager, Akash/Filecoin/CAS/S3 posture, development environment recipes, lifecycle observations, zero-to-idle/restore posture, managed environment lifecycle/services/agent-services/tasks/ports/SCM-auth posture, work-run activity/review/conversation/integration posture, change/rollout/recall/remediation cockpit, deployed-where and supply-chain posture, access/log/support lease posture, warm pools/prebuilds/cache/index posture, HypervisorOS estate, provider connectors, node health/cost/placement, Hypervisor App/Web/CLI-headless/console provider views |
| Private Workspace backed by cTEE, Plaintext-Free Runtime Mounting, Plaintext-Free Model Mounting, Custody Types, Custody Proof, Private Agency Transform, Candidate Coverage Profile, Counterfactual Lattice Execution, Cryptographic Operator Plane, Candidate-Lattice Private Decoding, External Model API Boundary, Execution Privacy Posture, persistent rented GPU Hypervisor Nodes, private files/folders, private strategy execution, deterrence/detection, and autonomy leases | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | private quant strategy profile, DePIN/cloud node privacy, provider-trust boundary, coverage/redundancy profiles, privacy posture labels, custody proofs, runtime/model/lattice/private-operator receipts, canary/watermark receipts |
| Workflow Compositor, shared builder substrate, high-level workflow/service graph shape, step contracts, directed recipes, Automations product surface, ioi.ai collaborative outcomes, and harness/model/provider selection hints | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md), [`foundry.md`](../components/hypervisor/foundry.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | Automations is the live durable workflow/service/mission surface; ioi.ai collaborative outcomes may hand off durable mission/workflow/service specs into Automations; Workbench is the live code/systems surface; Foundry is the model/worker/eval/dataset/training/package build surface. Compositor owns directed-work shape; selected HarnessProfiles resolve scoped steps. |
| IOI Authority Gateway and compatibility adapters | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | IDE/CLI/browser adapter specs, MCP gateways, shell wrappers, Git hooks, hosted-agent gateways; adapters mediate proposed actions without becoming runtime owners |
| Daemon and public runtime API, project/session/mission APIs, delegated work queue/item/run APIs, adapter target APIs, environment-ops APIs, short-lived access/log token APIs, ports/browser/support-bundle APIs | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | SDK parity guides, environment-ops parity research, delegated agent-work run contracts |
| CLI/headless operator surface and optional TUI presentation | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | CLI product context, headless scripting, CI, node ops, optional TUI presentation |
| SDK and ADK boundaries | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | agent-sdk package docs, future ADK docs, internal package-boundary docs |
| SDK, CLI/headless, GUI, harness, benchmark, compositor, and agent-harness-adapter boundaries | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | Compatibility row for shared client-surface validation; use the split CLI/headless and SDK/ADK rows above for ownership. External agent harnesses are adapters, not runtime truth. |
| wallet.network authority, auth factors, guardian surfaces, key shards, provider credential bindings, low-assurance access points, challenge escalation, autonomous-work authority gateway, wallet CLI/MCP/SDK authority clients, step-up grants, repo/product split, protocol package, SDK package, and schema boundary | [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md) | [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`implementation-matrix.md`](./implementation-matrix.md), [`wallet-protocol-sdk-packaging-plan.md`](./wallet-protocol-sdk-packaging-plan.md) | Autonomous-work authority gateway, CIRC/CEC, auth factor versus authority grant split, access-point bindings, step-up challenges, guardian surfaces, QR/push/CLI challenge binding, key-shard boundary, provider credential brokerage, wallet CLI/MCP as constrained authority clients; IOI monorepo owns Rust wallet types, service transitions, `@ioi/wallet-protocol`, `@ioi/wallet-sdk`, OpenAPI/JSON Schema artifacts, receipt fixtures, and conformance; wallet-network product repos consume those contracts and own UI/design/prototype state only |
| wallet.network product doctrine, reusable authority UX model, agent authority cockpit, presentation profiles, approval modes, cockpit role, exchange authority, trade authority, prediction authority, route-source boundaries, `ExchangeIntent`, `RouteCandidate`, `TradeIntent`, `PredictionIntent`, `PositionReceipt`, `PredictionReceipt`, `CapabilityLease`, risk coverage states, asset exposure, protection actions, approval inbox, wallet receipts, and wallet SDK events | [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md) | [`exchange.md`](../domains/decentralized/exchange.md), [`trade.md`](../domains/decentralized/trade.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | Wallet authority pipeline is reusable infrastructure; Wallet console is one high-trust presentation for agent authority and autonomous finance, while embedded dapps, mobile, CLI, MCP, and advanced consoles use lighter or denser shells over the same review contract; decentralized.exchange and decentralized.trade are non-custodial route/venue intelligence engines consumed by Wallet through API/RPC/SDK boundaries; direct pools, DEX routers, solvers, quote APIs, bridge routers, venue adapters, perps/margin/prediction-market policy, route-risk, position-risk, event-risk disclosure, protection center, Activity receipts |
| Capability and authority ontology | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`intent-resolution.md`](../../conformance/hypervisor-core/intent-resolution.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | agent tool vocabulary plan |
| aiagent.xyz worker marketplace and managed instances | [`aiagent-xyz-worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](../domains/aiagent/worker-endpoints.md), [`digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md), [`vertical-ontology-packs.md`](../domains/aiagent/vertical-ontology-packs.md), [`integration-surface-taxonomy.md`](../domains/aiagent/integration-surface-taxonomy.md), [`managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md), [`managed-agent-console-contract.md`](../domains/aiagent/managed-agent-console-contract.md) | ontology-bound digital and embodied worker substrate, `ManagedWorkerInstance` lifecycle, product context module inside canonical owner, marketplace neutrality doc |
| sas.xyz service marketplace | [`sas-xyz-service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas-xyz-service-endpoints.md`](../domains/sas/service-endpoints.md) | product context module inside canonical owner, service settlement docs |
| sas.xyz composed delivery evidence, `ServiceCompositionReceiptBundle`, contribution receipts, verifier refs, private-data posture, and dispute evidence refs | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`sas-xyz-service-marketplace.md`](../domains/sas/service-marketplace.md), [`sas-xyz-service-endpoints.md`](../domains/sas/service-endpoints.md), [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | composed service outcomes cannot settle, accept, or dispute from raw delivery blobs, token usage, or provider logs alone |
| ioi.ai control plane and Goal Chat boundary | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | ioi.ai Goal Chat is the intent/coordination surface that may invoke, inspect, summarize, and draft Hypervisor work; durable workflows/services hand off to Hypervisor Automations; execution remains daemon-owned |
| Storage backends | [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md) | [`filecoin-cas-backend-profile.md`](../components/storage-backends/filecoin-cas.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) |
| Filecoin/CAS/IPFS backend profile | [`filecoin-cas-backend-profile.md`](../components/storage-backends/filecoin-cas.md) | [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) |
| Runtime nodes, hosted workers, TEE, DePIN | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) | [`runtime-node-and-task-capsule-protocol.md`](../components/daemon-runtime/task-capsule-protocol.md) | hosted/self-hosted proof plans |
| Model routing, BYOK, run-to-idle | [`model-router-byok-run-to-idle.md`](../components/model-router/doctrine.md) | [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | model-router specs |
| Connectors, tools, MCP | [`connectors-tools-and-authority-registry.md`](../components/connectors-tools/doctrine.md) | [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | First-party Connectors / Tools / MCP surface, MCP servers, native connectors, workflow-as-tool subgraphs, skills/hooks guides, `RuntimeToolContract`, primitive capabilities, authority scopes, policy decisions, and receipt obligations |
| Events, receipts, traces, replay | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime evidence specs |
| Harness profile runtime loop | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`harness-profile-adapter.md`](../../conformance/hypervisor-core/harness-profile-adapter.md) | internal runtime loop plans |
| Marketplace neutrality and contribution accounting | [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | aiagent/sas docs |
| Security/privacy/policy invariants | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) | [`intent-resolution.md`](../../conformance/hypervisor-core/intent-resolution.md), [`effect-execution.md`](../../conformance/hypervisor-core/effect-execution.md) | runtime invariant specs |

## Edit Rules

- Add new runtime/client/package ownership language to the public daemon,
  event, and common-object contracts first. Internal package-boundary plans may
  track implementation sequencing, but they do not own canonical doctrine.
- Add new bare-metal node, measured boot, node-root, node integrity receipt,
  HypervisorOS image, or firmware/TPM profile language to
  [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) first. Do
  not let measured boot replace cTEE no-plaintext-custody or wallet.network
  authority.
- Add new AIIP packet, profile, channel, bounded-execution-domain, handoff,
  relay/router, settlement-intent, or inter-autonomous-system protocol language
  to [`aiip.md`](../foundations/aiip.md) first. Do not create separate bespoke
  interop protocols for Hypervisor, aiagent.xyz, sas.xyz, or external systems
  when AIIP semantics apply.
- Add new physical-action, robot fleet, actuator, embodied-worker, human
  supervision, emergency stop, sensor evidence, incident, or physical-liability
  language to [`physical-action-safety.md`](../foundations/physical-action-safety.md)
  first. Do not let embodied work execute as generic `tool.invoke`,
  `connector.call`, shell, robot-controller, or AIIP traffic without safety
  envelope semantics.
- Add new governed-autonomous-system-chain, Hypervisor Node, local settlement,
  autonomous-system interop, service-module invocation, or machine-economy stack
  language to
  [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md)
  first. Do not collapse Hypervisor clients, application surfaces, Hypervisor
  Node, Agentgres domain, and IOI L1 into one layer.
- Add new alignment-security, bounded-agency, process-containment,
  self-upgrade, or execution-boundary proof language to
  [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md)
  first. Do not canonize claims that IOI proves every model's private cognition
  or goals are safe; route such wording through explicit non-claims or ADRs.
- Add new Hypervisor App, Hypervisor Web, CLI/headless, optional TUI,
  Workbench, Automations, Foundry, Providers / Environments view, session, adapter-target,
  agent-harness-adapter, editor-target, extension-host, or GUI authority
  language to [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
  and daemon/runtime ownership docs before implementation plans rely on it.
  Hypervisor clients and application surfaces are operator surfaces and
  projections; they do not own runtime truth.
- Add new IOI Authority Gateway, IDE/CLI sidecar, shell wrapper, MCP gateway,
  API proxy, Git hook, browser adapter, hosted-agent
  gateway, or CI/CD mediation language to daemon/runtime ownership docs and
  daemon API contracts before implementation plans rely on it. These adapters
  submit proposed actions, observations, and approvals to the daemon; they do
  not own policy, durable runtime state, receipts, replay, secrets, or effects.
- Add new Autonomous System Package, lifecycle verb, package readiness,
  deployment profile slot, promotion slot, or `AutonomousSystemManifest`
  language to [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before Phase 5 connectors, Hypervisor, workflow compositor, SDK, or CLI
  surfaces depend on it.
- Add new MoW, worker-routing, Sparse Worker Category, Worker Training, batch
  planning, generation-batch, quality-gate, model-capacity, or training-cost
  doctrine to [`mixture-of-workers.md`](../foundations/mixture-of-workers.md)
  and [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md)
  before product/domain docs rely on it.
- Add new aiagent broad autonomous labor, digital/embodied worker ontology,
  vertical ontology pack, integration surface, managed worker lifecycle, or
  managed agent console language to the aiagent owner docs first:
  [`digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md),
  [`vertical-ontology-packs.md`](../domains/aiagent/vertical-ontology-packs.md),
  [`integration-surface-taxonomy.md`](../domains/aiagent/integration-surface-taxonomy.md),
  [`managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md),
  and [`managed-agent-console-contract.md`](../domains/aiagent/managed-agent-console-contract.md).
  Do not define bespoke vertical runtimes or authority paths in product docs.
- Add new ontology, DataRecipe, CanonicalObjectModel, ConnectorMapping,
  PolicyBoundDataView, DistilledOntologyDataset, EvaluationDataset,
  OntologyProjection, or
  ontology-to-worker doctrine to
  [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
  before product, connector, Agentgres, or Worker Training docs rely on it.
- Add new operator-facing CLI/headless or optional TUI control language to
  [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md),
  [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), and
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before product-surface docs rely on it.
- Add new SDK client behavior or ADK builder-framework behavior to
  [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) and
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before product-surface docs rely on it. SDK language should mean low-level
  client library. ADK language should mean autonomous-system builder framework.
- Add new shared object fields to
  [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before copying examples into endpoint docs.
- Add new Agentgres durability, consistency, SQL bridge, migration, index, or
  database-readiness doctrine to
  [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md)
  before product or implementation docs rely on it.
- Add new event, trace, receipt, scorecard, or replay fields to
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before referencing them in daemon, Agentgres, GUI, harness, or benchmark docs.
- Add new low-level proof gates to canonical runtime/event/conformance docs
  before adding them to internal implementation prompts.
- Keep internal master guides private when they contain raw competitive,
  transitional, or potentially misconstruable architecture notes. Treat them as
  execution inputs only; promote their settled outcomes into canonical docs or
  ADRs before making them durable references.

## Decision History Policy

Accepted architecture decision history belongs in
[`docs/decisions`](../../decisions/README.md). Do not recreate contradiction
logs as parallel doctrine; port durable rationale into ADRs and keep current
architecture prose clean.

Older plans may keep historical terms such as `adaptive work graph`, former artifact names, or
pre-split capability language only when they are clearly describing decision history.
New canonical architecture must use:

```text
adaptive_work_graph for public delegated execution strategy
prim:* for primitive execution capabilities
scope:* for wallet/provider authority scopes
grant:// or authority_grant_id for authority grants/leases
projection/cache/checkpoint for non-canonical client state
```
