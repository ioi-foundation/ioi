# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-06-23.

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate
authority documents so each facet has a clear role, boundary, and dependency
surface.

If you are new to the canon, start with [`START_HERE.md`](./START_HERE.md). It
gives the five-minute stack model, role-based reading paths, common boundary
mistakes, a route-by-problem map for implementers, and links to the
implementation matrix.

The architecture-level whitepaper source lives at
[`whitepaper.tex`](./whitepaper.tex). Treat it as the current synthesis and
publishing source, not as a replacement for the component owner docs. When the
whitepaper and a canonical owner disagree, update the whitepaper or the owner
map explicitly rather than letting two truths drift.

Use the problem map when you already know what you are building:

```text
Hypervisor cockpit / sessions / adapters
Wallet authority / exchange / trade
Private rented compute / cTEE / model-weight posture
Agentgres refs / storage / restore / artifact repair
aiagent managed workers / sas service outcomes
physical or embodied action safety
ecosystem assurance / certification / compliance / liability
provider integrations across local, cloud, DePIN, storage, and HypervisorOS
```

The core doctrine is:

> **IOI is an edge-in Web4 stack for alignment-secure machine authority:
> workers act under scoped authority, domains remember operational truth, and
> IOI L1 settles only the commitments that need public trust.**

The protocol thesis is:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

The category thesis is:

> **Web4 is the protocol category for machine authority: bounded autonomous
> actors receiving scoped power to perform consequential work with proof,
> revocation, interop, and settlement.**

In IOI terms, intelligent blockchains are self-driving bounded actors: they can
monitor, route work, request authority, execute, recover, improve future
behavior, and settle what matters, but only inside explicit authority, policy,
budget, safety, receipt, replay, rollback, recall, and proof envelopes.

The user-facing doctrine is: blockchain is the substrate, not the default task
language. Web4 surfaces should lead with authority, proof, revocation, replay,
and settlement outcomes while keeping underlying commitments inspectable through
receipt, state-root, dispute, governance, and developer views.

The provider-trust doctrine is: providers may supply cognition, compute, storage,
connectors, venues, and managed services, but machine authority must be portable
outside provider trust by default. Provider-trust routes are explicit,
policy-bound, receipted, and revocable where possible.

The Hypervisor/autonomous-execution canon is:

```text
ioi.ai Goal Chat = intent and coordination surface; proposes handoffs, not runtime truth
Hypervisor Daemon = hypervisor/control plane for autonomous execution
IOI daemon = hypervisor/control plane for autonomous execution
HypervisorOS = bare-metal node profile where daemon is node root
Workflow Compositor = high-level directed workflow/service graph surface
HarnessProfile = daemon-executed or daemon-mediated step-resolution adapter
Default Harness Profile = reference scaffold/fallback HarnessProfile
Persistent workspace intelligence = workspace/project/domain skills and memory
Hypervisor Core = shared product/runtime substrate whose execution owner is the daemon
Hypervisor App/Web/CLI-headless = first-class clients over Hypervisor Core
TUI = optional presentation of CLI/headless client
Hypervisor Workbench/Automations/Foundry = application surfaces over Hypervisor Core
Hypervisor Automations = durable workflow, trigger, schedule, API/service, and background-mission surface
Hypervisor delegated work = WorkQueue, WorkItem, WorkRun, conversation, review, and delivery projections for long-running agent work
ioi.ai = intent-to-outcome surface that may use multi-model/multi-path pursuit over Hypervisor
Hypervisor Foundry = object-first model, worker, eval, dataset, registry, route, endpoint, teacher-oversight/distillation, persistent training pipeline, packaging, and ontology-aware package build surface
Hypervisor sessions/providers/environments = default cross-session infrastructure views
Hypervisor Node = local autonomous-system settlement and interop domain
Hypervisor Adapters = mediated bridges to editors, terminals, browsers, VMs, OS surfaces, and nodes
IOI Authority Gateway = compatibility adapter profile for existing IDEs/agents
Private Workspace backed by cTEE = user-facing private workspace for persistent untrusted GPU nodes; Plaintext-Free Runtime Mounting is the daemon boundary; CLPD is the default protected-agency strategy
decentralized.exchange/trade = Wallet-native liquidity, exposure, and event-market routing
Hypervisor provider integrations = direct cloud, storage, GPU, confidential, DePIN, local, and customer infrastructure integrations
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

Product taxonomy:

> **The Hypervisor Daemon is the deterministic execution substrate for portable,
> verifiable autonomous systems. Hypervisor is the flagship product surface for
> building, deploying, and governing those systems.**

Product promise:

> **Hypervisor is the governed autonomy substrate where work becomes reusable
> capability.**

In this architecture, **work** is a live governed activity: a session, task,
run, connector action, code change, research path, training job, workflow step,
or service delivery. **Capability** is reusable autonomous capacity: a worker,
automation, model route, data recipe, eval, tool, package, conductor advisor,
service module, or marketplace listing. Hypervisor should make work safe and
useful first, then allow the right evidence-backed work to become reusable
capability.

Machine-economy canon:

> **Hypervisor Nodes are local settlement domains for autonomous systems; IOI L1
> is the global settlement layer for the machine economy.**

Interop canon:

> **AIIP moves autonomous work across systems. IOI settles what happened.**

Read the stack this way:

- the IOI kernel is the L0 substrate for instantiating domains and chains;
- IOI L1 anchors rights, settlement, registries, disputes, governance, release
  commitments, and public commitments;
- domain kernels run Agentgres, routing, policy, projections, and application
  state;
- governed autonomous-system chains are local stateful execution objects with
  policy, modules, proposals, receipts, and upgrade paths;
- Domain Ontologies and Data Recipes bind raw sources into trainable,
  queryable, receipted, and distillable domain truth;
- Hypervisor Daemon runtime nodes act as the autonomous-execution hypervisor/control
  plane, supervising workers, workflows, tools, models, connectors, computer-use
  leases, artifacts, policy, receipts, and replay;
- HypervisorOS is the bare-metal node profile where the Hypervisor Daemon is the
  node root; it improves control, integrity, containment, measurement,
  reproducibility, and policy enforcement, but cTEE still owns
  no-plaintext-custody privacy claims;
- Hypervisor manages sessions, environments, providers, and cross-session
  infrastructure posture directly; it manages machines, VMs, containers,
  microVMs, WASM workloads, images, volumes, networks, GPU pools, provider
  integrations, placement, health, cost, storage posture, cTEE posture,
  receipts, replay projections, archive refs, restore refs, and policy
  visibility through default Hypervisor session/project/provider views;
- Hypervisor surfaces should preserve the compounding loop from governed work
  to reusable capability:
  work happens, receipts and evidence accumulate, failures and wins are mined,
  Foundry creates or improves capability, aiagent.xyz attributes supply when
  marketplace workers or packages contribute, and future work routes better;
- Private Workspace backed by cTEE lets remote/persistent rented GPU nodes
  provide Hypervisor compute and persistence while private files, PII, strategy
  logic, credentials, and action authority stay out of provider-readable
  plaintext by default; Candidate-Lattice Private Decoding lets the node
  generate candidates while private heads select or deny outside node custody;
  Counterfactual Lattice Execution trades extra public token volume for lower
  online private-choice leakage, with Candidate Coverage Profile estimating
  when redundancy makes that trade cheap or when exponential decay makes CLPD/CLE
  the wrong privacy route;
  Plaintext-Free Runtime Mounting keeps tools and models limited to
  public/redacted projections, encrypted refs, private handles, and capability
  exits; the Cryptographic Operator Plane routes protected scoring, retrieval,
  and policy checks to FHE/MPC/local/threshold paths without exposing a new
  user-facing mode; third-party model APIs over sensitive plaintext are
  provider-trust, not base cTEE no-plaintext-custody;
- Hypervisor Nodes coordinate many governed autonomous-system chains, route work
  between them, manage local authority and receipts, and anchor selected roots
  upward when public trust or settlement requires it;
- AIIP is the RPC-shaped, receipt-native interop protocol for bounded
  autonomous work across microharnesses, workers, services, marketplaces,
  enterprises, third-party autonomous systems, and AS-L1s;
- Physical Action Safety governs embodied workers, robot fleets, actuator
  commands, human supervision, emergency stop, sensor evidence, incidents, and
  physical-action receipts; actuator-affecting actions must not execute as
  generic tool calls;
- Embodied Runtime defines robot/fleet identity, controller bindings, sensor and
  actuator registries, local control bridges, heartbeat/failsafe posture, world
  state, command queues, telemetry, physical replay, sim-to-real gates, and
  operator handoff for live physical domains;
- wallet.network supplies portable delegated authority for identity-bound
  agents, secrets, approvals, payments, exchanges, external credentials, data
  use, decryption, revocation, and protection actions; route sources produce
  exchange candidates but do not become authority;
- decentralized.exchange and decentralized.trade are Wallet-consumed
  route/venue intelligence engines for liquidity, exposure, and event markets;
  Hypervisor has direct provider
  integrations for cloud compute, storage, GPUs, confidential compute, DePIN,
  local machines, customer cloud, enterprise clusters, decentralized storage,
  and user-specified providers; candidates propose, while authority providers
  and local/domain governance authorize as required, Hypervisor executes or
  deploys, venues/providers perform, Agentgres records, and IOI L1 settles by
  trigger;
- Agentgres artifact refs define payload meaning, lifecycle, policy/authority
  linkage, receipts, replay/import metadata, archive/restore validity, and
  state-root validity;
- storage backends such as local disk, S3/object stores, Filecoin, CAS/IPFS, and
  provider/customer blob stores hold payload bytes;
- MoW routes bounded workers by policy, benchmarks, receipts, cost, trust, and
  contribution quality;
- Hypervisor Core is the shared product/runtime substrate whose execution owner
  is the Hypervisor Daemon; Hypervisor App, Hypervisor Web, and CLI/headless
  are first-class clients over Core, while Workbench, Automations, Foundry,
  Agent Studio, ODK, Domain Apps, Developer & Integrations, Governance,
  Operations, Work Ledger, Environments, Marketplace, and Robot Fleets /
  Embodied are projections over the same Core, not separate runtime truth
  paths;
- Hypervisor Workbench is the code/systems/workspace surface and may use VS
  Code, Cursor, Windsurf, JetBrains, browser IDEs, terminals, VMs, local apps,
  and HypervisorOS nodes as adapter targets; editor choice is a session
  preference resolved through an `AdapterConnectionProfile`, not Hypervisor's
  product identity;
- Hypervisor Automations is the durable orchestration surface for workflows,
  triggers, schedules, APIs/services, approval flows, queues, and background
  missions over the Workflow Compositor; it does not own runtime truth, wallet
  authority, receipts, or Agentgres truth;
- ioi.ai is the intent-to-outcome surface. For goals that need more than one
  path, it can coordinate multiple models, harnesses, workers, connectors,
  sessions, branches, and verifier lanes over Hypervisor, with evidence,
  receipts, authority, privacy posture, and final ownership synthesis;
- IOI Authority Gateway is the daemon sidecar/adapter profile for existing IDE,
  CLI, browser, hosted-agent, and MCP/tool ecosystems: keep your IDE, keep your
  model, and put consequential execution behind IOI;
- Workflow Compositor renders typed recipes, services, workflows, and directed
  step contracts over the shared builder substrate; selected HarnessProfiles
  resolve scoped steps. CLI/headless, SDK, ADK, harnesses, benchmarks, and IDE
  extensions are clients, builder frameworks, projections, or adapter targets
  rather than runtime owners;
- skills, Agent Wiki / `ioi-memory`, wiki facts, learned tool affordances, and
  durable behavior-affecting context are persistent workspace/project/domain
  intelligence and should survive model or harness swaps under compatibility,
  provenance, policy, and authority;
- external CLI or hosted agent harnesses such as Codex, Claude Code, Grok Build,
  OpenHands, Aider, shell/tmux agents, and CI agents are Agent Harness Adapters:
  they operate through environment-ops profiles and submit proposed work through
  Hypervisor Core and the daemon; they do not become Hypervisor clients or
  runtime truth;
- aiagent.xyz is a first-party protocol application that publishes,
  benchmarks, ranks, installs, compiles onboarding plans, initializes managed
  instances, and routes workers through AIIP and IOI settlement;
- sas.xyz is a first-party protocol application that sells worker-powered
  outcomes, including Worker Training contracts, through AIIP and IOI
  settlement;
- ioi.ai coordinates accounts, devices, publishing, restore, sync metadata,
  remote-runtime access, and console/org views over Hypervisor provider,
  environment, and session posture; ioi.ai Goal Chat may ask, invoke, inspect,
  summarize, and draft Hypervisor work, but durable workflows/services hand
  off to Hypervisor Automations and execution remains daemon-owned.

Agentgres should not be read as "state stored as Filecoin blobs." Agentgres is
the state machine, query substrate, and artifact-ref meaning/admission/validity
plane; storage backends are payload byte stores beneath Agentgres-governed refs.

Private state should not be read as "agent state only." Private user/app state
such as profile metadata, app preferences, workspace snapshots, service intake
forms, private outputs, and non-public managed-instance metadata may be stored
as encrypted payload bytes in storage backends, while Agentgres owns refs,
policy, receipts, state roots, and restore/import validity. Authority providers
and local/domain policy control viewing, decryption, mutation, export, and
restore paths; wallet.network is mandatory when portable delegated authority,
secret custody, decryption leases, external effects, or high-risk approval are
required.
IOI L1 receives selected public, economic, rights, dispute, registry, and
cross-domain commitments, not private
application databases.

These documents should be treated as architectural authority prose. They are
not implementation tickets, but they should constrain implementation choices,
naming, product boundaries, and future specs.

## Taxonomy

Architecture contains stable authority prose and low-level component
references. Conformance contracts live in [`docs/conformance`](../conformance/).
Implementation plans, runtime iteration specs, product-internal notes, protocol
corpora, prompt scratchpads, and generated formal outputs are retained outside
the forward-facing docs tree and do not supersede this architecture pack.
Internal master guides may contain raw strategic comparisons, transitional
language, or third-party architecture notes that are useful for execution but
easy to misconstrue as doctrine. Durable conclusions from those guides must be
distilled back into this architecture pack or into an accepted decision record.

## Navigation And Ownership

- [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) — canonical subject ownership, edit rules, and conflict policy.
- [`current-canon-defaults.md`](./_meta/current-canon-defaults.md) — current cross-owner defaults digest for quick alignment before opening subject owners.
- [`Architecture Decision Records`](../decisions/README.md) — accepted decision history for durable architecture choices.
- [`doc-classes.md`](./_meta/doc-classes.md) — documentation class vocabulary for future metadata/linting.

## High-Level Canonical Spec Files

- [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md) — category definition and stack map.
- [`domains/decentralized/README.md`](./domains/decentralized/README.md) — active decentralized.exchange and decentralized.trade doctrine for routing liquidity and exposure without becoming authority or trust roots; Hypervisor provider integrations remain direct and are covered by Hypervisor Environments / Providers canon.
- [`aiip.md`](./foundations/aiip.md) — AIIP work interop protocol, bounded execution domains, profiles, packets, and handoff semantics.
- [`physical-action-safety.md`](./foundations/physical-action-safety.md) — physical-action safety envelopes, independent local safety veto, human supervision, emergency stop, sensor evidence, actuator command receipts, and incident hooks for embodied workers.
- [`embodied-runtime.md`](./components/daemon-runtime/embodied-runtime.md) — embodied runtime, robot fleet runtime, embodied capability package binding, embodiment adapters, calibration/time-sync contracts, local control bridge, physical telemetry, raw robot logs, normalized episode datasets, replay, sim-to-real gates, and operator handoff.
- [`ecosystem-assurance-certification-liability.md`](./foundations/ecosystem-assurance-certification-liability.md) — assurance profiles, conformance/certification posture, jurisdiction policy packs, abuse/quarantine, liability/claims routing, and commercial assurance exports without becoming runtime, authority, truth, marketplace, or settlement.
- [`governed-autonomous-systems.md`](./foundations/governed-autonomous-systems.md) — governed autonomous-system chains, Hypervisor Nodes, local settlement domains, and the coherent machine-economy stack.
- [`verifiable-bounded-agency.md`](./foundations/verifiable-bounded-agency.md) — alignment-security thesis, bounded agency, and execution-boundary alignment.
- [`mixture-of-workers.md`](./foundations/mixture-of-workers.md) — MoW labor-routing doctrine, sparse worker categories, routing receipts, and router neutrality.
- [`worker-training-lifecycle.md`](./foundations/worker-training-lifecycle.md) — Worker Training lifecycle, Hypervisor Foundry product home, training receipts, and training-vs-mutation doctrine.
- [`domain-ontologies-and-data-recipes.md`](./foundations/domain-ontologies-and-data-recipes.md) — semantic data plane for domain ontologies, data recipes, connector mappings, evaluation datasets, and ontology-aware projections.
- [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md) — IOI L1 duties, L0/L1 boundary, smart contracts, gas boundaries.
- [`domain-kernels.md`](./foundations/domain-kernels.md) — L0 substrate, fractal/edge-in topology, application-domain kernels, and Agentgres hosting.
- [`agentgres/doctrine.md`](./components/agentgres/doctrine.md) — per-domain state substrate for canonical operational truth.
- [`agentgres/artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md) — ArtifactRef, PayloadRef, EvidenceBundle, DeliveryBundle, AgentStateArchive refs, lifecycle, authority, receipts, and restore validity.
- [`agentgres/postgres-bridge-and-readiness-contract.md`](./components/agentgres/postgres-bridge-and-readiness-contract.md) — Postgres bridge posture, consistency levels, durability/readiness contract.
- [`daemon-runtime/doctrine.md`](./components/daemon-runtime/doctrine.md) — universal execution endpoint for local, hosted, and DePIN nodes.
- [`daemon-runtime/hypervisoros.md`](./components/daemon-runtime/hypervisoros.md) — bare-metal Hypervisor node profile, measured boot, daemon-rooted workload launch, node enforcement profile, node integrity receipts, and HypervisorOS conformance.
- [`hypervisor/core-clients-surfaces.md`](./components/hypervisor/core-clients-surfaces.md) — Hypervisor Core, first-class clients, application surfaces, projects, sessions, missions, adapter connection profiles, access/log/support policies, and harness environment-ops contracts; App/Web/CLI-headless are clients, TUI is an optional CLI presentation, Workbench/Automations/Foundry and other application surfaces are projections over Core, Applications is the catalog/launcher, Open Application is the singular active-application slot, Environments appears through application, session, project, provider, org/admin, or operator-console views, and external CLI agents are harness adapters.
- [`hypervisor/foundry.md`](./components/hypervisor/foundry.md) — Hypervisor Foundry as the object-first model catalog, registry, model route/mount, tuning, teacher-session oversight, candidate-data quarantine, role-specialized distillation, persistent training pipeline, Foundry specs, dataset snapshots, run plans, trials, checkpoints, artifact/package conversion, evaluation, endpoint, metadata, monitoring, promotion, and ontology-aware build surface.
- [`ioi-ai/collaborative-outcome-pattern.md`](./domains/ioi-ai/collaborative-outcome-pattern.md) — ioi.ai intent-to-outcome coordination, multi-model/multi-path goal pursuit, attempt comparison, shared evidence projections, and final ownership synthesis over Hypervisor.
- [`hypervisor/providers-and-environments.md`](./components/hypervisor/providers-and-environments.md) — Hypervisor-managed sessions, environments, providers, cross-session infrastructure posture, direct provider integrations such as Akash compute/GPU and Filecoin storage/retrieval, zero-to-idle/restore posture, warmup/cache posture, services/tasks/ports/logs/SCM auth, access leases, archive refs, and restore refs.
- [`daemon-runtime/private-workspace-ctee.md`](./components/daemon-runtime/private-workspace-ctee.md) — Private Workspace backed by cTEE for persistent rented GPU Hypervisor Nodes, Candidate-Lattice Private Decoding, private files/folders, private strategy execution, autonomy leases, declassification gates, and no-plaintext protected classes.
- [`daemon-runtime/runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md) — local/hosted/DePIN/TEE execution modes.
- [`wallet-network/doctrine.md`](./components/wallet-network/doctrine.md) — identity, auth factors, guardian surfaces, key shards, secrets, authority scopes, approvals, payments, wallet CLI/MCP authority-client boundaries, exchange/trade authority.
- [`wallet-network/product-exchange-risk.md`](./components/wallet-network/product-exchange-risk.md) — Wallet product doctrine, agent authority cockpit, exchange/trade authority, route-source boundaries, risk labels, asset/position exposure, protection actions, approval inbox, wallet receipts, and SDK events.
- [`domains/aiagent/worker-marketplace.md`](./domains/aiagent/worker-marketplace.md) — worker marketplace, managed instances, and routing application domain.
- [`domains/sas/service-marketplace.md`](./domains/sas/service-marketplace.md) — Service-as-Software outcome marketplace application domain.
- [`domains/ioi-ai/control-plane.md`](./domains/ioi-ai/control-plane.md) — lightweight account, device, restore, publishing, and remote-runtime control plane.
- [`storage-backends/doctrine.md`](./components/storage-backends/doctrine.md) — storage backends as payload byte stores below Agentgres-governed artifact refs.
- [`storage-backends/filecoin-cas.md`](./components/storage-backends/filecoin-cas.md) — Filecoin/CAS/IPFS as one content-addressed storage backend profile.
- [`model-router/doctrine.md`](./components/model-router/doctrine.md) — model registry, BYOK, local mounting, run-to-idle compute.
- [`connectors-tools/doctrine.md`](./components/connectors-tools/doctrine.md) — typed tools, connector authority, risk classes.
- [`domains/marketplace-neutrality.md`](./domains/marketplace-neutrality.md) — anti-cannibalization doctrine, contribution receipts, attribution.
- [`security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md) — non-negotiable security and authority invariants.

## Low-Level Reference Files

- [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md) — shared envelopes, ID namespaces, primitive capabilities, authority scopes.
- [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](./domains/aiagent/worker-endpoints.md) — aiagent.xyz worker and inter-agent endpoints.
- [`sas-xyz-service-endpoints.md`](./domains/sas/service-endpoints.md) — sas.xyz order, delivery, provider, and dispute endpoints.
- [`daemon-runtime/api.md`](./components/daemon-runtime/api.md) — public daemon runtime API, event streaming, inspect, scorecard, replay.
- [`agentgres/api-object-model.md`](./components/agentgres/api-object-model.md) — Agentgres APIs, object classes, operation log, runtime v0 state.
- [`agentgres/projection-system-reference.md`](./components/agentgres/projection-system-reference.md) — CSPS taxonomy reference for projection-native state systems.
- [`wallet-network/api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md) — wallet.network auth factors, guardian surfaces, key shards, provider credential bindings, authority scopes, grants, approvals, brokerage, wallet CLI/MCP authority clients, exchange, exposure, protection, receipts, and revocation.
- [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) — IOI L1 contract interfaces.
- [`daemon-runtime/task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md) — runtime assignment, task capsules, privacy modes, attestation.
- [`agentgres/artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md) — artifact/package refs, bundles, archive refs, verification, and restore validity.
- [`model-router/api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) — model provider, endpoint, route, invocation, BYOK, mounting.
- [`connectors-tools/contracts.md`](./components/connectors-tools/contracts.md) — RuntimeToolContract, connector/tool APIs, risk classes.
- [`daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md) — runtime events, receipts, delivery bundles, traces, quality.

## Boundary And Generated References

- [`vocabulary.md`](./_meta/vocabulary.md) — runtime, audit, substrate, projection, and legacy naming vocabulary.
- [`intent-resolution.md`](../conformance/hypervisor-core/intent-resolution.md) — CIRC intent-resolution conformance invariant.
- [`effect-execution.md`](../conformance/hypervisor-core/effect-execution.md) — CEC effect-execution and completion-evidence conformance invariant.
- [`harness-profile-adapter.md`](../conformance/hypervisor-core/harness-profile-adapter.md) — adapter conformance for heterogeneous harnesses and worker/module profiles.

## Source Of Truth By Subject

The edit-first source of truth for each subject is
[`source-of-truth-map.md`](./_meta/source-of-truth-map.md). Plans, specs, prompts, and
evidence files are supporting references. When they conflict with
`docs/architecture/`, update the architecture owner first and then reconcile the
supporting file.

## One-Sentence Boundary Summary

| Facet | Canonical Role |
|---|---|
| IOI L1 | Registry, rights, settlement, governance, bonds, disputes, and public trust commitments. |
| AIIP | RPC-shaped, receipt-native interop protocol for bounded autonomous work, authority leases, receipts, settlement intents, disputes, and handoffs. |
| Bounded Execution Domain | Any local, hosted, enterprise, marketplace, robot, worker, service, microharness, or AS-L1 domain that performs scoped autonomous work under policy and receipts. |
| Governed Autonomous-System Chain | Local stateful execution object with policy, modules, proposals, receipts, state roots, and governed upgrades. |
| Hypervisor Node | Local settlement, orchestration, domain policy, state, replay, routing, and interop domain for many governed autonomous-system chains. |
| Verifiable Bounded Agency | Alignment-security thesis: probabilistic workers may propose, but only bounded, authorized, receipted effects may cross the deterministic execution boundary. |
| Mixture of Workers | Labor-routing architecture that selects bounded workers by policy, benchmark evidence, cost, trust, and contribution quality. |
| Worker Training | Supply-creation lifecycle for turning workflows, examples, corrections, data, gates, and training profiles into deployable benchmarked workers. |
| Domain Ontologies, Data Recipes, and ODK | Semantic data plane plus ontology-aware builder kit that turns sources, connector payloads, traces, schemas, and policies into ontology-bound, optionally distilled training/evaluation/runtime/projection truth and repeatable generated surfaces, domain apps, eval packs, workers, and packages. |
| Ecosystem Assurance | Cross-domain profile, evidence, certification, compliance, quarantine, liability, and commercial export layer that makes autonomous systems institutionally legible without owning execution, authority, truth, marketplace state, or settlement. |
| Domain Kernel | Application-domain policy/runtime deployment for Agentgres and routing. |
| Agentgres | Per-domain canonical operational state, receipts, projections, quality, and contribution accounting. |
| Hypervisor Daemon / Runtime Node | Hypervisor/control plane for autonomous execution across workflows, workers, tools, models, connectors, computer-use leases, artifacts, policy, receipts, and replay. |
| HypervisorOS | Bare-metal Hypervisor node profile where the daemon is the node root; owns measured node boot, daemon-rooted workload launch, node enforcement posture, node integrity receipts, and bare-metal conformance without replacing cTEE privacy or wallet.network authority. |
| Hypervisor Core | Shared product/runtime substrate used by Hypervisor clients and application surfaces; its execution owner is the Hypervisor Daemon and its step/module backend converges on the Rust/WASM workload/kernel substrate. |
| Hypervisor App / Web / CLI-headless | First-class clients over Hypervisor Core for native desktop, browser/team/remote, and terminal/headless operation; TUI is an optional CLI presentation. |
| Hypervisor Applications / Open Application | Applications is the catalog/search/launcher/management surface; Open Application is the singular active-application slot. Product surfaces over Hypervisor Core include Workbench, Environments, Agent Studio, Foundry, ODK, Domain Apps, Developer & Integrations, Governance, Operations, Work Ledger, Marketplace, and Robot Fleets / Embodied as roadmap. Automations is a shell-blessed durable work container. Favorites, recommendations, promoted apps, and org shortcuts are preferences/catalog affordances, not canonical shell categories. |
| Learning / Patterns / Examples / Training | Role-guided recipe and enablement facet that turns tracks, speedruns, solution diagrams, examples, starter automations, data recipes, ontology packs, eval packs, and package templates into governed sessions, automations, Foundry jobs, Domain Apps, receipts, replay, promotion, and marketplace paths. It appears through Home, Applications, Marketplace, Foundry, ODK, and onboarding rather than as a separate product surface. |
| ioi.ai Collaborative Outcome Pattern | ioi.ai intent-to-outcome coordination that may use multiple models, harnesses, workers, connectors, sessions, branches, and verifier lanes over Hypervisor when a goal calls for it. |
| Hypervisor Environments / Providers | First-party Applications catalog entry, Open Application, session, project, provider, org/admin, and operator-console views plus daemon/Core objects for sessions, environments, providers, nodes, VMs, containers, microVMs, WASM workloads, images, volumes, networks, GPU pools, DePIN/cloud/local/bare-metal runtime inventory, CloudRoute candidates, direct Akash/Filecoin-style provider/storage integrations, zero-to-idle/restore posture, warmup/cache posture, placement, health, cost, storage posture, cTEE posture, receipts, replay projections, and policy visibility without creating a separate peer product, runtime, authority, truth, or storage layer. `Providers / Environments` remains the architectural family alias; `Environments` is the product surface. |
| Wallet Lanes / Provider Integrations | Wallet is the authority cockpit for agents and autonomous finance. Auth factors open accounts, guardian surfaces and key shards secure high-risk authority, provider credential bindings stay brokered, decentralized.exchange is a route-intelligence engine for liquidity, decentralized.trade is a venue/market-intelligence engine for exposure including prediction markets/event contracts, and Hypervisor integrates directly with compute, storage, GPU, confidential, DePIN, local, customer-cloud, and enterprise providers. Candidates propose; authority providers and local/domain governance authorize as required, with wallet.network mandatory for portable delegated authority and high-risk external effects; Hypervisor executes or deploys; venues/providers perform; Agentgres records; IOI L1 settles by trigger. |
| Private Workspace backed by cTEE | User-facing private workspace and daemon execution profile for persistent rented GPU nodes that run useful compute without receiving protected plaintext by default; Plaintext-Free Runtime Mounting is the daemon boundary, CLPD is the default protected-agency strategy, Candidate Coverage Profile estimates proposal redundancy, Counterfactual Lattice Execution trades extra public token volume for lower online private-choice leakage, the Cryptographic Operator Plane handles protected private operators internally, External Model API Boundary distinguishes private-native/redacted-API/provider-trust/unsafe paths, and deterrence/detection receipts support canaries, watermarks, and disputes. |
| IOI CLI/headless | Human terminal, scripting, CI, node-ops, and headless operator client over daemon/public runtime APIs; TUI is an optional interactive presentation of this client. |
| IOI SDK | Low-level protocol/client library over daemon, Agentgres, wallet.network, AIIP, and IOI L1 contracts; never the canonical execution owner. |
| IOI ADK | Autonomous development kit for building workers, service modules, harnesses, evals, manifests, receipts, deployment profiles, and governed autonomous systems. |
| Shared Builder Substrate | Shared graph model, typed node contracts, schemas, recipes, daemon execution path, and receipt model used by Hypervisor builder lenses. |
| Workflow Compositor | High-level directed workflow/service graph surface over Hypervisor Core and the shared builder substrate. It owns graph shape, step contracts, dependencies, review points, delivery contracts, and selection hints; selected HarnessProfiles resolve scoped steps. |
| Agent Operating Plane | Daemon-owned agent/session/turn/work-run control plane for configured agents, conversation streams, subagents, runner reconciliation, usage, and exec/security telemetry. |
| HarnessProfile | Daemon-executed or daemon-mediated step-resolution adapter/profile. |
| Default Harness Profile | IOI reference scaffold/fallback HarnessProfile, not the only admissible harness and not a meta-harness. |
| Persistent workspace intelligence | Workspace/project/domain skills, Agent Wiki / `ioi-memory`, wiki facts, tool affordances, route preferences, and failure lessons that persist across model/harness swaps when allowed. |
| Hypervisor Workbench | Code/systems/workspace surface for autonomous systems; observes, requests, approves, interrupts, debugs, and explains daemon-governed work without owning runtime truth. |
| Hypervisor Adapters | Mediated bridges from Hypervisor Sessions to VS Code, Cursor, Windsurf, JetBrains, browser IDEs, terminals, Git, browsers, VMs, local OS surfaces, cloud resources, and HypervisorOS nodes. |
| Agent Harness Adapters | Mediated bridges for external CLI/hosted agent harnesses such as Codex, Claude Code, Grok Build, OpenHands, Aider, shell/tmux agents, CI agents, and hosted coding agents. |
| IOI Authority Gateway | Compatibility sidecar/adapters for existing IDEs, CLI agents, hosted agents, browser tools, and MCP ecosystems; routes proposed actions through daemon policy, authority, receipts, and replay without becoming a second runtime. |
| wallet.network | Sovereign authority wallet and control cockpit for autonomous agents and autonomous finance; owns identity, auth factors, guardian surfaces, key shards, provider credential bindings, secrets, authority scopes, approvals, payments, exchange/trade authority, risk disclosure, protection actions, and revocation. |
| aiagent.xyz | Canonical Web4 marketplace for ontology-bound digital and embodied workers, managed instances, benchmark profiles, Sparse Worker Categories, installs, and routing eligibility. |
| sas.xyz | Canonical Web4 marketplace for autonomous service outcomes, including Worker Training as Service-as-Software. |
| ioi.ai | Lightweight account/control plane for devices, restore routing, publishing, sync metadata, remote-runtime entitlement, and console/org Environments views. |
| ai:// | Naming and manifest resolution protocol for intelligence, workers, services, apps, and domains. |
| Agentgres Artifact-Ref Plane | Artifact identity, payload refs, evidence/delivery/archive refs, lifecycle, policy/authority refs, receipts, replay/import metadata, restore validity, and state-root validity. |
| Storage Backends | Payload byte stores such as local disk, S3/object stores, Filecoin, CAS/IPFS, provider blob stores, and customer VPC blob stores. |
| DePIN/TEE Nodes | Execution venues that run Hypervisor Daemon profiles, not the Web4 apps themselves. |

## Core Layering

```text
IOI L1
  registry, rights, settlement, governance, bonds, disputes, roots

Application Domains
  aiagent.xyz, sas.xyz, ioi.ai, Hypervisor local domains, enterprise domains
  each runs kernel/runtime deployment + Agentgres domain

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, service modules, proposals, receipts, and upgrade paths

AIIP Work Interop Layer
  capability discovery, quotes, invokes, handoffs, authority leases, receipts, settlement intents, disputes, reputation queries, and channel/profile registration

Semantic Data Plane
  domain ontologies, canonical object models, data recipes, connector mappings, policy-bound data views, distilled ontology datasets, evaluation datasets, ontology-aware projections

MoW Routing Layer
  sparse worker categories, routing decisions, contribution policies, benchmark eligibility

Execution Hypervisor / Runtime Nodes
  local Hypervisor Daemon under a Hypervisor Node, hosted Hypervisor Daemon, provider daemon, DePIN node, TEE node, customer VPC

HypervisorOS / Bare-Metal Runtime Nodes
  measured node image, minimal base, Hypervisor Daemon as node root,
  microVM/container/WASM/model-server substrates, node measurement receipts

Hypervisor Node / Local Settlement Domain
  Hypervisor Core, Hypervisor Daemon, Agentgres, wallet.network authority path,
  local registries, receipts, replay, interop, and local settlement

Client Surfaces
  Hypervisor App, Hypervisor Web, Hypervisor CLI/headless,
  Workbench/Automations/Foundry and other application surfaces,
  ioi.ai collaborative outcome projections, Environments views,
  Workflow Compositor, IOI Authority Gateway adapters, @ioi/agent-sdk, IOI ADK,
  browser apps, agent harness adapters, benchmarks

Storage Plane
  local disk, S3/object stores, Filecoin, CAS/IPFS, provider/customer blob stores for payload bytes

Authority Plane
  wallet.network for identity, secrets, authority scopes, payments, approvals, revocation

Assurance Plane
  conformance profiles, certification claims, jurisdiction policy packs,
  evidence bundles, quarantine advisories, liability claim routes, commercial exports
```

## Key Non-Negotiables

1. Agentgres does not run on IOI L1. It runs per application/domain.
2. aiagent.xyz and sas.xyz are not separate chains by default. They are canonical Web4 application domains with their own Agentgres backends and IOI L1 smart-contract settlement rails.
3. IOI L1 is not the operational notebook. It stores registry, rights, economic commitments, disputes, and sparse roots.
4. IOI gas is consumed at coordination and settlement boundaries, not per model thought, tool call, or workflow node.
5. HarnessProfiles must be daemon-executed or daemon-mediated,
   marketplace-neutral, and must not cannibalize worker/service markets through
   silent appropriation; the Default Harness Profile is the reference
   scaffold/fallback, not the only admissible harness or a meta-harness.
6. wallet.network is the portable delegated authority plane for secrets, external credentials, spend, decryption, high-risk approvals, and provider-facing authority. Agents and runtimes receive authority scopes, not raw secrets.
7. DePIN nodes are execution venues; Web4 apps define state, rights, UX, contracts, and outcomes.
8. Storage backends store payloads; trust comes from Agentgres refs, manifests, hashes, signatures, receipts, policy/authority refs, and settlement roots when applicable.
9. Agentgres state MUST NOT be reduced to opaque Filecoin blobs. Agentgres owns canonical operations, object heads, indexes, constraints, projections, subscriptions, delivery state, receipt metadata, artifact refs, archive refs, replay/import metadata, and restore validity.
10. Compute nodes initialize Hypervisor Daemon runtime-node profiles, optionally bridging into runtime services; the SDK is a client over that substrate, not the substrate itself.
11. HypervisorOS is a bare-metal node profile, not a peer runtime. It gives serious nodes daemon-rooted control and measurement, but it does not make consumer GPUs confidential compute or replace cTEE no-plaintext-custody.
12. Hypervisor manages sessions, environments, providers, and infrastructure posture directly. Environments views are not a peer runtime, wallet, Agentgres domain, storage authority, or L1 settlement layer; Hypervisor Daemon executes; authority providers and local/domain governance authorize as required; Agentgres records truth; storage backends hold bytes.
13. decentralized.exchange/trade are route/venue intelligence engines that propose candidates for liquidity and exposure, and Hypervisor provider integrations propose routes for execution; they are not mandatory UIs, authority, custody, provider, venue, storage, or settlement owners.
14. CLI/headless, SDK, and ADK are separate surfaces: CLI/headless is the operator/scripting/CI client, TUI is an optional CLI presentation, SDK is the low-level client library, and ADK is the autonomous-system builder framework.
15. Hypervisor App, Hypervisor Web, CLI/headless, SDK, ADK, Workflow
    Compositor, agent harness adapters, benchmarks, and
    Workbench/Automations/Foundry surfaces, other application surfaces, and
    Environments views must share daemon/domain contracts rather
    than creating private runtime truth paths.
16. Adapter targets must resolve through connection profiles, external harnesses
    must use environment-ops APIs, remote access/log/support tokens must be
    short-lived and receipted, and background automations must be explicit
    `HypervisorMission` objects rather than hidden interactive sessions.
17. Worker is the protocol actor; model is a cognition backend; agent is the configurable product object and user-facing worker experience.
18. MoW is labor routing across bounded workers, not a fifth Web primitive and not model-provider routing.
19. Worker Training creates or improves capability but does not grant authority; wallet.network or equivalent authority grants power.
20. Workers train on ontology-bound, policy-bound, and when useful distilled data, not raw blobs or ambient connector payloads.
21. Models and agents may reason or propose; Hypervisor Daemon authority decides what crosses the deterministic execution boundary.
22. IOI Authority Gateway adapters, including IDE extensions, CLI wrappers, MCP gateways, Git hooks, API proxies, browser adapters, and CI gates are mediation surfaces only. They must route consequential actions through daemon policy, authority, receipts, and replay, and they must not claim total interception of opaque third-party runtimes.
23. IOI's alignment-security claim is execution-boundary alignment: it constrains consequential effects through bounded authority, policy, receipts, and verification; it must not be framed as proving every model's private cognition or goals are safe.
24. Providers may supply cognition, compute, storage, connector access, venues, and managed services, but they are not the default authority root, secret owner, receipt truth, settlement root, or revocation plane. Provider-trust routes require explicit policy posture and receipts.
25. Hypervisor Workbench, Automations, Foundry, Hypervisor App, and Hypervisor Web are not the Hypervisor Node. They are clients or application surfaces; the Hypervisor Node is the local settlement and interop domain composed around Hypervisor Daemon, Agentgres, wallet.network authority paths, registries, receipts, and replay.
26. Governed autonomous-system chains are system-local state machines, not necessarily standalone public blockchains or IOI L1s. IOI L1 anchors selected roots and settles global machine-economy rights, disputes, reputation, and economics.
27. The marketplace is not the protocol. aiagent.xyz and sas.xyz are first-party applications of AIIP and IOI settlement, while IOI mainnet remains the generic settlement layer for autonomous systems.
28. AIIP is the shared interop semantics for local microharness routing and external autonomous-system handoffs. Transports and settlement depth may vary; protocol grammar should not fragment.
29. Ecosystem Assurance is a profile/evidence/export layer, not a runtime,
    authority wallet, Agentgres domain, marketplace ranking engine, legal advice
    system, insurance adjudicator, or settlement layer. Certification badges,
    policy packs, audit exports, and quarantine advisories must route action
    through the owning domain.
