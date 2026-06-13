# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-06-12.

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate
authority documents so each facet has a clear role, boundary, and dependency
surface.

If you are new to the canon, start with [`START_HERE.md`](./START_HERE.md). It
gives the five-minute stack model, role-based reading paths, common boundary
mistakes, and links to the implementation matrix.

The core doctrine is:

> **IOI is an edge-in Web4 stack for alignment-secure machine authority:
> workers act under scoped authority, domains remember operational truth, and
> IOI L1 settles only the commitments that need public trust.**

The protocol thesis is:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

The Hypervisor/autonomous-execution canon is:

```text
Hypervisor Daemon = hypervisor/control plane for autonomous execution
IOI daemon = hypervisor/control plane for autonomous execution
HypervisorOS = bare-metal node profile where daemon is node root
Default Harness Profile = daemon-executed loop-native orchestration profile
Hypervisor Fleet = general infrastructure manager whose first-class workload is autonomous systems
Hypervisor Node = local autonomous-system settlement and interop domain
Hypervisor IDE = IDE-grade operator console
Electron/VS Code fork = canonical app shell
IOI Authority Gateway = compatibility adapter profile for existing IDEs/agents
Private Workspace backed by cTEE = user-facing private workspace for persistent untrusted GPU nodes; Plaintext-Free Runtime Mounting is the daemon boundary; CLPD is the default protected-agency strategy
decentralized.* resource lanes = route liquidity and exposure; Hypervisor Cloud Resource Lane routes execution through direct provider integrations
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

Product taxonomy:

> **The Hypervisor Daemon is the deterministic execution substrate for portable,
> verifiable autonomous systems. Hypervisor is the flagship product surface for
> building, deploying, and governing those systems.**

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
- Hypervisor Fleet is the general infrastructure manager whose first-class
  workload is autonomous systems; it manages machines, VMs, containers,
  microVMs, WASM workloads, images, volumes, networks, GPU pools, provider
  integrations, placement, health, cost, storage posture, cTEE posture,
  receipts, replay projections, and policy visibility; it appears inside
  Hypervisor IDE and console.ioi.ai, but it does not execute work, authorize
  power, admit truth, or own payload bytes;
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
- wallet.network authorizes identity, secrets, approvals, payments, exchanges,
  data use, decryption, revocation, and protection actions; route sources
  produce exchange candidates but do not become authority;
- decentralized.exchange and decentralized.trade are source-agnostic resource
  lanes for liquidity and exposure route intelligence; the Cloud Resource Lane
  handles execution route intelligence through direct provider connectors,
  local inventory, customer clouds, DePIN markets, storage networks,
  and user-specified routes; lanes propose candidates, while Wallet authorizes,
  Hypervisor executes or deploys, venues/providers perform, Agentgres records,
  and IOI L1 settles by trigger;
- Agentgres artifact refs define payload meaning, lifecycle, policy, authority,
  receipts, replay/import metadata, archive/restore validity, and state-root
  validity;
- storage backends such as local disk, S3/object stores, Filecoin, CAS/IPFS, and
  provider/customer blob stores hold payload bytes;
- MoW routes bounded workers by policy, benchmarks, receipts, cost, trust, and
  contribution quality;
- Hypervisor IDE is the IDE-grade operator console and application workbench for
  autonomous systems, exposed through the Electron/VS Code fork as the
  canonical app shell and backed by local or remote daemon profiles; Fleet,
  Foundry, Workspaces, Agents, Services, Models, cTEE/Privacy, Receipts/Audit,
  and Connectors should be lenses over the same substrate, not separate runtime
  truth paths;
- IOI Authority Gateway is the daemon sidecar/adapter profile for existing IDE,
  CLI, browser, hosted-agent, and MCP/tool ecosystems: keep your IDE, keep your
  model, and put consequential execution behind IOI;
- agent-ide and the workflow compositor render typed recipes over the shared
  builder substrate; CLI/TUI, SDK, ADK, harnesses, benchmarks, and IDE
  extensions are clients, builder frameworks, or projections rather than
  runtime owners;
- aiagent.xyz is a first-party protocol application that publishes,
  benchmarks, ranks, installs, initializes managed instances, and routes
  workers through AIIP and IOI settlement;
- sas.xyz is a first-party protocol application that sells worker-powered
  outcomes, including Worker Training contracts, through AIIP and IOI
  settlement;
- ioi.ai coordinates accounts, devices, publishing, restore, sync metadata,
  remote-runtime access, and the console.ioi.ai web/org Fleet surface.

Agentgres should not be read as "state stored as Filecoin blobs." Agentgres is
the state machine, query substrate, and artifact-ref authority; storage backends
are payload byte stores beneath Agentgres-governed refs.

Private state should not be read as "agent state only." Private user/app state
such as profile metadata, app preferences, workspace snapshots, service intake
forms, private outputs, and non-public managed-instance metadata may be stored
as encrypted payload bytes in storage backends, while Agentgres owns refs,
policy, receipts, state roots, and restore/import validity. wallet.network
authorizes viewing/decryption/mutation. IOI L1 receives selected public,
economic, rights, dispute, registry, and cross-domain commitments, not private
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
- [`Architecture Decision Records`](../decisions/README.md) — accepted decision history for durable architecture choices.
- [`doc-classes.md`](./_meta/doc-classes.md) — documentation class vocabulary for future metadata/linting.

## High-Level Canonical Spec Files

- [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md) — category definition and stack map.
- [`decentralized-resource-lanes.md`](./foundations/decentralized-resource-lanes.md) — decentralized.exchange, decentralized.trade, and Hypervisor Cloud Resource Lane doctrine for routing liquidity, exposure, and execution without becoming authority or trust roots; decentralized.cloud is parked future product space, not present canon spine.
- [`aiip.md`](./foundations/aiip.md) — AIIP work interop protocol, bounded execution domains, profiles, packets, and handoff semantics.
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
- [`daemon-runtime/hypervisoros.md`](./components/daemon-runtime/hypervisoros.md) — bare-metal Hypervisor node profile, measured boot, daemon-rooted workload launch, node integrity receipts, and HypervisorOS conformance.
- [`hypervisor/fleet.md`](./components/hypervisor/fleet.md) — Hypervisor Fleet as the general infrastructure manager whose first-class workload is autonomous systems, spanning machines, VMs, containers, microVMs, WASM workloads, DePIN, cloud, local, edge, customer, and bare-metal nodes, with Fleet surfaces in Hypervisor IDE and console.ioi.ai.
- [`daemon-runtime/private-workspace-ctee.md`](./components/daemon-runtime/private-workspace-ctee.md) — Private Workspace backed by cTEE for persistent rented GPU Hypervisor Nodes, Candidate-Lattice Private Decoding, private files/folders, private strategy execution, autonomy leases, declassification gates, and no-plaintext protected classes.
- [`daemon-runtime/runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md) — local/hosted/DePIN/TEE execution modes.
- [`wallet-network/doctrine.md`](./components/wallet-network/doctrine.md) — identity, secrets, authority scopes, approvals, payments, exchange/trade authority.
- [`wallet-network/product-exchange-risk.md`](./components/wallet-network/product-exchange-risk.md) — Wallet product doctrine, exchange/trade authority, route-source boundaries, risk labels, asset/position exposure, protection actions, approval inbox, wallet receipts, and SDK events.
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
- [`wallet-network/api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md) — wallet.network authority scopes, grants, approvals, brokerage, exchange, exposure, protection, receipts, and revocation.
- [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) — IOI L1 contract interfaces.
- [`daemon-runtime/task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md) — runtime assignment, task capsules, privacy modes, attestation.
- [`agentgres/artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md) — artifact/package refs, bundles, archive refs, verification, and restore validity.
- [`model-router/api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) — model provider, endpoint, route, invocation, BYOK, mounting.
- [`connectors-tools/contracts.md`](./components/connectors-tools/contracts.md) — RuntimeToolContract, connector/tool APIs, risk classes.
- [`daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md) — runtime events, receipts, delivery bundles, traces, quality.

## Boundary And Generated References

- [`vocabulary.md`](./_meta/vocabulary.md) — runtime, audit, substrate, projection, and legacy naming vocabulary.
- [`CIRC.md`](../conformance/agentic-runtime/CIRC.md) — hidden intent-resolution conformance invariant.
- [`CEC.md`](../conformance/agentic-runtime/CEC.md) — hidden completion-evidence conformance invariant.

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
| Hypervisor Node | Local settlement, orchestration, authority, state, replay, routing, and interop domain for many governed autonomous-system chains. |
| Verifiable Bounded Agency | Alignment-security thesis: probabilistic workers may propose, but only bounded, authorized, receipted effects may cross the deterministic execution boundary. |
| Mixture of Workers | Labor-routing architecture that selects bounded workers by policy, benchmark evidence, cost, trust, and contribution quality. |
| Worker Training | Supply-creation lifecycle for turning workflows, examples, corrections, data, gates, and training profiles into deployable benchmarked workers. |
| Domain Ontologies and Data Recipes | Semantic data plane that turns sources, connector payloads, traces, schemas, and policies into ontology-bound, optionally distilled training, evaluation, runtime, and projection truth. |
| Domain Kernel | Application-domain authority/runtime deployment for Agentgres and routing. |
| Agentgres | Per-domain canonical operational state, receipts, projections, quality, and contribution accounting. |
| Hypervisor Daemon / Runtime Node | Hypervisor/control plane for autonomous execution across workflows, workers, tools, models, connectors, computer-use leases, artifacts, policy, receipts, and replay. |
| HypervisorOS | Bare-metal Hypervisor node profile where the daemon is the node root; owns measured node boot, daemon-rooted workload launch, node integrity receipts, and bare-metal conformance without replacing cTEE privacy or wallet.network authority. |
| Hypervisor Fleet | General infrastructure manager whose first-class workload is autonomous systems; manages nodes, providers, VMs, containers, microVMs, WASM workloads, images, volumes, networks, GPU pools, DePIN/cloud/local/bare-metal runtime inventory, Cloud Resource Lane and CloudRoute candidates, placement, health, cost, storage posture, cTEE posture, receipts, replay projections, and policy visibility; surfaces inside Hypervisor IDE and console.ioi.ai without owning execution, authority, truth, or bytes. |
| Decentralized Resource Lanes / Cloud Resource Lane | Route-intelligence lanes: decentralized.exchange routes liquidity, decentralized.trade routes exposure, and Hypervisor Cloud Resource Lane routes execution through direct provider integrations. Lanes propose candidates; wallet.network authorizes; Hypervisor executes or deploys; venues/providers perform; Agentgres records; IOI L1 settles by trigger. |
| Private Workspace backed by cTEE | User-facing private workspace and daemon execution profile for persistent rented GPU nodes that run useful compute without receiving protected plaintext by default; Plaintext-Free Runtime Mounting is the daemon boundary, CLPD is the default protected-agency strategy, Candidate Coverage Profile estimates proposal redundancy, Counterfactual Lattice Execution trades extra public token volume for lower online private-choice leakage, the Cryptographic Operator Plane handles protected private operators internally, External Model API Boundary distinguishes private-native/redacted-API/provider-trust/unsafe paths, and deterrence/detection receipts support canaries, watermarks, and disputes. |
| IOI CLI/TUI | Human terminal and TUI operator client over daemon/public runtime APIs. |
| IOI SDK | Low-level protocol/client library over daemon, Agentgres, wallet.network, AIIP, and IOI L1 contracts; never the canonical execution owner. |
| IOI ADK | Autonomous development kit for building workers, service modules, harnesses, evals, manifests, receipts, deployment profiles, and governed autonomous systems. |
| Shared Builder Substrate | Shared graph model, typed node contracts, schemas, recipes, daemon execution path, and receipt model used by Hypervisor builder lenses. |
| agent-ide / Workflow Compositor | GUI/workflow projection that renders typed recipes and workflows over the shared builder substrate. |
| Hypervisor IDE | IDE-grade operator console for autonomous systems; observes, requests, approves, interrupts, debugs, and explains daemon-governed work without owning runtime truth. |
| Electron/VS Code Fork | Canonical Hypervisor app shell for IDE and local runtime surfaces. |
| IOI Authority Gateway / Hypervisor Guard | Compatibility sidecar/adapters for existing IDEs, CLI agents, hosted agents, browser tools, and MCP ecosystems; routes proposed actions through daemon policy, authority, receipts, and replay without becoming a second runtime. |
| wallet.network | Sovereign authority wallet for identity, secrets, keys, authority scopes, approvals, payments, exchange/trade authority, risk disclosure, protection actions, and revocation. |
| aiagent.xyz | Canonical Web4 marketplace for portable digital workers, benchmark profiles, Sparse Worker Categories, installs, and routing eligibility. |
| sas.xyz | Canonical Web4 marketplace for autonomous service outcomes, including Worker Training as Service-as-Software. |
| ioi.ai | Lightweight account/control plane for devices, restore routing, publishing, sync metadata, remote-runtime entitlement, and console.ioi.ai Fleet web/org surfaces. |
| ai:// | Naming and manifest resolution protocol for intelligence, workers, services, apps, and domains. |
| Agentgres Artifact-Ref Plane | Artifact identity, payload refs, evidence/delivery/archive refs, lifecycle, policy, authority, receipts, replay/import metadata, restore validity, and state-root validity. |
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
  Hypervisor IDE, Hypervisor Daemon, Agentgres, wallet.network authority path,
  local registries, receipts, replay, interop, and local settlement

Client Surfaces
  Hypervisor IDE, agent-ide, IOI Authority Gateway adapters, IOI CLI/TUI, @ioi/agent-sdk, IOI ADK, browser apps, harnesses, benchmarks

Storage Plane
  local disk, S3/object stores, Filecoin, CAS/IPFS, provider/customer blob stores for payload bytes

Authority Plane
  wallet.network for identity, secrets, authority scopes, payments, approvals, revocation
```

## Key Non-Negotiables

1. Agentgres does not run on IOI L1. It runs per application/domain.
2. aiagent.xyz and sas.xyz are not separate chains by default. They are canonical Web4 application domains with their own Agentgres backends and IOI L1 smart-contract settlement rails.
3. IOI L1 is not the operational notebook. It stores registry, rights, economic commitments, disputes, and sparse roots.
4. IOI gas is consumed at coordination and settlement boundaries, not per model thought, tool call, or workflow node.
5. The Default Harness Profile must be daemon-executed, marketplace-neutral, and must not cannibalize worker/service markets through silent appropriation.
6. wallet.network is the authority plane. Agents and runtimes receive authority scopes, not raw secrets.
7. DePIN nodes are execution venues; Web4 apps define state, rights, UX, contracts, and outcomes.
8. Storage backends store payloads; trust comes from Agentgres refs, manifests, hashes, signatures, receipts, policy, authority, and settlement roots when applicable.
9. Agentgres state MUST NOT be reduced to opaque Filecoin blobs. Agentgres owns canonical operations, object heads, indexes, constraints, projections, subscriptions, delivery state, receipt metadata, artifact refs, archive refs, replay/import metadata, and restore validity.
10. Compute nodes initialize Hypervisor Daemon runtime-node profiles, optionally bridging into runtime services; the SDK is a client over that substrate, not the substrate itself.
11. HypervisorOS is a bare-metal node profile, not a peer runtime. It gives serious nodes daemon-rooted control and measurement, but it does not make consumer GPUs confidential compute or replace cTEE no-plaintext-custody.
12. Hypervisor Fleet is a general infrastructure manager whose first-class workload is autonomous systems, not a peer runtime, wallet, Agentgres domain, storage authority, or L1 settlement layer. Fleet manages machines and workload posture while coordinating governance; Hypervisor Daemon executes; wallet.network authorizes; Agentgres records truth; storage backends hold bytes.
13. Decentralized resource lanes propose routes for liquidity and exposure, and Cloud Resource Lane proposes routes for execution; they are not authority, custody, provider, venue, storage, or settlement owners. Parked future decentralized.cloud must not be treated as present canon or a mandatory gateway.
14. CLI/TUI, SDK, and ADK are separate surfaces: CLI/TUI is the operator interface, SDK is the low-level client library, and ADK is the autonomous-system builder framework.
15. CLI/TUI, agent-ide, SDK, ADK, Hypervisor IDE, harnesses, benchmarks, and Fleet surfaces must share daemon/domain contracts rather than creating private runtime truth paths.
16. Worker is the protocol actor; model is a cognition backend; agent is product-facing or colloquial language.
17. MoW is labor routing across bounded workers, not a fifth Web primitive and not model-provider routing.
18. Worker Training creates or improves capability but does not grant authority; wallet.network or equivalent authority grants power.
19. Workers train on ontology-bound, policy-bound, and when useful distilled data, not raw blobs or ambient connector payloads.
20. Models and agents may reason or propose; Hypervisor Daemon authority decides what crosses the deterministic execution boundary.
21. IOI Authority Gateway, Hypervisor Guard, IDE extensions, CLI wrappers, MCP gateways, Git hooks, API proxies, browser adapters, and CI gates are mediation surfaces only. They must route consequential actions through daemon policy, authority, receipts, and replay, and they must not claim total interception of opaque third-party runtimes.
22. IOI's alignment-security claim is execution-boundary alignment: it constrains consequential effects through bounded authority, policy, receipts, and verification; it must not be framed as proving every model's private cognition or goals are safe.
23. Hypervisor IDE is not the Hypervisor Node. The IDE is an operator console; the Hypervisor Node is the local settlement and interop domain composed around Hypervisor Daemon, Agentgres, wallet.network authority paths, registries, receipts, and replay.
24. Governed autonomous-system chains are system-local state machines, not necessarily standalone public blockchains or IOI L1s. IOI L1 anchors selected roots and settles global machine-economy rights, disputes, reputation, and economics.
25. The marketplace is not the protocol. aiagent.xyz and sas.xyz are first-party applications of AIIP and IOI settlement, while IOI mainnet remains the generic settlement layer for autonomous systems.
26. AIIP is the shared interop semantics for local microharness routing and external autonomous-system handoffs. Transports and settlement depth may vary; protocol grammar should not fragment.
