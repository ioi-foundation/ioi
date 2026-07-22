# Fractal Kernel, L0 Substrate, and Application-Domain Kernels

Status: canonical architecture authority.
Canonical owner: this file for root/domain kernel boundaries and domain-kernel responsibilities.
Supersedes: overlapping plan prose when kernel ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-07-21.
Doctrine status: canonical
Implementation status: mixed (daemon + Agentgres substrate real; fractal domain-kernel topology speculative)
Last implementation audit: 2026-07-05

## Canonical Definition

The IOI kernel is the runtime/admission core that executes deterministic state
transitions, enforces policy and authority decisions from their owning
providers, manages receipts, coordinates domain-local work, and serves as the
substrate on which Agentgres domains run. It does not create authority by
itself.

A domain kernel is an owner-qualified logical deployment and composition, not
a requirement that every responsibility live in one process, executable,
source package, or Rust module. A deployment may co-locate or separate its
owner-specific services across processes and nodes. Every canonical transition
must nevertheless converge on the same deterministic admission boundary,
authority crossing, and Agentgres operation log. Extracting mechanics from one
implementation package is conformant only when it preserves that single-gateway
property: consequential capability use still crosses the selected provider's
applicable `AuthorityGrant` or `CapabilityLease` and the daemon/kernel admission
path, and the extracted service does not become a parallel authority or truth
owner.

Domain kernels are also where MoW routing becomes operational. They bind user
intent, worker candidates, policy, authority, runtime placement, receipts, and
settlement mirrors into domain-specific decisions.

Product/category framing:

> **IOI is the open operating stack that turns intelligence into bounded
> autonomous institutions. L0 makes each institution safely distributable
> across its governed compute, state, verification, human, and embodied members;
> AIIP makes selective, positive-surplus interoperation between separately
> sovereign institutions contractible; IOI L1 supplies optional shared trust and
> economic finality.**

The L0 builder proposition is a modular application framework and operating
substrate for bounded distributed autonomous systems: teams can create, run,
govern, interoperate, coordinate useful work across admitted members, recover,
migrate, and dissolve sovereign intelligent blockchains with customizable
admission and finality. IOI's differentiated primitive is the complete
constitution-to-effect lifecycle for bounded agency, not generic chain
scaffolding or a mandatory hub.

## Kernel as L0 Substrate

The IOI kernel has **L0 responsibilities**. It is the reusable substrate and
toolchain for instantiating sovereign execution domains, including ordinary
application domains, non-intelligent chains/state machines, and intelligent
blockchains that bind workers, policies, receipts, and settlement.

In Web4 terms, the IOI kernel is the portable machine-authority kernel. It
turns identity, authority requests, policy decisions, runtime assignments,
operation logs, receipts, state roots, and settlement mirrors into repeatable
domain machinery.

An intelligent blockchain is not a public chain that happens to call an AI API.
It is a bounded autonomous-system state machine whose transitions may be
proposed, routed, evaluated, or improved by intelligence while canonical
admission remains constrained by a constitution, deterministic policy and
authority, ordered operational truth, receipts, replay, lifecycle control, and
proposal-mediated improvement. It additionally requires cryptographic
continuity: monotonic sequence, expected predecessor, operation/batch
commitment, admission proof, resulting state root, and receipt root for every
admitted transition. Without that commitment chain it is a bounded autonomous
application, not an intelligent blockchain. The classification does not require public
consensus, a native token, or multiple nodes. A single-authority/PoA-1 system is
still an intelligent blockchain when those boundaries are real; consensus only
changes its trust and failure model.

Most users should not experience these kernels as raw chain UIs. They experience
them as workspaces, applications, sessions, authority grants, receipts, replay,
revocation, packages, worker installs, and settlement records. Chain commitments
remain inspectable through proof, state-root, dispute, governance, and developer
views when the user, auditor, counterparty, or autonomous system needs to verify
the substrate.

L0 does not mean "one more global chain under IOI L1." It means the portable
kernel layer that can generate and operate many domains. For systems that
explicitly enroll in its services, IOI L1 may anchor selected public
commitments, IOI Network governance decisions, and recognized release roots;
it does not execute the substrate or manage every application state transition.

The architecture is fractal:

```text
IOI kernel / L0 substrate
  reusable domain, runtime, policy, receipt, and state-machine primitives

IOI L1 / root coordination layer
  registry, contracts, public settlement, governance

Application-domain kernel deployments
  aiagent.xyz, sas.xyz, ioi.ai, Hypervisor local domains, enterprise domains
  each with its own Agentgres state substrate

Governed autonomous-system chains
  system-local state machines, not necessarily single-node, with modules,
  proposals, receipts, and upgrade paths

Same-system distributed work
  native L0 role topology, runtime assignment, work/resource/authority leases,
  evidence, reconciliation, and embodied fleet policy across admitted members

Hypervisor Nodes
  local operational-finality and interop domains coordinating many governed chains

Semantic data plane
  Domain Ontologies, Data Recipes, connector mappings, policy-bound data views

Execution worker nodes
  local, hosted, DePIN, TEE, customer VPC
  run Hypervisor Daemon runtime-node profiles and execute work

Client surfaces
  Hypervisor App, Hypervisor Web, IOI CLI/headless, optional TUI, @ioi/agent-sdk,
  IOI ADK, browser apps
  submit, inspect, scaffold, and control work through stable domain/runtime contracts

Hypervisor core workspaces
  Home, Systems, Projects, Applications, Work
  organize admitted system context and typed work projections without owning truth

Shell-placed owner application
  Automations
  keeps one owner-application identity while remaining a permanent launch destination

Hypervisor application surfaces
  Studio, Automations, Ontology, Data, Governance, Provenance, Evaluations,
  Improvement, Foundry, Packages with optional Marketplace mode, Developer
  Workspace, Developer Console, plus the Environments and Operations substrate
  lane, generated and installed System interfaces,
  and the conditional Embodied Systems `owner_application` planned registration (contextual and
  nonlaunchable until its route and implementation are built)
  organize the same Core by job-to-be-done without owning runtime truth
```

This is an **edge-in topology**. Traditional blockchain applications usually
start from a global chain, place application contracts on it, and make edge
clients mirror or submit into that center. IOI inverts that shape:

```text
local edge / runtime work
  -> domain kernel + Agentgres operational truth
  -> Domain Ontologies and Data Recipes for locally canonical semantic meaning
  -> GoalRun for bounded local work
  -> optional same-system distribution across admitted members when placement,
     parallelism, locality, verification, or embodiment creates value
  -> optional OutcomeRoom only when collective machinery creates positive participant-level surplus
  -> optional AIIP handoff only after exact-root terms acceptance and admitted leases
  -> otherwise remain local
  -> receipts, evidence, verification, artifacts, state roots, and settlement mirrors
  -> local economic settlement by default
  -> sparse commitments to the declared external settlement profile when
     selected; IOI L1 only under explicit connected/secured enrollment
```

The same kernel pattern recurs at multiple grains: local Hypervisor domains,
hosted first-party domains, enterprise domains, sovereign third-party domains,
and public L1 commitments. The responsibilities differ by layer, but the
operation-log, policy, receipt, replay, and projection doctrine stays coherent.

A Hypervisor Node is one such local domain composition: Hypervisor Core
clients/surfaces, Hypervisor Daemon, Agentgres, wallet.network authority paths,
local registries, receipts, replay, and runtime profiles. It may host many
governed autonomous-system chains, but it does not become IOI L1.

## Root vs Domain

### IOI Kernel / L0 Substrate

The L0 substrate provides:

- reusable package/release, live-system genesis, constitution, lifecycle,
  deployment, ordering, oracle, and network-enrollment contracts for one
  logical bounded autonomous system;
- domain scaffolding primitives;
- state transition and replay conventions;
- manifest and envelope schema families;
- daemon/runtime-node profile contracts;
- same-system role topology, runtime assignment, scoped work/resource/authority
  leases, evidence, and reconciliation patterns across admitted members;
- policy, authority, and receipt semantics;
- Agentgres domain integration patterns;
- export/import, sealed archive, and upgrade conventions.

The substrate can be used to create intelligent and non-intelligent sovereign
domains. A domain only becomes part of public IOI trust when it explicitly
enrolls and anchors the relevant commitments, manifests, rights, settlement, or
governance decisions. Open L0 compatibility has no mandatory IOI L1 dependency
or network fee.

Builder-facing doctrine:

> **Build and settle your autonomous system at the edge. When external
> capability, authority, evidence, resources, or trade creates positive
> participant-level surplus, interoperate selectively through AIIP. Distribute
> internal work through native L0 membership and assignment contracts; select
> IOI Network services only when neutral shared trust adds further value.**

### IOI L1 / Root Layer

The root layer coordinates public trust and economic commitments.

It owns:

- `ai://` root registry;
- global publisher identity commitments;
- first-party smart contracts;
- settlement commitments;
- governance;
- root protocol schemas.

### Application-Domain Kernel

Each serious IOI application domain runs its own owner-qualified kernel/runtime
deployment. "Owns" below means singular protocol responsibility and admitted
truth, not that every listed mechanism must be implemented inside one source
module or process.

Examples:

```text
aiagent.xyz domain kernel
sas.xyz domain kernel
ioi.ai control-plane kernel
Hypervisor local/domain kernel
enterprise customer kernel
third-party sovereign app kernel
```

A domain kernel owns:

- Agentgres canonical operation log;
- domain write authority or forwarding;
- domain state roots;
- projections;
- subscriptions;
- run routing;
- MoW routing decisions;
- same-system RoleTopology, RuntimeAssignment, work-lease, evidence, and
  reconciliation state for useful distribution across admitted members;
- DomainOntology, DataRecipe, ConnectorMapping, PolicyBoundDataView, and
  OntologyProjection state;
- Worker Training lifecycle state;
- benchmark and evaluation validation;
- receipt validation;
- artifact indexing;
- wallet authority integration;
- declared external settlement and network-service adapters, including IOI L1
  synchronization only when an active connected/secured enrollment selects the
  specific service;
- Hypervisor Node state-transition commitment records when the domain hosts local
  autonomous-system chains.

## Why Agentgres Requires a Domain Kernel

Agentgres is too operational, high-volume, projection-heavy, and application-specific to live on IOI L1.

Agentgres needs a domain kernel because it must manage:

- canonical app operations;
- runs and orders;
- workflow state;
- patch/change records;
- delivery bundles;
- receipts;
- projections;
- quality ledgers;
- contribution accounting;
- subscriptions;
- local/static/live read paths.

These are domain responsibilities, not mainnet responsibilities.

## App-Domain Examples

### aiagent.xyz Domain

```text
aiagent.xyz kernel deployment
  Agentgres namespace: worker_market
  projections: listings, installs, managed instances, usage, quality, contribution, reputation
  optional adapter sync: selected registry, category, benchmark, rights, license,
    reputation, and settlement services; IOI L1 only under matching active enrollment
  storage: worker packages, manifests, training lineage refs, instance archive refs, receipts, artifacts
```

### sas.xyz Domain

```text
sas.xyz kernel deployment
  Agentgres namespace: service_market
  projections: service listings, worker-training contracts, orders, SLA, delivery, disputes, provider state
  optional adapter sync: selected escrow, bond, dispute, reputation, rights,
    public-commitment, and settlement services; IOI L1 only under matching active enrollment
  storage: delivery artifacts, training/evaluation refs, evidence bundles, receipts
```

### ioi.ai Control-Plane Domain

```text
ioi.ai kernel deployment
  Agentgres namespace: user_control_plane
  objects: Goal Spaces, OutcomeRoom refs, GoalRuns, plans, attempt summaries,
           cross-session outcome graphs, accounts, devices, archive refs,
           restore lifecycle, publication state, compute entitlements
  projections: goal/frontier graph, participants/claims, evidence and replay,
               account runtime profiles, devices, restore/runtime/sync status
  declared adapters: account/subscription entitlement, publication, Work Credit,
    goal-budget, billing, contribution, network-service, and settlement refs;
    public/IOI services only under exact policy and active selected enrollment
  storage: sealed archive refs, permitted room artifacts, sync metadata,
           publication artifacts, receipts, runtime status pointers
```

When ioi.ai's domain hosts an OutcomeRoom system it may operate that room's
declared ordering/admission state under the room `system_id`, constitution, and
active profiles; host identity does not replace logical room identity. A
federated room still leaves each participant's
operational truth in its home domain and carries signed permitted refs over
AIIP; ioi.ai is not a universal room database.

## Communication Surfaces

Domain kernels communicate with other components through stable envelopes, not ad hoc calls.

Possible transports:

- local IPC / Unix socket / named pipe;
- gRPC;
- QUIC;
- HTTPS;
- WebSocket/SSE for event streams.

Stable message classes:

```text
RunRequest
TaskCapsule
RuntimeEvent
CapabilityRequest
PolicyDecision
ArtifactRef
ReceiptBundle
DeliveryBundle
WorkerTrainingEnvelope
BenchmarkEnvelope
RoutingDecisionEnvelope
SettlementCommit
```

The transport can vary. The envelopes should not.

## Relationship to Execution Nodes

Domain kernels are not necessarily the nodes that execute every job.

```text
Domain kernel:
  maintains marketplace/application state and routing

Execution node:
  runs a Hypervisor Daemon runtime-node profile for a worker/workflow/model/tool job

Storage plane:
  stores packages and artifacts

L1:
  settles public rights and commitments
```

For run-per-launch work, the domain kernel may route to:

- user-local Hypervisor Daemon managed through Hypervisor App, Hypervisor Web,
  CLI/headless, Developer Workspace surfaces, or Environments views;
- hosted Hypervisor Daemon;
- provider runtime;
- DePIN node;
- TEE-verified node;
- customer VPC.

The routing result is a `RuntimeAssignment` or equivalent record. It binds the
task/run/order to a runtime node, daemon profile, compute session, authority
posture, package refs, verification requirements, and payment quote. It does
not bind work to the SDK as an execution substrate.

This is native same-system coordination when the assigning domain and runtime
member remain under one `system_id` and constitution. It may use remote
transports and the same typed envelope conventions as external work without
becoming AIIP. AIIP begins only when the assignment or handoff crosses to an
independently governed system with a separate authority, truth, risk, and exit
boundary.

## Deployment Is A Declared Profile

Deployment has independent dimensions and must not be compressed into one
"consensus mode" toggle:

```text
logical identity and constitution
  + environment/custody profile
  + member-node roles and failure domains
  + useful-work role topology, placement, lease, and reconciliation policy
  + ordering/admission/finality profile
  + replication, durability, failover, fencing, and recovery policy
  + oracle/evidence and degraded-mode policy
  + network enrollment profile
```

Environment/custody deployments include:

1. **Single-node trusted domain** — early, local, or deliberately simple.
2. **Replicated hosted domain** — first-party services with declared replicas.
3. **Enterprise-private domain** — customer-controlled kernel/Agentgres.
4. **Sovereign third-party domain** — independently governed Web4 domain.
5. **First-party marketplace domain** — aiagent.xyz/sas.xyz.

Ordering and finality are separately declared as `single_authority`,
`replicated_single_authority`, `threshold_authority`, `bft_consensus`, or
`external_chain_finality`. Node roles are separately declared as admission
writer, hot standby, state or projection replica, execution worker, artifact
replica, verifier, threshold-authority member, availability witness, gateway,
or consensus member. The canonical member sets live
in [`canonical-enums.md`](./canonical-enums.md).

One autonomous system has one stable `system_id` across its declared
member nodes. A node is a failure, placement, custody, execution, verification,
or admission role inside that logical system; it is not a new system merely
because another process or machine was deployed. Conversely, two independently
governed systems do not become one system merely because they share a cluster.

The kernel therefore distinguishes three coordination planes: continuity
coordination for replication/failover, same-system distributed work for useful
placement and cooperation across admitted members, and cross-system federation
through AIIP. The first two use native L0 membership, RuntimeAssignment,
GoalRun/work leases, domain state/evidence, and—where physical—Embodied Runtime
and fleet-policy contracts. Only the third requires AIIP and exact cross-party
terms. These planes reuse the existing substrate; they do not introduce a
second swarm scheduler or shared state system.

Adding a member node is a governed membership operation. It may improve
availability, read or execution throughput, artifact locality, verification
diversity, or tolerated failure domains only to the extent the deployment
profile, replication protocol, fencing, and admission policy actually prove.
It never silently grants write authority, changes quorum, expands budgets or
capabilities, or upgrades the assurance label. Single-writer promotion is
legitimate only with a declared promotion rule, catch-up/root proof, new writer
epoch, prior-writer fencing, recovery objectives, and a conformance test that
excludes dual writers. A deliberately single-node profile may instead fail
closed or perform a receipted checkpoint/log restore. Threshold, BFT, and
external-finality profiles use their declared profile-native view/round,
membership, or external-finality recovery proofs rather than inventing writer
epochs. Automation may execute only the pre-authorized branch; otherwise
recovery remains explicit and operator/governance controlled.

This is a material advantage over deploying two ordinary application instances:
the kernel supplies a system-level membership, ordering, authority, receipt,
replay, failover, recovery, useful-work placement, lease, evidence, and
reconciliation contract. A React application may be the leading operator or
domain UI, but React replicas still depend on that substrate; UI framework
choice is not the value proposition.

## Root Commitment Policy

A domain kernel does not publish every state root to any external network.

It invokes a declared external network-service or settlement adapter only for
the exact commitments selected by policy, such as:

- registry commitments;
- contract events;
- escrow/settlement state;
- reputation/contribution roots;
- dispute evidence roots;
- public publication commitments.

IOI L1 is one optional adapter. It is valid only while the system has an active
`ioi_connected` or `ioi_secured` enrollment selecting the matching
`service_kind`, terms, and public-commitment policy. A registry or reputation
service selection is independent from the economic rail used to pay its fee.

## Non-Negotiables

1. Every serious application domain needs its own logical kernel + Agentgres
   deployment. The deployment may compose separately packaged or placed
   owner-specific services, but it must preserve one admission path, one
   authority-crossing discipline, and one Agentgres truth boundary.
2. IOI L1 remains the optional shared IOI Network
   registry/settlement/governance layer for explicitly enrolled systems, not
   the domain kernel or L0 substrate.
3. Execution nodes are interchangeable venues, not domain state owners by default.
4. Domain kernels must not create split-brain state separate from Agentgres.
5. All surfaces must use stable runtime/substrate envelopes.
6. Client surfaces such as Hypervisor App, Hypervisor Web, CLI/headless,
   optional TUI, SDK, ADK, Developer Workspace, Workflow Compositor, Foundry, and
   Environments views must not bypass domain kernels or daemon
   runtime contracts for canonical work.
7. A GoalRun, attempt, participant, or room does not receive its own blockchain
   by default. Deterministic domain admission, branches, signatures, receipts,
   and replay are sufficient until independent ordering, rights, reputation,
   dispute, or economic finality requires consensus.
8. Cross-domain OutcomeRooms must declare hosted or federated admission and
   retain local Agentgres truth; no shared board or mutable global graph is a
   domain kernel by implication.
9. One logical autonomous system may span multiple nodes; membership never
   implies authority, and node addition never changes admission or finality
   without a governed profile revision.
10. Constitution, deployment, ordering/finality, oracle/evidence, continuity,
    and network-enrollment profiles are explicit durable objects, not runtime
    flags inferred from topology.
11. `ioi_compatible` systems owe no ambient L1 fee and receive no IOI Network
    assurance claim. Shared services and stronger assurance require explicit
    enrollment and declared consideration.
12. A domain remains complete locally. AIIP compatibility, discovery, or a
    shared objective creates no cooperation duty; cross-domain work requires
    exact-root terms acceptance and admitted participant, work, resource,
    budget, and authority leases (`INV-30`).
13. Do not model same-system distributed work as AIIP. Native L0 membership,
    assignment, GoalRun/work leases, evidence, reconciliation, and Embodied
    Runtime contracts govern internal work; AIIP is reserved for independently
    governed system boundaries (`INV-32`).

## One-Line Doctrine

> **The IOI architecture is fractal and edge-in: L0 creates and operates bounded
> autonomous institutions and coordinates continuity plus useful work across
> their admitted edge members; AIIP makes selective positive-surplus federation
> between independently governed systems contractible; and IOI L1 supplies
> optional shared trust and economic finality.**
