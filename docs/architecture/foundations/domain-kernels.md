# Fractal Kernel, L0 Substrate, and Application-Domain Kernels

Status: canonical architecture authority.
Canonical owner: this file for root/domain kernel boundaries and domain-kernel responsibilities.
Supersedes: overlapping plan prose when kernel ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-24.

## Canonical Definition

The IOI kernel is the runtime/authority core that executes deterministic state transitions, validates policies, manages receipts, coordinates domains, and serves as the substrate on which Agentgres domains run.

Domain kernels are also where MoW routing becomes operational. They bind user
intent, worker candidates, policy, authority, runtime placement, receipts, and
settlement mirrors into domain-specific decisions.

## Kernel as L0 Substrate

The IOI kernel has **L0 responsibilities**. It is the reusable substrate and
toolchain for instantiating sovereign execution domains, including ordinary
application domains, non-intelligent chains/state machines, and intelligent
blockchains that bind workers, policies, receipts, and settlement.

L0 does not mean "one more global chain under IOI L1." It means the portable
kernel layer that can generate and operate many domains. IOI L1 anchors public
commitments, governance decisions, and canonical release roots for that
substrate; it does not execute the substrate or manage every application state
transition.

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
  local state machines with modules, proposals, receipts, upgrade paths

Hypervisor Nodes
  local settlement and interop domains coordinating many governed chains

Semantic data plane
  Domain Ontologies, Data Recipes, connector mappings, policy-bound data views

Execution worker nodes
  local, hosted, DePIN, TEE, customer VPC
  run Hypervisor Daemon runtime-node profiles and execute work

Client surfaces
  Hypervisor App, Hypervisor Web, IOI CLI/headless, optional TUI, @ioi/agent-sdk,
  IOI ADK, Workbench, Workflow Compositor, browser apps
  submit, inspect, scaffold, and control work through stable domain/runtime contracts

Hypervisor application surfaces
  Workbench, Foundry, Agents / Workers, Models, Connectors / Tools / MCP,
  Data / Knowledge, Ontology, Authority / Govern, Receipts / Replay,
  Operate / Monitoring, Providers / Environments, Privacy / cTEE,
  Change Plane, Marketplace, Patterns / Examples / Training, Domain Apps
  organize the same Core by job-to-be-done without owning runtime truth
```

This is an **edge-in topology**. Traditional blockchain applications usually
start from a global chain, place application contracts on it, and make edge
clients mirror or submit into that center. IOI inverts that shape:

```text
local edge / runtime work
  -> domain kernel + Agentgres operational truth
  -> Domain Ontologies and Data Recipes for semantic data truth
  -> receipts, artifacts, state roots, and settlement mirrors
  -> sparse public commitments to IOI L1 when registry, settlement, dispute,
     or governance trust is required
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

- domain scaffolding primitives;
- state transition and replay conventions;
- manifest and envelope schema families;
- daemon/runtime-node profile contracts;
- policy, authority, and receipt semantics;
- Agentgres domain integration patterns;
- export/import, sealed archive, and upgrade conventions.

The substrate can be used to create intelligent and non-intelligent sovereign
domains. A domain only becomes part of public IOI trust when it anchors the
relevant commitments, manifests, rights, settlement, or governance decisions to
IOI L1.

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

Each serious IOI application domain runs its own kernel/runtime deployment.

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
- DomainOntology, DataRecipe, ConnectorMapping, PolicyBoundDataView, and
  OntologyProjection state;
- Worker Training lifecycle state;
- benchmark and evaluation validation;
- receipt validation;
- artifact indexing;
- wallet authority integration;
- IOI L1 contract synchronization.
- Hypervisor Node local settlement records when the domain hosts local
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
  contract sync: worker registry, sparse categories, benchmark roots, licenses, install rights, usage settlement
  storage: worker packages, manifests, training lineage refs, instance archive refs, receipts, artifacts
```

### sas.xyz Domain

```text
sas.xyz kernel deployment
  Agentgres namespace: service_market
  projections: service listings, worker-training contracts, orders, SLA, delivery, disputes, provider state
  contract sync: escrows, SLA bonds, delivery acceptance, payout, disputes, training acceptance roots
  storage: delivery artifacts, training/evaluation refs, evidence bundles, receipts
```

### ioi.ai Control-Plane Domain

```text
ioi.ai kernel deployment
  Agentgres namespace: user_control_plane
  projections: account runtime profiles, devices, archive refs, restore status, publishing flows, compute entitlement
  contract sync: account-level entitlement, publication, billing, and settlement refs when applicable
  storage: sealed archive refs, sync metadata, runtime status pointers
```

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
  CLI/headless, Workbench surfaces, or Providers / Environments views;
- hosted Hypervisor Daemon;
- provider runtime;
- DePIN node;
- TEE-verified node;
- customer VPC.

The routing result is a `RuntimeAssignment` or equivalent record. It binds the
task/run/order to a runtime node, daemon profile, compute session, authority
posture, package refs, verification requirements, and payment quote. It does
not bind work to the SDK as an execution substrate.

## Kernel Deployment Modes

1. **Single-node trusted domain** — early/simple deployment.
2. **Replicated hosted domain** — first-party apps at scale.
3. **Enterprise-private domain** — customer-controlled kernel/Agentgres.
4. **Sovereign third-party domain** — independent Web4 application domain.
5. **First-party marketplace domain** — aiagent.xyz/sas.xyz.

## Root Commitment Policy

A domain kernel does not publish every state root to IOI L1.

It synchronizes with IOI L1 only for:

- registry commitments;
- contract events;
- escrow/settlement state;
- reputation/contribution roots;
- dispute evidence roots;
- public publication commitments.

## Non-Negotiables

1. Every serious application domain needs its own kernel + Agentgres deployment.
2. IOI L1 remains the registry/settlement/governance layer, not the domain kernel or L0 substrate.
3. Execution nodes are interchangeable venues, not domain state owners by default.
4. Domain kernels must not create split-brain state separate from Agentgres.
5. All surfaces must use stable runtime/substrate envelopes.
6. Client surfaces such as Hypervisor App, Hypervisor Web, CLI/headless,
   optional TUI, SDK, ADK, Workbench, Workflow Compositor, Foundry, and
   Providers / Environments views must not bypass domain kernels or daemon
   runtime contracts for canonical work.

## One-Line Doctrine

> **The IOI architecture is fractal and edge-in: the L0 kernel instantiates domains, edge runtimes perform work, domain kernels manage operational truth, and IOI L1 anchors public commitments.**
