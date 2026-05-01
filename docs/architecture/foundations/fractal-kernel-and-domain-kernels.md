# Fractal Kernel, L0 Root, and Application-Domain Kernels

Status: canonical architecture authority.
Canonical owner: this file for root/domain kernel boundaries and domain-kernel responsibilities.
Supersedes: overlapping plan prose when kernel ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

The IOI kernel is the runtime/authority core that executes deterministic state transitions, validates policies, manages receipts, coordinates domains, and serves as the substrate on which Agentgres domains run.

The architecture is fractal:

```text
IOI L1 / root coordination layer
  registry, contracts, public settlement, governance

Application-domain kernel deployments
  aiagent.xyz, sas.xyz, Autopilot domains, enterprise domains
  each with its own Agentgres state substrate

Execution worker nodes
  local, hosted, DePIN, TEE, customer VPC
  run IOI daemon profiles and execute work
```

## Root vs Domain

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
Autopilot local/domain kernel
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
- receipt validation;
- artifact indexing;
- wallet authority integration;
- IOI L1 contract synchronization.

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
  projections: listings, installs, usage, quality, contribution, reputation
  contract sync: worker registry, licenses, install rights, usage settlement
  storage: worker packages, manifests, receipts, artifacts
```

### sas.xyz Domain

```text
sas.xyz kernel deployment
  Agentgres namespace: service_market
  projections: service listings, orders, SLA, delivery, disputes, provider state
  contract sync: escrows, SLA bonds, delivery acceptance, payout, disputes
  storage: delivery artifacts, evidence bundles, receipts
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
SettlementCommit
```

The transport can vary. The envelopes should not.

## Relationship to Execution Nodes

Domain kernels are not necessarily the nodes that execute every job.

```text
Domain kernel:
  maintains marketplace/application state and routing

Execution node:
  runs a worker/workflow/model/tool job

Storage plane:
  stores packages and artifacts

L1:
  settles public rights and commitments
```

For run-per-launch work, the domain kernel may route to:

- user-local Autopilot;
- hosted IOI daemon;
- provider runtime;
- DePIN node;
- TEE-verified node;
- customer VPC.

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
2. IOI L1 remains the registry/settlement/governance layer, not the domain kernel.
3. Execution nodes are interchangeable venues, not domain state owners by default.
4. Domain kernels must not create split-brain state separate from Agentgres.
5. All surfaces must use stable runtime/substrate envelopes.

## One-Line Doctrine

> **The IOI architecture is fractal: mainnet coordinates public commitments; domain kernels manage app truth; execution nodes perform work.**
