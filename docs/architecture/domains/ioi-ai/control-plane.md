# ioi.ai Control Plane Specification

Status: canonical architecture authority.
Canonical owner: this file for ioi.ai account, device, restore, publishing, entitlement, and remote-runtime coordination boundaries.
Supersedes: product prose that implies ioi.ai owns raw secrets, full traces, user workspaces, always-on execution, or marketplace operational truth.
Superseded by: none.
Last alignment pass: 2026-05-14.

## Canonical Definition

**ioi.ai is the lightweight user/control-plane application domain for IOI accounts, devices, runtime discovery, restore routing, publishing flows, training metadata pointers, sync metadata, billing/entitlements, and remote-runtime coordination.**

It is not the heavy agent runtime, credential vault, marketplace database, or canonical state store for all user work.

## What ioi.ai Owns

ioi.ai may own:

- account profile and login state;
- device registrations;
- runtime profile registry for a user or org;
- latest state-root pointers;
- sealed archive refs and restore routing metadata;
- publishing flows into aiagent.xyz and sas.xyz;
- training run metadata pointers and benchmark/job status pointers;
- remote compute entitlement and billing metadata;
- managed worker instance entitlement pointers when a user's aiagent.xyz
  instance needs restore, billing, or runtime-discovery coordination;
- workspace sync metadata;
- lightweight runtime status such as `idle`, `running`, `archived`, or `needs_restore`;
- account-level notification and recovery flows.

## What ioi.ai Does Not Own

ioi.ai must not become:

- a raw credential vault;
- a store for full private workspaces;
- an always-on VM host by default;
- a store for large trace bundles or artifact bytes;
- a store for raw training datasets or full training traces by default;
- the canonical Agentgres database for every domain;
- the worker marketplace truth source;
- the MoW router or worker-routing truth source;
- the service-order operational truth source;
- the final settlement authority.

Those roles belong to wallet.network, Agentgres domains, Filecoin/CAS, aiagent.xyz, sas.xyz, runtime nodes, and IOI L1.

## Control-Plane Flow

```text
user signs in
→ ioi.ai resolves account/device/runtime profile
→ Agentgres refs identify latest state roots and sealed archive CIDs
→ wallet.network verifies restore authority and grants key leases
→ runtime router selects local, hosted, provider, DePIN, TEE, or customer runtime
→ IOI daemon/runtime node rehydrates or resumes work
→ restored/imported state records receipts back into Agentgres
```

The product promise can be:

```text
Log in to back up, restore, sync, publish, and recover your Autopilot/IOI runtime state.
```

The architecture promise is narrower:

```text
identity -> runtime profile -> encrypted archive refs -> wallet leases -> daemon/runtime node -> verified rehydration
```

## Optional Intake Worker

ioi.ai may use an **Intake Worker** as its Window-of-Intelligence front door.
This worker can classify user intent, privacy posture, authority needs, budget,
runtime preference, restore state, publishing target, and candidate
worker/service routes.

The Intake Worker is a worker, not ioi.ai itself and not the MoW router. It may
be implemented with any suitable cognition backend, including a dense model,
MoE-backed model, hybrid attention/state model, subquadratic long-context model,
retrieval/context-graph system, or mutable-context worker. The useful property
is not the architecture label; it is that the worker can be evaluated, bounded
by policy, improved through receipted training or context updates, and prevented
from silently taking over marketplace routing.

Allowed Intake Worker outputs include:

- intent and task-class classification;
- privacy and authority recommendations;
- runtime placement suggestions;
- restore or archive action suggestions;
- publishing-flow recommendations;
- candidate worker/service discovery requests;
- proposed context mutations for user-approved doctrine or preference changes;
- MoW route request envelopes for the relevant domain.

The Intake Worker must not own Sparse Worker Category rankings, aiagent.xyz
listing truth, sas.xyz service-order truth, wallet approvals, or contribution
accounting. It can help the user ask for work; it cannot privately decide the
economy.

## Hot Records

ioi.ai should keep only lightweight records hot:

- user/runtime IDs;
- device IDs;
- latest Agentgres state-root pointers;
- archive CIDs and blob refs;
- archive schema and policy hashes;
- preferred compute profile;
- runtime status;
- restore permissions;
- retention policy;
- billing/subscription entitlement;
- publish/sync metadata.
- training/publishing status metadata.

## Cold State Boundary

Heavy state belongs elsewhere:

```text
Agentgres:
  canonical operations, object heads, receipts, archive refs, restore receipts

Filecoin/CAS/blob storage:
  sealed encrypted archive bytes, traces, evidence bundles, artifact payloads, training datasets

wallet.network:
  key leases, secrets, restore authority, training-data approvals, decryption leases, revocation

IOI daemon/runtime node:
  active execution and rehydrated runtime process
```

## Remote Runtime Coordination

When ioi.ai starts or resumes work on remote compute, it coordinates a runtime assignment. It does not initialize the SDK as the execution substrate.

```text
ioi.ai control plane
→ domain kernel/runtime router
→ ComputeSession
→ IOI daemon/runtime-node profile
→ optional RuntimeAgentService bridge
→ worker package or task capsule
```

The SDK may submit, inspect, stream, or control the run as a client. It is not the runtime node.

Worker Training and benchmark jobs follow the same boundary:

```text
ioi.ai entitlement / publishing metadata
→ domain kernel/runtime router
→ ComputeSession
→ IOI daemon/runtime-node profile
→ training, evaluation, or benchmark job
→ Agentgres receipts and refs
```

ioi.ai can coordinate entitlement, restore, publishing, and status visibility
for training flows. It does not own raw datasets, canonical training lineage,
or worker-routing truth.

Managed aiagent.xyz instances follow the same split:

```text
aiagent.xyz install / instance record
→ ioi.ai account entitlement or restore pointer, when needed
→ domain kernel/runtime router
→ ComputeSession
→ IOI daemon/runtime-node profile
→ browser console, API, or workflow client over daemon APIs
→ Agentgres receipts, usage, memory refs, and archive refs
```

aiagent.xyz may provide the web-native console for an installed instance. ioi.ai
may coordinate account, entitlement, restore, and runtime discovery. Neither
surface becomes the daemon runtime or wallet authority plane.

For aiagent.xyz invocation flows, ioi.ai is an access and coordination helper,
not the marketplace or routing authority. The user may start from ioi.ai, but
the worker listing, install, managed-instance record, MoW routing eligibility,
invocation summary, usage, quality, and contribution records belong to the
aiagent.xyz domain and its Agentgres state. The run itself belongs to the
selected IOI daemon/runtime-node profile.

## Relationship To Other Domains

- aiagent.xyz owns worker listings, manifests, installs, managed instance
  records, invocation surfaces, MoW routing eligibility, quality, and
  marketplace records.
- sas.xyz owns service orders, outcome workspaces, deliveries, approvals, disputes, and settlement mirrors.
- local Autopilot owns the desktop/workbench experience and local projections.
- Autopilot Foundry owns the local Worker Training product experience.
- wallet.network owns authority, secrets, key leases, payment approvals, and revocation.
- Agentgres owns operational truth and archive refs.
- IOI L1 anchors settlement, rights, registry commitments, bonds, and disputes.

## Non-Negotiables

1. ioi.ai must stay thin enough that users can remain local-first and sovereign.
2. Restore must require wallet.network authority verification and Agentgres restore receipts.
3. ioi.ai stores archive refs and metadata, not raw sealed-state bytes by default.
4. ioi.ai does not replace aiagent.xyz, sas.xyz, wallet.network, Agentgres, Filecoin/CAS, or IOI daemon runtime nodes.
5. Remote compute entitlement must resolve to explicit runtime assignments, not ambient execution authority.

## One-Line Doctrine

> **ioi.ai coordinates access to a user's IOI world; it does not become that world.**
