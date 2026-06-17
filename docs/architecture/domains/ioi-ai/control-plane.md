# ioi.ai Control Plane Specification

Status: canonical architecture authority.
Canonical owner: this file for ioi.ai account, device, restore, publishing, entitlement, console/provider-environment views, and remote-runtime coordination boundaries.
Supersedes: product prose that implies ioi.ai owns raw secrets, full traces, user workspaces, always-on execution, or marketplace operational truth.
Superseded by: none.
Last alignment pass: 2026-06-07.

## Canonical Definition

**ioi.ai is the lightweight user/control-plane application domain for IOI accounts, devices, runtime discovery, restore routing, publishing flows, training metadata pointers, sync metadata, billing/entitlements, console/org administration, Hypervisor provider/environment web views, and remote-runtime coordination.**

It is not the heavy agent runtime, credential vault, marketplace database, or canonical state store for all user work.

Product boundary doctrine:

```text
ioi.ai Goal Chat is where users ask.
Hypervisor is where autonomous work runs.
Hypervisor Automations is where durable workflows and services are built.
Hypervisor Foundry is where models, workers, evals, datasets, endpoints,
training jobs, registries, and ontology-aware packages are made.
```

## ioi.ai Goal Chat Boundary

**ioi.ai Goal Chat** is an intent, discovery, and coordination surface.

It may:

- collect a user's goal, constraints, preferences, and account context;
- invoke an existing Hypervisor automation, worker, service, or session;
- start an ad hoc Hypervisor run through daemon/Core contracts;
- inspect and summarize receipts, run state, restore state, and provider
  posture that the user is authorized to view;
- draft a proposed AutomationSpec, service recipe, Foundry job, or marketplace
  publish flow for explicit user review;
- draft or open an ioi.ai Outcome Room over Hypervisor when the goal needs
  multi-agent/multi-session search, benchmark races, eval gates, or competing
  harness/model strategies;
- route the user to Hypervisor App, Hypervisor Web, wallet.network, aiagent.xyz,
  sas.xyz, or console views when the job belongs there.

It must not:

- become the durable workflow/service builder;
- become the daemon runtime, message board truth, leaderboard truth, or attempt
  truth source for an Outcome Room;
- own Hypervisor Automations specs or run truth;
- own Workflow Compositor graph truth;
- own Hypervisor Daemon execution semantics;
- own wallet.network authority, secrets, capability leases, or declassification;
- own Agentgres operational truth, receipts, artifact refs, or restore validity;
- silently convert an ad hoc chat into a durable automation or service.

Handoff rule:

```text
Chat can propose.
Hypervisor Automations must own durable automation/service deployment.
Hypervisor Daemon must own execution.
wallet.network must own authority.
Agentgres must own admitted truth.
```

When a user says "turn this into an automation," "make this run every day,"
"expose this as an API," or similar, ioi.ai should create a draft handoff into
Hypervisor Automations rather than storing the durable system as chat state.

## What ioi.ai Owns

ioi.ai may own:

- account profile and login state;
- private profile metadata refs and policy pointers, when the profile payload
  itself is encrypted and governed through Agentgres refs;
- device registrations;
- node registry and runtime-node inventory metadata;
- runtime profile registry for a user or org;
- latest state-root pointers;
- sealed archive refs and restore routing metadata;
- publishing flows into aiagent.xyz and sas.xyz;
- training run metadata pointers and benchmark/job status pointers;
- remote compute entitlement and billing metadata;
- provider integration metadata for DePIN, cloud, GPU, storage, customer VPC,
  and HypervisorOS targets;
- Hypervisor provider/environment web/org/admin view state for node, VM,
  container, microVM, WASM, image, volume, network, GPU pool, provider, status,
  policy visibility, cost posture, remote access, billing, and team posture;
- Private Workspace cTEE node status, entitlement, and restore pointers;
- managed worker instance entitlement pointers when a user's aiagent.xyz
  instance needs restore, billing, or runtime-discovery coordination;
- workspace sync metadata;
- private app-state sync pointers for encrypted user/app payloads stored behind
  Agentgres artifact refs;
- lightweight runtime status such as `idle`, `running`, `archived`, or `needs_restore`;
- lightweight provider/environment status such as `healthy`, `degraded`, `draining`,
  `offline`, `needs_restore`, or `policy_blocked`;
- account-level notification and recovery flows.

## What ioi.ai Does Not Own

ioi.ai must not become:

- a raw credential vault;
- a store for full private workspaces;
- a plaintext store for private user/app profile payloads, service intake
  forms, app preferences, workspace snapshots, or non-public service outputs;
- an always-on VM host by default;
- the owner of Hypervisor provider/environment substrate semantics;
- the owner of Hypervisor provider/environment execution, authority, or truth;
- the owner of Private Workspace cTEE execution semantics;
- a store for large trace bundles or artifact bytes;
- a store for raw training datasets or full training traces by default;
- the canonical Agentgres database for every domain;
- the worker marketplace truth source;
- the MoW router or worker-routing truth source;
- the service-order operational truth source;
- the final settlement authority.

Those roles belong to Hypervisor provider/environment canon, Hypervisor Daemon
runtime nodes, wallet.network, Agentgres domains, storage backends,
aiagent.xyz, sas.xyz, and IOI L1.

## Hypervisor Provider And Environment Views

`console.ioi.ai` is the natural cloud/org view for Hypervisor provider and
environment posture. It may show and coordinate node, provider, restore,
entitlement, billing, and policy posture, but it does not become Hypervisor's
execution, authority, or truth substrate.

```text
console.ioi.ai Provider / Environment View
  accounts
  orgs
  devices
  entitlements
  node registry
  VM/container/microVM/WASM inventory
  image, volume, network, and GPU-pool posture
  runtime discovery
  restore routing
  provider integrations
  provider/environment status
  billing
  remote access
  org/admin policy visibility
```

The companion local/operator presentations live in Hypervisor App, Hypervisor
Web, and CLI/headless projections:

```text
Hypervisor App / Web Provider / Environment View
  attached nodes
  persistent workspaces
  active agents/workers/services
  model mounts
  cTEE posture
  receipts and trace summaries
  approvals
  logs/replay projections
  node attach/detach
  start/stop/resume/archive/restore

CLI/headless Provider / Environment Projection
  node ops
  health/logs/receipts
  scripted provider and restore workflows
```

Provider/environment canon is owned by
[`components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md).
ioi.ai owns the web/account/org coordination view; Hypervisor App/Web/CLI
clients host the hands-on operator presentations; Hypervisor Daemon executes;
wallet.network authorizes; Agentgres records admitted truth.

## Control-Plane Flow

```text
user signs in
→ ioi.ai resolves account/device/runtime profile
→ Agentgres refs identify latest state roots and sealed archive CIDs
→ wallet.network verifies restore authority and grants key leases
→ runtime router selects local, hosted, provider, DePIN, Private Workspace cTEE,
  TEE, or customer runtime
→ Hypervisor Daemon runtime node rehydrates or resumes work
→ restored/imported state records receipts back into Agentgres
```

The product promise can be:

```text
Log in to back up, restore, sync, publish, and recover your Hypervisor/IOI runtime state.
```

The architecture promise is narrower:

```text
identity -> runtime profile -> encrypted archive refs -> wallet leases -> daemon/runtime node -> verified rehydration
```

For app personalization, the same boundary applies:

```text
wallet.network authenticates and authorizes the user
  -> ioi.ai, aiagent.xyz, or sas.xyz resolves app/profile refs
  -> Agentgres provides state-rooted private user/app refs and receipts
  -> storage backend returns encrypted payload bytes
  -> browser/local authority view decrypts only what policy allows
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
- node IDs, provider IDs, and runtime profile IDs;
- latest Agentgres state-root pointers;
- archive CIDs and blob refs;
- archive schema and policy hashes;
- encrypted private profile/app-state refs;
- preferred compute profile;
- provider integration status and cost/entitlement pointers;
- Private Workspace profile, guardian pointer, and latest safe state-root pointer;
- runtime status;
- provider/environment status and policy-visibility metadata;
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

Storage backends:
  sealed encrypted archive bytes, traces, evidence bundles, artifact payloads, training datasets

wallet.network:
  key leases, secrets, restore authority, training-data approvals, decryption leases, revocation

Hypervisor Daemon runtime node:
  active execution and rehydrated runtime process

Private Workspace backed by cTEE:
  daemon-owned workspace/execution semantics for rented nodes that must stay
  useful without receiving protected plaintext; Candidate-Lattice Private
  Decoding is the default protected-agency strategy

Hypervisor provider/environment views:
  general infrastructure inventory for autonomous systems, including
  VM/container/microVM/WASM posture, placement, health, cost, cTEE posture,
  storage posture, receipt/replay projections, and provider coordination
```

## Remote Runtime Coordination

When ioi.ai starts or resumes work on remote compute, it coordinates a runtime assignment. It does not initialize the SDK as the execution substrate.

```text
ioi.ai control plane
→ domain kernel/runtime router
→ ComputeSession
→ Hypervisor Daemon runtime-node profile, including Private Workspace cTEE when selected
→ optional RuntimeAgentService bridge
→ worker package or task capsule
```

The SDK may submit, inspect, stream, or control the run as a client. It is not the runtime node.

Provider/environment placement follows the same boundary:

```text
console.ioi.ai, Hypervisor App/Web provider view, or CLI/headless provider projection
→ Hypervisor provider/environment placement projection
→ wallet.network authority check
→ domain kernel/runtime router
→ Hypervisor Daemon runtime-node profile
→ Agentgres receipts, state roots, artifact refs, and projection updates
```

Hypervisor provider/environment views can recommend or display placement. They
do not grant authority, execute the workload, or admit truth.

Worker Training and benchmark jobs follow the same boundary:

```text
ioi.ai entitlement / publishing metadata
→ domain kernel/runtime router
→ ComputeSession
→ Hypervisor Daemon runtime-node profile
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
→ Hypervisor Daemon runtime-node profile
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
selected Hypervisor Daemon runtime-node profile.

## Relationship To Other Domains

- aiagent.xyz owns worker listings, manifests, installs, managed instance
  records, invocation surfaces, MoW routing eligibility, quality, and
  marketplace records.
- sas.xyz owns service orders, outcome workspaces, deliveries, approvals, disputes, and settlement mirrors.
- local Hypervisor owns Hypervisor App/Web/CLI client experiences and local
  projections.
- Hypervisor Foundry owns the Worker Training application surface.
- Hypervisor provider/environment canon owns general infrastructure-manager
  semantics for autonomous systems, with views in Hypervisor App, Hypervisor
  Web, CLI/headless, and console.ioi.ai.
- wallet.network owns authority, secrets, key leases, payment approvals, and revocation.
- Agentgres owns operational truth and archive refs.
- Private Workspace backed by cTEE owns cTEE semantics for persistent rented GPU
  nodes.
- IOI L1 anchors settlement, rights, registry commitments, bonds, and disputes.

## Non-Negotiables

1. ioi.ai must stay thin enough that users can remain local-first and sovereign.
2. Restore must require wallet.network authority verification and Agentgres restore receipts.
3. ioi.ai stores archive refs, private-state refs, and coordination metadata,
   not raw sealed-state bytes or private user/app plaintext by default.
4. ioi.ai does not replace aiagent.xyz, sas.xyz, wallet.network, Agentgres, storage backends, or Hypervisor Daemon runtime nodes.
5. Remote compute entitlement must resolve to explicit runtime assignments, not ambient execution authority.
6. Private Workspace/cTEE node status in ioi.ai is coordination metadata, not
   proof that the control plane owns private execution or keys.
7. Provider/environment status in ioi.ai is coordination metadata, not proof
   that ioi.ai owns execution, authority, cTEE custody, Agentgres truth, or
   payload bytes.

## One-Line Doctrine

> **ioi.ai coordinates access to a user's IOI world; it does not become that world.**
