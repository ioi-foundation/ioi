# Hypervisor Fleet

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Fleet as the autonomous infrastructure manager and multi-surface fleet substrate.
Supersedes: product prose that treats Fleet as a standalone app, a daemon runtime, an authority plane, or a vCenter clone before autonomous-infra ownership is defined.
Superseded by: none.
Last alignment pass: 2026-06-06.

## Canonical Definition

**Hypervisor Fleet is the control substrate for autonomous infrastructure across
DePIN, cloud, local, edge, customer, and bare-metal nodes.**

It manages runtime inventory, provider integrations, placement, health, cost,
storage posture, cTEE posture, receipts, replay projections, policy visibility,
node lifecycle, and infrastructure-manager workflows for autonomous work.

It does not execute work, authorize power, admit operational truth, or own
payload bytes.

Core doctrine:

```text
Fleet coordinates and governs.
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres records admitted truth.
Storage backends hold bytes.
IOI L1 settles only triggered public/economic/cross-domain commitments.
```

Short form:

> **Hypervisor Fleet is the autonomous infrastructure manager. It appears inside
> Hypervisor IDE and console.ioi.ai, but its authority comes from
> wallet.network, its truth comes from Agentgres, and execution remains
> daemon-owned.**

## Why Fleet Exists

Traditional infrastructure managers were built around machines:

```text
VMs
clusters
storage
networks
snapshots
permissions
monitoring
```

Hypervisor Fleet is built around autonomous work running across infrastructure:

```text
Hypervisor runtime nodes
DePIN compute
cloud GPU endpoints
Akash and similar compute markets
Filecoin/CAS/S3/local storage posture
cTEE private workspaces
Agentgres domains
model mounts
workers and service packages
provider cost, health, trust, and placement
receipts, approvals, and replay projections
```

The starting wedge is not "clone vCenter." The starting wedge is replacing the
missing infrastructure manager for autonomous and DePIN-native workloads, then
expanding toward traditional VMware, Proxmox, KubeVirt, Nutanix, Kubernetes,
and bare-metal estate management where useful.

## Surfaces

Fleet is a substrate abstraction with multiple surfaces, not another mental app
that users must manage separately.

```text
Hypervisor IDE Fleet Surface
  hands-on operator cockpit for personal and persistent workspaces

console.ioi.ai Fleet Surface
  web/org/admin control plane for accounts, devices, entitlements,
  remote access, billing, node registry, provider integrations,
  and team fleet posture
```

Hypervisor IDE may host Fleet as one application/lens among substrate-backed
applications:

```text
Workspaces
Fleet
Foundry
Agents
Services
Models
cTEE / Privacy
Receipts / Audit
Connectors
```

Foundry, Fleet, and future verticals are application lenses over the same
daemon, Agentgres, wallet.network, cTEE, AIIP, and provider substrate. They do
not create separate runtime truth.

## Owns

Fleet may own or coordinate:

- node registry and node inventory;
- site, provider, region, cluster, and runtime profile inventory;
- DePIN compute endpoint metadata;
- cloud GPU and VM endpoint metadata;
- storage-backend posture for local disk, S3/object stores, Filecoin, CAS/IPFS,
  provider blob stores, and customer VPC blob stores;
- runtime assignment visibility and placement recommendations;
- cost, quota, lease, entitlement, and utilization projections;
- node health, heartbeat, version, upgrade, and maintenance windows;
- cTEE posture, Private Workspace status, custody-profile visibility, and
  declassification posture projections;
- model-mount inventory and route posture;
- worker/service deployment visibility;
- receipts, trace summaries, replay availability, and policy-violation
  projections;
- backup, archive, snapshot, and restore workflow visibility;
- migration-cockpit planning for VMware, Proxmox, KubeVirt, Kubernetes,
  Nutanix, HypervisorOS, cloud, and DePIN targets;
- Fleet policy visibility and proposal surfaces;
- org/team/admin fleet views through console.ioi.ai;
- personal/operator workspace fleet views through Hypervisor IDE.

## Does Not Own

Fleet must not become:

- the execution runtime;
- a second daemon beside the Hypervisor Daemon;
- a wallet or authority plane;
- a raw secret vault;
- a plaintext workspace or app-state store;
- the canonical Agentgres database;
- the owner of Agentgres operation admission;
- the owner of cTEE no-plaintext-custody semantics;
- a store for large trace bundles or artifact payload bytes;
- the owner of model weights or model-provider custody guarantees;
- the marketplace truth source for aiagent.xyz or sas.xyz;
- the settlement layer for IOI L1-triggered commitments;
- a UI-only canvas without runtime, authority, receipt, and state projections.

Those roles belong to Hypervisor Daemon, wallet.network, Agentgres, cTEE,
storage backends, aiagent.xyz, sas.xyz, runtime nodes, and IOI L1.

## Lifecycle

```text
provider account or local node is registered
  -> wallet.network authority binds access or admin scopes
  -> Fleet records node/provider/runtime metadata and policy refs
  -> Hypervisor Daemon heartbeat or provider connector updates status
  -> Agentgres projections expose state roots, receipts, archive refs, and run status
  -> Fleet recommends or displays placement, cost, health, cTEE posture, and replay state
  -> operator approves node/workspace/run changes through Hypervisor IDE or console.ioi.ai
  -> Hypervisor Daemon executes the authorized work
  -> Agentgres records admitted operations and receipt refs
  -> storage backends hold payload bytes
  -> Fleet updates observability and control projections
```

## Minimal Implementation Objects

```yaml
FleetNode:
  node_id: node://...
  owner_ref: wallet://... | org://...
  node_kind:
    local | cloud_vm | cloud_gpu | depin_compute | akash |
    customer_vpc | kubernetes | kubevirt | proxmox | vmware |
    nutanix | hypervisoros | tee | bare_metal
  daemon_ref: daemon://... | null
  agentgres_domain_ref: agentgres://domain/... | null
  runtime_profile_ref: runtime_profile://...
  authority_refs:
    - grant://...
  status:
    unknown | registered | healthy | degraded | draining |
    offline | archived | needs_restore | policy_blocked
  ctee_posture:
    private_workspace_supported: true | false
    plaintext_custody_allowed: true | false
    custody_profile_ref: artifact://... | null
  provider:
    provider_ref: provider://...
    region: string | null
    cost_profile_ref: cost://... | null
  storage_posture_refs:
    - storage_posture://...
  receipt_refs:
    - receipt://...
  projection_watermark: domain_seq:... | null
```

```yaml
FleetRuntimeAssignmentView:
  assignment_id: runtime_assignment://...
  node_id: node://...
  run_ref: run:...
  workspace_ref: workspace://... | null
  worker_or_service_ref: worker://... | service://... | null
  placement_reason:
    - cost
    - latency
    - data_locality
    - ctee_posture
    - model_availability
    - authority
    - policy
  authority_refs:
    - grant://...
  agentgres_operation_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  status:
    proposed | approved | running | blocked | completed |
    archived | restored | failed
```

```yaml
FleetStoragePosture:
  storage_posture_id: storage_posture://...
  storage_plane:
    local_disk | s3 | filecoin | cas | ipfs |
    provider_blob | customer_vpc_blob | object_store
  artifact_refs:
    - artifact://...
  payload_availability:
    available | degraded | missing | verifying
  retention_policy_ref: policy://...
  replication_policy_ref: policy://...
  privacy_class:
    public | internal | confidential | secret
  authority_refs:
    - grant://...
```

## Admission / Settlement Boundary

Fleet proposes, coordinates, displays, and routes operator intent. It does not
admit truth.

```text
Fleet action proposal
  -> wallet.network authority check
  -> Hypervisor Daemon execution or provider connector action
  -> Agentgres operation / receipt / artifact-ref admission
  -> Fleet projection update
```

Fleet-managed infrastructure events may trigger IOI L1 only when public,
economic, rights, registry, dispute, reputation, marketplace, or cross-domain
commitments require it. Ordinary node health, placement, restore, and workspace
operations remain domain-local through Agentgres and receipts.

## Trace And Replay Flow

Traces bubble up through Fleet as observability, not truth ownership.

```text
Hypervisor Daemon emits trace/receipt events
  -> Agentgres records refs, receipts, state roots, projection watermarks
  -> storage backends hold large trace/log payloads
  -> Fleet indexes fleet-level observability
  -> Hypervisor IDE opens workspace/run-level replay
```

Fleet may render:

- node health;
- active runs;
- agent/workspace status;
- receipt timelines;
- trace summaries;
- replay availability;
- cost, latency, errors, and provider incidents;
- cTEE posture;
- policy violations;
- storage availability and restore posture.

Fleet must not be the canonical trace store. Trace payload bytes belong in
storage backends behind Agentgres refs; trace reconstructability is grounded in
Agentgres operations, receipt refs, artifact refs, and projection watermarks.

## Conformance Checks

- Fleet cannot execute a workload without routing through a Hypervisor Daemon
  or declared provider connector boundary.
- Fleet cannot issue authority grants; authority must come from wallet.network.
- Fleet cannot append accepted Agentgres operations directly unless acting
  through the admitted domain API under policy and authority.
- Fleet cannot treat Filecoin/CAS/S3/local disk availability as artifact truth.
- Fleet cannot treat cTEE status as proof that private execution is safe unless
  the daemon/cTEE custody receipts support the claim.
- Fleet cannot route private workspace plaintext to provider-rooted nodes
  unless policy explicitly allows plaintext custody.
- Fleet cannot make IOI L1 the default settlement path for ordinary runtime
  operations.
- Fleet observability must link back to receipts, Agentgres refs, artifact refs,
  or trace refs.

## Anti-Patterns

Reject these:

1. Fleet as a separate execution runtime beside Hypervisor Daemon.
2. Fleet as a wallet or secret vault.
3. Fleet as a central plaintext workspace database.
4. Fleet as a UI-only dashboard disconnected from authority, receipts, and
   Agentgres projections.
5. Fleet as a vCenter clone before autonomous-infra controls are first-class.
6. Fleet as a replacement for Agentgres truth, cTEE custody, or wallet.network
   authority.
7. Fleet logs as canonical proof without receipt and artifact-ref linkage.
8. Fleet storage status as proof that payload meaning or restore validity is
   accepted.
9. One GUI app per vertical when a Hypervisor IDE application lens over the
   same substrate is sufficient.

## Related Canon

- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../daemon-runtime/private-workspace-ctee.md`](../daemon-runtime/private-workspace-ctee.md)
- [`../daemon-runtime/runtime-nodes-tee-depin.md`](../daemon-runtime/runtime-nodes-tee-depin.md)
- [`../daemon-runtime/hypervisoros.md`](../daemon-runtime/hypervisoros.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
- [`../storage-backends/doctrine.md`](../storage-backends/doctrine.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../../domains/ioi-ai/control-plane.md`](../../domains/ioi-ai/control-plane.md)
