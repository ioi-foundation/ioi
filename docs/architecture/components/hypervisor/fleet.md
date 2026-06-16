# Hypervisor Fleet

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Fleet as the general infrastructure
manager and multi-surface fleet substrate whose first-class workload is
autonomous systems.
Supersedes: product prose that treats Fleet as a standalone app, a daemon
runtime, an authority plane, an agent-only dashboard, or a vCenter clone without
autonomous-infra ownership.
Superseded by: none.
Last alignment pass: 2026-06-07.

## Canonical Definition

**Hypervisor Fleet is the general infrastructure and runtime-fleet manager for
machines, workloads, private workspaces, and autonomous systems across DePIN,
cloud, local, edge, customer, and bare-metal nodes.**

It manages runtime inventory, VM/container/microVM/WASM workload posture,
images, volumes, networks, snapshots, provider integrations, placement, health,
cost, storage posture, cTEE posture, receipts, replay projections, policy
visibility, node lifecycle, cloud-route intelligence, and
infrastructure-manager workflows.

It does not execute work, authorize power, admit operational truth, or own
payload bytes.

Core doctrine:

```text
Fleet manages infrastructure and autonomous runtime posture.
Fleet coordinates and governs.
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres records admitted truth.
Storage backends hold bytes.
IOI L1 settles only triggered public/economic/cross-domain commitments.
```

Short form:

> **Hypervisor Fleet is a general infrastructure manager whose first-class
> workload is autonomous systems. It appears as an application surface inside
> Hypervisor App, Hypervisor Web, CLI/headless projections, and console.ioi.ai, but
> its authority comes from wallet.network, its truth comes from Agentgres, and
> execution remains daemon-owned.**

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

Hypervisor Fleet intentionally enters that infrastructure-manager category, but
with autonomous systems as the native workload rather than an afterthought.

```text
Traditional hypervisors virtualize machines.
Hypervisor virtualizes machines, workloads, private workspaces,
and autonomous authority.
```

Hypervisor Fleet is built around both classical infrastructure and autonomous
work running across it:

```text
VMs, containers, microVMs, WASM workloads
images, volumes, networks, snapshots, backups, restore
node pools, GPU pools, leases, quotas, migration, health, logs, cost
Hypervisor runtime nodes
DePIN compute
cloud GPU endpoints
Akash and similar compute markets
Filecoin/CAS/S3/local storage posture
CloudRoute candidates
cTEE private workspaces
Agentgres domains
model mounts
workers and service packages
provider cost, health, trust, and placement
receipts, approvals, and replay projections
```

The starting wedge is persistent private autonomous work across local, cloud,
and DePIN infrastructure. The target category is broader: VMware, Proxmox,
KubeVirt, Nutanix, Kubernetes, and bare-metal estate management rebuilt around
private workspaces, model mounts, authority scopes, receipts, replay, cTEE
posture, and service outcomes.

Fleet should therefore avoid two opposite mistakes:

```text
too narrow: "agent dashboard"
too shallow: "vCenter clone"
```

The canonical position is:

> **Hypervisor Fleet is infrastructure management rebuilt for autonomous
> systems, while remaining a serious infrastructure manager.**

## Classical Infrastructure Scope

Fleet may manage or project classical infrastructure primitives when they are
needed for Hypervisor estates:

```text
VMs
containers
microVMs
WASM workloads
images
volumes
networks
firewall / egress policies
snapshots
backups
restore points
node pools
GPU pools
provider connectors
quotas
leases
health checks
logs and metrics
cost and utilization
migration plans
maintenance windows
RBAC / authority mappings
```

These primitives are not separate from autonomous-system management. They are
the substrate persistent agents, workers, services, model servers, private
workspaces, and HypervisorOS nodes require.

## Direct Provider Integrations

Hypervisor integrates directly with the providers that run and store autonomous
work.

Fleet may route workloads through:

- local machines and homelabs;
- user-owned or org-owned AWS, Google Cloud, Azure, and other cloud accounts;
- enterprise Kubernetes, KubeVirt, VMware, Proxmox, Nutanix, or bare-metal
  estates;
- hyperscaler confidential-compute services;
- cloud GPU providers;
- DePIN compute markets;
- decentralized storage networks;
- provider-specific GPU or storage markets;
- user-specified provider routes.

`decentralized.cloud` is parked future product space, not present Fleet canon.
It may later become a public provider catalog, P2P/PQ-aware cloud routing layer,
compute/storage receipt explorer, provider reputation surface, or infrastructure
marketplace, but current Hypervisor/Fleet architecture must not depend on it.

It does not own:

- Hypervisor execution;
- Fleet truth;
- provider infrastructure;
- user or org authority;
- secrets;
- private workspace plaintext;
- Agentgres operation admission;
- storage payload meaning;
- declassification decisions;
- IOI L1 settlement.

Correct product framing:

```text
Hypervisor has direct provider integrations for compute, storage, GPUs,
confidential compute, DePIN, local machines, and customer infrastructure.
Hypervisor Fleet compares and displays infrastructure posture.
wallet.network authorizes spend, provider access, secret release, and policy.
Hypervisor Daemon or provider connector deploys and runs.
Providers supply resources.
Agentgres records receipts and state refs.
```

Incorrect product framing:

```text
cloud provider catalog = compute provider.
provider catalog or cloud router = Hypervisor execution owner.
future decentralized.cloud = mandatory gateway for cloud or DePIN.
cheap DePIN GPU route = private route.
```

## Surfaces

Fleet is an application surface over Hypervisor Core with multiple client
presentations, not another mental app that users must manage separately.

```text
Hypervisor App Fleet Surface
  hands-on operator cockpit for personal and persistent workspaces

Hypervisor Web Fleet Surface
  browser/team/remote cockpit for remote workspaces, provider integrations,
  team posture, and restore/entitlement flows

CLI/headless Fleet Projection
  terminal/headless operator surface for node ops, placement, logs, receipts,
  health, and scripted infrastructure workflows; a TUI may present this
  interactively but does not create separate runtime truth

console.ioi.ai Fleet Surface
  web/org/admin control plane for accounts, devices, entitlements,
  remote access, billing, node registry, provider integrations,
  and team fleet posture
```

Hypervisor App and Hypervisor Web may host Fleet as one application surface
among Core-backed surfaces:

```text
Workbench
Fleet
Foundry
Agents
Services
Models
cTEE / Privacy
Receipts / Audit
Connectors
```

Workbench, Foundry, Fleet, and future verticals are application surfaces over
the same Hypervisor Core, Hypervisor Daemon, Agentgres, wallet.network, cTEE,
AIIP, and provider substrate. They do not create separate runtime truth.

## Owns

Fleet may own or coordinate:

- node registry and node inventory;
- site, provider, region, cluster, and runtime profile inventory;
- VM, container, microVM, WASM, image, volume, network, snapshot, backup,
  restore, migration, quota, lease, and node-pool visibility;
- GPU pool, model-server placement, and accelerator utilization visibility;
- DePIN compute endpoint metadata;
- cloud GPU and VM endpoint metadata;
- CloudRoute candidate metadata;
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
- personal/operator workspace fleet views through Hypervisor App and
  Hypervisor Web;
- terminal/headless fleet views through CLI/headless projections.

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
  -> operator approves node/workspace/run changes through Hypervisor App, Hypervisor Web, CLI/headless, or console.ioi.ai
  -> Hypervisor Daemon executes the authorized work
  -> Agentgres records admitted operations and receipt refs
  -> storage backends hold payload bytes
  -> Fleet updates observability and control projections
```

Provider selection lifecycle:

```text
agent, workflow, service, or operator requests infrastructure
  -> Hypervisor creates workload/resource intent
  -> direct provider connectors, local inventory, customer cloud connectors,
     DePIN markets, storage networks, or user-specified routes return
     CloudRoute candidates
  -> Fleet compares price, latency, hardware, GPU class, storage locality,
     privacy posture, cTEE posture, attestation, jurisdiction, reliability,
     provider reputation, and budget
  -> wallet.network authorizes spend, admin scopes, provider account use,
     secret release, or declassification policy where needed
  -> Hypervisor Daemon or approved provider connector deploys/runs workload
  -> Agentgres records execution receipts, state refs, artifact refs, and
     restore/replay metadata
  -> Fleet updates placement, cost, risk, receipt, and replay projections
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

```yaml
CloudRoute:
  route_id: cloud_route://...
  workload_id: workload://...
  requester:
    user://... | org://... | agent://... | hypervisor://...
  purpose: string
  resource_requirements:
    cpu: optional
    memory: optional
    gpu:
      class: H100 | A100 | RTX_4090 | RTX_3090 | other | null
      vram_gb: number | null
    storage: optional
    bandwidth: optional
  privacy_requirements:
    posture:
      public_compute | provider_trust | ctee_split_path |
      confidential_compute | customer_cloud | local_only
    plaintext_custody_allowed: true | false
    attestation_required: true | false
  storage_requirements:
    persistence: ephemeral | persistent | archive
    encrypted_payloads_required: true | false
    allowed_backends:
      - local_disk
      - s3
      - filecoin
      - cas
      - provider_blob
      - customer_vpc_blob
  budget:
    max_cost: optional
    max_duration: optional
  jurisdiction:
    - region_policy://...
  candidates:
    - cloud_candidate://...
  selected_candidate: cloud_candidate://... | null
  provider_trust_model:
    local | customer_controlled | confidential_compute |
    provider_trust | ctee_split | unsafe
  attestation_requirements: attestation_policy://... | null
  secret_release_policy: policy://...
  wallet_policy_hash: sha256:...
  authority_refs:
    - grant://...
  expected_cost: cost://... | null
  risk_labels:
    - CloudRiskLabel
  receipt_refs:
    - receipt://...
  status:
    proposed | approved | denied | running | completed |
    failed | cancelled | archived
```

```yaml
CloudCandidate:
  candidate_id: cloud_candidate://...
  source:
    provider_connector | hyperscaler | cloud_gpu_provider |
    user_specified | local_inventory | customer_cloud |
    depin_compute_market |
    decentralized_storage_network | enterprise_cluster
  provider_ref: provider://...
  resource_type:
    gpu | cpu | storage | enclave | vm | container |
    kubernetes | bare_metal | hypervisoros
  hardware: string | null
  region: string | null
  price_estimate: cost://...
  availability:
    available | scarce | delayed | unknown
  privacy_posture:
    public_compute | provider_trust | ctee_split_path |
    confidential_compute | customer_cloud | local_only | unsafe
  attestation:
    available: true | false
    descriptor_ref: attestation://... | null
  storage_persistence:
    ephemeral | persistent | archive | unknown
  network_profile: network_profile://...
  reputation_score: number | null
  risk_labels:
    - Provider-Trust Route
    - Confidential Compute
    - Attestation Available
    - Attestation Missing
    - TEE-Limited
    - GPU Plaintext Risk
    - cTEE Split Path
    - Local-Only
    - Customer Cloud
    - Decentralized Provider
    - Storage Retrieval Risk
    - Region Risk
    - Cost Spike Risk
    - No Persistent Storage
    - Encrypted Archive Required
```

```yaml
FleetWorkloadPrimitive:
  primitive_id: workload_primitive://...
  primitive_type:
    vm | container | microvm | wasm | image | volume |
    network | snapshot | backup | restore_point |
    gpu_pool | node_pool | migration_plan | provider_connector
  provider_ref: provider://... | null
  node_refs:
    - node://...
  authority_refs:
    - grant://...
  agentgres_operation_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  status:
    proposed | active | degraded | migrating | archived | failed
  autonomous_runtime_refs:
    - daemon://...
    - workspace://...
    - run:...
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
  -> Hypervisor App, Hypervisor Web, or CLI/headless opens workspace/run-level replay
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
- Fleet cannot treat VM/container/microVM/WASM lifecycle actions as exempt from
  authority, receipts, and Agentgres admission merely because they are
  "infrastructure."
- Fleet cannot issue authority grants; authority must come from wallet.network.
- Fleet cannot append accepted Agentgres operations directly unless acting
  through the admitted domain API under policy and authority.
- Fleet cannot treat Filecoin/CAS/S3/local disk availability as artifact truth.
- Fleet cannot treat cTEE status as proof that private execution is safe unless
  the daemon/cTEE custody receipts support the claim.
- Fleet cannot route private workspace plaintext to provider-rooted nodes
  unless policy explicitly allows plaintext custody.
- Fleet cannot treat a CloudRoute candidate as authority, proof of
  provider privacy, or permission to spend funds or release secrets.
- Fleet cannot compare provider candidates on price alone when privacy posture,
  attestation, jurisdiction, persistence, storage locality, or cTEE posture
  materially affects the workload.
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
5. Fleet as only an agent dashboard with no serious infrastructure primitives.
6. Fleet as only a vCenter clone with no autonomous-system, cTEE, receipt,
   authority, or service-outcome semantics.
7. Splitting VM/fleet management and agent/workspace management into separate
   substrates that cannot share daemon, wallet.network, Agentgres, and receipt
   contracts.
8. Claiming VMware, Proxmox, or Nutanix parity before the core infrastructure
   primitives exist.
9. Fleet as a replacement for Agentgres truth, cTEE custody, or wallet.network
   authority.
10. Fleet logs as canonical proof without receipt and artifact-ref linkage.
11. Fleet storage status as proof that payload meaning or restore validity is
    accepted.
12. One GUI app per vertical when a Hypervisor application surface over the
    same Core is sufficient.
13. Promoting parked future `decentralized.cloud` into a mandatory cloud
    gateway.
14. Treating cheap DePIN GPU availability as a privacy guarantee.
15. Treating confidential compute as magic without attestation, key-release,
    workload-design, cTEE, side-channel, and provider assumptions.

## Related Canon

- [`../../domains/decentralized/cloud-parked-future.md`](../../domains/decentralized/cloud-parked-future.md)
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../daemon-runtime/private-workspace-ctee.md`](../daemon-runtime/private-workspace-ctee.md)
- [`../daemon-runtime/runtime-nodes-tee-depin.md`](../daemon-runtime/runtime-nodes-tee-depin.md)
- [`../daemon-runtime/hypervisoros.md`](../daemon-runtime/hypervisoros.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
- [`../storage-backends/doctrine.md`](../storage-backends/doctrine.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../../domains/ioi-ai/control-plane.md`](../../domains/ioi-ai/control-plane.md)
