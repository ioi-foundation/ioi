# Hypervisor Providers And Environments

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor-managed providers, environments,
cross-session infrastructure posture, zero-to-idle, archive/restore posture,
and provider integration doctrine.
Supersedes: prior live canon that split provider and environment posture into a
separate application surface.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Canonical Definition

**Hypervisor manages sessions, environments, and provider resources directly.**

Provider and environment capabilities are part of the default Hypervisor UX and
daemon/Core contracts. They are not a separate product, application surface, or
truth layer.

Core doctrine:

```text
Sessions are the unit.
Environments are managed resources behind sessions.
Providers are cross-session resources.
Hypervisor coordinates environment and provider posture.
Hypervisor Daemon executes lifecycle operations.
wallet.network authorizes spend, access, secrets, SCM auth, and declassification.
Agentgres records admitted truth, receipts, state roots, archive refs, and
restore validity.
Storage backends hold payload bytes.
IOI L1 settles only triggered public/economic/cross-domain commitments.
```

The product shape:

```text
Hypervisor App / Hypervisor Web / CLI-headless
  -> Home
  -> Sessions
  -> Projects
  -> Providers
  -> Environments
  -> Workbench
  -> Agents
  -> Models
  -> Privacy
  -> Foundry
  -> Authority
  -> Receipts
```

Provider and infrastructure posture should appear inside the default
Hypervisor shell, session detail views, project settings, provider settings,
and org/admin web views. It should not require users to enter a separate
provider-management product.

## Owns

Hypervisor owns the product/control view for:

```text
cross-session environment inventory
provider integrations
provider accounts and connector posture
local/cloud/DePIN/customer/bare-metal resource posture
environment classes
environment lifecycle
session access leases
services, tasks, ports, logs, and support posture
SCM auth requirements
cost, health, utilization, and placement views
zero-to-idle and restore posture
archive/restore refs as projections over Agentgres truth
```

The Hypervisor Daemon owns lifecycle execution semantics for create, start,
stop, mark-active, archive, unarchive, restore, delete, service/task execution,
port sharing, log access, and environment operations.

## Does Not Own

Hypervisor provider/environment views do not own:

```text
wallet.network authority
secrets or durable credentials
Agentgres operation admission
restore validity
artifact meaning
storage payload bytes
provider infrastructure
IOI L1 settlement
private workspace plaintext on provider-rooted nodes
```

Provider state is evidence. Agentgres state is truth.

Encrypted archive blobs are restore material. They are not restore truth by
themselves. A blob can be necessary restore material without being sufficient
restore authority.

## Direct Provider Integrations

Hypervisor integrates directly with providers that run or store autonomous
work.

Direct provider classes include:

```text
local machines and homelabs
user-owned or org-owned AWS / Google Cloud / Azure accounts
enterprise Kubernetes / KubeVirt / VMware / Proxmox / Nutanix / bare metal
hyperscaler confidential-compute services
cloud GPU providers
DePIN compute markets
decentralized storage networks
provider-specific GPU or storage markets
user-specified provider routes
```

Provider integrations should preserve provider-specific semantics instead of
flattening everything into a fake generic cloud.

Examples:

```text
Akash
  direct DePIN compute/GPU provider integration with deployment, provider bid,
  lease, GPU attribute, persistent volume, IP lease, log/event, shell/exec,
  stop/close, and redeploy semantics

Filecoin
  storage-backend integration for content-addressed encrypted archives,
  payloads, evidence bundles, retrieval, replication, renewal, and repair
  posture
```

Akash can run compute, GPUs, model servers, public trunks, and cTEE split-path
workloads when policy allows. Filecoin can hold encrypted payload/archive bytes
and retrieval commitments. Neither owns Hypervisor execution, wallet authority,
Agentgres artifact meaning, private plaintext, or restore validity.

`decentralized.cloud` is parked future product space. It is not present canon,
not a required cloud gateway, and not the provider abstraction for Hypervisor.

## Environment Ops

Canonical environment ops objects:

```text
HypervisorEnvironmentClass
HypervisorEnvironmentOpsProfile
HypervisorEnvironmentLifecycleState
HypervisorEnvironmentActivitySignal
HypervisorSessionAccessLease
HypervisorEnvironmentService
HypervisorEnvironmentTask
HypervisorEnvironmentPort
HypervisorScmAuthRequirement
```

Hypervisor may initiate or display:

```text
create / create_from_project / create_from_context_url
start / stop / mark_active
service start / stop
task start / stop
port share / revoke
SCM auth satisfaction flow
archive / unarchive / restore / delete
activity and idle posture
access/log/support leases
```

Ownership boundary:

```text
Hypervisor displays and coordinates posture.
Hypervisor Daemon executes lifecycle operations.
wallet.network authorizes spend, secrets, SCM auth, access, support, and
declassification.
Agentgres records lifecycle receipts, archive refs, restore refs, state roots,
activity signals, and provider evidence.
Storage backends hold encrypted payload/archive bytes.
Providers expose native state as evidence, not canonical restore truth.
```

## Session UX Doctrine

Provider and infrastructure posture should be visible through sessions.

Session detail surfaces should include environment/provider panels such as:

```text
Environment
Provider
Services
Tasks
Ports
Logs
Cost
Archive / Restore
cTEE posture
Access leases
SCM auth
```

Cross-session views are still useful, but they should be framed as Hypervisor
views:

```text
Providers
Environments
Nodes
Storage
Costs
Health
Restore
```

Avoid making users learn a separate provider-management product.

## Lifecycle

```text
operator opens Hypervisor
  -> selects or creates a session
  -> Hypervisor resolves environment class and provider candidates
  -> wallet.network authorizes spend, access, SCM auth, or secret release
  -> Hypervisor Daemon creates/starts/attaches the environment
  -> services, tasks, ports, logs, and adapters bind to the session
  -> Agentgres records receipts, state roots, archive refs, and restore refs
  -> storage backends persist encrypted payload/archive bytes
  -> session becomes active, idle, archived, restore_available, or deleted
```

## Conformance Checks

- No live canon may split provider/environment posture into a separate app,
  surface, runtime, or truth layer.
- Provider and infrastructure posture belongs to Hypervisor sessions,
  environment views, provider views, and daemon APIs.
- Provider state must be evidence, not Agentgres truth.
- Encrypted blobs may be restore material, but restore validity must be
  operation-backed through Agentgres.
- Access, logs, support, ports, SCM auth, archive, restore, service, and task
  actions must be policy-bound and receipted when they affect authority,
  privacy, replay, cost, or restore.
- Cheap DePIN compute must not be described as private unless cTEE, TEE,
  local-only, or customer-controlled posture supports that claim.

## Anti-Patterns

Avoid:

```text
provider posture = separate app
provider posture = application surface
provider posture = runtime truth
provider posture = provider authority
provider posture = Agentgres replacement
provider posture = storage truth
cloud provider catalog = compute provider
future decentralized.cloud = mandatory gateway
provider lifecycle state = restore truth
encrypted blob = restore truth
cheap DePIN GPU route = private route
```

Correct:

```text
Hypervisor manages sessions, environments, and providers.
Sessions are the unit.
Providers are cross-session resources.
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres records truth.
Storage backends hold bytes.
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`../daemon-runtime/api.md`](../daemon-runtime/api.md)
- [`../daemon-runtime/private-workspace-ctee.md`](../daemon-runtime/private-workspace-ctee.md)
- [`../daemon-runtime/runtime-nodes-tee-depin.md`](../daemon-runtime/runtime-nodes-tee-depin.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
- [`../storage-backends/doctrine.md`](../storage-backends/doctrine.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
