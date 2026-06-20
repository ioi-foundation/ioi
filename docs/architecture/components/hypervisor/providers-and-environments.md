# Hypervisor Providers And Environments

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor-managed providers, environments,
cross-session infrastructure posture, zero-to-idle, archive/restore posture,
and provider integration doctrine.
Supersedes: prior live canon that split provider and environment posture into a
separate application surface.
Superseded by: none.
Last alignment pass: 2026-06-19.

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
target-vs-observed environment and workload state
change plans, release channels, maintenance windows, suppression windows,
adjudication, recall, and remediation posture
supply-chain, SBOM, vulnerability, and deployed-where evidence as
Agentgres-backed refs
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

## Environment Ops

Canonical environment ops objects:

```text
HypervisorEnvironmentClass
HypervisorEnvironmentOpsProfile
HypervisorEnvironmentLifecycleState
HypervisorEnvironmentStatus
HypervisorEnvironmentComponentStatus
HypervisorWorkspaceInitializer
HypervisorEnvironmentActivitySignal
HypervisorSessionAccessLease
HypervisorEnvironmentService
HypervisorEnvironmentTask
HypervisorEnvironmentPort
HypervisorScmAuthRequirement
HypervisorTargetState
HypervisorObservedState
HypervisorEnvironmentInstallation
DeployedWhereIndex
HypervisorChangePlan
ChangePlanGate
ReleaseChannel
MaintenanceWindow
SuppressionWindow
CanaryRun
AdjudicationReceipt
RecallPolicy
RecallReceipt
RemediationPlan
SupplyChainManifestRef
SBOMRef
VulnerabilityFinding
PatchSlaPolicy
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

## Environment Status Object

The environment lifecycle projects through a structured status object with
component sub-phases, so sessions render real provisioning instead of a flat step
list or a timed animation. The object follows established remote-development
environment status conventions and is fully IOI-native: the truth is Agentgres,
the authority is wallet.network, and the state bytes are encrypted-blob storage.
Provider/container/PTY/file-watcher output remains evidence, not truth.

```text
HypervisorEnvironmentStatus
  schema_version: ioi.hypervisor.environment_status.v1
  environment_ref
  provider_placement_ref
  phase: creating | starting | running | updating | stopping | stopped |
         archived | failed
  components:
    provisioner       { phase, evidence_ref, detail }            # node/VM/host lane
    workspace_content { phase, initializer_ref, custody_posture, evidence_ref }
    sandbox           { phase, container_ref, evidence_ref }     # devcontainer/microVM/host lane
    secrets           { phase, capability_lease_refs, evidence_ref }
    automations       { phase, evidence_ref }
    model_mount       { phase, model_route_ref, evidence_ref }   # IOI-native
    harness           { phase, harness_session_ref, evidence_ref } # IOI-native
  ports: [ HypervisorEnvironmentPort ]
  failure_message? / warning_message?
  state_root_ref
  workspace_artifact_ref
  runtimeTruthSource: daemon-runtime
```

Each component carries one phase from a shared taxonomy:

```text
pending | creating | initializing | ready | degraded | failed
```

The workspace is hydrated by a typed initializer (a context URL or a git spec),
carrying its custody posture and authority scopes rather than an owner token:

```text
HypervisorWorkspaceInitializer
  schema_version
  specs: [ { context_url } | { git { remote_uri, clone_target, target_mode } } ]
  custody_posture: public_trunk | redacted_projection | ctee_private_workspace
  authority_scope_refs
```

Ports are structured and wallet-gated, not owner-token shared:

```text
HypervisorEnvironmentPort
  port, protocol
  access_policy: private | session_lease | shared
  capability_lease_ref
  url
  exposure_state: closed | lease_required | open
```

The status object streams to clients as session events, not a one-shot poll:

```text
GET /v1/hypervisor/sessions/:session_id/events  (text/event-stream)
  event: environment_status   # full or delta HypervisorEnvironmentStatus
  event: terminal_chunk
  event: workspace_change
  event: receipt_projection
  event: readiness
```

Shape mapping (conventional remote-environment status shapes map into IOI-native
objects; truth, authority, and state are IOI-native):

```text
Conventional remote-environment shape     ->  IOI-native
top-level environment phase               ->  HypervisorEnvironmentStatus.phase
per-component sub-status                   ->  components.{provisioner,workspace_content,
  (machine/content/devcontainer/               sandbox,secrets,automations} + model_mount + harness
   secrets/automations)
component phase enum                       ->  shared component phase taxonomy
workspace initializer (context url / git)  ->  HypervisorWorkspaceInitializer + custody_posture
port admission + owner token               ->  HypervisorEnvironmentPort + access_policy + wallet lease
runner / executor phase                    ->  provider_placement readiness
environment status stream                  ->  session events SSE environment_status event
control-plane DB (authoritative state)     ->  Agentgres admitted truth (projection) +
                                               encrypted-blob workspace state
owner-token authority                      ->  wallet.network capability leases / approvals
```

The status object is a projection of Agentgres-admitted truth: component phases,
ports, and initializer state are not authoritative until the daemon records the
operation, state root, authority context, and receipt that produced them.

## Change Plane

Hypervisor should manage infrastructure and autonomous-work changes as explicit
plans, not as invisible provider control loops.

The canonical change-plane flow is:

```text
policy, release channel, and desired posture
  -> HypervisorTargetState
  -> HypervisorObservedState from daemon/provider/scanner evidence
  -> HypervisorChangePlan with gates and constraints
  -> wallet, maintenance-window, suppression-window, privacy, and spend checks
  -> staged daemon/provider execution
  -> canary, adjudication, recall, or remediation receipts
  -> Agentgres-admitted truth and projections
```

This is broader than software deployment. A change plan may cover release
upgrades, configuration changes, connector changes, secret rotation, model-route
changes, provider placement, workspace image changes, dependency/schema
migrations, vulnerability remediation, restore repair, or environment
reconciliation.

### Target And Observed State

`HypervisorTargetState` is the policy-shaped target for an environment,
session, service, worker, model route, connector, or project. It should prefer
durable intent over brittle exact pins when policy allows:

```text
release channel
allowed version or model-route range
required labels, attestations, or SBOM posture
provider class and placement constraints
cTEE/private workspace posture
budget, latency, region, data-locality, and support constraints
maintenance window and suppression window refs
dependency and migration constraints
```

`HypervisorObservedState` is admitted evidence about what is actually deployed
or running. It may originate from daemon heartbeats, provider connectors,
runtime probes, log streams, vulnerability scanners, package registries,
artifact registries, model registries, or storage-backend checks. Observed state
does not become truth until Agentgres admits the evidence, object refs, state
roots, authority context, and receipts that produced it.

`HypervisorEnvironmentInstallation` binds an installed product, worker, model
route, service, connector, module, image, dataset, or automation to an
environment/session/project with:

```text
installation_ref
environment_ref / session_ref / project_ref
artifact_ref / model_route_ref / worker_package_ref / connector_ref
target_state_ref
observed_state_ref
release_channel_ref?
authority_scope_refs
receipt_refs
```

### Plans, Gates, And Execution

`HypervisorChangePlan` is the visible, inspectable unit of environment change.
It should include:

```text
plan_ref
target_ref and observed_ref
plan_type
steps and rollback_steps
required ChangePlanGate refs
affected sessions, environments, providers, services, model routes, workers,
connectors, secrets, ports, storage refs, and datasets
maintenance_window_ref / suppression_window_ref
authority_scope_refs
expected spend and risk posture
privacy and cTEE posture
state_root_ref and receipt_refs
reason_when_blocked
```

Change plans may be proposed by Automations, Workbench, Foundry, ioi.ai,
provider views, scanner findings, policy engines, or human operators. They are
executed only through Hypervisor Core and the daemon/provider boundary.
wallet.network authorizes spend, secret release, SCM auth, access,
declassification, and emergency overrides. Agentgres records plan lifecycle,
state roots, receipts, rollback outcomes, and replay projections.

`ChangePlanGate` covers constraints that must be satisfied before execution:

```text
wallet approval
maintenance window
suppression window not active
release channel eligibility
recall not active
dependency/schema migration readiness
health, liveness, and readiness checks
SBOM/vulnerability policy
cTEE/private workspace posture
budget, region, data locality, support, and provider-capacity checks
operator required approval or break-glass receipt
```

If no plan can execute, the product should show the blocked reason and the
object or policy that would unblock it. Silent "no work" states are not a
canonical Hypervisor UX.

### Channels, Windows, And Suppression

`ReleaseChannel` groups eligible releases, model routes, worker packages,
connectors, modules, images, or automation versions by policy posture. A
session or environment may track a channel instead of a fixed version when the
operator wants governed continuous improvement.

`MaintenanceWindow` defines when disruptive or risky plans may run.
`SuppressionWindow` blocks additional work after a human hold, failed rollout,
incident signal, privacy concern, provider degradation, or automated failure
threshold. Human suppression must be respected until an authorized actor clears
it. Automated suppression may allow rollback or urgent remediation when policy
permits.

### Canary, Adjudication, Recall, And Remediation

`CanaryRun` is a staged execution slice with explicit cohort, health,
readiness, eval, receipt, and rollback criteria.

`AdjudicationReceipt` records whether a canary, rollout, model-route change,
connector change, or remediation met its acceptance criteria. Promotion,
rollback, or further rollout should depend on admitted adjudication, not raw
provider logs.

`RecallPolicy` and `RecallReceipt` are how Hypervisor blocks or rolls off bad
releases, model routes, workers, connectors, images, datasets, automation
versions, or provider placements. A recall must:

```text
identify the affected range or artifact refs
block further promotion or placement while active
prioritize roll-off, rollback, or patched replacement plans
record issuer, reason, risk posture, and authority refs
emit receipts for affected environments and sessions
```

`RemediationPlan` is a change plan specialized for repairing a risk:
vulnerability, bad release, failed migration, broken connector, compromised
secret, invalid archive material, provider outage, cTEE posture regression, or
deployed-where mismatch.

### Supply Chain And Deployed-Where Evidence

`DeployedWhereIndex` answers what version, image, worker, model route, connector,
dataset, automation, or package is active in which session, environment,
provider, project, tenant, region, or customer-controlled domain.

`SupplyChainManifestRef`, `SBOMRef`, `VulnerabilityFinding`, and
`PatchSlaPolicy` are evidence-backed refs used by change gates and recalls.
Scanner output, registry metadata, and provider inventory are evidence until
Agentgres admits them with source, time, artifact refs, state roots, and
receipt context.

Deployed-where and vulnerability posture should be visible from provider,
environment, project, application, receipt, and automation views because IOI
operates autonomous work across more than one deployment plane.

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

Session lifecycle logs should be projected in human-readable phases similar to
provider environment consoles, but the canonical object names remain
Hypervisor/Agentgres objects:

```text
Booting Hypervisor node
  provider VM, local machine, HypervisorOS node, or customer cluster starts

Preparing provider or local environment
  disk, network, builder/cache, image, volume, GPU, and trace setup

Restoring workspace and archive material
  encrypted payloads, artifact refs, archive refs, repo refs, and cache refs
  hydrate the workspace from storage backends

Reconciling container or dev environment
  devcontainer, container, microVM, WASM workload, package, or host lane is
  created, updated, or reused

Starting access services
  SSH, browser, editor, terminal, port, log, and support access surfaces bind to
  session leases

Mounting model, harness, and privacy posture
  model route, harness selection, cTEE/private workspace posture, and authority
  scopes are bound under daemon gates

Admitting session execution
  recipe admission -> harness binding admission -> launch -> spawn ->
  readiness -> terminal attach, with Agentgres refs, receipts, and state roots

Attaching adapters
  editor, terminal, browser, OS, VM, node, and hosted-worker adapters attach as
  transports or projections, not runtime truth

Running and monitoring
  file watchers, SCM status, services, tasks, ports, logs, model/harness
  transcripts, periodic consistency checks, receipts, and activity signals
  stream into projections

Archiving or zero-to-idle
  session pauses, seals outputs, updates archive refs, writes restore receipts,
  and releases provider resources according to policy

Restoring or reinitializing
  Hypervisor replays Agentgres truth, validates restore receipts and state
  roots, resolves archive/payload refs, rehydrates provider material, then
  re-admits access and execution contracts

Shutting down
  leases are revoked or expired, ports close, transcripts seal, receipts commit,
  and provider resources stop or delete by policy
```

Provider logs, container IDs, SSH readiness, devcontainer output, file watcher
events, and resource usage are evidence. They help explain the lifecycle and
debug incidents, but they do not replace Agentgres operation admission, object
heads, state roots, receipt refs, archive refs, and restore receipts.

Encrypted blobs, Filecoin payloads, S3 objects, local cache directories, and
container volumes may be continuously updated restore material, similar to
pushing workspace state to a durable remote. They become valid restore inputs
only when Agentgres records the operation that created or adopted them, the
state root or object heads they bind, the policy/authority context, and the
restore/import receipt chain.

## Conformance Checks

- No live canon may split provider/environment posture into a separate app,
  surface, runtime, or truth layer.
- Provider and infrastructure posture belongs to Hypervisor sessions,
  environment views, provider views, and daemon APIs.
- Provider state must be evidence, not Agentgres truth.
- The environment status object, its component phases, ports, and initializer
  must be projections of Agentgres-admitted operations, not authoritative state;
  port exposure and secret injection must be wallet capability-gated, not
  owner-token shared.
- Encrypted blobs may be restore material, but restore validity must be
  operation-backed through Agentgres.
- Access, logs, support, ports, SCM auth, archive, restore, service, and task
  actions must be policy-bound and receipted when they affect authority,
  privacy, replay, cost, or restore.
- Change plans must be visible units with gates, affected objects, blocked
  reasons, daemon/provider execution, Agentgres lifecycle refs, and receipts.
- Target state, observed state, scanner findings, registry metadata, provider
  logs, and raw health output are evidence until Agentgres admits them.
- Release channel promotion, rollback, recall, remediation, emergency override,
  secret release, spend, and private/cTEE placement must route through the
  appropriate wallet and policy gates.
- Active recalls must block affected versions, routes, workers, connectors,
  images, datasets, or placements until an admitted clearance or authorized
  exception exists.
- Deployed-where indexes must derive from admitted environment/session/project
  refs and receipts, not provider inventory alone.
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
provider lifecycle state = restore truth
encrypted blob = restore truth
cheap DePIN GPU route = private route
target state = provider truth
observed state = Agentgres truth without admission
scanner output = authority
rollout = wallet/network bypass
release channel = blind auto-upgrade
maintenance window = calendar note outside policy
suppression window = hidden provider flag
recall = unreceipted provider toggle
deployed-where = raw provider inventory
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
