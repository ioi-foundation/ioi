# Hypervisor Providers And Environments

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor-managed providers, environments,
cross-session infrastructure posture, zero-to-idle, archive/restore posture,
development environment recipes, lifecycle observability, and provider
integration doctrine.
Supersedes: prior live canon that split provider and environment posture into a
standalone provider-management product or peer control plane.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: partial (env lifecycle, providers, readiness, warm pools, and placement built; DePIN/storage posture families vary)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs`
Last implementation audit: 2026-07-19

## Canonical Definition

**Hypervisor manages sessions, environments, and provider resources directly.**

Provider and environment capabilities are part of Hypervisor UX and daemon/Core
contracts. They may appear through the Applications catalog, the singular Open
Application slot, session detail, project settings, provider settings, org/admin views, or
operator console panels. They are not a separate product, cloud-console clone,
runtime, or truth layer.

Core doctrine:

```text
Sessions are the unit.
Environments are managed resources behind sessions.
Providers are cross-session resources.
Hypervisor coordinates environment and provider posture.
Hypervisor Daemon executes lifecycle operations.
The applicable local/domain or protocol authority provider authorizes
environment effects. wallet.network owns portable delegation and its designated
spend, secret, SCM-auth, access, declassification, and high-risk scopes.
Agentgres records admitted truth, receipts, state roots, archive refs, and
restore validity.
Storage backends hold payload bytes.
The system settles locally unless its declared profile selects an external
service such as IOI L1 for triggered public/economic/cross-domain commitments.
```

Environments are the bridge between Hypervisor's Type 1, Type 2, and Type 3
substrate modes. They are the VM-like governed unit that can contain:

```text
VMs
containers / microVMs / WASM
sandboxes
model runtimes
MCP servers
connectors
browsers
terminals
repos and mounted project folders
datasets and artifact stores
robot simulators or embodied adapters
policy envelopes
authority grants
budget limits
receipts and restore points
```

Type 1 substrate mode supplies bare-metal/appliance/cluster capacity. Type 2
substrate mode supplies hosted local developer/operator environments. Type 3
autonomy mode runs sessions, WorkRuns, workers, tools, models, authority, and
receipts above those resources. Environments are where those layers meet.

The product shape:

```text
Hypervisor App / Hypervisor Web / CLI-headless
  -> Home
  -> Projects
  -> Automations
  -> Applications
  -> Sessions

Applications Catalog / Open Application / Contextual Views
  -> Environments
  -> Operations
  -> Governance
  -> Provenance
  -> Developer Workspace
  -> Foundry
```

Provider and infrastructure posture should appear inside the default
Hypervisor shell through Applications, Open Application, session detail
views, project settings, provider settings, and org/admin web views. It should
not require users to enter a separate provider-management product.

## Owns

Hypervisor owns the product/control view for:

```text
cross-session environment inventory
provider integrations
provider accounts and connector posture
local/cloud/DePIN/customer/bare-metal resource posture
environment classes
development environment recipes
environment lifecycle
environment lifecycle observations
session access leases
services, tasks, ports, logs, and support posture
agent work services, service refs, health checks, and work-run observability
SCM auth requirements
snapshots, backups, archive material, and restore posture
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
stop, mark-active, snapshot, backup, archive, unarchive, restore, delete,
service/task execution, port sharing, log access, lifecycle observation, and
environment operations.

## Does Not Own

Environments views do not own:

```text
local/domain/protocol authority, including wallet.network-owned portable authority
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

The current BYO provider object plane and adapter priority ladder live in
[`byo-provider-plane.md`](./byo-provider-plane.md). That ladder is an
implementation sequence, not ontology and not placement preference: start with
SSH/bare-metal conformance, then simple GPU VM providers, GPU runtime clouds,
GPU marketplaces, enterprise hyperscalers, customer clusters, DePIN compute,
and decentralized storage custody. The durable Hypervisor objects remain
provider-neutral, and placement must be driven by policy, authority, budget,
privacy posture, receipts, and user preference rather than a hardcoded vendor
winner.

`decentralized.cloud` is the optional first-party resource-intelligence engine
behind optimized placement. It may return resource candidates, provider quotes,
custody plans, failover plans, reliability evidence, and spend estimates.
Hypervisor still owns provider account binding, environment lifecycle, VM/runtime
provisioning, snapshot, restore, teardown, and receipts. Direct connected
infrastructure must continue to work without routing through `decentralized.cloud`.

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

## Deployment Continuity And Managed Optionality

Hypervisor deployment postures form one contract continuum:

```text
embedded single-user / workstation
  -> self-hosted organization server
  -> customer cluster, VPC, or infrastructure
  -> optional IOI-managed placement and operations
```

The same environment recipes, daemon lifecycle operations, readiness gates,
Agentgres truth contracts, authority requirements, receipt semantics, and
portable package/System identities apply across those postures. Local and
self-hosted deployments are eligible for production claims only after their
profile-specific durability, availability, isolation, custody, recovery, and
sovereign-local conformance gates pass; they are not intrinsically demo or
development modes. Stable package hashes and `system_id` values may survive an
admitted transition, but deployment-local sessions, principals, keys, grants,
writer epochs, provider bindings, and custody or assurance claims are
re-resolved or explicitly migrated rather than assumed equivalent.

Three operations remain distinct:

```text
connect
  register candidate account, entitlement, provider, runtime-discovery,
  coordination, and service-binding relationships

operate
  admit exact leases, RuntimeAssignments, placement, data views, charges,
  authority, and receipts for selected services

migrate
  execute an owner-authorized HypervisorChangePlan that verifies copied state,
  applies the selected ordering/finality transition and resource fences,
  preserves a rollback window, and records the source disposition
```

Connecting `ioi.ai`, a provider, or another managed plane grants no effect
authority, exports no state, secret, credential, or institutional-learning
material, changes no writer or custodian, transfers no package or System
ownership, and starts no billing by itself. Sync, hosted backup, collaboration,
managed workers, remote operations, support or telemetry export, managed
placement, and custody transfer each require explicit configuration, applicable
information-flow and institutional-learning evaluation, authority, admission,
and receipts.

A placement or custody transition follows:

```text
copy or checkpoint
  -> verify target import and readiness
  -> quiesce and fence the source as the selected profile requires
  -> admit a successor writer epoch or native membership/quorum/finality transition
  -> observe the rollback window
  -> admit explicit source retention, replica, archive, or teardown disposition
```

Copying bytes never transfers truth. Replication and retained backups remain
valid when admitted. For a `single_authority` or otherwise single-writer
profile, the invariant is one current admitted writer with an exact successor
epoch and explicit custody/fencing, not one physical copy. Threshold, BFT,
external-finality, and other multi-writer-capable profiles instead require
their native membership, quorum, ordering, finality, and recovery transition
proofs. If cutover cannot complete, the source retains the selected profile's
mutation authority or the transition enters typed blocked/reconciliation
state; it never creates conflicting admitted mutation authority.

Disconnecting or revoking a managed binding expires its managed leases and
re-evaluates the exact dependency closure. Locally satisfied work may continue
under still-valid authority, temporal, budget, partition, and writer-fence
profiles. Work requiring a removed managed dependency becomes typed unavailable
or explicitly degraded. Disconnect must not delete, widen, silently migrate, or
invalidate locally owned Systems, packages, Agentgres truth, receipts, restore
material, or export paths.

The isolated, attachment, detachment, and migration consequences are tested by
the target
[`sovereign-local-completeness.md`](../../../conformance/hypervisor-core/sovereign-local-completeness.md)
contract; no current end-to-end evaluator is implied.

## General VM And Runtime Lifecycle

Hypervisor should support general VM creation and lifecycle control for any
applicable use case where the selected substrate actually supports it. A VM is
not limited to "agent work"; it may host a model server, Developer Workspace, browser
session, build environment, connector worker, service endpoint, automation
runner, private workspace, or ordinary operator-managed workload, so long as it
is governed by the same authority, cost, custody, receipts, and restore rules.

The canonical lifecycle vocabulary is:

```text
Create VM
Start / stop / restart
SSH / console
Attach disk / volume
Attach GPU where available
Snapshot
Archive
Restore
Expose ports / IP leases
Run agent/session/development workspace
Record cost / state root / receipts
Tear down
```

The same lifecycle grammar extends to adjacent runtime classes where the
provider supports them:

```text
VM
microVM
container
devcontainer
GPU runtime
browser
model server
HypervisorOS node
```

Provider adapters must preserve substrate-specific semantics. A Kubernetes
namespace, KubeVirt VM, Akash lease, Vast instance, RunPod-style runtime,
hyperscaler VM, Filecoin archive, or SSH bare-metal node can all satisfy parts
of the lifecycle, but they must not be collapsed into a fake generic cloud.
If a provider cannot support an operation, the adapter should fail closed with
a named reason and receipt rather than pretending parity.

## Development Environment Substrate Doctrine

Autonomous software work is a stateful, interactive, adversarial workload, not
a fungible stateless application pod. Hypervisor must avoid rebuilding a
generic application orchestrator underneath the product.

Default posture:

```text
untrusted autonomous code work -> VM, microVM, HypervisorOS node, or customer
  boundary with a real kernel/isolation boundary
devcontainer/container -> reproducible setup format or inner sandbox lane,
  not sufficient cross-tenant security by itself
Kubernetes/container platform -> possible provider substrate and evidence
  source, not Hypervisor runtime truth or the default isolation claim
git branch/worktree -> code/materialization isolation, not runtime isolation
```

Raw worktrees are insufficient for parallel background agents unless each
WorkRun also receives isolated runtime state: dependency installs, caches,
ports, databases, services, network namespace, credentials, logs, and restore
material. A worktree or branch may back the code proposal, but the environment
must still isolate the processes and state that execute the proposal.

Development environments need more permissive capabilities than ordinary
application workloads: package installation, nested container/tool use, test
databases, language servers, build caches, service ports, browser automation,
and sometimes root-like operations. If the platform grants those capabilities
inside a shared kernel or shared runtime state, it must not claim strong
agent-grade isolation. For untrusted or cross-tenant autonomous agents,
containers may run inside a VM/microVM/HypervisorOS boundary; they must not be
the sole boundary.

Hypervisor should use declarative APIs and control theory where useful, but
the canonical product contract is:

```text
recipe declares desired environment
daemon resolves and admits a concrete plan
provider substrate executes as evidence
Agentgres records truth and restore validity
```

Provider-native schedulers, orchestrators, volume controllers, ingress
proxies, DNS, cache layers, image pullers, and autoscalers are implementation
details. They may contribute observations and resource evidence, but they must
not become the canonical state machine, authority path, or restore source.

## Autonomous Readiness And Setup Automation

Reproducible setup is necessary but not sufficient. Agent-ready environments
must self-assemble without hidden human steps. A recipe should compile project
setup, prebuild/warmup, dependency install, code generation, database migration,
seed data, service startup, health checks, port policy, model/harness defaults,
and required credentials into an admitted readiness plan.

Environment tasks and services should be typed:

```text
HypervisorEnvironmentTask
  task_ref
  command_ref
  trigger: prebuild | environment_start | post_start | manual | recovery
  idempotent: true | false | policy_declared
  timeout_policy_ref
  resource_class_ref
  authority_scope_refs
  output_artifact_refs
  receipt_policy_ref

HypervisorEnvironmentService
  service_ref
  command_ref
  lifecycle: required | optional | agent_service | support
  healthcheck_ref
  port_refs
  restart_policy_ref
  log_ref
  authority_scope_refs
  receipt_policy_ref
```

Readiness is admitted only when the daemon can prove the environment is fit for
the intended WorkRun:

```text
HypervisorEnvironmentReadinessGate
  gate_ref
  environment_ref
  development_environment_recipe_resolution_ref
  required_task_refs
  required_service_refs
  required_port_refs
  required_connector_refs
  required_secret_refs
  required_scm_auth_refs
  required_network_refs
  required_resource_isolation_ref
  readiness_mode: full | degraded | dry_run_only | blocked
  blocked_reasons
  evidence_refs
  receipt_refs
```

Onboarding or productivity claims should be measured against this readiness
gate, not against "container started" or "shell attached." A new user or agent
should be able to create repeatable, programmatically provisioned environments;
if readiness requires manual commands, the missing task/service/authority edge
must be visible in the recipe resolution.

## Environment Ops

Canonical environment ops objects:

```text
HypervisorEnvironmentClass
HypervisorEnvironmentOpsProfile
HypervisorDevelopmentEnvironmentRecipe
HypervisorDevelopmentEnvironmentRecipeResolution
HypervisorEnvironmentLifecycleState
HypervisorEnvironmentStatus
HypervisorEnvironmentComponentStatus
HypervisorEnvironmentLifecycleObservation
HypervisorProviderFailureIncident
HypervisorEnvironmentRecoveryCandidate
HypervisorEnvironmentRecoveryAttempt
HypervisorEnvironmentStopPolicy
HypervisorEnvironmentSnapshot
HypervisorEnvironmentBackup
HypervisorWorkspaceInitializer
HypervisorEnvironmentActivitySignal
HypervisorSessionAccessLease
HypervisorEnvironmentService
HypervisorEnvironmentTask
HypervisorEnvironmentPort
HypervisorScmAuthRequirement
HypervisorEnvironmentSubstratePolicy
HypervisorEnvironmentResourceIsolationProfile
HypervisorEnvironmentConnectivityProfile
HypervisorEnvironmentStartupPlan
HypervisorEnvironmentReadinessGate
HypervisorResourcePool
HypervisorResourceBudget
HypervisorResourceAllocationRequest
HypervisorResourceAllocationDecision
HypervisorSchedulerCatchupPolicy
HypervisorWorkQueue
HypervisorWorkItem
HypervisorWorkRun
HypervisorWorkRunConversationProjection
HypervisorWorkRunIntegrationStatus
HypervisorWorkRunReviewState
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
development recipe validate / admit / resolve
start / stop / mark_active
service start / stop
task start / stop
port share / revoke
SCM auth satisfaction flow
snapshot / backup / finalization
archive / unarchive / restore / delete
timeout / idle / maximum lifetime policy
graceful / immediate / abort stop policy
activity and idle posture
access/log/support leases
lifecycle observations and condition timeline
provider failure classify / recovery candidate preview / recovery attempt
failover / rebuild / WorkRun retry / fail-closed recovery decision
capacity shock classify / allocation request / allocation decision
preempt / pause / defer / degrade / shift provider / request budget
catch-up policy for delayed scheduled work
```

Ownership boundary:

```text
Hypervisor displays and coordinates posture.
Hypervisor Daemon executes lifecycle operations.
The applicable local/domain or protocol authority provider authorizes
environment effects. wallet.network owns portable delegation and its designated
spend, secret, SCM-auth, access, support, declassification, and high-risk
scopes.
Agentgres records lifecycle receipts, archive refs, restore refs, state roots,
activity signals, lifecycle observations, and provider evidence.
Storage backends hold encrypted payload/archive bytes.
Providers expose native state as evidence, not canonical restore truth.
```

## Environment Status Object

The environment lifecycle projects through a structured status object with
component sub-phases, so sessions render real provisioning instead of a flat step
list or a timed animation. The object follows established remote-development
environment status conventions and is fully IOI-native: the truth is Agentgres,
the authority comes from the applicable local/domain or protocol provider, and
the state bytes are encrypted-blob storage.
Provider/container/PTY/file-watcher output remains evidence, not truth.

```text
HypervisorEnvironmentStatus
  schema_version: ioi.hypervisor.environment_status.v1
  environment_ref
  provider_placement_ref
  development_environment_recipe_ref
  development_environment_recipe_resolution_ref
  phase: creating | starting | running | updating | recovering | stopping |
         stopped | archived | failed
  components:
    recipe            { phase, development_environment_recipe_ref, development_environment_recipe_resolution_ref, evidence_ref }
    provisioner       { phase, evidence_ref, detail }            # node/VM/host lane
    workspace_content { phase, initializer_ref, custody_posture, evidence_ref }
    sandbox           { phase, container_ref, evidence_ref }     # devcontainer/microVM/host lane
    resource_isolation { phase, isolation_profile_ref, evidence_ref }
    connectivity      { phase, connectivity_profile_ref, evidence_ref }
    secrets           { phase, capability_lease_refs, evidence_ref }
    automations       { phase, evidence_ref }
    agent_work        { phase, work_run_refs, evidence_ref }     # IOI-native
    model_mount       { phase, model_route_ref, evidence_ref }   # IOI-native
    harness           { phase, harness_session_ref, evidence_ref } # IOI-native
  ports: [ HypervisorEnvironmentPort ]
  failure_message? / warning_message?
  lifecycle_observation_refs
  initializer_metrics
  snapshot_ref?
  backup_ref?
  state_root_ref
  workspace_artifact_ref
  runtimeTruthSource: daemon-runtime
```

Each component carries one phase from a shared taxonomy:

```text
pending | creating | initializing | ready | degraded | recovering | failed
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
per-component sub-status                   ->  components.{provisioner,
                                               workspace_content, sandbox,
                                               resource_isolation, connectivity,
                                               secrets, automations,
                                               model_mount, harness}
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

## Development Environment Recipe

`HypervisorDevelopmentEnvironmentRecipe` is the reusable setup contract for
Developer Workspace and other development-oriented sessions. It describes how a
development environment should be assembled, but it is not provider truth,
storage truth, wallet authority, or runtime execution by itself.

Recipes may be authored from project files, templates, organization policy,
prior sessions, human configuration, or generated setup plans. The canonical
recipe is the admitted Hypervisor object; source files and local UI forms are
inputs.

```text
HypervisorDevelopmentEnvironmentRecipe
  schema_version
  development_environment_recipe_ref: development-environment-recipe://.../revision/...
  content_hash
  project_ref?
  environment_class_ref?
  substrate: host | devcontainer | container | microvm | wasm |
             browser_sandbox | vm | hypervisoros_node
  image_ref? / devcontainer_ref? / base_snapshot_ref?
  checkout:
    remote_uri
    target_ref
    checkout_location
    workspace_location
  workspace_initializer_ref
  init_tasks
  prebuild_tasks
  post_start_tasks
  services
  agent_services
  ports
  editor_adapter_preferences
  tooling_or_extension_refs
  environment_variable_refs
  secret_requirement_refs
  scm_auth_requirement_refs
  connectivity_profile_ref
  cache_policy_ref
  warmup_policy_ref
  readiness_gate_policy_ref
  resource_isolation_profile_ref
  snapshot_policy_ref
  backup_policy_ref
  archive_policy_ref
  idle_timeout_policy_ref
  maximum_lifetime_policy_ref
  resource_class_ref
  storage_quota_ref
  model_configuration_ref?
  harness_profile_policy_ref?
  work_queue_policy_ref?
  privacy_posture_ref
  authority_scope_templates
  receipt_policy_ref
```

`HypervisorDevelopmentEnvironmentRecipeResolution` is the daemon-produced,
Agentgres-recorded decision that turns a recipe into concrete
session/environment ingredients. A `resolved` decision may feed a startup
plan; a `blocked` decision may not.

```text
HypervisorDevelopmentEnvironmentRecipeResolution
  schema_version
  development_environment_recipe_resolution_ref:
    development-environment-recipe-resolution://.../revision/...
  resolution_hash
  disposition: resolved
  development_environment_recipe_ref
  development_environment_recipe_content_hash
  session_ref / environment_ref
  provider_candidate_ref
  resolved_image_ref / resolved_substrate
  resolved_initializer_ref
  resolved_ports
  resolved_tasks
  resolved_services
  resolved_agent_services
  resolved_connectivity_profile_ref
  resolved_resource_isolation_profile_ref
  readiness_gate_ref
  resolved_editor_adapters
  required_authority_scope_refs
  required_secret_refs
  required_scm_auth_refs
  storage_refs
  cache_refs
  state_root_ref
  receipt_refs
  runtimeTruthSource: daemon-runtime
```

The owner allocates
`development_environment_recipe_resolution_ref` independently before hashing.
`resolution_hash` then covers the canonical resolved payload from
`schema_version` through `cache_refs`, including that allocated ref and the
exact nullable fields, while excluding only `resolution_hash` and the later
Agentgres root and receipts. Those later records bind the resolution ref and
hash externally.

A blocked candidate is not a partially populated resolution. It emits a
separate refusal:

```text
HypervisorDevelopmentEnvironmentRecipeResolutionRefusal
  schema_version
  refusal_ref
  refusal_hash
  development_environment_recipe_ref
  development_environment_recipe_content_hash
  session_ref / environment_ref
  provider_candidate_ref?
  reason_codes
  evidence_refs
  state_root_ref
  receipt_refs
```

The owner allocates `refusal_ref` before hashing. `refusal_hash` covers the
canonical refusal body through `evidence_refs`, including the allocated ref,
and excludes only itself plus the later state root and receipts. A refusal
never shares a ref or hash with a resolved decision.

`HypervisorEnvironmentStartupPlan` is the immutable daemon-admitted bridge from
that resolved recipe to one concrete startup attempt. It freezes what will
start, where it will start, which dependencies and gates must become ready, and
which evidence the lifecycle must emit. The plan does not execute, grant
authority, own provider truth, or make readiness true by declaration.

```text
HypervisorEnvironmentStartupPlan
  schema_version
  startup_plan_ref: environment-startup-plan://.../revision/...
  plan_hash
  environment_ref
  session_ref?
  system_ref?  # required when the environment serves an admitted System
  work_subject_ref?  # required when the startup attempt is bound to work
  development_environment_recipe_ref
  development_environment_recipe_content_hash
  development_environment_recipe_resolution_ref
  development_environment_recipe_resolution_hash
  placement_decision_ref
  runtime_assignment_ref?
  runtime_operator: ioi_managed | customer_managed | local | hybrid
  provider_account_ref?
  provider_adapter_revision_ref?
  source_ref / artifact_ref / configuration_ref
  ordered_task_refs
  service_refs
  agent_service_refs
  port_refs
  readiness_gate_ref
  connectivity_profile_ref
  resource_isolation_profile_ref
  custody_and_privacy_profile_refs
  temporal_verification_profile_ref
  authority_currentness_floor_ref
  lifecycle_continuity_floor_ref?
  ordering_finality_profile_ref?
  required_identity_context_ref
  required_authority_scope_refs
  resolved_authority_decision_refs
  authority_lease_refs
  capability_lease_refs
  required_secret_refs
  secret_capability_lease_refs
  required_scm_auth_refs
  resource_budget_ref
  budget_lease_ref?
  resource_allocation_ref?
  stop_policy_ref
  recovery_policy_ref
  rollback_policy_ref
  expected_receipt_contract_refs
```

The same recipe may resolve to different startup plans across local,
customer-managed, and IOI-managed postures. Every lifecycle observation and
startup receipt binds the exact plan ref and hash. The owner allocates
`startup_plan_ref` independently before hashing. `plan_hash` covers the
canonical immutable plan body from `schema_version` through
`expected_receipt_contract_refs`, including the allocated ref and every exact
nullable System/work-subject, temporal, currentness-floor, continuity-floor,
and ordering/finality field; it excludes only `plan_hash`. Admission,
execution, Agentgres roots, lifecycle receipts, readiness observations, and
refusal reasons are different records that bind the plan ref and hash, so they
cannot create a receipt/hash cycle or mutate the plan.

```text
HypervisorEnvironmentStartupAdmission
  schema_version
  startup_admission_ref / startup_admission_hash
  startup_plan_ref / startup_plan_hash
  authority_decision_refs / lease_refs
  temporal_and_continuity_evaluation_refs
  budget_and_writer_fence_refs
  state_root_ref / receipt_refs
  decision: admitted

HypervisorEnvironmentStartupExecution
  schema_version
  startup_execution_ref / startup_execution_hash
  startup_plan_ref / startup_plan_hash
  startup_admission_ref / startup_admission_hash
  provider_operation_refs
  readiness_observation_refs
  resulting_environment_state_ref
  state_root_ref / receipt_refs

HypervisorEnvironmentStartupRefusal
  schema_version
  startup_refusal_ref / startup_refusal_hash
  startup_plan_ref / startup_plan_hash
  reason_codes
  failed_precondition_refs
  state_root_ref / receipt_refs
```

A derived-record owner allocates each admission, execution, or refusal ref
independently before hashing. The corresponding hash covers the complete
canonical record from `schema_version` through `decision`,
`resulting_environment_state_ref`, or `failed_precondition_refs`, respectively,
including the allocated record ref and exact plan binding. It excludes only
itself plus the later `state_root_ref` and `receipt_refs`. Those Agentgres root
and receipt records commit the derived ref and hash externally; they are never
inputs to the hash they attest.

A refused candidate remains a resolution refusal or startup-admission refusal;
it never becomes an admitted startup plan with an embedded `blocked_reason`.

Changed placement, provider adapter, authority decision or lease, secret
capability, readiness, privacy, budget, or recovery resolution requires a
successor plan; a client may never patch the admitted plan in place. Reusable
recipes point only toward declarative setup and policy inputs. The concrete
startup plan points one-way back to the exact recipe and resolution, never the
reverse.

Plan admission freezes exact predecessors; it does not make mutable evidence
current forever or extend a lease's lifetime. Immediately before startup and
at every consequential effect boundary, the daemon revalidates each applicable
authority, capability, secret, and budget lease's exact ref/hash, subject,
scope, revocation and temporal validity, remaining budget,
provider/placement binding, and writer/fence state. Missing, stale, revoked,
exhausted, mismatched, or uncertain required evidence blocks execution and
requires re-resolution plus a successor plan rather than execution from the
frozen plan alone.

Historical `recipe_ref`, `resolution_ref`, `required_wallet_scope_refs`, and
`HypervisorEnvironmentRecipeResolution` spellings are read-only v1
compatibility aliases. Boundary adapters may read them, but canonical state
emits the owner-qualified development-environment and provider-neutral
authority names above so they cannot collide with `DataRecipe`,
`HypervisorSessionLaunchRecipe`, `WorkflowTemplate`, or `GoalRunProfile`.

`HypervisorEnvironmentSubstratePolicy` records why the selected substrate is
allowed for the workload and tenant posture:

```text
HypervisorEnvironmentSubstratePolicy
  policy_ref
  workload_kind: human_dev | autonomous_agent | agent_service |
                 training | eval | service_runtime | support
  tenant_posture: single_user | org_internal | cross_tenant | marketplace
  trust_posture: trusted_user | untrusted_code | protected_workspace |
                 provider_trust | customer_boundary
  allowed_substrates:
    - vm
    - microvm
    - hypervisoros_node
    - customer_vpc
    - container_inside_vm
    - devcontainer_inside_vm
    - local_host
  forbidden_substrates:
    - shared_kernel_container_only
    - raw_worktree_only
  minimum_isolation:
    process | container | vm_kernel | hardware_tee | ctee_private_workspace
  receipt_policy_ref
```

`HypervisorEnvironmentResourceIsolationProfile` is the per-environment contract
for noisy-neighbor control. It exists because development environments have
spiky CPU needs, high-churn storage, shared caches, language servers, nested
tools, and interactive terminals:

```text
HypervisorEnvironmentResourceIsolationProfile
  isolation_profile_ref
  environment_ref
  cpu:
    reserved_cores?
    burst_policy_ref?
    terminal_interactivity_protection: true | false
  memory:
    limit
    swap_policy_ref?
    oom_policy_ref
  storage:
    workspace_quota
    cache_quota
    iops_limit?
    bandwidth_limit?
    backup_restore_bandwidth_policy_ref?
  network:
    bandwidth_limit?
    egress_policy_ref
    namespace_isolated: true | false
  ports:
    namespace_isolated: true | false
    conflict_detection: true
  caches:
    cache_scope: per_environment | per_project | per_node | read_only_shared
    write_isolation_required: true | false
  placement:
    density_policy_ref
    noisy_neighbor_guard: true
  evidence_refs
  receipt_refs
```

`HypervisorEnvironmentConnectivityProfile` makes internal network access a
typed posture instead of a tunnel workaround:

```text
HypervisorEnvironmentConnectivityProfile
  connectivity_profile_ref
  environment_ref
  network_scope:
    public_internet | private_vpc | customer_vpc | local_only |
    declassified_proxy | no_egress
  internal_service_refs
  iam_or_provider_role_refs
  connector_refs
  forbidden_routes
  tunnel_required: true | false
  tunnel_risk_ref?
  egress_policy_ref
  evidence_refs
  receipt_refs
```

Connectivity must be enough for the intended workflow: clone, branch, install,
build, test, run services, use internal APIs, validate, commit, push, and open
review artifacts when policy allows. A shell with source code but no path to
run or validate the system is not a complete agent work environment.

Recipes should make the development path ergonomic without hiding governance.
Image selection, dependency setup, port exposure, SSH/editor/browser access,
secret injection, SCM auth, model/harness defaults, and cache/restore behavior
must still pass through daemon admission, the applicable local/domain/protocol
authority, including wallet.network where its scopes apply, and Agentgres
refs/receipts when they affect truth.

Snapshot, backup, and archive are distinct:

```text
Snapshot
  forkable point-in-time workspace material; useful for restore previews,
  patch branches, comparisons, and new session initialization.

Backup
  durability material for content recovery; useful for resilience and
  provider failure recovery.

Archive
  policy-bound zero-to-idle or restore chain with Agentgres archive refs,
  restore refs, state roots, authority context, and receipts.
```

Snapshot or backup bytes may live in local disk, object storage, CAS/Filecoin,
or provider storage. They are restore material only. Restore validity remains
Agentgres-operation-backed.

## Agent Work Services In Environments

Long-running software-engineering agents, code-review agents, migration agents,
and other autonomous work loops may run inside a Hypervisor environment as
declared services. The service is an environment component, not the durable work
object. The durable work objects are `HypervisorWorkItem`,
`HypervisorWorkRun`, receipts, artifacts, and Agentgres-admitted run history.

An environment-resident agent service should declare:

```text
service_reference
service_role: agent_service
install_or_package_ref
binary_or_container_hash
start_command_ref
ready_or_healthcheck_command_ref
memory_store_ref
port_refs
log_ref
support_bundle_policy_ref
runner_reconciliation_ref
llm_usage_event_sink_ref
exec_security_event_sink_ref
authority_scope_refs
work_queue_ref
receipt_policy_ref
```

The daemon may install, start, stop, health-check, and attach to this service
through environment ops, but the service must not hold durable authority by
default. It receives only short-lived leases, brokered credentials, connector
handles, model-route access, and environment access needed for admitted work.
Runner reconciliation, usage reporting, and exec/security events are service
telemetry inputs; they must bind back to WorkRun, Session, Agentgres, receipt,
and state-root refs before they become durable truth.

Agent services should use stable service references so clients, automation
steps, and comments can target the running service without relying on a raw TCP
port, raw host path, or provider-native process ID. Ports may be exposed for
compatibility, but exposure must be lease-bound and policy-visible.

The environment status object should show agent-work posture alongside recipe,
provisioner, workspace content, services, tasks, ports, model mount, and harness
posture:

```text
agent_work
  phase: none | installing | starting | ready | running |
         waiting_for_input | ready_for_review | degraded | failed | stopped
  active_work_run_refs
  current_activity
  conversation_projection_refs
  integration_status_refs
  log_ref
  support_bundle_ref
```

User comments, file-review comments, pull-request review input, and operator
steering should enter the work run as conversation input or review events, not
as direct mutation of the service's private loop. This keeps the human-agent
handoff ergonomic while preserving daemon, wallet.network, Agentgres, and
receipt boundaries.

## Lifecycle Observability

`HypervisorEnvironmentLifecycleObservation` is the append-only observation
timeline for environment lifecycle UX, debugging, and support. It explains what
happened, where time was spent, and why a session is blocked or degraded. It is
evidence until admitted by Agentgres and bound to receipts where required.

```text
HypervisorEnvironmentLifecycleObservation
  schema_version
  observation_ref
  session_ref
  environment_ref
  observed_at
  stage:
    queued | resolving_recipe | provisioning | prebuilding |
    pulling_image | warming_cache | initializing_content |
    restoring_snapshot | restoring_backup | restoring_archive |
    reconciling_sandbox | enforcing_resource_isolation |
    checking_connectivity | starting_services | starting_agent_work |
    binding_access | mounting_model | binding_harness | ready | active |
    idle | backing_up | snapshotting | archiving | detecting_failure |
    planning_recovery | failing_over | rebuilding | retrying_workrun |
    validating_restore | stopping | deleting | wiping_state | failed
  component:
    recipe | provisioner | workspace_content | sandbox | secrets |
    automations | services | agent_work | tasks | ports | model_mount |
    harness | adapters | storage | provider | resource_isolation |
    connectivity | cache
  condition_kind:
    content_ready | ever_ready | backup_complete | backup_failed |
    snapshot_complete | snapshot_failed | stopped_by_request |
    aborted | timeout | provider_unavailable | node_unavailable |
    volume_attached | volume_mounted | state_wiped | force_killed |
    network_degraded | archive_invalid | snapshot_invalid |
    backup_invalid | restore_invalid | waiting_for_input |
    ready_for_review | blocked_by_policy | blocked_by_authority |
    port_conflict | cache_collision | noisy_neighbor_detected |
    cpu_starved | memory_pressure | iops_throttled |
    network_bandwidth_throttled | image_pull_slow | failed
  severity: info | warning | error
  message
  metrics:
    duration_ms?
    bytes?
    image_bytes?
    cache_hit?
    cpu_wait_ms?
    memory_pressure?
    iops?
    io_wait_ms?
    network_bytes?
    port_conflict?
  evidence_ref
  provider_event_ref?
  agentgres_operation_refs
  receipt_refs
  state_root_ref?
```

`HypervisorEnvironmentStatus` is the current projection. Lifecycle observations
are the timeline behind that projection. Provider logs, container IDs, terminal
output, file watchers, and resource metrics can contribute observations, but
they do not become restore truth or authority.

## Provider Failure And Domain Recovery

Provider failure recovery is a first-class Hypervisor attempt, not an implied
side effect of a provider status badge, storage repair, or session restart.

Provider failure includes provider outage, VM loss, host unreachability, storage
route unavailability, corrupt snapshot material, missing logs or terminal
streams, runner split-brain, capacity eviction, credential revocation, and cTEE
posture regression.

Environment recovery and outcome recovery are different. Recreating a VM,
restoring a workspace, or reconnecting a provider does not establish whether a
remote API, payment, message, deployment, robot, or other external system
committed an effect before a timeout. Every consequential WorkRun/step must
declare one recovery class:

```text
replayable
  safe to execute again under fresh policy and authority

checkpointable
  resume from a named admitted checkpoint without repeating prior effects

compensatable
  retry or replacement requires an explicit compensating action and receipt

reconciliation_required
  query the external system and admit the observed outcome before deciding

non_retryable
  fail closed and require operator/domain decision; no automatic replay
```

The recovery sequence is:

```text
HypervisorEnvironmentLifecycleObservation
  -> HypervisorProviderFailureIncident
  -> HypervisorEnvironmentRecoveryCandidate[]
  -> authority/cost/policy preview
  -> HypervisorEnvironmentRecoveryAttempt
  -> daemon/provider execution
  -> Agentgres operation refs, state roots, and receipts
  -> session/project/WorkRun projections update
```

`HypervisorProviderFailureIncident` records the admitted failure boundary. It
separates provider evidence from the last Agentgres-admitted runtime truth:

```text
HypervisorProviderFailureIncident
  schema_version
  incident_ref
  session_ref
  environment_ref
  provider_ref
  work_run_refs
  effect_recovery_classes_by_work_run:
    replayable | checkpointable | compensatable |
    reconciliation_required | non_retryable
  detected_at
  detected_by_ref
  failure_kind:
    provider_outage | vm_lost | host_unreachable |
    control_plane_unavailable | storage_unavailable |
    archive_invalid | snapshot_invalid | backup_invalid |
    port_unavailable | log_stream_lost | terminal_stream_lost |
    runner_split_brain | capacity_eviction | credential_revoked |
    ctee_attestation_regression
  lifecycle_observation_refs
  provider_evidence_refs
  affected_component_refs
  last_admitted_state_root_ref
  latest_receipt_refs
  blocked_reason?
  status: open | recovering | failed_closed | recovered | abandoned | escalated
```

`HypervisorEnvironmentRecoveryCandidate` is the preview object. Every recovery
choice must name what it will try, what it expects to preserve or lose, and
which authority or spend it needs before execution:

```text
HypervisorEnvironmentRecoveryCandidate
  schema_version
  candidate_ref
  incident_ref
  recovery_mode:
    restore_snapshot | restore_backup | restore_archive |
    failover_provider | rebuild_from_recipe | retry_workrun |
    reconcile_external_effect | compensate_effect |
    abandon_fail_closed
  target_provider_ref?
  target_environment_class_ref?
  restore_material_refs
  expected_preserved_refs
  expected_lost_refs
  required_authority_refs
  cost_estimate_ref?
  risk_labels
  validation_requirements
  effect_reconciliation_and_compensation_refs
```

`HypervisorEnvironmentRecoveryAttempt` is the effectful recovery object. It
binds the selected candidate, authority context, daemon/provider execution,
restore validation, WorkRun reconciliation, and resulting receipts:

```text
HypervisorEnvironmentRecoveryAttempt
  schema_version
  recovery_attempt_ref
  incident_ref
  selected_candidate_ref
  requested_by_ref
  authority_grant_refs
  spend_limit_ref?
  support_access_ref?
  state_root_before_ref
  restore_material_refs
  restore_validation_refs
  work_run_reconciliation:
    git_worktree_refs
    agentgres_patch_branch_refs
    preserved_output_refs
    lost_material_refs
    retry_work_item_refs
    abandoned_work_item_refs
    ambiguous_effect_refs
    external_reconciliation_refs
    compensation_refs
  daemon_operation_refs
  provider_operation_refs
  receipt_refs
  effect_reconciliation_receipt_refs
  compensation_receipt_refs
  outcome: recovered | partially_recovered | failed_closed | abandoned | escalated
  state_root_after_ref?
```

Recovery attempts do not make provider or storage state authoritative. A
successful recovery means the daemon executed the selected path, Agentgres
admitted the resulting operation refs/state roots/restore validity, and receipts
explain what was preserved, lost, retried, invalidated, or failed closed.
It does not imply that an ambiguous external effect was recovered; that claim
requires the declared reconciliation or compensation path and its own admitted
receipts.

User-facing recovery UX must expose:

```text
failure classification
provider evidence vs Agentgres truth
candidate recovery modes
target provider/environment refs
authority and spend requirements
restore material and validation refs
WorkRun branch/worktree and Agentgres patch-branch reconciliation
lost/preserved/retried material
effect recovery class and ambiguous external-effect posture
reconciliation/compensation decisions and receipts
receipts, replay, and proof refs
```

## Autonomous-System Node Addition And Failover Boundary

Environment provisioning is necessary but insufficient for a machine to become
a member of a bounded autonomous system. The governed join sequence is:

```text
provision environment
  -> establish node identity and attestation
  -> propose system membership
  -> governance admits scoped role assignments
  -> verify constitution, manifest, and deployment roots
  -> restore checkpoint where required
  -> catch up the ordered operation log
  -> verify current state root and watermarks
  -> establish role lease, membership epoch, and any writer fence
  -> mark observed readiness
  -> rebalance eligible reads, execution, artifacts, or verification work
```

The environment owner manages provider placement and machine lifecycle. The
autonomous-system owner manages logical membership, roles, ordering, authority,
and continuity. Provider auto-scaling can create candidates; only the declared
membership policy can admit them. Automatic scaling is normally limited to
projection replicas, execution workers, and artifact replicas. Writers,
authority members, consensus members, guardians, and assurance-bearing
verifiers require governed changes.

Replicas can improve read capacity, execution throughput, durability, artifact
locality, and availability. They do not create safe same-head write throughput:
that requires one fenced writer, an explicit ownership partition, threshold
admission, or a declared consensus protocol. Uncontrolled multi-writer mutation
is split brain. Environment recovery also does not equal logical-system
failover; writer promotion requires system catch-up/root evidence, a higher
epoch, and old-writer fencing (`INV-22` through `INV-24`).

## Capacity, Budget, And Allocation Pressure

Capacity shock and budget exhaustion are Operations resource and scheduler
problems, not proof that compute seconds are the product goal. Compute seconds,
token counts, GPU occupancy, runtime seconds, and queue depth are internal
capacity signals. User-facing completion remains verified accepted work,
blocked-state clarity, and outcome proof.

Operations owns the cross-workload resource posture for:

```text
capacity pools
resource queues
rate limits
provider quotas
spend ceilings
budget burn
scarcity windows
priority classes
preemption decisions
degradation policies
catch-up policies
verified-work efficiency
```

`HypervisorResourcePool` describes available or constrained resource supply:

```text
HypervisorResourcePool
  schema_version
  resource_pool_ref
  scope_ref: org://... | project://... | provider://... | node://...
  resource_kind:
    cpu | gpu | memory | storage | model_api | connector_api |
    browser_sandbox | worker_runtime | training_runtime |
    confidential_compute | physical_device | io_bandwidth |
    network_bandwidth | cache | port_namespace | custom
  provider_refs
  region_refs
  data_residency_refs
  capacity_limit
  committed_usage
  available_usage
  rate_limit_refs
  quota_refs
  health_posture
  observed_at
  evidence_refs
```

`HypervisorResourceBudget` describes spend, quota, and policy limits. It may
reference wallet.network grants or other authority-provider refs when it grants
portable delegated spend, provider credentials, or budget increases. Ordinary
local priority, project quota, queue policy, and reporting state remain
Hypervisor/org governance until they require delegated authority.

```text
HypervisorResourceBudget
  schema_version
  budget_ref
  scope_ref: org://... | project://... | session://... | work_run://...
  budget_kind: spend | token | runtime_seconds | gpu_seconds | provider_quota | rate_limit | storage
  hard_limit
  soft_limit
  current_burn_ref
  forecast_ref
  reset_window
  authority_provider_refs
  authority_grant_refs
  local_policy_refs
  status: healthy | warning | exhausted | suspended | increased | revoked
```

`HypervisorResourceAllocationRequest` is the proposed allocation for work that
needs scarce capacity:

```text
HypervisorResourceAllocationRequest
  schema_version
  allocation_request_ref
  requester_ref
  workload_kind:
    session | work_run | automation | scheduled_job | training_pipeline |
    eval | managed_worker | model_route | release_job | connector_job
  workload_refs
  resource_pool_refs
  budget_refs
  priority_class:
    safety_critical | user_blocking | deadline | interactive |
    production | standard | background | speculative
  deadline?
  required_capabilities
  privacy_and_residency_constraints
  estimated_usage
  expected_verified_work
  degradation_options:
    reduce_parallelism | lower_model_route | smaller_gpu | defer |
    checkpoint_and_pause | skip_noncritical | provider_shift |
    require_manual_budget
  status: proposed | queued | admitted | blocked | superseded | cancelled
```

`HypervisorResourceAllocationDecision` is the admitted scarce-resource decision.
It is the common spine for queue ordering, budget exhaustion, throttling,
preemption, provider shift, and scheduler catch-up under pressure:

```text
HypervisorResourceAllocationDecision
  schema_version
  allocation_decision_ref
  allocation_request_ref
  decided_at
  decided_by_ref
  decision:
    admit | queue | throttle | degrade | preempt | pause | defer |
    cancel | shift_provider | request_budget | fail_closed
  reason_code:
    capacity_available | capacity_exhausted | budget_warning |
    budget_exhausted | quota_exhausted | rate_limited |
    deadline_priority | safety_priority | policy_denied |
    privacy_or_residency_block | provider_unhealthy |
    verified_work_low_value | duplicate_catchup
  affected_workload_refs
  preempted_workload_refs
  preserved_checkpoint_refs
  lost_or_discarded_refs
  retry_or_resume_policy_ref
  catchup_policy_ref?
  authority_requirement_refs
  authority_grant_refs
  cost_delta_ref?
  expected_verified_work_delta_ref?
  agentgres_operation_refs
  receipt_refs
  status: admitted | blocked | executed | superseded | failed
```

`HypervisorSchedulerCatchupPolicy` makes missed scheduled work explicit:

```text
HypervisorSchedulerCatchupPolicy
  schema_version
  catchup_policy_ref
  schedule_ref
  missed_window
  action:
    skip | run_latest | run_all | coalesce | bounded_backfill |
    require_approval | fail_closed
  max_backfill_runs?
  priority_class
  budget_ref
  authority_requirement_refs
  receipt_refs
```

Budget exhaustion must be discovered before provider mutation or new external
spend. A blocked allocation should name the exhausted budget/quota/rate-limit,
the workloads affected, the proposed degradation or catch-up path, the
authority needed to increase budget, and the receipts that prove the decision.

Preemption and cancellation are effectful decisions. They must emit
user-visible reasons, checkpoint or lost-material refs when applicable,
resume/retry policy, and receipts. High-priority work can be admitted under
scarcity only through explicit priority and policy refs; invisible starvation is
not a canonical Hypervisor state.

Work Analytics may report compute seconds, token counts, GPU occupancy, spend,
latency, queue depth, and retry rate, but it must relate those signals to
verified accepted work, quality deltas, completion, failure, cancellation, and
user/business outcome refs. Raw usage is not success.

## Change Plane

Hypervisor should manage infrastructure and autonomous-work changes as explicit
plans, not as invisible provider control loops.

Governance release/change controls are the product cockpit over the Change
Plane. They coordinate
capability promotion, release, rollout, pause, rollback, recall, kill-switch,
remote-config, release-target, gate, cohort, and deployment-risk decisions
across reusable capability. They may appear as an Applications catalog surface,
Open Application, org/admin view, Foundry handoff, Automations handoff, or
contextual detail drawer.

The Change Plane does not replace local surface ownership:

```text
Environments
  runtime environment lifecycle and provider placement evidence

Work
  typed GoalRun, AutomationRun, Session, WorkRun, retry, failure, and incident projections

Operations resource facet
  quota, queue, capacity, rate-limit, utilization, and spend posture

Foundry
  build/eval/training, registration, artifact conversion, and promotion
  candidates

Automations
  trigger, workflow, service, API, schedule, and run lifecycle

Packages / Provenance
  package install/publish/recall evidence, artifact refs, contribution refs,
  and settlement handoffs; Marketplace remains an optional discovery/commerce mode

Governance / Work
  human approval and policy review gates (Governance); remediation, incident,
  and support workstreams (Work)

Provenance / Ontology
  dependency, provenance, and impact graph

Provenance
  trace, receipt, proof, settlement, and replay inspection (the legacy Work
  Ledger views converge here)
```

Those surfaces feed Change Plane gates and blocked reasons, but they do not
become rollout truth. Change Plane projections do not become Agentgres truth
until admitted with refs, receipts, state roots, and authority context.

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

`CapabilityLifecycleControl` is the cross-surface projection used by Governance
release/change controls and Change Plane views to inspect and coordinate
reusable capability lifecycle. It is not a new truth store.

```text
lifecycle_ref
capability_ref
capability_kind:
  model_route | worker | agent_harness | tool | mcp_server | connector |
  automation | service | environment_recipe | environment_image | package |
  domain_blueprint | domain_app | physical_device | fleet_policy
owner_surface_ref
lifecycle_state
current_version_ref
target_version_ref
release_target_refs
rollout_policy_ref
rollback_policy_ref
recall_policy_ref
gate_refs
authority_refs
dependency_impact_refs
resource_queue_refs
job_run_refs
incident_refs
receipt_refs
replay_refs
proof_refs
operator_contract_refs
```

The projection may aggregate target state, observed state, change plans,
resource queues, jobs, evals, approvals, issue state, lineage impact, receipts,
and proof refs from other owners. Effectful transitions still execute through
Hypervisor Core, daemon/provider boundaries, the applicable local/domain or
protocol authority provider, Agentgres admission, and receipt/replay semantics.

### Plans, Gates, And Execution

`HypervisorChangePlan` is the visible, inspectable unit of environment change.
It should include:

```text
schema_version
plan_ref
plan_hash
target_ref and observed_ref
system_ref?
work_subject_ref?
plan_type
steps and rollback_steps
required ChangePlanGate refs
affected sessions, environments, providers, services, model routes, workers,
connectors, secrets, ports, storage refs, and datasets
maintenance_window_ref / suppression_window_ref
authority_scope_refs
temporal_verification_profile_ref
authority_currentness_floor_ref
lifecycle_continuity_floor_ref?
ordering_finality_profile_ref?
expected spend and risk posture
privacy and cTEE posture
when placement or custody changes:
  source_authoritative_refs
  target_candidate_refs
  export_or_checkpoint_ref
  target_import_and_validation_ref
  quiescence_policy_ref
  cutover_epoch_and_writer_fence_ref |
    native_membership_quorum_finality_transition_ref
  rollback_window_ref
  source_retention_replica_archive_or_teardown_policy_ref
  expected_portability_receipt_contract_refs
```

The owner allocates `plan_ref` independently before hashing. `plan_hash` covers
the complete canonical immutable plan body above, including the allocated ref,
exact nullable System/work-subject and temporal/continuity fields, and every
ordered step, gate, rollback, and migration input; it excludes only
`plan_hash`. State roots, receipts, observations, execution output, and refusal
reasons are never members of that preimage.

Change plans may be proposed by Automations, Developer Workspace, Foundry, ioi.ai,
provider views, scanner findings, policy engines, or human operators. They are
executed only through Hypervisor Core and the daemon/provider boundary.
The applicable local/domain or protocol authority provider authorizes each
effect; wallet.network owns portable delegation and its designated spend,
secret release, SCM-auth, access, declassification, emergency-override, and
high-risk scopes. Agentgres records plan lifecycle, state roots, receipts,
rollback outcomes, and replay projections.

Proposal, admission, execution, and refusal stay distinct:

```text
HypervisorChangePlanAdmission
  schema_version
  change_plan_admission_ref / change_plan_admission_hash
  plan_ref / plan_hash
  admitted_gate_refs
  authority_decision_refs / lease_refs
  temporal_and_continuity_evaluation_refs
  budget_and_writer_fence_refs
  state_root_ref / receipt_refs
  decision: admitted

HypervisorChangePlanExecution
  schema_version
  change_plan_execution_ref / change_plan_execution_hash
  plan_ref / plan_hash
  change_plan_admission_ref / change_plan_admission_hash
  applied_step_refs
  resulting_state_refs
  canary_or_validation_refs
  rollback_or_reconciliation_refs
  state_root_ref / receipt_refs

HypervisorChangePlanRefusal
  schema_version
  change_plan_refusal_ref / change_plan_refusal_hash
  plan_ref / plan_hash
  reason_codes
  failed_gate_refs
  state_root_ref / receipt_refs
```

The owner allocates each admission, execution, or refusal ref independently
before hashing. The corresponding hash covers the complete canonical record
from `schema_version` through `decision`, `rollback_or_reconciliation_refs`, or
`failed_gate_refs`, respectively, including the allocated record ref and exact
plan binding. It excludes only itself plus the later `state_root_ref` and
`receipt_refs`. Those Agentgres root and receipt records commit the derived ref
and hash externally; they are never inputs to the hash they attest. Admission
and execution never rewrite the immutable plan or launder an execution result
into its proposal hash.

Placement or custody migration preserves a `system_id` only when the applicable
governed-System `LifecycleTransitionEnvelope.identity_continuity_decision_ref`
authorizes that identity-preserving transition. Providers and Environments own
the physical copy, readiness, fence, cutover, rollback, and source-disposition
procedure; they do not own same-System identity. Otherwise the import is a fork
or successor with its own identity. Connection, copy, restore material,
provider readiness, or possession of the prior bytes cannot make that
decision. The portability and migration receipt chain described here is target
contract only; no current end-to-end migration producer or evaluator is
claimed.

`ChangePlanGate` covers constraints that must be satisfied before execution:

```text
applicable local/domain/protocol authority approval
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

wallet.network approval is mandatory only when a gate invokes portable
delegated authority or one of its owned spend, secret/decryption,
declassification, external-effect, or high-risk scopes.

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

`CapabilityRegressionRecord` binds a regression discovered during offline eval,
shadow mode, canary, rollout, production, or recall review to the affected
capability, baseline/candidate versions, release target, scorecard, evidence
refs, affected scope, recommended action, and adjudication refs. It is the
handoff object between Foundry/eval evidence and Change Plane consequences.
Governance release/change controls may pause, roll back, recall, constrain,
shadow longer, or queue patched retry from that record, but the record does not
by itself grant training reuse or runtime mutation.

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
  -> Hypervisor resolves a development environment recipe when applicable
  -> Hypervisor resolves environment class and provider candidates
  -> the applicable authority provider admits the effect; wallet.network
     handles its designated portable, spend, access, SCM-auth, or secret scopes
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

Resolving development environment recipe
  project setup, image/devcontainer/microVM/host lane, checkout path, init
  tasks, services, ports, editor adapters, cache policy, model/harness defaults,
  privacy posture, and authority templates resolve into an admitted plan

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

Snapshotting or backing up
  forkable workspace material, durability material, initializer metrics,
  finalization state, and provider/storage evidence are recorded as restore
  material, not restore truth

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

- No live canon may split provider and environment posture into a separate app,
  surface, runtime, or truth layer.
- Provider and infrastructure posture belongs to Hypervisor sessions,
  environment views, provider views, and daemon APIs.
- Provider state must be evidence, not Agentgres truth.
- Untrusted or cross-tenant autonomous agent development environments must not
  use a shared-kernel container as the sole isolation boundary. Use VM,
  microVM, HypervisorOS, customer VPC, hardware TEE, cTEE private workspace, or
  another policy-admitted boundary appropriate to the workload.
- Git branches and worktrees are code/materialization isolation only. Parallel
  WorkRuns must also isolate runtime state: services, databases, ports, caches,
  network namespace, credentials, logs, and restore material.
- Generic application orchestrators may be provider substrates, but they must
  not become Hypervisor's canonical environment state machine, authority path,
  or restore truth.
- Development environment recipes are setup contracts and desired posture; they
  do not authorize secret use, expose ports, execute tasks, or mutate restore
  truth without daemon admission, the applicable local/domain/protocol
  authority, including wallet.network where its scopes apply, and Agentgres
  operation/receipt refs.
- Agent-ready recipes must compile into typed tasks, services, readiness gates,
  resource-isolation profiles, connectivity profiles, and lifecycle
  observations. "Container started" or "shell attached" is not sufficient
  readiness for autonomous work.
- Resource management must track CPU burst/interactivity, memory pressure,
  storage quota, IOPS, backup/restore bandwidth, network bandwidth, port
  namespaces, and cache scope when those affect developer or agent experience.
- The environment status object, its component phases, ports, and initializer
  must be projections of Agentgres-admitted operations, not authoritative state;
  port exposure and secret injection must be wallet capability-gated, not
  owner-token shared.
- Lifecycle observations explain readiness, progress, failures, time spent,
  snapshots, backups, and teardown conditions; they are evidence until admitted
  and must not replace status projections, receipt refs, or state roots.
- Provider failure recovery must flow through a visible incident, candidate
  preview, effectful recovery attempt, WorkRun reconciliation, Agentgres
  operation refs, state roots, and receipts. A failed provider session must not
  disappear or silently restart without lost/preserved/retried state.
- Every consequential WorkRun must declare its effect recovery class;
  environment restore must never be presented as outcome restore when an
  external effect is ambiguous. Reconciliation-required and non-retryable work
  must fail closed instead of replaying automatically.
- Snapshot, backup, and archive semantics must remain distinct. Snapshots are
  forkable point-in-time material, backups are durability material, and archives
  are policy-bound restore chains with Agentgres refs and receipts.
- Encrypted blobs may be restore material, but restore validity must be
  operation-backed through Agentgres.
- Access, logs, support, ports, SCM auth, archive, restore, service, and task
  actions must be policy-bound and receipted when they affect authority,
  privacy, replay, cost, or restore.
- Change plans must be visible units with gates, affected objects, blocked
  reasons, daemon/provider execution, Agentgres lifecycle refs, and receipts.
- Target state, observed state, scanner findings, registry metadata, provider
  logs, and raw health output are evidence until Agentgres admits them.
- Capacity shock and budget exhaustion must produce visible allocation
  decisions that name affected workloads, priority policy, exhausted budget or
  quota, preemption/degradation/catch-up action, authority requirement,
  expected verified-work impact, and receipts.
- Budget exhaustion must block new external spend before provider mutation;
  budget increases, provider credentials, or delegated spend require the
  appropriate authority-provider refs.
- Scheduler catch-up must be policy-bound. Missed scheduled work may be
  skipped, coalesced, backfilled, run latest, require approval, or fail closed,
  but it must not replay blindly.
- Work Analytics may use compute seconds, token counts, runtime seconds, and
  GPU occupancy as internal signals only when tied to accepted verified work,
  quality, latency, failure, retry, cancellation, or budget outcomes.
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
provider posture = standalone provider-management product
provider posture = runtime truth
provider posture = provider authority
provider posture = Agentgres replacement
provider posture = storage truth
cloud provider catalog = compute provider
provider lifecycle state = restore truth
encrypted blob = restore truth
provider recovery = invisible restart
environment restore = proof that an external outcome committed or did not commit
automatic retry of reconciliation-required or non-retryable effects
shared-kernel container = sufficient boundary for untrusted autonomous agents
raw git worktree = isolated agent environment
Kubernetes or provider scheduler = Hypervisor truth
container started = environment ready
shell attached = agent work loop validated
port conflict = user problem
shared writable cache = harmless optimization
image pull / backup / restore IO starvation = invisible implementation detail
CPU throttling terminal lag = acceptable scheduler behavior
raw compute seconds = product success
budget exhaustion = provider bill surprise
queue priority = hidden provider scheduler
scheduler catch-up = replay everything blindly
cheap DePIN GPU route = private route
target state = provider truth
observed state = Agentgres truth without admission
scanner output = authority
rollout = wallet.network bypass
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
The applicable local/domain or protocol authority provider authorizes;
wallet.network owns portable delegation and its designated high-risk scopes.
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
