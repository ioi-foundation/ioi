# aiagent.xyz Managed Worker Instance Lifecycle

Status: canonical architecture authority.
Canonical owner: this file for persistent aiagent managed worker instance lifecycle, payment lapse, archive, restore, export, migration, and deletion semantics.
Supersedes: plan prose and endpoint examples when lifecycle state conflicts.
Superseded by: none.
Last alignment pass: 2026-06-29.
Doctrine status: canonical
Implementation status: planned (lifecycle design; no managed-instance instantiation)
Last implementation audit: 2026-07-05

## Canonical Definition

`ManagedWorkerInstanceLifecycle` is the admitted lifecycle for a user-, org-, or
project-bound worker instance initialized from a worker package. Product UX may
call the instance an agent, but canonical state remains a managed worker
instance backed by a Hypervisor Daemon runtime node and Agentgres truth.

Compute entitlement may lapse. User-owned context must remain restorable,
exportable, or deletable according to retention, archive, authority, and policy.

## Owns

This lifecycle owns:

- instance state transitions;
- runtime assignment lifecycle;
- managed-instance configuration revision lifecycle;
- managed-instance change-plan, apply, canary, and rollback lifecycle;
- package-supported model route selection lifecycle;
- onboarding plan and readiness-profile lifecycle;
- contact/delivery channel binding lifecycle;
- notification, digest, escalation, and quiet-hours policy lifecycle;
- warm, persistent, idle, and zero-to-idle semantics;
- payment lapse and suspension behavior;
- authority grant revocation or freezing behavior;
- portable Agent Wiki / `ioi-memory` binding lifecycle;
- memory profile, projection, archive, export, delete, and forget policy;
- restore/import receipts;
- provider exit and migration behavior;
- package delisting and version upgrade behavior.

## Does Not Own

The lifecycle does not own:

- the worker package manifest;
- execution semantics;
- model weights or global model routing;
- authority ownership;
- storage payload bytes;
- physical-action safety;
- marketplace payment contracts by itself.

## Lifecycle

```text
discover
  -> install
  -> plan_onboarding
  -> initialize
  -> configure_instance
  -> configure_channels
  -> grant_authority
  -> assign_runtime
  -> active
  -> plan_change
  -> apply_change
  -> rollback_change
  -> idle
  -> zero_to_idle
  -> resume
  -> upgrade
  -> suspend
  -> payment_past_due
  -> archive
  -> restore
  -> migrate
  -> export
  -> delete
  -> forget
```

State rules:

- `payment_past_due` freezes new billable work and high-risk standing orders.
- Active authority leases may be revoked, expired, or narrowed by policy.
- A managed instance may select or change a package-supported model route only
  through policy, budget, privacy posture, and authority checks. A route change
  is instance configuration, not a new marketplace benchmark claim unless the
  resulting composition is benchmarked.
- Post-hire customization is a lifecycle operation. Safe live changes, such as
  delivery cadence, quiet hours, notification-only contact channels, budget
  caps, memory-retention preference within policy, or package-supported model
  route choice, may apply through a `ManagedWorkerInstanceConfigRevision`.
  Tool bindings, connector changes, standing orders, harness/profile changes,
  and route-policy changes require a `ManagedWorkerInstanceChangePlan` with
  risk classification, authority requirements, receipts, and, when required,
  dry-run, canary, or rollback posture. Core behavior, new action classes,
  broader authority classes, new safety envelopes, or benchmark-affecting
  package changes require a package/composition revision and appropriate eval
  or promotion gates.
- Package-author updates must resolve against each installed instance. Minor
  compatible updates may follow the owner's auto-update policy. Major,
  authority-broadening, privacy-changing, benchmark-stale, or safety-relevant
  updates must surface an explicit change plan and rollback target.
- Onboarding readiness must be explicit. A managed instance can activate only
  in the readiness mode admitted by the completed onboarding plan: `full`,
  `degraded`, `notification_only`, `dry_run_only`, or `blocked`.
- Warm runtime may degrade to `zero_to_idle` before archive.
- Runtime/node failure must not make the node the source of truth for durable
  context. Accepted memory changes are admitted as Agentgres operations and
  restored through wiki/memory/archive refs when policy allows.
- Archive stores encrypted payload bytes through Agentgres artifact refs,
  memory archive refs, and storage backend payload refs.
- Restore is an Agentgres-backed operation, not silent file mutation.
- Export requires the relevant authority provider or local/domain governance
  gate and produces export receipts. wallet.network is mandatory when export
  needs portable delegated authority, decryption, external effects, or
  high-risk approval.
- Delete/forget semantics distinguish billing deletion, archive deletion, and
  policy-governed memory erasure.

## Minimal Implementation Object

```yaml
ManagedWorkerInstanceLifecycle:
  lifecycle_id: lifecycle:...
  worker_instance_id: agent://...
  worker_package_ref: package://...
  owner_ref: account://... | org://... | wallet://...
  install_ref: install:...
  onboarding_plan_ref: onboarding_plan://...
  readiness_profile_ref: readiness://...
  runtime_assignment_ref: runtime_assignment:...
  worker_composition_ref: composition://...
  active_config_revision_ref: config_revision://...
  pending_change_plan_refs:
    - change_plan://...
  rollback_config_revision_ref: config_revision://... | null
  selected_model_route_ref: model_route://...
  execution_privacy_posture_ref: privacy_posture://...
  agent_wiki_ref: wiki://...
  memory_profile_ref: memory_profile://...
  active_memory_projection_refs:
    - memory_projection://...
  contact_channel_bindings:
    - channel_ref: contact_channel://...
      channel_kind:
        web_console | email | sms | slack | discord | telegram |
        webhook | mcp_callback | mobile_push | custom_channel
      posture:
        notification_only | summary_delivery | interactive_thread |
        approval_deeplink | workflow_callback
      connector_ref: connector://... | null
      authority_grant_refs:
        - grant://... # only when the channel performs effectful platform work
      redaction_policy_ref: policy://...
      quiet_hours_policy_ref: policy://...
      last_test_receipt_ref: receipt://...
  notification_policy_ref: policy://...
  instance_update_policy_ref: policy://...
  runtime_management_channel_ref: management_channel://... | null
  state:
    discover | installed | onboarding_planned | initializing |
    configuring_channels | authority_pending | active | idle | zero_to_idle | suspended |
    payment_past_due | archived | restoring | migrated | exported |
    deleted | forgotten
  persistence_profile:
    ephemeral | session | zero_to_idle | persistent
  authority_grant_refs:
    - grant:...
  memory_policy_ref: policy:...
  archive_policy:
    archive_after: duration
    retain_for: duration
    storage_policy_ref: policy:...
  restore_policy:
    restore_requires: authority_step_up | wallet_step_up | org_quorum | admin_policy
    restore_receipt_required: true
  export_policy:
    export_requires: authority_step_up | wallet_step_up | org_quorum | admin_policy
  deletion_policy:
    delete_runtime_state: bool
    delete_archives: bool
    forget_semantic_memory: bool
  latest_state_root: state_root:...
  archive_refs:
    - archive://...
  memory_archive_refs:
    - memory_archive://...
  receipt_refs:
    - receipt://...
```

## Configuration Revisions And Change Plans

Persistent agents are not set-and-forget objects. They can be customized after
hire, but customization must be represented as admitted lifecycle state rather
than silent console mutation or imperative backend patching.

`ManagedWorkerInstanceConfigRevision` is the durable desired configuration for a
managed instance. It records package version, supported model/harness/runtime
selection, memory posture, connectors, contact channels, schedules, budgets,
standing orders, and policy refs. It does not execute by itself.

`ManagedWorkerInstanceChangePlan` is the transition from one configuration
revision to another. It owns the diff, risk class, required approvals, required
authority/provider gates, dry-run or canary posture, runtime reconfiguration or
restart behavior, rollback target, and receipt obligations.

```yaml
ManagedWorkerInstanceConfigRevision:
  config_revision_id: config_revision://...
  worker_instance_ref: agent://...
  base_package_version_ref: package_version://...
  worker_composition_ref: composition://...
  selected_model_route_ref: model_route://...
  harness_profile_ref: harness://...
  runtime_profile_ref: runtime_profile://...
  persistence_profile: ephemeral | session | zero_to_idle | persistent
  memory_profile_ref: memory_profile://...
  connector_binding_refs:
    - connector_binding://...
  contact_channel_refs:
    - contact_channel://...
  standing_order_refs:
    - standing_order://...
  schedule_refs:
    - schedule://...
  budget_policy_ref: policy://...
  notification_policy_ref: policy://...
  authority_requirement_refs:
    - scope:...
  created_by_ref: account://... | org://... | agent://...
  receipt_refs:
    - receipt://...

ManagedWorkerInstanceChangePlan:
  change_plan_id: change_plan://...
  worker_instance_ref: agent://...
  from_config_revision_ref: config_revision://...
  to_config_revision_ref: config_revision://...
  change_kinds:
    - live_config | connector_binding | contact_channel | schedule |
      standing_order | model_route | harness_profile | package_version |
      runtime_assignment | memory_policy | authority_scope
  risk_class:
    low | moderate | high | regulated | physical_action
  required_gates:
    - local_governance | authority_provider | wallet_network |
      dry_run | canary | benchmark_refresh | human_approval
  dry_run_refs:
    - run://...
  canary_policy_ref: policy://... | null
  rollback_config_revision_ref: config_revision://...
  runtime_reconfiguration:
    hot_reload | restart_worker | replace_runtime | migrate_runtime |
    suspend_until_manual_apply
  status:
    draft | waiting_for_authority | ready | applying | applied |
    rejected | rolled_back | superseded
  receipt_refs:
    - receipt://...
```

Runtime management channels are projection/control channels from aiagent.xyz to
the assigned Hypervisor Daemon runtime node. A hosted aiagent deployment may
operate its own Hypervisor fleet for managed instances; customer, local, or
enterprise deployments may expose an outbound/reverse management channel for
console projection and lifecycle commands. In every case, the runtime node
executes and local policy may deny a requested change. The channel is not a
secret tunnel, not Agentgres truth, and not a bypass around daemon admission,
authority gates, receipts, or private-workspace boundaries.

## Admission / Settlement Boundary

Lifecycle transitions that affect ownership, payment, authority, archive,
restore, deletion, or migration are Agentgres operations with receipts. IOI L1
receives commitments only for install rights, subscription settlement, disputes,
provider exit claims, reputation roots, or cross-domain migration commitments.

## Events And Receipts

- `ManagedWorkerInstalledReceipt`
- `ManagedWorkerOnboardingPlannedReceipt`
- `ManagedWorkerReadinessChangedReceipt`
- `ManagedWorkerInitializedReceipt`
- `ManagedWorkerContactChannelBoundReceipt`
- `ManagedWorkerContactChannelTestedReceipt`
- `ManagedWorkerNotificationPolicyChangedReceipt`
- `RuntimeAssignedReceipt`
- `ManagedWorkerConfigRevisionCreatedReceipt`
- `ManagedWorkerChangePlanCreatedReceipt`
- `ManagedWorkerChangePlanAppliedReceipt`
- `ManagedWorkerChangePlanRolledBackReceipt`
- `ManagedWorkerPackageUpdatePlannedReceipt`
- `ManagedWorkerRuntimeReconfiguredReceipt`
- `ManagedWorkerModelRouteSelectedReceipt`
- `ManagedWorkerMemoryProfileBoundReceipt`
- `ManagedWorkerMemoryProjectionUpdatedReceipt`
- `ManagedWorkerMemoryArchiveCreatedReceipt`
- `ManagedWorkerSuspendedReceipt`
- `PaymentPastDueReceipt`
- `ZeroToIdleReceipt`
- `ArchiveCreatedReceipt`
- `RestoreImportedReceipt`
- `ManagedWorkerMigratedReceipt`
- `ManagedWorkerExportedReceipt`
- `ManagedWorkerDeletedReceipt`
- `ManagedWorkerForgottenReceipt`

## Conformance Checks

- Payment lapse cannot silently delete user context.
- Runtime/node failure cannot silently delete accepted memory.
- Harness-local memory cannot become durable managed-instance memory without a
  `ContextMutationEnvelope` and receipt.
- Model or harness swaps must consume policy-filtered memory projections rather
  than raw archive payloads by default.
- Restore must be operation-backed through Agentgres.
- Export requires explicit authority.
- Activation requires a completed onboarding plan or a deliberate degraded-mode
  readiness profile with visible missing capability.
- Contact channels cannot receive secrets, decryption material, protected
  plaintext, or durable authority grants. They may receive redacted summaries,
  delivery artifacts, status notifications, and wallet/console deep links.
- If a contact channel is also a work integration, it must bind to an
  `IntegrationSurfaceProfile`, connector posture, authority scopes, and receipts.
- Standing orders pause or narrow on lapse unless policy says otherwise.
- Provider exit produces migration/archive/incident receipts.
- Package delisting does not erase user-owned archives.
- Model route changes produce receipts and cannot silently reuse stale
  benchmark claims for routing eligibility.
- Post-hire customization must produce a config revision or change plan. Console
  controls cannot patch runtime state directly.
- Package updates cannot silently broaden connector scopes, action classes,
  private-data posture, physical-action posture, memory-sharing posture, or
  standing orders.
- A runtime management channel may carry lifecycle commands and projections, but
  durable state still comes from Agentgres refs and daemon receipts.

## Anti-Patterns

- Deleting a user's agent memory because a subscription payment failed.
- Treating a web console as the instance state owner.
- Restoring from encrypted blobs without Agentgres operation receipts.
- Letting a provider keep authority leases after suspension.
- Treating `zero_to_idle` as deletion.
- Treating Slack, email, SMS, Discord, Telegram, webhook, or MCP callback
  delivery as proof that the worker has authority to act in that system.
- Treating persistent background agents as set-and-forget when their package,
  route, connector, memory, delivery, budget, or authority posture can drift.
- Letting aiagent.xyz mutate customer/local runtime state through a management
  channel without an admitted change plan and receipts.

## Related Canon

- [`worker-marketplace.md`](./worker-marketplace.md)
- [`worker-endpoints.md`](./worker-endpoints.md)
- [`managed-agent-console-contract.md`](./managed-agent-console-contract.md)
- [`artifact-ref-plane.md`](../../components/agentgres/artifact-ref-plane.md)
- [`storage-backends/doctrine.md`](../../components/storage-backends/doctrine.md)
