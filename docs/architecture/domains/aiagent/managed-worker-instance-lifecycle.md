# aiagent.xyz Managed Worker Instance Lifecycle

Status: canonical architecture authority.
Canonical owner: this file for persistent aiagent managed worker instance lifecycle, payment lapse, archive, restore, export, migration, and deletion semantics.
Supersedes: plan prose and endpoint examples when lifecycle state conflicts.
Superseded by: none.
Last alignment pass: 2026-06-23.

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
- package-supported model route selection lifecycle;
- onboarding plan and readiness-profile lifecycle;
- contact/delivery channel binding lifecycle;
- notification, digest, escalation, and quiet-hours policy lifecycle;
- warm, persistent, idle, and zero-to-idle semantics;
- payment lapse and suspension behavior;
- authority grant revocation or freezing behavior;
- memory/archive/export/delete policy;
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
  -> configure_channels
  -> grant_authority
  -> assign_runtime
  -> active
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
- Onboarding readiness must be explicit. A managed instance can activate only
  in the readiness mode admitted by the completed onboarding plan: `full`,
  `degraded`, `notification_only`, `dry_run_only`, or `blocked`.
- Warm runtime may degrade to `zero_to_idle` before archive.
- Archive stores encrypted payload bytes through Agentgres artifact refs.
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
  selected_model_route_ref: model_route://...
  execution_privacy_posture_ref: privacy_posture://...
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
  receipt_refs:
    - receipt://...
```

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
- `ManagedWorkerModelRouteSelectedReceipt`
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

## Anti-Patterns

- Deleting a user's agent memory because a subscription payment failed.
- Treating a web console as the instance state owner.
- Restoring from encrypted blobs without Agentgres operation receipts.
- Letting a provider keep authority leases after suspension.
- Treating `zero_to_idle` as deletion.
- Treating Slack, email, SMS, Discord, Telegram, webhook, or MCP callback
  delivery as proof that the worker has authority to act in that system.

## Related Canon

- [`worker-marketplace.md`](./worker-marketplace.md)
- [`worker-endpoints.md`](./worker-endpoints.md)
- [`managed-agent-console-contract.md`](./managed-agent-console-contract.md)
- [`artifact-ref-plane.md`](../../components/agentgres/artifact-ref-plane.md)
- [`storage-backends/doctrine.md`](../../components/storage-backends/doctrine.md)
