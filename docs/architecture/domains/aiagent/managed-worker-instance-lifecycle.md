# aiagent.xyz Managed Worker Instance Lifecycle

Status: canonical architecture authority.
Canonical owner: this file for persistent aiagent managed worker instance lifecycle, payment lapse, archive, restore, export, migration, and deletion semantics.
Supersedes: plan prose and endpoint examples when lifecycle state conflicts.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Canonical Definition

`ManagedWorkerInstanceLifecycle` is the admitted lifecycle for a user-, org-, or
project-bound worker instance initialized from a worker package. Product UX may
call the instance an agent, but canonical state remains a managed worker
instance backed by a Hypervisor Daemon runtime node and Agentgres truth.

Compute entitlement may lapse. User-owned context must remain restorable,
exportable, or deletable according to retention, archive, wallet authority, and
policy.

## Owns

This lifecycle owns:

- instance state transitions;
- runtime assignment lifecycle;
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
- wallet authority;
- storage payload bytes;
- physical-action safety;
- marketplace payment contracts by itself.

## Lifecycle

```text
discover
  -> install
  -> initialize
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
- Active wallet leases may be revoked, expired, or narrowed by policy.
- Warm runtime may degrade to `zero_to_idle` before archive.
- Archive stores encrypted payload bytes through Agentgres artifact refs.
- Restore is an Agentgres-backed operation, not silent file mutation.
- Export requires wallet authority and produces export receipts.
- Delete/forget semantics distinguish billing deletion, archive deletion, and
  policy-governed memory erasure.

## Minimal Implementation Object

```yaml
ManagedWorkerInstanceLifecycle:
  lifecycle_id: lifecycle:...
  worker_instance_id: agent://...
  worker_package_ref: package://...
  owner_ref: wallet://...
  install_ref: install:...
  runtime_assignment_ref: runtime_assignment:...
  state:
    discover | installed | initializing | active | idle | zero_to_idle |
    suspended | payment_past_due | archived | restoring | migrated |
    exported | deleted | forgotten
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
    restore_requires: wallet_step_up | org_quorum | admin_policy
    restore_receipt_required: true
  export_policy:
    export_requires: wallet_step_up
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
- `ManagedWorkerInitializedReceipt`
- `RuntimeAssignedReceipt`
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
- Standing orders pause or narrow on lapse unless policy says otherwise.
- Provider exit produces migration/archive/incident receipts.
- Package delisting does not erase user-owned archives.

## Anti-Patterns

- Deleting a user's agent memory because a subscription payment failed.
- Treating a web console as the instance state owner.
- Restoring from encrypted blobs without Agentgres operation receipts.
- Letting a provider keep authority leases after suspension.
- Treating `zero_to_idle` as deletion.

## Related Canon

- [`worker-marketplace.md`](./worker-marketplace.md)
- [`worker-endpoints.md`](./worker-endpoints.md)
- [`managed-agent-console-contract.md`](./managed-agent-console-contract.md)
- [`artifact-ref-plane.md`](../../components/agentgres/artifact-ref-plane.md)
- [`storage-backends/doctrine.md`](../../components/storage-backends/doctrine.md)
