# aiagent.xyz Managed Agent Console Contract

Status: canonical architecture authority.
Canonical owner: this file for aiagent managed-instance web console projections.
Supersedes: product prose that treats the marketplace console as execution truth.
Superseded by: none.
Last alignment pass: 2026-06-29.
Doctrine status: canonical
Implementation status: planned (console contract design)
Last implementation audit: 2026-07-05

## Canonical Definition

The Managed Agent Console is a web projection over a `ManagedWorkerInstance`.
It lets users inspect, chat with, configure, pause, resume, approve, revoke,
restore, export, update, roll back, and audit a managed instance. It does not
execute the worker and does not own runtime truth.

Execution remains with a Hypervisor Daemon runtime node. Authority is resolved
by local/domain governance and authority providers; wallet.network is mandatory
for portable delegated authority, secrets, spend, decryption, external effects,
and high-risk approvals. Truth remains with Agentgres. Payload bytes remain in
storage backends under Agentgres-governed refs.

For user-facing managed instances, the console is the default human interaction
surface. It should make browser chat, form submission, approvals, receipts,
runtime status, pause/revoke controls, and subscription state available without
requiring the user to understand local Hypervisor execution. API, MCP,
model-compatible, workflow, and local-install controls are integration exports
over the same instance, not separate agents.

The console also owns the user-facing configuration path for contact and
delivery channels. A background agent should be able to report through the
user's preferred workflow surface, such as email, SMS, Slack, Discord, Telegram,
mobile push, webhook, MCP callback, or a custom channel, while preserving the
same redaction, authority, receipt, quiet-hours, and revoke controls as the web
console.

The console is also the default management surface for post-hire customization.
It may create configuration revisions, preview change plans, request dry-runs or
canaries, apply approved changes, and roll back to prior revisions. Those
actions remain proposals over the managed-instance lifecycle; the assigned
Hypervisor Daemon runtime node executes or rejects the change, and Agentgres
admits the resulting state and receipts.

## Owns

The console owns presentation of:

- thread/chat projections;
- active and historical sessions;
- standing orders and schedules;
- approvals and capability leases;
- receipts and usage;
- runtime status;
- memory summaries and archive state;
- active configuration, pending change plans, update availability, canary and
  rollback status;
- pause/resume/suspend/archive/restore/export/delete requests;
- integration export projections;
- contact/delivery channel bindings and notification policy;
- support/dispute links.

## Does Not Own

The console does not own:

- worker execution;
- authority grants, secrets, or decryption keys;
- Agentgres state roots;
- private workspace plaintext;
- provider lifecycle;
- lifecycle/change-plan truth;
- authority-client or API-token custody;
- model-compatible or MCP runtime truth;
- L1 settlement truth.

## Lifecycle

```text
open console
  -> load ManagedWorkerInstance projection
  -> display thread/run/authority/receipt state
  -> user proposes control or configuration action
  -> create or select ManagedWorkerInstanceConfigRevision
  -> create or select ManagedWorkerInstanceChangePlan when required
  -> authority/daemon gate
  -> Hypervisor Daemon executes or rejects
  -> Agentgres admits receipt/state transition
  -> console refreshes projection
```

## Minimal Implementation Object

```yaml
ManagedAgentConsoleProjection:
  console_ref: console://...
  worker_instance_ref: agent://...
  visible_surfaces:
    - chat
    - sessions
    - approvals
    - receipts
    - usage
    - memory
    - runtime
    - archive_restore
    - integration_exports
    - contact_channels
    - configuration
    - change_plans
    - package_updates
  control_actions:
    - pause
    - resume
    - suspend
    - archive
    - restore
    - export
    - delete
    - revoke_authority
    - bind_contact_channel
    - test_contact_channel
    - disable_contact_channel
    - update_notification_policy
    - propose_config_revision
    - preview_change_plan
    - request_dry_run
    - apply_change_plan
    - rollback_config_revision
    - select_model_route
    - request_package_update
  contact_channel_refs:
    - contact_channel://...
  active_config_revision_ref: config_revision://...
  pending_change_plan_refs:
    - change_plan://...
  available_package_update_refs:
    - package_version://...
  runtime_management_channel_ref: management_channel://... | null
  authority_review_refs:
    - review:...
  receipt_refs:
    - receipt://...
  projection_checkpoint_ref: projection:...
```

## Admission / Settlement Boundary

Console actions are proposals. Consequential actions must pass the relevant
authority provider or local/domain governance gate plus daemon policy, then
become Agentgres operations and receipts. wallet.network is required when the
action needs portable delegated authority, secrets, spend, decryption, external
effects, or high-risk approval.
Marketplace or L1 settlement is used only when install rights, subscription,
dispute, payout, reputation, or public commitments require it.

Integration exports are also proposals or projections. Creating, rotating, or
revoking an authority client for API, model-compatible, MCP, workflow, or local
install use must pass the relevant authority gate and emit receipts.

Contact channel changes are also proposals. Binding a notification-only channel
may require ordinary account verification or local/org governance. Binding a
channel that lets the worker read, write, command, or mutate the external
system requires the matching connector, authority scopes, approval policy, and
receipts.

Configuration changes are proposals over the managed-instance lifecycle. Safe
live edits may create and apply a config revision. Connector, standing-order,
tool, harness, route-policy, runtime, package-version, memory-sharing,
privacy-posture, or authority-broadening changes must create a change plan with
the required gate, dry-run, canary, or rollback posture. A hosted aiagent fleet,
customer VPC node, local Hypervisor node, or private runtime may expose a
runtime management channel, but the console must treat it as a daemon-mediated
projection/control channel, not execution truth.

## Events And Receipts

- `ConsoleOpenedReceipt`
- `ConsoleControlRequestedReceipt`
- `ConsoleAuthorityReviewReceipt`
- `ConsoleContactChannelBoundReceipt`
- `ConsoleNotificationPolicyChangedReceipt`
- `ConsoleConfigRevisionRequestedReceipt`
- `ConsoleChangePlanReviewedReceipt`
- `ConsoleChangePlanApplyRequestedReceipt`
- `ConsoleConfigRollbackRequestedReceipt`
- `ManagedWorkerPausedReceipt`
- `ManagedWorkerResumedReceipt`
- `ManagedWorkerArchiveRequestedReceipt`
- `ManagedWorkerRestoreRequestedReceipt`
- `ConsoleProjectionRefreshedReceipt`

## Conformance Checks

- Console controls call daemon/authority APIs; they do not mutate instance
  state directly.
- Console reads are projections over Agentgres/daemon state.
- Browser chat is a client surface over managed-instance thread/run APIs, not a
  hidden runtime loop.
- Console configuration controls create config revisions or change plans; they
  do not imperatively patch runtime state.
- Runtime management channels may surface local/customer/hosted runtime state,
  but the console must disclose whether the instance is hosted, local,
  customer-owned, private, TEE, DePIN, or provider-backed.
- Package updates show compatibility, authority, privacy, benchmark, canary, and
  rollback posture before applying.
- Integration exports disclose scopes, expiry or rotation policy, spend limits
  where applicable, and revoke state.
- Contact channels disclose redaction policy, delivery scope, approval-deeplink
  behavior, quiet hours, last delivery/test status, and whether the channel is
  notification-only or also a work integration.
- Private workspace data is never displayed without the required viewing,
  decryption, or declassification authority.
- SMS/email links may open or notify the console but cannot carry grants,
  secrets, or durable authority.

## Anti-Patterns

- Treating aiagent.xyz as the runtime because it has a chat page.
- Letting console JavaScript hold durable worker credentials.
- Treating the console as a raw remote shell into a customer/local runtime.
- Auto-applying package updates that broaden authority or invalidate benchmark
  posture without explicit review.
- Using SMS as authentication for sensitive actions instead of an escalation
  link into a controlled approval surface.
- Hiding payment lapse, archive, or restore state behind generic billing UI.

## Related Canon

- [`managed-worker-instance-lifecycle.md`](./managed-worker-instance-lifecycle.md)
- [`worker-endpoints.md`](./worker-endpoints.md)
- [`wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`daemon-runtime/api.md`](../../components/daemon-runtime/api.md)
