# Shared work-lifecycle conformance

Status: active mechanism conformance target; shared kernel and local durable
reference store built, owner-route integration not built.
Canonical inputs:
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
[`invariants.md`](../../architecture/foundations/invariants.md),
[`doctrine.md`](../../architecture/components/daemon-runtime/doctrine.md), and
[`api.md`](../../architecture/components/daemon-runtime/api.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile tests the shared Rust lifecycle kernel and its daemon-local durable
adapter. The kernel supports GoalRun, GoalGroundingLoop, WorkRun,
AutomationRun, HarnessInvocation, ContextCell, and opaque external handles
without replacing their owners. It validates content commitments, exact-head
CAS, object-scoped idempotency, independent kind-specific phase/authority
tables, typed child refs, monotonic record time, cancellation fanout, replay,
and archive/snapshot construction. The adapter persists immutable records,
repairs rebuildable projections, and refuses fork, gap, tamper, orphan, and
lossy-filename collisions.

No GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
ContextCell, or external-handle write route currently calls this adapter. The
status endpoint is read-only. The local filesystem store is a reference
mechanism, not a production Agentgres ownership claim. Automatic hot-log
pruning and archive-only resume are not enabled.

## Required behavior

### WLC-1 — Kind-specific tables remain independent

Each object kind has its own initial phase, legal edges, and permitted
authority classes. An independent reference matcher must agree exhaustively
with the executable table, including unknown phases, without importing a
universal `running/completed/failed` lifecycle.

### WLC-2 — Exact head and exact replay

Genesis has no expected head. Every successor binds the current content head.
The same object-scoped idempotency key and identical bytes replay; changed
bytes conflict. Stale heads, foreign owner/kind/ref bindings, invalid hashes,
time regression, duplicate genesis, forks, gaps, and orphans fail before the
active projection changes.

### WLC-3 — Child refs are typed index facts

Attach/detach records bind the canonical identity scheme for their declared
relation. They update only the parent's rebuildable active-child index and
never mutate or claim lifecycle ownership of the child. Re-attaching an active
child or detaching an absent child fails unless the exact original record is an
idempotent replay.

### WLC-4 — Cancellation is a receipted fanout, not a phase string

Cancellation metadata is valid only on declared cancel/revoke edges and carries
a future drain deadline. Active compensatable effects require a compensation
policy; active ambiguous or irreversible effects require a reconciliation
policy. The deterministic plan includes the applicable request-cancel, drain,
fence, lease-revoke, timeout, rollback, compensation, reconciliation, and
receipt-lineage actions. It cannot claim those actions completed.

### WLC-5 — Crash repair preserves exact truth

If an immutable record reaches disk before projection replacement, reload
replays records, restores the same active phase/head/children/idempotency state,
and repairs the projection. Retrying the same record returns replay, not a
second fact.

### WLC-6 — Compaction retains lineage

Compaction writes a canonical immutable archive segment and a snapshot bound to
the archive root and through-head. Full replay and snapshot state retain the
same active phase, head, child index, idempotency map, and receipt lineage.
Pruning remains forbidden until archive-only resume and fault-injection proof
land.

### WLC-7 — Availability is reported without owner-integration overclaim

`GET /v1/hypervisor/work-lifecycle/status` reports mechanism counts and per-kind
table sizes. It must expose an empty `live_owner_route_bindings` list and
`live_owner_route_status: not_bound` until real owners commit their lifecycle
facts through the mechanism.

## Focused proof

Run:

```bash
npm run hypervisor-conformance:work-lifecycle
```

The tier invokes `scripts/verify-hypervisor-work-lifecycle-plane.mjs`, which
checks the canonical/source honesty markers and runs the focused service-kernel
and daemon-store tests.

## Open live gates

- owner-specific adapters at every legal GoalRun, GoalGroundingLoop, WorkRun,
  AutomationRun, HarnessInvocation, ContextCell, and external-handle mutation;
- owner authority/grant/revocation verification before kernel admission;
- Agentgres-backed append and cross-process exact-head concurrency;
- owner events and completion receipts after durable transition commit;
- execution and reconciliation receipts for every cancellation target;
- automatic archive selection, retention, pruning, and archive-only resume;
- crash/fault injection around record fsync, directory fsync, projection rename,
  archive write, snapshot write, and restore;
- mixed-version legal-table rollout and downgrade refusal; and
- private-subject policy filtering for any future object inspection API.

Until those gates land, this is a reusable lifecycle integrity mechanism and
durable local reference, not a live replacement for domain-owner lifecycle
planes.
