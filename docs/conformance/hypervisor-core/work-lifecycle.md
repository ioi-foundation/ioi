# Shared work-lifecycle conformance

Status: target conformance contract. Current owner planes retain independent
lifecycles; no shared lifecycle kernel, local durable reference store, status
route, or owner-route integration is claimed.
Canonical inputs:
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
[`invariants.md`](../../architecture/foundations/invariants.md),
[`doctrine.md`](../../architecture/components/daemon-runtime/doctrine.md), and
[`api.md`](../../architecture/components/daemon-runtime/api.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile specifies a future shared lifecycle integrity mechanism for
GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
ContextCell, and opaque external handles without replacing their owners.
Current master has no such shared kernel or daemon-local adapter. Existing
owner-specific lifecycle implementations are adjacent precedents only and must
not be reported as WLC conformance.

A conforming mechanism must validate content commitments, exact-head CAS,
object-scoped idempotency, independent kind-specific phase/authority tables,
typed child refs, monotonic record time, cancellation fanout, replay, and
archive/snapshot construction. A local reference store, if introduced, would
still not own production Agentgres truth or permit pruning before archive-only
resume evidence.

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

If a `GET /v1/hypervisor/work-lifecycle/status` projection is introduced, it
must report mechanism counts and per-kind table sizes and expose an empty
`live_owner_route_bindings` list and
`live_owner_route_status: not_bound` until real owners commit their lifecycle
facts through the mechanism.

## Required proof

A future executable tier must cover exhaustive table/reference legality,
same-body replay, changed-body and stale-head conflict, typed child refs,
cancellation planning, record/projection crash repair, fork/gap/tamper/orphan
refusal, archive/snapshot lineage, and owner-integration nonclaims. Current
master has no `work-lifecycle` tier or dedicated shared-plane verifier.

## Open live gates

- the shared lifecycle kernel, durable reference adapter, and honest status
  projection;
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

Until those gates land, this is a target contract, not a reusable implemented
mechanism, durable local reference, or replacement for domain-owner lifecycle
planes.
