# Shared work-lifecycle conformance

Status: target conformance contract. Current owner planes retain independent
lifecycles; no shared lifecycle kernel, local durable reference store, status
route, or owner-route integration is claimed.
Canonical inputs:
[`objects/work-results-and-lifecycle.md`](../../architecture/foundations/objects/work-results-and-lifecycle.md),
[`invariants.md`](../../architecture/foundations/invariants.md),
[`doctrine.md`](../../architecture/components/daemon-runtime/doctrine.md), and
[`api.md`](../../architecture/components/daemon-runtime/api.md).
Last audited: 2026-07-22.

## Scope and honest implementation posture

This profile specifies a future shared lifecycle integrity mechanism for
GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
ContextCell, and opaque external handles without replacing their owners.
Current master has no such shared kernel or daemon-local adapter. Existing
owner-specific lifecycle implementations are adjacent precedents only and must
not be reported as WLC conformance.

A conforming mechanism must validate content commitments, exact-head CAS,
object-scoped idempotency, independent kind-specific phase/authority tables,
typed child refs, finite and acyclic work-owning admission, ancestor-bound
narrowing, atomic disjoint reservations, monotonic record time, cancellation
fanout, replay, and archive/snapshot construction. A local reference store, if
introduced, would still not own production Agentgres truth or permit pruning
before archive-only resume evidence.

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

### WLC-3 — Child refs are typed, and work-owning edges conserve bounds

Attach/detach records bind the canonical identity scheme for their declared
relation. They update only the parent's rebuildable active-child index and
never mutate or claim lifecycle ownership of the child. Re-attaching an active
child or detaching an absent child fails unless the exact original record is an
idempotent replay.

Relations that delegate execution, authority, or consumable capacity are
work-owning admission edges; dependency, evidence, membership, and result links
remain non-authorizing facts. Every mutation that can activate or widen such an
edge validates the complete effective ancestor chain at exact current heads.
It refuses a cycle, an unbounded active graph, a stale ancestor or allocation
head, widened authority/deadline/context/resource scope, an exceeded applicable
depth/direct-child/active-descendant limit, or overlapping sibling
reservations. Each conserved resource dimension is checked separately after
funding policy-required verification, integration, cancellation,
reconciliation, and receipt obligations. A lock around unchanged remaining-
capacity comparisons is insufficient unless the same admission commits the
disjoint hold.

Create, attach, reattach, resume/rearm, replacement, reassignment, and bound
amendment use the same rule. Process death, bare detach, cancellation intent,
or timeout cannot release the reservation or permit parent success until the
child effect is terminal or fenced, or explicitly ambiguous with receipts and
a funded reconciliation obligation. A live reassignment must atomically
revalidate both ancestor chains and transfer—never free or duplicate—the edge,
effect responsibility, reservation, receipts, and unresolved obligations.

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
cycle and stale-ancestor refusal, ancestor depth/width/active-descendant
enforcement, per-dimension authority and resource narrowing, simultaneous
sibling reservation conservation, protected recovery/integration capacity,
rearm/replacement revalidation, non-duplicating reassignment transfer,
crash-without-release, cancellation planning, record/projection crash repair,
fork/gap/tamper/orphan refusal,
archive/snapshot lineage, and owner-integration nonclaims. Current master has no
`work-lifecycle` tier or dedicated shared-plane verifier.

## Open live gates

- the shared lifecycle kernel, durable reference adapter, and honest status
  projection;
- owner-specific adapters at every legal GoalRun, GoalGroundingLoop, WorkRun,
  AutomationRun, HarnessInvocation, ContextCell, and external-handle mutation;
- owner authority/grant/revocation verification before kernel admission;
- ancestor-bound admission and atomic disjoint reservation at every
  work-owning child create/attach/rearm/replacement/reassignment path;
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
