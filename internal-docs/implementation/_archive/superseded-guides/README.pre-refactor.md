# Private implementation system

This ignored directory is the private implementation and orchestration layer
for the architecture in [`docs/architecture/`](../../docs/architecture/).
Canon and accepted ADRs own meaning. The
[`M0–M14 master guide`](./ioi-target-end-state-master-implementation-guide.md)
is the sole implementation sequencer. Nothing else here may order stages,
activate work, change canon, or manufacture a product claim.

## First-read path

Read one straight path for an implementation cut:

1. [`program-state.json`](./program-state.json) — generated session orientation;
2. the [master guide](./ioi-target-end-state-master-implementation-guide.md) —
   sole order, gates, aggregates, and claim ladder;
3. one [`work-items/*.v1.json`](./work-items/) record — bounded plan and private
   status owner;
4. an explicitly master-activated [`stage-guides/`](./stage-guides/) or
   [`proof-gates/`](./proof-gates/) module, when applicable — reusable method
   only;
5. the record's canon owners and accepted ADRs — target meaning;
6. current code plus the record's retained evidence — bounded implementation
   truth; and
7. the evidence index and exact content-bound `*_EXIT=` line — proof.

Route presence, an HTTP 200, mock data, a screenshot, a plan, or a task exit
code is not implementation proof. Product authority is supplied by the
applicable local/domain policy and wallet grant or sealed intent, revalidated
at the final invoker and bound to receipts. An unsigned review hash chain is
workflow evidence only and grants no product authority.

## Truth and document classes

Live cut status exists only in work-item JSON and the derived
`program-state.json`. The master owns sequence, not current status. Modules own
reusable implementation methods. Generated files own deterministic views.
Evidence owns only its exact declared fact. Audits are dated observations.
Archives preserve inert bodies. Root tombstones preserve stable links and point
to the current owner.

The status-free
[`source-dispositions.v1.json`](./source-dispositions.v1.json) is the master's
§14 attachment for exact path/class/destination decisions. The generated
[`source manifest`](./generated/source-manifest.v1.json) proves current
materializations and baseline-body preservation but approves nothing.

Every build-relevant canon obligation is joined to one stage and bounded
records in
[`generated/architecture-coverage.v1.json`](./generated/architecture-coverage.v1.json).
Current Hypervisor shells, routes, seeds, fixtures, controls, and honest
nonclaims are joined in
[`generated/hypervisor-surface-coverage.v1.json`](./generated/hypervisor-surface-coverage.v1.json).
Both are projections, never secondary sequencers.

## Write and validate projections

From the repository root, regenerate deterministic private projections in this
order:

```text
node internal-docs/implementation/tools/sync-runtime-action-schema.mjs --write
node internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs --write
node internal-docs/implementation/tools/generate-approved-sequencer-diff.mjs --write
node internal-docs/implementation/tools/generate-architecture-coverage.mjs --write
HYPERVISOR_BASE_URL=http://127.0.0.1:4173 node internal-docs/implementation/tools/capture-hypervisor-live-crawl.mjs --write
node internal-docs/implementation/tools/generate-hypervisor-surface-coverage.mjs --write
node internal-docs/implementation/tools/generate-program-state.mjs --write
node internal-docs/implementation/tools/freeze-source-manifest.mjs --write
```

`migrate-work-items.mjs` and `bootstrap-source-registry.mjs` are sealed,
one-time reconciliation controls, not routine writers. The finalized source
registry is checked read-only with
`node internal-docs/implementation/tools/bootstrap-source-registry.mjs --check`;
an unknown path requires a reviewed exact registry disposition. The sequencer
diff writer refuses any master text that differs from its separately sealed
SA-1-through-SA-9 approval oracle.

The live-crawl writer is GET-only and must target a freshly launched supported
Hypervisor server. Its retained response status/body digests prove transport
reachability only. The generated Hypervisor projection preserves the separate
desktop/narrow visual `SKIP` whenever the supported in-app browser is
unavailable; the GET crawl never substitutes for that obligation.

Then run the private acceptance bar:

```text
node internal-docs/implementation/tools/check-implementation-estate.mjs
```

The stable program-state compatibility command remains:

```text
node internal-docs/implementation/check-program-state.mjs
```

The checkers emit explicit `SKIP` plus nonclaims when a recognized older or
dirty checkout cannot prove a retained fact. `SKIP` is never success, closure,
or permission to widen a claim.

## Evidence and history

Dated architecture and plan audits live under [`audits/`](./audits/), including
the [coverage audit](./audits/2026-07-22-architecture-coverage.md),
[unification plan](./audits/2026-07-22-directory-unification-plan.md), and
[reconciliation records](./audits/reconciliation/). Superseded bodies remain
under [`_archive/`](./_archive/); compatibility paths at the root are short
pointers. Neither area is part of the first-read execution path, and neither
schedules work.

Legacy root implementation-plan paths are logic-free compatibility pointers.
Every exact original body is retained under the approved audit/archive path,
and the source manifest verifies all baseline digests. There are zero
compatibility holds and no tracked verifier depends on a private root body.

## Change discipline

When canon changes, regenerate architecture coverage, review every changed
owner digest, update bounded records and the master only when sequencing must
change, then regenerate program state. Preserve M9–M14, federation,
two-sovereign, connected/secured-service, demand/L1, cohort, and live-embodied
gates. No private file is force-added, published as canon, or moved into a
tracked architecture path.
