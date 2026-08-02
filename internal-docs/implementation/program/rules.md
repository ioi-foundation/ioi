# Program rules

Document role: stable program-wide rules, stated once. Every stage module and
work item inherits this file and must not restate it.

Owns: authority order, conflict procedure, admission rule, completion bundle,
mandatory rails, stop rules, and the proof doctrine.

Does not own: architecture doctrine (canon owns it), sequencing
([`sequence.v1.json`](./sequence.v1.json) owns it), or durable cut status (the
owning work-item record owns it).

## 1. Authority order

When sources disagree, the first match wins:

1. the subject owner named in
   [`source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md)
   and an accepted ADR;
2. [`execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md)
   for canonical build order and claim horizons;
3. [`canon-to-code-delta.md`](../../../docs/architecture/_meta/canon-to-code-delta.md)
   and
   [`implementation-matrix.md`](../../../docs/architecture/_meta/implementation-matrix.md)
   for non-status object crossings, concept ownership, and durable-form doctrine;
4. the owning `ioi.program.work_item.v1` record for durable cut status;
5. current code and retained evidence for runtime truth, bounded to the exact
   scope they establish;
6. [`sequence.v1.json`](./sequence.v1.json) for stage order, dependencies, and
   exit gates;
7. a `modules/` file for the reusable method a stage delegates to it;
8. `_archive/` records as historical evidence only.

Publication date, document length, the word "master" in a title, or an
`AUTHORITATIVE` label in an ignored file never outranks that order.

## 2. Conflict procedure

1. Stop only the affected work item.
2. Name the exact owner and the conflicting statements.
3. Classify the conflict as doctrine, status, sequencing, or stale detail.
4. Resolve doctrine in the canon owner or an accepted ADR — never inside a work
   item. Architecture ambiguity is surfaced as a canon/ADR gap.
5. Resolve durable cut status in the owning work-item record and regenerate
   derived views in the same transaction.
6. Resolve sequencing in `sequence.v1.json`, after execution horizons.
7. Preserve the superseded source under `_archive/` with its digest and
   provenance. Preservation never requires an obsolete body in the active
   reader path.

A claim may be narrowed immediately when evidence fails. It may be widened only
after owner doctrine, implementation truth, and proof agree.

## 3. Status truth

- Durable cut status lives in exactly one owner per work item, declared by that
  record's `status_authority` field.
- For the cuts also carried by the tracked, merged records under
  [`docs/architecture/_meta/work-items/`](../../../docs/architecture/_meta/work-items/),
  the tracked record is the status authority and the private record mirrors it.
  `tools/reconcile-status.mjs` fails closed when they disagree.
- For every other cut, the private record is the status authority.
- [`NOW.md`](../NOW.md) and
  [`generated/program-state.v1.json`](../generated/program-state.v1.json) are derived
  projections. They are never a second status owner or a second sequencer.
- No pointer, index, README, or module upgrades a cut, stage, route, contract,
  product, or claim.

## 4. Admission rule

A work item starts only when:

- its claim can fail;
- its canon owners and current work-item records have been read;
- the current canon-impact projection maps every in-scope canonical owner and
  contract to this stage and a bounded record, with no unreviewed changed owner
  digest;
- every dependency is another work-item id or an explicitly approved external
  gate — prose placeholders do not form the dependency graph;
- its selected deployment profile and nonclaims are explicit;
- upstream contracts are verified or explicitly simulated;
- metrics and thresholds are frozen before observation;
- every consequential effect names its final invoker;
- applicable `PG-*` gates are mapped without changing their definitions;
- negative and inconclusive results have a durable retention path;
- the product projection, if any, cannot fabricate missing owner truth.

## 5. Completion bundle

No schema, route, UI, test, or receipt closes a work item alone. A `verified`
item contains all applicable parts of:

```text
owner-approved contract and invariants
  + registered schema and generated Rust/TypeScript form
  + compatibility and migration rules
  + Rust daemon admission/execution path
  + Agentgres operation/head/root/receipt/replay path
  + authority, safety, IFC, budget, fence, and idempotency checks
  + positive, negative, substitution, stale-state, and fault evidence
  + policy-filtered product projection and honest degraded states
  + work-item-record update and regenerated derived projections
  + exported evidence index
  + explicit remaining nonclaims
```

An item is `blocked`, not partial-success, when a required owner boundary is
replaced by a fixture or manual edit.

## 6. What is not proof

A passing process exit code, route presence, HTTP 200, screenshot, mock data,
plan, status declaration, or task exit code is not implementation proof.

Proof is an expected-path literal bound to exact artifact bytes or a committed
artifact identity, retained under `evidence/`, plus the adversarial, denial,
recovery, replay, and fault evidence the stage requires.

Product authority is supplied by the applicable local/domain policy and wallet
grant or sealed intent, revalidated at the final invoker and bound to receipts.
Private review records and audit ledgers are workflow evidence, not product
authority. An unsigned review hash chain grants nothing.

`SKIP` is never success, closure, or permission to widen a claim.

## 7. Mandatory rails

The rails in [`sequence.v1.json`](./sequence.v1.json) (`R-CONTRACT`,
`R-RUNTIME`, `R-TRUTH`, `R-AUTH`, `R-PRODUCT`, `R-OPS`) advance inside every
stage. They must not become competing roadmaps.

A macro runtime cut is valid only when it replaces a fail-closed or split JS
surface with a positive Rust daemon API, moves the selected route family's
admission, authority, receipt, Agentgres commit, projection, replay, and
protocol shape together, deletes or demotes the old authoring path in the same
cut, adds positive and negative conformance, and regenerates the affected
coverage projections once at the macro boundary.

Green current-tier conformance is necessary but never proves terminal
ownership.

## 8. Adversarial proof matrix

Every active stage selects the applicable rows from
[`modules/adversarial-proof-matrix.md`](../modules/adversarial-proof-matrix.md).
Positive tests demonstrate a path; these failure classes determine whether the
claim is bounded.

## 9. Stop rules

Stop and correct course when:

- a contract has no clear canonical owner;
- an effect path cannot name and guard its final invoker;
- accepted truth can originate in a client, JavaScript facade, prompt, harness,
  MCP transport, adapter, cache, or UI;
- proof depends on trusting the producer under evaluation;
- a GoalRun, accepted outcome, or System cannot reconstruct after the selected
  restart/fault profile;
- provider exit loses protected institutional state or misses frozen floors;
- sovereign cooperation lacks participant-level positive surplus;
- embodied promotion requires remote intelligence to become the local safety
  loop;
- public-network economics require compulsory local settlement, internal
  traffic, subsidy concealment, or token appreciation.

## 10. Scope preservation

No stage, module, or cleanup pass may prune a canonical horizon to simplify the
estate. M0–M14, `FUTURE` conditional work, federation, two-sovereign operation,
connected and secured services, optional L1, embodiment, assurance,
marketplaces, and economics remain in scope and remain classified in
[`program/canon-map.v1.json`](./canon-map.v1.json).

Horizon labels are maturity statements, never scope cuts.

## 11. Source-neutral durable record

Canon, ADRs, program identifiers, record names, stage and module prose, branch
names, commit messages, and PR narrative describe IOI-owned requirements and
invariants without naming the external products that motivated them. A record is
named for what it proves, never for what it was copied from or compared against.

Source identities remain permitted, and are sometimes required, in exactly three
places: noncanonical research material, restricted provenance evidence, and
legally required attribution. An evidence manifest that must enumerate real file
paths — a residue census, an overlay manifest, a licence inventory — names what
is on disk, because an evidence manifest that renames its subjects is not
evidence.

The boundary is stated honestly rather than overclaimed. Ordinary git history
already contains source names, and commits that delete source-derived files show
those names in their diffs. Removing every occurrence from git objects would
require a destructive history rewrite and would conflict with required
provenance and licensing, so none is undertaken. The guarantee is: no source
names in new architectural semantics or authored change narrative, no
source-derived ownership in the shipped product, and complete attribution
retained wherever it is legally or evidentially required.
