# Narrative evidence — route/final-invoker census corrective successor

This file is NARRATIVE. It is not the proof carrier and no admitting caller reads
it. The proof carrier is the machine-only retained log
`../route-final-invoker-census-corrective-successor.exit.v1.txt`, which conforms
to `ioi.program.literal_exit.v1` and binds `typed-delta.v1.json` by digest.
Keeping the two apart is the whole correction: the predecessor's exit artifact
was a file exactly like this one, and it was admitted as a literal-exit log.

## What was withdrawn, and why

`route-final-invoker-census-successor-after-publication-rebuild` reached
`verified` and was withdrawn by owner ruling on 2026-07-29 for two defects that
are unrelated to whether its census work was any good:

1. **The exit artifact was prose.** `evidence/M9/route-final-invoker-census-successor-after-publication-rebuild.exit.v1.txt`
   opens with a bare literal line followed by paragraphs. It is not a
   `ioi.program.literal_exit.v1` log, and `check-literal-exit-contract` reports
   93 malformed lines against it. The transition tool admitted it because
   `tools/transition.mjs` did not ask the shared literal-log validator that the
   checker in the same directory already used.
2. **The record's requirement contradicted its own evidence.** The requirement
   demanded that the deleted handler be *retired*. Its evidence correctly
   reported `RETIRED ... = 0`. The requirement was wrong, not the evidence.

Both the malformed artifact and the contradictory requirement are retained
BYTE-INTACT. They are the evidence of what went wrong, and a successor that
tidied them away would destroy the only record of the defect.

## What the typed delta shows

Derived by machine from two committed census artifacts — `98d4f2281` (the
predecessor's own declared base) and the census as retained at `7ee7acc2e` —
with every leaf field classified as locator, judgment, review provenance, or
identity BEFORE the diff runs, and an unclassified field refusing the
derivation outright.

| Delta kind | Count |
| --- | --- |
| `admitted_identity` | 4 |
| `retired_identity` | **0** |
| `locator_rebind` | 828 |
| `judgment_change` | 3 |
| unchanged | 245 |
| review provenance restamped only (not a delta kind) | 496 |

1572 + 4 admitted − 0 retired = 1576, and the row partition sums to 1576. Both
reconciliations hold.

**The route survived.** `POST /v1/hypervisor/environments/:id/scm/publish` is in
the after census. What was deleted was a handler FUNCTION in one file; the route
identity re-bound onto the rebuilt handler in another. A deletion in a diff is
not a retirement in a census, and the two are now mechanically distinct: a
retirement removes an identity, a rebind moves a locator, and no locator field
can produce a retirement row.

## A finding the prose could not carry

> **Ratified 2026-07-29.** The owner ratified these typed counts as the truth of record:
> 4 admitted / 0 retired / 828 locator rebinds / 3 judgment changes / 245 unchanged /
> 496 provenance-only restamps = 1,576. The withdrawn narrative's **six judgment re-reviews**
> is superseded as correction `cc-0001` in
> [`_archive/attestations/claim-corrections.v1.json`](../../../_archive/attestations/claim-corrections.v1.json).
> The superseded line is NOT edited where it lives: that artifact belongs to a withdrawn
> verification and its bytes are the evidence of what was withdrawn. `tools/check-attestations.mjs`
> re-reads the line on every run and fails closed if it ever stops saying what the correction corrects.

The withdrawn record's narrative reported **six** judgment re-reviews. The typed
derivation over that record's own declared window finds **three**:

- `POST /v1/hypervisor/environments/:id/:action` — information-flow gate state,
  note, and symbols moved.
- `POST /v1/hypervisor/environments/:id/scm/publish` — final-invoker symbol,
  durable-record symbols, recovery, and three gate symbol sets moved, alongside
  its locator rebind.
- `POST /v1/hypervisor/maintenance/idle-sweep` — final-invoker symbol and
  handler effect calls moved.

The three it does not reproduce — `POST /v1/hypervisor/exec`,
`POST /v1/hypervisor/terminals`, `POST /v1/hypervisor/workruns/:id/execute` —
moved only locator fields and `reviewed_as_of` in that window. Widening the
comparison back past the containment cut does not produce the claimed durability
or gate drops for them either: their `durable_record_receipt_evidence.state`
reads `handler_evidence_symbols_observed` before containment, at `98d4f2281`,
and at `7ee7acc2e` alike.

This is stated as a finding about the NARRATIVE, not about the census. The
census is coherent; the prose summarising it was not checkable, which is exactly
why a count in prose is not evidence and a typed artifact is.

## Review-provenance restamping is deliberately not a delta kind

496 entries differ only by `reviewed_as_of`. Restamping a review date neither
locates an identity nor asserts anything about it. Folding it into
`locator_rebind` would inflate the rebind count with rows where nothing moved;
folding it into `judgment_change` would claim re-reviews that never happened.
It is counted separately and named as not-a-delta-kind, so the four-kind
vocabulary stays closed and stays true.

## Bars run

```text
node internal-docs/implementation/tools/check-route-census-maintenance.mjs   PASS (0 error, 0 warn, 0 skip)
```

## What this does not claim

A coherent, typed census proves closure and coherence. It never proves that any
final-invoker judgment is order-proven, that the publication plane is correct,
or that any surface it names behaves as its classification suggests. This
successor also makes no claim about the predecessor's census work, which stands
on its own retained evidence; it corrects the FORM of the exit artifact and the
WORDING of the requirement, and nothing else.
