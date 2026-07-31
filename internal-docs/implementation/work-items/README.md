# Work items

One `ioi.program.work_item.v1` record per implementation cut. A record is the
bounded plan for its cut and, unless a merged tracked record covers the same
cut, its status owner.

## Filing

| Directory | Holds |
| --- | --- |
| [`active/`](./active/) | records that have advanced past `proposed` |
| [`proposed/`](./proposed/) | records that have not started |

Filing is derived from status, never asserted. `tools/sort-work-items.mjs`
re-files, and `tools/transition.mjs` calls it as part of its transaction, so a
record is never in the wrong directory after a status change.

## Status authority

A cut that also exists under
[`docs/architecture/_meta/work-items/`](../../../docs/architecture/_meta/work-items/)
takes its status from that merged tracked record; the private record mirrors it.
Every other cut takes its status from the private record.
`tools/reconcile-status.mjs` fails closed when a mirror disagrees with its
authority, and only ever copies from the merged record to the mirror.

## Record roles

| Role | Meaning |
| --- | --- |
| `implementation_cut` | Builds something. |
| `aggregate_exit` | Joins named children into a stage or substage exit. Manufactures no child status. |
| `private_verifier` | A checker the estate itself needs. Grants no product authority. |
| `conditional_future` | Canonically required, activated by a named external condition. |

## Validation

`tools/check-work-item-shape.mjs [id ...]` is the per-record bar and runs on one
record at a time. The deep historical bar — aggregate closure, content-bound
literal exits, checkout code anchors — belongs to
`tools/certify-stage.mjs` and `tools/check-program.mjs`.

Scope, canon owners, and exit definitions for the stage a record belongs to live
in [`../stages/`](../stages/); reusable method lives in
[`../modules/`](../modules/). A record never restates either.
