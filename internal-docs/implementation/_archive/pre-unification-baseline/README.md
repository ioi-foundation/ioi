# Internal Implementation Guides

Status: internal navigation entry point.

Authority: [`docs/architecture/`](../../docs/architecture/) and accepted ADRs
remain canonical. This ignored directory contains private execution
scaffolding, evidence, compatibility pointers, and specialist ledgers.

## Active Guide

Use
[`ioi-target-end-state-master-implementation-guide.md`](./ioi-target-end-state-master-implementation-guide.md)
as the sole active internal implementation sequencer.

It owns only:

- implementation-stage activation and dependency order;
- proof and release gates;
- source-plan disposition;
- exit-proof definitions and status-owner pointers.

It does not own architecture doctrine or canonical object meaning. Private cut
status lives in machine-checked
[`work-items/*.v1.json`](./work-items/) records beside this guide; the ignored
`program-state.json` is their derived session-orientation projection. Neither
the queue nor its projection is architecture canon or tracked public doctrine.

## Reconciliation Index

- [`implementation-plan-estate-reconciliation.md`](./implementation-plan-estate-reconciliation.md)
  classifies every plan-bearing file and routes each fact to one owner.
- [`m0-m14-plan-gap-audit.md`](./m0-m14-plan-gap-audit.md) is the dated
  demanded/specified/proven/missing planning audit and contains the quarantined
  sequencer-amendment proposals.
- [`work-items/`](./work-items/) contains the private machine records for
  admitted and proposed cuts.

Validate the private estate with `npm run check:work-items`, regenerate the
local orientation with `npm run generate:program-state`, and then run
`node internal-docs/implementation/check-program-state.mjs`. A clean checkout
without this ignored directory must make an honest nonclaim rather than
inventing or publishing the private queue.

## Research Method

Use the
[`IOI Comparative Architecture Improvement Goal Prompt`](../prompts/architecture-relative-comparison/goal-prompt.md)
for bounded, current, facet-specific research-to-canon passes. It is a
reference method, not a roadmap: each run may recommend or apply owner-level
changes, but it cannot schedule implementation, reorder stages, redefine
`PG-*` gates, or widen status and release claims.
Completed, rejected, deferred, and no-change passes are discoverable through
the [`research run index`](../prompts/architecture-relative-comparison/runs/index.md).

## Preserved Sources

All other files in this directory remain in place for their detailed research,
proof ledgers, migration history, schemas, or compatibility links. Enter them
through the master guide's source-coverage ledger. A preserved source does not
schedule work merely because its body still contains phases, priorities, or an
older “master guide” title.

Ignored prompt packs, capture corpora, UX graft plans, and `.internal/plans/`
files are evidence or conditional specialist inputs. They do not outrank the
master's disposition or current canon.

## Conflict Rule

```text
canonical subject owner / accepted ADR
  -> canonical execution horizons and non-status mapping/crossing indexes
  -> machine-checked work-item status records and retained evidence
  -> active canonical specialist migration ledger
  -> this master guide
  -> master-activated specialist ledger or work package
  -> preserved research, prompts, captures, and historical plans
```

When a lower layer disagrees with a higher one, preserve the lower source,
record the conflict in the master, and execute the higher rule.
