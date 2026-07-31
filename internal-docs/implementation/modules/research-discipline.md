---
module_id: research-discipline
module_class: method
title: Relative-comparison research discipline
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: []
legacy_id: _archive/superseded-guides/ioi-target-end-state-master-implementation-guide.md#135-relative-comparison-research-discipline
canon_owners:
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/_meta/execution-horizons.md
  - docs/architecture/_meta/canon-to-code-delta.md
  - docs/architecture/_meta/implementation-matrix.md
  - docs/architecture/_meta/vocabulary.md
  - docs/architecture/_meta/doc-classes.md
  - docs/decisions/README.md
---

# Relative-Comparison Research Discipline

## What this module owns

This module owns the reusable method for one bounded comparative pass asking
whether outside material would materially improve one success-critical facet of
IOI: how the facet is bounded, what is frozen before external material is read,
what the comparison must contain, what verification it must survive, where its
output may land, and what it may never do. It is a reusable method only: it never
orders work, never carries status, and is never a sequencer.

## Pulled by

[`program/sequence.v1.json`](../program/sequence.v1.json) carries no `modules[]`
entry whose `id` is `research-discipline`, so no `applies_to_stages` binding
exists to report and `stage_ids` is empty. A stage pulls this method only once
the sequencer gains that entry; no stage inherits it automatically and no work
item may claim it as an activated stage module. The retained source-disposition
ledger classified the prompt pack as `reference_guardrail` scoped to "M0 +
selected M-stage and rails" — provenance for whoever adds the sequencer entry,
not a binding, and it licenses no pull. The missing binding is recorded under
[Canon gaps](#canon-gaps).

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md) | Which canonical owner a surgical change routes to, and whether a facet is one owner or an inseparable owner cluster. |
| [`docs/decisions/README.md`](../../../docs/decisions/README.md) | The accepted-ADR path a research-originated doctrine change must take instead of landing in a plan or work item. |
| [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md) | Canonical build order and claim horizons that research may inform but never activate or reorder. |
| [`_meta/canon-to-code-delta.md`](../../../docs/architecture/_meta/canon-to-code-delta.md) | The non-status crossing record read to establish implementation truth before comparing, and updated by a landed change. |
| [`_meta/implementation-matrix.md`](../../../docs/architecture/_meta/implementation-matrix.md) | Concept ownership and durable-form doctrine that keeps a transformed target source-neutral rather than source-shaped. |
| [`_meta/vocabulary.md`](../../../docs/architecture/_meta/vocabulary.md) | The naming boundary external terminology may not cross into canon. |
| [`_meta/doc-classes.md`](../../../docs/architecture/_meta/doc-classes.md) | The document class a dated research report holds, and why it is not canonical doctrine. |

## Retained obligations

Run the `IOI Comparative Architecture Improvement Goal Prompt` when a current
project, standard, research result, operating mechanism, failure, or user
workflow may materially improve one success-critical facet. The prompt lives at
`internal-docs/prompts/architecture-relative-comparison/goal-prompt.md`, cited
as a literal path because that pack sits outside the tracked estate.

### What each pass must do

Each pass:
- selects one bounded facet or inseparable owner cluster;
- freezes current canon, implementation truth, success measures, and the null
  alternative **before** external research begins;
- compares four things: current IOI, the strongest current mechanisms, the
  transformed source-neutral IOI target, and the unchanged path;
- requires independent adversarial verification and the relevant product, fault,
  exit, and adoption pressure tests;
- may feed a surgical canonical owner or ADR change, an existing M-stage work
  item, a bounded prototype, a monitoring trigger, or a recorded rejection;
- retains its dated report under the ignored prompt pack.

### What a pass may never do

The prompt is a research method, not another work package, architecture owner, or
sequencer. Research cannot activate or reorder M-stages, redefine or close a
`PG-*` gate (owned by [`modules/mechanism-gates.md`](./mechanism-gates.md)),
change implementation status without code evidence, or promote external
terminology into canon.

### Negative results are complete results

A verified `no_change` result is complete research when the current IOI shape
remains stronger — a finished pass with a retained report, not a failed or
abandoned one, and no obligation to re-run.

## Applying it in a work item

- Name the single bounded facet or inseparable owner cluster and the canonical
  owner(s) from the source-of-truth map that hold it.
- Retain the pre-research freeze as evidence: exact canon digest or revision,
  implementation-truth snapshot, frozen success measures and thresholds, and
  the null alternative, all recorded before the first external source is read.
- Retain the four-way comparison artifact — current IOI, strongest current
  mechanisms, transformed source-neutral target, unchanged path — with the
  source-neutralization step shown.
- Retain the independent adversarial verification by a reviewer who is not the
  pass author, plus the product, fault, exit, and adoption pressure-test results.
- Declare which single disposition from the list above was selected, and the
  dated report path under the ignored prompt pack.
- Carry the nonclaims explicitly: no stage activated, nothing reordered, no
  `PG-*` gate closed, no implementation status changed, no external term promoted.

## Terminal evidence

The method's contribution to a stage exit closes when the dated report exists
under the ignored prompt pack, the pre-research freeze and four-way comparison
are retained, the independent adversarial verification and required pressure
tests are recorded with outcomes, and the selected disposition has landed in its
own owner — merged owner or accepted ADR edit, admitted work item, bounded
prototype with its own evidence, registered monitoring trigger, recorded
rejection, or verified `no_change`. Research evidence is workflow evidence: it
never substitutes for the owning work item's completion bundle in
[`program/rules.md`](../program/rules.md) and never widens a claim by itself.

## Canon gaps

- **Sequencer binding.** No `modules[]` entry exists for `research-discipline`,
  so this method has no stage pull. Owner to resolve:
  [`program/sequence.v1.json`](../program/sequence.v1.json), by appending one
  module entry with explicit `applies_to_stages`.
- **Prompt-pack location.** The operative prompt and its dated reports are
  retained outside the tracked repository, so no canon owner or estate check can
  verify their existence, digest, or content. Owner to resolve:
  [`_meta/doc-classes.md`](../../../docs/architecture/_meta/doc-classes.md), for
  whether they have a tracked class and home.
- **Independence standard.** Canon does not define what makes adversarial
  verification "independent" for a research pass — reviewer separation, tooling
  separation, or both. Owner to resolve:
  [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md)
  by naming the owner, or an accepted ADR under
  [`docs/decisions/`](../../../docs/decisions/README.md).
- **Source-neutrality test.** Canon forbids promoting external terminology but
  names no test for when a transformed target is genuinely source-neutral rather
  than a renamed import. Owner to resolve:
  [`_meta/vocabulary.md`](../../../docs/architecture/_meta/vocabulary.md) with
  [`_meta/implementation-matrix.md`](../../../docs/architecture/_meta/implementation-matrix.md).
