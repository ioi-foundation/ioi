---
module_id: docs-and-comms
module_class: method
title: Public builder and product communication
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M9, M14]
legacy_id: WP-DOCS
canon_owners:
  - docs/architecture/_meta/execution-horizons.md
  - docs/architecture/_meta/implementation-matrix.md
  - docs/architecture/_meta/doc-classes.md
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/_meta/vocabulary.md
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
---

# Public Builder And Product Communication

## What this module owns

This module owns the reusable method for outward-facing builder documentation,
product communication, and launch material: how a documented capability is
labelled for maturity, how commands and contracts are chosen so documentation
stays runnable and stable, how doctrine is referenced rather than duplicated,
and what publication is forbidden from implying. It is a method only — it never
orders work, never carries status, and is never a sequencer; sequencing comes
from [`sequence.v1.json`](../program/sequence.v1.json), status from the owning
work-item record, doctrine from the canon owners below.

## Pulled by

Per `modules[docs-and-comms].applies_to_stages` in
[`sequence.v1.json`](../program/sequence.v1.json): [`M9`](../stages/m9.md) and
[`M14`](../stages/m14.md). No other binding exists: a stage wanting this method
must first add itself to that `applies_to_stages` list, since a prose reference
in a stage module does not create a binding.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md) | Canonical claim horizons, and the operator journey and public contracts outward-facing material may narrate. |
| [`_meta/implementation-matrix.md`](../../../docs/architecture/_meta/implementation-matrix.md) | Concept implementation status and durable form — the row a documented capability describes, which documentation reads and never moves. |
| [`_meta/doc-classes.md`](../../../docs/architecture/_meta/doc-classes.md) | Document classes, placement, and the orthogonal doctrine/implementation status axis underlying any maturity label. |
| [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md) | The subject owner every doctrine link resolves to, and the split-brain rule that makes copying doctrine a defect. |
| [`_meta/vocabulary.md`](../../../docs/architecture/_meta/vocabulary.md) | Product / admin-builder / protocol language layers: which vocabulary a given audience's material may expose. |
| [`hypervisor/core-clients-surfaces.md`](../../../docs/architecture/components/hypervisor/core-clients-surfaces.md) | Public product surfaces, workspace/application taxonomy, and honest surface states that product communication may depict. |
| [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md) | Public daemon/runtime endpoint, event, and error shapes that count as stable public contracts. |
| [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md) | SDK, CLI/headless, GUI, harness, and adapter boundaries bounding which commands may be published as runnable. |
| [`foundations/ecosystem-assurance-certification-liability.md`](../../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md) | Assurance stage, certification claims, and the `ioi_compatible`/`ioi_connected`/`ioi_secured` claim ceilings that bound published wording. |

## Retained obligations

**Maturity labelling.** Builder documentation must distinguish `Current`,
`Preview`, and `Concept`. Every documented capability, command, endpoint,
surface, and screenshot carries exactly one of those labels, and the label is
bounded by the evidence the owning work-item record retains — not by authorial
intent, a roadmap, or a design. An unlabelled capability is a defect, not a
`Current` one. Canon supplies the truth the label rests on: the status axis in
`_meta/doc-classes.md` and the row in `_meta/implementation-matrix.md`. This
method reads those; it never mints or upgrades them.

**Runnable commands and stable public contracts.** A published command must
execute as written against the supported client, CLI/headless, or SDK boundary
owned by `daemon-runtime/doctrine.md`; a published endpoint, event, or error
shape must be one canonically owned by `daemon-runtime/api.md`; a depicted
product surface must be one owned by `hypervisor/core-clients-surfaces.md`.
Examples may not depend on an internal-only route, fixture profile, harness
flag, or private estate path. Audience vocabulary follows the language layers in
`_meta/vocabulary.md`; architecture terms never become product copy by default.

**Link to canon, never copy it.** Every doctrinal statement resolves to the
subject owner named in `_meta/source-of-truth-map.md`. Duplicated doctrine
creates a second owner and is a split-brain defect however accurate the copy
reads. An unavoidable excerpt is marked as one and carries its owner path so
drift stays detectable.

**When material may be published.** Content architecture — structure, drafts,
information architecture, candidate copy — may proceed continuously and is not
itself gated by a stage. `Current` claims and launch material are different:
they are pulled only by a stage that has reached the sequencer's terminal state,
and published only at the claim level the retained evidence supports. Stage
state, exit gate, and claim ladder are defined in
[`sequence.v1.json`](../program/sequence.v1.json); claim horizons by
`_meta/execution-horizons.md`; posture wording ceilings by
`foundations/ecosystem-assurance-certification-liability.md`.

**What publication never does.** A documentation site, screenshot, or static
demo never upgrades implementation status — nor does a changelog entry,
tutorial, video, launch post, conference demo, or landing page. Publication is a
projection of the owning record, never a second status owner and never evidence
that a capability exists. The general form of this rule lives in
[`rules.md`](../program/rules.md) and is not restated here.

## Applying it in a work item

- Add every canon owner whose doctrine the published material links to the
  record's `canon_owners`, and register each documented public contract in
  `contract_families` bound to that owner path.
- Carry a per-artifact maturity ledger: artifact → `Current` | `Preview` |
  `Concept` → the `evidence_refs` entry bounding the label and the canon owner
  its doctrine links to.
- Prove runnability in `positive_proof` with an expected-path literal bound to
  exact artifact bytes for each published command or contract example, executed
  through the supported boundary rather than a harness or fixture profile.
- Record the copy/link audit in `adversarial_or_fault_proof`: copied-doctrine
  scan, dead- or wrong-owner link scan, unlabelled-capability scan, and
  private-path or internal-route leak scan.
- State in `remaining_nonclaims` that the published artifacts grant no status,
  no assurance posture, and no claim level beyond the one the stage's
  permitted-claim manifest names.
- Name the withdrawal path in `rollback_or_stop_rule`: which published artifacts
  are corrected or unpublished, and by whom, when a claim is narrowed.

## Terminal evidence

The method's contribution to a stage exit closes when the published set is
enumerated with a maturity label and evidence ref per artifact, every documented
command and contract has a retained expected-path literal, every doctrinal
statement resolves to a canon owner with no copied doctrine outstanding, the
published claim level matches the stage's permitted-claim manifest, and the
publication-upgrades-nothing nonclaim is retained in the owning record.

## Canon gaps

- No canon owner maps the builder-facing labels `Current` / `Preview` /
  `Concept` onto canon's `Doctrine status` / `Implementation status` axis or the
  implementation matrix's durable-form vocabulary. Owners to resolve it:
  `_meta/doc-classes.md` with `_meta/implementation-matrix.md`.
- No canon owner names the public documentation site or launch estate itself;
  whether those surfaces register as Hypervisor surfaces or sit outside the
  registration family is unstated. Owner: `hypervisor/core-clients-surfaces.md`.
- Canon bounds what an enrolled posture may claim but does not name who approves
  public wording before any posture exists — the `Preview` and `Concept`
  material this method also governs. Owner:
  `foundations/ecosystem-assurance-certification-liability.md`.
