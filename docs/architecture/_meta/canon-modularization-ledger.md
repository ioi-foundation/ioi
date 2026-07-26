# Canon Terminology And Modularization Ledger

Status: refactor delivery record.
Canonical owner: this file for the audit findings, rename ledger, module map, and before/after measurements of the 2026-07-25 terminology and modularization pass. It owns no architecture contract.
Supersedes: nothing. It records a change; it does not carry doctrine.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: reference
Implementation status: mixed (a point-in-time refactor record; the checks it describes are executable and named below)
Implementation refs:
  - `scripts/check-architecture-docs.mjs`
  - `scripts/lib/architecture-docs-integrity.mjs`
Last implementation audit: 2026-07-25

## What this file is

A record of one refactor pass over `docs/architecture/**`, the architecture ADRs,
and the documentation checks. It exists so the reasoning behind the renames and
module boundaries survives, and so the claims below can be audited.

**Verification posture.** Statements marked *verified* were produced by running a
command whose output is recorded. Statements marked *asserted* are author
judgement. Do not read an assertion as a check.

**Commits referenced.** `a894b2505` is the pre-change baseline. `bf34db013` is an
unrelated pre-existing work-in-progress commit carried onto this branch
unchanged; it added ~30 lines to the file that was split, so a losslessness check
must diff against `bf34db013` while a corpus baseline must use `a894b2505`. All
counts below use `wc -l` and state which commit they come from.

## Baseline (verified, at `a894b2505`)

| Measure | Value |
| --- | --- |
| Markdown files under `docs/architecture/**` | 96 |
| Total lines | 100,910 |
| Files over 800 lines or 50 KB, excluding `_archive/` | 31 |
| Largest file | `foundations/common-objects-and-envelopes.md` — 11,013 lines / 485.4 KB / 128 H2 sections |
| `Canonical owner:` string length of that file | 816 characters, naming ~20 unrelated subjects |
| Vocabulary entries | 458, of which 449 sat in a single flat 2,305-line H2 with no per-term anchor |
| `npm run check:architecture-docs` | **failed** — 172 failures, every one from a developer's gitignored nested git worktree under `internal-docs/implementation/worktrees/` |

The baseline check failure was environmental, not a canon defect — but it was a
real defect in the *check*: it walked the filesystem and could not tell a nested
checkout of this repository from this repository's own corpus.

## Phase B findings — terminology

The boundary table for every protected term is owned by
[`term-boundaries.md`](../foundations/term-boundaries.md). This section records
only what the audit *found*.

| Finding | Class | Resolution |
| --- | --- | --- |
| A canonical `Term \| Canonical Meaning \| Must Not Mean` table with **24** term rows existed but was buried as an H3 (`### Terminology Boundary Table`) under `## Package Release And Live-System Genesis`, inside an 11,013-line file. Nothing linked to it. | `ownership_move` | Promoted to `foundations/term-boundaries.md`, registered in README and the source-of-truth map, replaced in place by a link. |
| The most fundamental base categories had **no** vocabulary entry: `System`, `Session`, `Project`, `Automation`, `Assistant`, `Run`, `WorkRun`, `Task`, `Receipt`, `Lease`, `Binding`, `Projection`, `Envelope`, `Profile`, `Decision`, `Substrate`, `Product`, `Protocol`, `Domain`, `Service`, `Provider`, `Harness`, `Facilitator`, `Campaign`. 449 entries existed, all compound names built *from* those categories. | `new_architectural_requirement` | All are now boundary rows. 53 of the 58 rows carry an ontological category; 5 (`Run`, `Task`, `State`, `Domain`, `Facilitator`) carry `—` **by design** — the row exists to say the bare term is not canonical, so assigning it a category would contradict the row. |
| `Assistant` appeared 2 times in `docs/architecture/**/*.md`, both as a legacy UI label (`Upgrade Assistant`), plus once in `whitepaper.tex`. No canon statement said an Assistant is not a durable object. | `new_architectural_requirement` | `Assistant` is categorised `faculty` with an explicit "no identity, state, lifecycle, authority, budget, receipt, or projection" boundary. |
| `Facilitator` appeared **zero** times, though the product boundary depends on ioi.ai *facilitation* not becoming ambient authority. | `new_architectural_requirement` | `Facilitation` added as a `faculty`; `Facilitator` marked not-a-canonical-term. |
| `RunEnvelope` (`run://`) and `WorkRun` (`work_run://`) were two names for one concept. `RunEnvelope`: 4 doc references, **0** code references. `WorkRun`: 99 doc, 26 code. `WorkRunEnvelope` did not exist. | `canonical_rename` | `WorkRun` is canonical; `run://`, `run_id`, `/v1/runs/{run_id}` recorded as **retained wire identifiers**. |
| `Task` carried four unrelated meanings: `TaskEnvelope` (a work request), `TaskCapsule` (a runtime assignment payload), `TaskBriefPayload` (a context handoff brief), and MCP task handles. | `canonical_rename` | `Task` marked not-a-canonical-standalone-term; the request concept is **work request** (public copy: RFW). `task://` and `task_id` retained. |
| `Domain` was overloaded across bounded execution domain, Domain Ontology, domain object, and the `docs/architecture/domains/` directory, which holds *product* domains. | `editorial_clarification` | `Domain` marked always-qualified with the four senses enumerated. |
| 335 distinct `*Receipt`, 209 `*Envelope`, and 54 `*Profile` names exist in `docs/architecture/**/*.md`. The proliferation is not itself a defect — each is owner-qualified — but bare `Run`, `Profile`, and `Envelope` had no rule. | `contract_normalization` | Bare `Run`, `Profile`, `Task`, `State`, `Domain`, `Facilitator` are explicitly non-canonical as standalone names. |

## Phase B/F findings — product and substrate boundary

| Finding | Class | Resolution |
| --- | --- | --- |
| `README.md` states that ioi.ai Goal Space "does not own admitted goal lifecycle, plan selection, execution effects, wallet authority, or global truth", but nothing said so at the object level and no document stated the `Session` / `GoalRun` / `OutcomeRoom` layering. | `new_architectural_requirement` | `term-boundaries.md` owns a section: *Session, GoalRun, and OutcomeRoom Are Three Different Things*, with a which-layer-owns-which table. It quotes the canon's own formulation from `source-of-truth-map.md` — ioi.ai "dogfoods Hypervisor rather than receiving privileged substrate semantics… GoalRun solely owns admitted `goal://` identity and lifecycle" — rather than inventing new doctrine. Enforced by `check-architecture-docs.mjs`. |
| **Caught in review, not shipped.** The first cut assigned `objects/goal-pursuit.md`'s doctrine owner to `domains/ioi-ai/control-plane.md`, inverting that boundary. | `semantic_correction` | Corrected to `components/daemon-runtime/doctrine.md`. |
| **Caught in review, not shipped.** The first cut asserted "GoalRun and OutcomeRoom are substrate primitives that ioi.ai productizes", CI-pinned that novel phrasing, and dropped `governed-autonomous-systems.md` as `OutcomeRoom` co-owner — while `source-of-truth-map.md:167` names it jointly with `collaborative-outcome-pattern.md`. | `semantic_correction` | Co-owner restored; the section now separates *object identity/admission* (substrate) from *doctrine ownership* (per the map, jointly owned) and defers to the owners on substance. The CI pin now quotes pre-existing canon only. |
| **Caught in review, not shipped.** The first cut claimed present-tense that a deployment with no ioi.ai account "creates, admits, runs, verifies, and replays" GoalRuns and OutcomeRooms. `control-plane.md` records that the current product "has not yet passed that end-to-end standalone contract." | `semantic_correction` | Requalified as the **target** contract, with the not-yet-passed status stated inline and `implementation-matrix.md` named as the place to check. |
| **Caught in review, not shipped.** `Facilitation` was defined as ioi.ai help in "drafting, **routing**, synthesis, and presentation". The canon denies ioi.ai routing truth in four places. | `semantic_correction` | "routing" removed; the Must-Not-Mean column now explicitly forbids any claim on route, worker, harness, verifier, or materialization truth. |

## Phase E — rename and compatibility ledger

No identifier that ships in code was renamed. `git diff --name-only a894b2505..HEAD -- crates packages apps` shows only three Rust doc-comment files, changed to repoint documentation references.

| Current name | Canonical name | Reason | Change class | Canon owner | Compatibility impact |
| --- | --- | --- | --- | --- | --- |
| `RunEnvelope` | `WorkRun` | Two names for one concept; the generic one had no code anchor | `canonical_rename` | [`objects/work-execution.md`](../foundations/objects/work-execution.md) | **None at the wire.** `run://`, `run_id`, `/v1/runs/{run_id}` retained and registered |
| `TaskEnvelope` | work request (public: RFW) | `Task` carried four meanings; RFW already shipped publicly | `canonical_rename` | [`objects/work-execution.md`](../foundations/objects/work-execution.md) | **None at the wire.** `task://`, `task_id` retained and registered |
| `### Terminology Boundary Table` | [`term-boundaries.md`](../foundations/term-boundaries.md) | An independently owned subject hidden inside an unrelated one | `ownership_move` | itself | none; zero inbound references to the lost anchor |
| `WorkflowTemplate`/`Skill*` envelopes, formerly H3s under package genesis | [`objects/reusable-work-definitions.md`](../foundations/objects/reusable-work-definitions.md) | Reusable work definitions are meaningful with no System, package, or release | `module_extraction` | itself | headings promoted H3 → H2; **anchor slugs unchanged** |
| `ImprovementGovernanceProfileEnvelope` | [`objects/bounded-improvement.md`](../foundations/objects/bounded-improvement.md) | **Caught in review**: declared in `bounded-system-genesis.md` while three registries claimed it for `bounded-improvement.md` | `ownership_move` | itself | none |

### Term rows reworded during the promotion (`semantic_correction`)

The promotion was **not** purely structural, and the first version of this ledger
wrongly said it was. 7 of the 24 original rows changed normative text:

| Row | Change |
| --- | --- |
| `Agent` | Meaning replaced. Restored after review to keep the original "compatibility alias that may be worker-backed" framing and its subordination to Worker, per non-negotiable 12. |
| `Worker` | Must-Not-Mean widened to add "a model; a harness". |
| `Session` | Must-Not-Mean widened to add durable pursuit, standing behavior, collective pursuit, execution-attempt truth. |
| `Memory` | Must-Not-Mean widened to add "anything the selected model, harness, or local cache owns". |
| `Receipt` | Must-Not-Mean widened to add automatic correctness/verification/acceptance/adjudication/settlement/payout. |
| `Capability`, `Authority` | Gained explicit `prim:*` / `scope:*` bindings. |

Each widening restates a rule the canon already carried elsewhere
(`README.md` non-negotiables 12, 20, 21; `current-canon-defaults.md`), but they
are normative constraints on protected terms and are recorded here as semantic,
not structural.

### Retained wire identifiers

Recorded in [`term-boundaries.md`](../foundations/term-boundaries.md#retained-wire-identifiers).
Each was confirmed present in shipped code before being classified as retained:
`run://` (42 hits), `task://` (25), `goal://` (199), `agent://` (96) across
`crates/`, `packages/`, `apps/`; `/v1/runs/{run_id}` in the daemon run routes.

## Phase D — before/after module map

`foundations/common-objects-and-envelopes.md` became a family: one index owning
the shared kernel, plus 18 modules each owning one architectural responsibility.
The body split is a line-exact contiguous partition — independently verified as
zero prose lines dropped, zero content duplicated, zero broken anchors.

| Module | Lines | Doctrine owner |
| --- | ---: | --- |
| `common-objects-and-envelopes.md` (index) | 779 | — |
| `objects/reusable-work-definitions.md` | 245 | `hypervisor/core-clients-surfaces.md` |
| `objects/bounded-system-genesis.md` | 1,768 | `foundations/governed-autonomous-systems.md` |
| `objects/interop-and-collaboration-terms.md` | 1,054 | `foundations/aiip.md`; `CollaborationTerms` jointly with `collaborative-outcome-pattern.md` + `governed-autonomous-systems.md` |
| `objects/authority-and-access.md` | 559 | `wallet-network/doctrine.md` |
| `objects/work-execution.md` | 489 | `daemon-runtime/doctrine.md` |
| `objects/evidence-and-delivery.md` | 197 | `daemon-runtime/events-receipts-delivery-bundles.md` |
| `objects/economics-and-settlement.md` | 413 | `foundations/economic-flywheel-and-pricing-boundaries.md` |
| `objects/semantic-plane.md` | 446 | `foundations/domain-ontologies-and-data-recipes.md` |
| `objects/institutional-learning.md` | 515 | `foundations/institutional-learning-boundary.md` |
| `objects/model-foundry-and-training.md` | 862 | `hypervisor/foundry.md` |
| `objects/embodied-systems.md` | 1,061 | `daemon-runtime/embodied-runtime.md` |
| `objects/memory-and-promotion.md` | 319 | `daemon-runtime/portable-memory-vault.md` |
| `objects/bounded-improvement.md` | 386 | `foundations/bounded-recursive-improvement.md` |
| `objects/goal-pursuit.md` | 334 | `daemon-runtime/doctrine.md` |
| `objects/collaborative-pursuit.md` | 858 | `ioi-ai/collaborative-outcome-pattern.md` + `foundations/governed-autonomous-systems.md` |
| `objects/work-results-and-lifecycle.md` | 372 | `daemon-runtime/doctrine.md` |
| `objects/goal-run-execution.md` | 840 | `daemon-runtime/doctrine.md` (step resolution only: `default-harness-profile.md`) |
| `foundations/term-boundaries.md` | 247 | itself |

**Six** modules exceed the 800-line threshold this pass introduced —
`bounded-system-genesis` (1,768), `embodied-systems` (1,061),
`interop-and-collaboration-terms` (1,054), `model-foundry-and-training` (862),
`collaborative-pursuit` (858), `goal-run-execution` (840). Each carries a
recorded waiver. Corpus-wide, files over 800 lines or 50 KB went **31 → 36**:
the pass replaced one 11,013-line file with six merely-large ones and did not
reduce total size debt. No module was created to hit a line target.

## Phase H — reader-journey context load (verified)

Bytes of the owner documents a reader must open, `a894b2505` versus now. Every
file set is listed so each row is reproducible.

| Journey | Files before | KB before | Files after | KB after | Change |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Understand what Hypervisor is | 2 | 73 | 2 | 74 | +0% |
| 2. Understand what ioi.ai adds | 2 | 64 | 3 | 87 | **+35%** |
| 3. Start a generic Session with any harness/model/provider | 2 | 253 | 2 | 253 | +0% |
| 4. Contextual assistance without inventing an Assistant object | 2 | 651 | 1 | 23 | −97% |
| 5. Hand work from Hypervisor into an ioi.ai GoalRun | 2 | 518 | 3 | 84 | −84% |
| 6. Materialize an OutcomeRoom from an admitted GoalRun | 2 | 552 | 2 | 104 | −81% |
| 7. Invoke equivalent capabilities natively and over MCP | 2 | 177 | 2 | 177 | +0% |
| 8. Where authority, policy, admission, and receipts occur | 3 | 718 | 4 | 266 | −63% |
| 9. Determine the canonical owner of any major object | 2 | 616 | 2 | 180 | −71% |
| 10. Which implementation stage owns an unimplemented requirement | 2 | 287 | 2 | 287 | +0% |
| 11. Amend one architecture module without loading the canon | 1 | 487 | 1 | 22 | −96% |
| 12. Trace a requirement from canon to conformance evidence | 2 | 495 | 2 | 26 | −95% |
| **Total** | | **4,891** | | **1,583** | **−68%** |

File sets:

```text
J1  before/after  README.md + _meta/start-here.md
J2  before  _meta/start-here.md + domains/ioi-ai/control-plane.md
    after   + foundations/term-boundaries.md
J3  before/after  hypervisor/core-clients-surfaces.md + daemon-runtime/default-harness-profile.md
J4  before  common-objects-and-envelopes.md + _meta/vocabulary.md
    after   foundations/term-boundaries.md
J5  before  common-objects-and-envelopes.md + ioi-ai/control-plane.md
    after   objects/goal-pursuit.md + objects/goal-run-execution.md + ioi-ai/control-plane.md
J6  before  common-objects-and-envelopes.md + ioi-ai/collaborative-outcome-pattern.md
    after   objects/collaborative-pursuit.md + ioi-ai/collaborative-outcome-pattern.md
J7  before/after  connectors-tools/contracts.md + daemon-runtime/api.md
J8  before  common-objects-and-envelopes.md + wallet-network/doctrine.md + events-receipts-delivery-bundles.md
    after   objects/authority-and-access.md + objects/evidence-and-delivery.md
            + wallet-network/doctrine.md + events-receipts-delivery-bundles.md
J9  before/after  _meta/source-of-truth-map.md + common-objects-and-envelopes.md
J10 before/after  _meta/implementation-matrix.md + _meta/execution-horizons.md
J11 before  common-objects-and-envelopes.md          after  objects/work-execution.md
J12 before  common-objects-and-envelopes.md + conformance/hypervisor-core/work-lifecycle.md
    after   objects/work-results-and-lifecycle.md + same conformance file
```

Read the total honestly. **Seven of the twelve "before" sets contain the same
485 KB file**, so roughly 3,398 KB of the 4,891 KB total is one document counted
seven times. That is the finding, not an artifact: one file dominated every
shared-object journey. It is not a claim that the corpus shrank — it did not
(see the 31 → 36 oversized count above).

Two rows need caveats:

- **J2 got worse (+35%)** and is reported as such. Before, "what does ioi.ai add"
  had no document that answered it unambiguously, and a reader could finish
  believing GoalRun is an ioi.ai object.
- **J4's −97% overstates a reduction.** The `Assistant` boundary did not exist
  before, so the "before" figure measures a search that would have *failed*, not
  a cheaper load. The honest claim is *newly answerable*, not *97% cheaper*.

Journeys 1, 3, 7, 10 are unchanged because their owners were not touched. J3
(253 KB) and J10 (287 KB) remain the heaviest and are named as gaps below.

## Phase G — regression protection added

All fail closed in `npm run check:architecture-docs`; each was verified by
breaking the property and observing a non-zero exit.

| Check | Failure mode it closes |
| --- | --- |
| Nested git checkouts skipped when walking `internal-docs/` — **and never under `docs/architecture/`** | A developer worktree failed the whole check; the opposite scoping would let a `.git` marker silently delete a canon subtree from every check |
| Anchor validation on every internal `.md#fragment` link | Link checking only proved the *file* existed |
| Shared-object family section resolution | 20 contract assertions were hard-coded to one file path and would have silently stopped asserting |
| Cross-file duplicate object declarations | The split made a cross-module duplicate possible for the first time |
| **Owner-of-record accuracy** | Catches an object declared in module A while the index and matrices claim it for module B. This defect shipped in the first cut and passed every other check |
| Module registration in the family index and in a navigation surface | An unregistered module is unreachable and its ownership cannot be resolved |
| File size threshold (800 lines / 50 KB) with a named waiver per file, **36 waivers**, stale waivers also fail | Size debt accumulated silently; there was no threshold at all |
| `term-boundaries.md` required rows and substrate/product statements | The boundary owner could be quietly hollowed out |
| Retired terminology outside a retirement context | The alias register listed names nothing enforced |

## Disclosures

These are the things a reviewer would otherwise have to discover.

1. **A pre-existing check was loosened mid-pass and has been restored.** The
   first cut widened `lineIsAllowedLegacyNote` (adding `must not`, `not mean`,
   `deprecated`, `forbidden`, `retired`) and blanket-exempted
   `term-boundaries.md`. That silently retired the `cap:*` / capability-grant
   gate, the canon's most consequential naming rule, while the same diff added a
   comment asserting those tokens "should never appear." The allowance is now
   byte-identical to the pre-change version, and the alias register's exemption
   is scoped to the `## Deprecated and Forbidden Aliases` section only.
2. **The retired-terminology check was initially trivially bypassable** — its
   allowance matched a bare `not` anywhere within ±2 lines. It now requires an
   explicit retirement word or a negation bound to the term itself.
3. **`docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`
   was rewritten**: 22 `canonical_owner_ref` values repointed to the owning
   modules. It is the only machine artifact touched by this pass.
4. **`scripts/lib/m0-program-control-model.mjs` `CANON_BASIS_FILES` was
   extended.** The split moved 10,263 lines of owner canon out of a sha256-pinned
   drift-detection basis that still named only the 779-line index. The 18 modules
   are now pinned. **This changes the pinned set and will require an M-sequencer
   program-state refresh**, which is deliberately not performed here.
5. **`internal-docs/implementation/` is gitignored.** Anchor rewrites were
   applied to files there so those records stay consistent, but **those edits are
   not part of any commit.** One pre-existing broken anchor was found and left
   alone rather than silently fixed:
   `internal-docs/implementation/program/canon-map.v1.json` references
   `#autonomoussystemactivationproposalenvelope`, which has never existed.
6. **~189 links point at the family index with no anchor** (tracked `.md` only:
   158). They resolve, and now land on a complete module registry. They were not
   individually repointed. An earlier draft of this ledger said 372; that figure
   double-counted a nested checkout of this same repository.
7. **8 owner cells still cite the index** (7 in `implementation-matrix.md`, 1 in
   `canon-to-code-delta.md`). Each names an object that is not declared anywhere
   in the family — `prim:*`, `MCPPrimitiveNormalization`, `HypervisorFoundry`,
   `WorkerPackage`, and similar — so the index citation is a supporting
   reference, not a stale owner. The new owner-of-record check skips these by
   design and would fail on a genuine mis-assignment.
8. **Per-module implementation status is not a fresh audit except in three
   cases.** The first cut derived 19 status lines from one blanket paragraph and
   stamped `Last implementation audit: 2026-07-25` on all of them without
   performing an audit — and three of the derived lines said "planned / not
   started" for object planes with **mounted daemon routes on master**. Those
   three (`semantic-plane`, `institutional-learning`,
   `model-foundry-and-training`) are now corrected to `partial`, carry
   `Implementation refs` to the mounting sites, and are dated
   `2026-07-25 (route-mount audit against current master)`. The other 15 carry
   `2026-07-19 (inherited from the pre-split file; not independently
   re-audited)`.
9. **`check-pre-next-leg` fails on this branch and did before this pass.** All
   4,391 failure references are stale Rust route anchors under `crates/node/`;
   this pass changed no `.rs` logic. The gate depends on gitignored local
   sequencer state, so a clean baseline comparison in a fresh worktree was not
   possible.

## Remaining gaps, ranked by impact

1. **`components/hypervisor/core-clients-surfaces.md` — 4,569 lines, 43 H2
   sections.** Now the largest canonical file, mixing Hypervisor Core, clients,
   product IA, ~14 application surfaces, adapters, and environment ops. Strongest
   remaining split candidate; waiver marked `REVIEW:`. Dominates journey 3.
2. **`components/daemon-runtime/events-receipts-delivery-bundles.md` — 4,018
   lines, 41 receipt families.** Dominates journey 8's remaining 266 KB.
3. **`_meta/implementation-matrix.md` — 245 KB in 398 lines.** Rows several
   thousand characters wide. Dominates journey 10. Content is right; the shape is
   hostile to reading and diffing.
4. **Total size debt was not reduced** (31 → 36 oversized files). The pass moved
   from one unreadable file to several large ones. Items 1–3 are where the next
   pass should go.
5. **Daemon, GoalRun, and OutcomeRoom profile semantics are not yet aligned to
   the reconciled canon.** This is expected and explicitly deferred to a
   subsequent pass: this pass states the target contract and records the delta;
   it must never be read as a claim that the runtime already conforms. Track it
   in [`canon-to-code-delta.md`](./canon-to-code-delta.md).
6. **An M-sequencer program-state refresh is required** because
   `CANON_BASIS_FILES` changed (disclosure 4).
7. **`WorkRunEnvelope` has no schema section.** `WorkRun` is canonical and
   code-anchored, but the family still carries its shape under the retained
   `RunEnvelope` heading.
8. **`SkillEntry` lifecycle is undefined.** The envelope exists; no owner
   document describes its revisioning or narrowing rules beyond one boundary row.
