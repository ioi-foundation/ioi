# Implementation-Plan Estate Reconciliation

Classification: `WORK-RECORD`.
Status: non-authoritative reconciliation work record.
Doctrine status: reference
Implementation status: built (this inventory artifact only; no product, stage, or cut status)

Snapshot inputs: ignored implementation estate from
`feat/estate-camera-pipeline` at `a894b2505`; tracked planning estate from
`origin/master` at `69592149186cb29383a397ad0aa3ad6f5ab4ab7b` (the merge of PR #103), inspected on 2026-07-22.
The authority findings below also include the approved stateless-guide slice
applied to the reconciliation worktree's ignored master-guide copy.

This report owns no architecture doctrine, implementation sequence, stage or
cut status, closure claim, product claim, or source disposition. It records a
point-in-time classification and routes every operative fact to its one owner.
It does not activate work, amend the M0-M14 sequencer, close a stage, or treat
workflow evidence as product authority. Work-item evidence is an unsigned
development-workflow record; wallet grants, sealed intents, and receipts remain
the product authority boundary.

## Classification contract

Each inventoried source has exactly one class in this report:

- `AUTHORITY` owns only the narrow fact family named in its row. An internal
  specialist authority never becomes a peer architecture owner or sequencer.
- `PROJECTION` is derived from named owners. Its row names a regeneration or
  validation command; the command proves only its stated scope.
- `WORK-RECORD` preserves one cut, audit, or research run and cannot direct new
  work or carry status for a different cut.
- `SUPERSEDED` has no operative owner role. Historical detail remains evidence
  at its stable path, with an execution-routing tombstone to the current owner.

`SUPERSEDED` is a logical classification, not permission to move a file. The
master guide's preservation rule currently forbids deleting, moving, or
stripping source plans. Consequently every physical archive action requested by
the reconciliation prompt is blocked unless the user first approves a
sequencer amendment. This cut keeps all ignored sources in place.

## One owner per fact

| Fact family | Sole owner | Non-owner treatment |
| --- | --- | --- |
| Architecture meaning, object contracts, authority boundaries, and product membership | The subject owner routed by [`source-of-truth-map.md`](../source-of-truth-map.md), or an accepted ADR | Guides, matrices, deltas, plans, captures, and work records point to the owner. |
| Canonical dependency and claim horizons | [`execution-horizons.md`](../execution-horizons.md) | It owns horizon doctrine, not live cut activation or status. |
| M0-M14 activation, implementation-stage dependencies, proof/claim gates, and source-plan disposition | `internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md` | No other file may reorder or activate the spine. |
| Concept-to-owner and durable-form mapping | [`implementation-matrix.md`](../implementation-matrix.md) | It points to cut records for status and cannot override a subject owner. |
| Object-to-owner/code-anchor crossings and contract-dependency pointers to application projections | [`canon-to-code-delta.md`](../canon-to-code-delta.md) | Its bounded anchor coverage is not work-item or stage status. |
| Per-cut implementation status and retained nonclaims | The matching `ioi.program.work_item.v1` record | Matrix and delta rows carry doctrine, code/evidence pointers, and record links only. |
| Aggregated session orientation | `internal-docs/implementation/program-state.json`, as a derived projection of records and retained evidence | It is not a status owner, grants and closes nothing, and is regenerated at master-guide section 13.3 step 9. |
| A claimed proof | Committed artifact or retained log with the literal applicable `*_EXIT=` value, cited by the cut record | Command process status alone never upgrades a claim. |
| `PG-*` gate definitions, evidence requirements, and specialized gate-closure ledger | `internal-docs/implementation/canon-mechanism-hardening-action-plan.md` | This is the master's explicit specialist-ledger exception. Cut status still belongs to work-item records; gate activation/order stays with the master. |
| `UX-00`, taxonomy-migration coverage, pressure tests, and usability measures | `internal-docs/implementation/hypervisor-bounded-das-application-taxonomy-winning-state-plan.md` | Canon owns names and membership; the master owns activation. |
| M8 statistical, evaluator-integrity, exposure, fault, and experiment methodology | `internal-docs/implementation/bounded-recursive-improvement-campaign-discovery-plan.md` | Canon owns Campaign meaning; the master owns activation. |
| Runtime trust-audit method classification and extraction proof obligations | `internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md` | Current code is runtime truth; the residual JSON is only its checked projection. |
| Architecture reader orientation | [`start-here.md`](../start-here.md) | It owns reading paths, not the doctrine summarized along them. |
| Ignored-estate navigation | `internal-docs/implementation/README.md` | It routes to the master and preserved sources; it owns no sequence or status. |

## Ignored `internal-docs/implementation/` inventory

The inventory includes every file in the inspected directory, including
post-consolidation runtime and work-record additions that are absent from the
master guide's section 14 inventory.

| Source | Exact class | Narrow owner or derivation | Pointer and archive disposition |
| --- | --- | --- | --- |
| `README.md` | `AUTHORITY` | Local navigation and conflict-order entry point only. The master owns sequence; tracked canon owns doctrine. | Keep at the stable path. Its current pointer to the master is sufficient; any preserved "program status" wording is subordinate to the master's Status Truth Rule. |
| `bounded-recursive-improvement-campaign-discovery-plan.md` | `AUTHORITY` | Conditional M8 experiment methodology: statistics, evaluator integrity, exposure, search order, fault, and experiment design. Canon owns the Campaign contract. | Keep in place with its existing execution-routing preamble. Do not archive while the master preservation rule stands. |
| `canon-mechanism-hardening-action-plan.md` | `AUTHORITY` | Definitions, required evidence, and the specialized closure ledger for the 58 `PG-*` gates. It owns no architecture doctrine, cut status, or M-stage activation. | Keep in place with its existing routing preamble. Master sections 2.3, 13.3 step 6, and 14.1 retain this explicit specialist-ledger exception; do not silently relocate it. |
| `canon-sota-improvement-review.md` | `WORK-RECORD` | Dated 2026-07-16 comparative audit, methodology, findings, and research provenance. | Keep as historical evidence. Recommendations point to canonical owners or the master and schedule nothing. |
| `check-program-state.mjs` | `AUTHORITY` | Validation contract for the local program-state projection; it owns no stage fact. | Keep beside the ignored projection. Run `node internal-docs/implementation/check-program-state.mjs`. |
| `hypervisor-bounded-das-application-taxonomy-winning-state-plan.md` | `AUTHORITY` | Specialist `UX-00` ledger, migration detail, seed coverage, pressure tests, and usability measures. | Keep in place with its routing preamble. Product names/membership point to canon; activation points to M6/M9 and `WP-UX` in the master. |
| `hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md` | `WORK-RECORD` | Completed model-mount/JS-daemon retirement checkpoint and regression provenance. | Keep at its backlink-stable path. Its phase sequence is historical; current runtime owners and checked code carry present truth. |
| `hypervisor-unified-rust-daemon-lifecycle-migration.md` | `SUPERSEDED` | No owned fact; it is already a compatibility tombstone for a removed plan. | Keep the pointer in place. It routes to the master, current daemon canon, and current runtime evidence. Physical archive is prohibited. |
| `ioi-design-system-portable-package-plan.md` | `SUPERSEDED` | Track 1 obligations were absorbed/completed; remaining adoption and ESM ideas are reference detail pulled only by M6/M9 `WP-UX` and the current package owner. | Keep in place with its existing partially-absorbed tombstone. Do not execute its rollout as an independent queue or physically archive it. |
| `ioi-target-end-state-master-implementation-guide.md` | `AUTHORITY` | Sole internal M0-M14 sequencer, implementation-stage activation/proof gates, and source-disposition ledger. Architecture owners still outrank it for meaning. | Keep in place and never duplicate. The approved stateless-guide slice now places the Status Truth Rule at the front door, replaces dated stage narratives with record/projection pointers, and makes section 13.3 step 9 the projection-regeneration rule. Its exact ignored-file change is preserved by the tracked [`WORK-RECORD` manifest](../reconciliation/stateless-master-guide.v1.json) and [reviewable patch](../reconciliation/stateless-master-guide.v1.patch). Further amendments require explicit user approval. |
| `ioi-undeniable-product-proof-implementation-guide.md` | `SUPERSEDED` | The first-proof profile, goal-pass discipline, scorecard, release ladder, and stop rules were absorbed; its dependency graph owns nothing. | Keep at the stable path with its existing sequencing-superseded tombstone to the master and comparative-research prompt. Physical archive is prohibited. |
| `low-level-implementation-milestones.md` | `SUPERSEDED` | Compatibility pointer only; it contains no operative low-level milestone sequence. | Keep the stable backlink and route sequencing to the master. Physical archive is prohibited. |
| `program-state.json` | `PROJECTION` | Derived aggregate of the master, work-item records, committed evidence, and current repository/PR facts. | Regenerate with `npm run generate:program-state` in the section 13.3 status transaction; validate with `node internal-docs/implementation/check-program-state.mjs`. Keep machine-local and ignored. |
| `refine-architecture.md` | `SUPERSEDED` | June pressure-audit evidence only. Its "master" title, Current Spine, application taxonomy, paths, and phase order own nothing. | Keep at the ADR/test-backlink path with its existing sequencing-superseded tombstone to the master and canon. Physical archive is prohibited. |
| `runtime-action-schema.json` | `PROJECTION` | Byte mirror of `docs/architecture/_meta/schemas/runtime-action-schema.json`; the tracked schema is the only owner. | Refresh only from the tracked owner; validate with `cmp -s internal-docs/implementation/runtime-action-schema.json docs/architecture/_meta/schemas/runtime-action-schema.json`. |
| `runtime-kernel-namespace-residual.v1.json` | `PROJECTION` | Derived residual module/type/method census over current Rust code and the trust audit. | Regenerate with the owning audit/code transaction; validate with `node scripts/internal/verify-runtime-kernel-trust-audit.mjs`. |
| `runtime-kernel-service-trust-boundary-audit.md` | `AUTHORITY` | Specialist method-by-method trust classification, standing extraction invariants, and required negative proofs. It does not own runtime truth, stage order, or architecture doctrine. | Keep in place. Activation comes only through M0.9/`WP-RUNTIME`; validate the complete inventory with `node scripts/internal/verify-runtime-kernel-trust-audit.mjs`. |
| `runtime-module-map.md` | `SUPERSEDED` | No current layout fact: it names deleted JS-daemon and bridge roots. Current daemon canon, code, and checked implementation projections own layout. | Keep the existing stale-reference tombstone and stable path. Never use the body as a current map; physical archive is prohibited. |
| `runtime-package-boundaries.md` | `SUPERSEDED` | Reference checklist only; current canonical runtime owners own boundaries, and its paths/taxonomy require refresh. | Keep the existing conditional-reference tombstone. Route every applied boundary to canon/current code; do not execute it as a plan or physically archive it. |
| `work-item-m1-5-protected-transitions.md` | `WORK-RECORD` | Human-readable M1.5 cut design/progress log. The machine record `docs/architecture/_meta/work-items/m1-5-protected-transitions.v1.json` is the only cut-status owner. | Keep the append-only detail in place. Add a routing pointer to the JSON record rather than treating the Markdown `Status:` or increment labels as live status; do not strip the preserved body. |

## Tracked `_meta` planning and status estate

| Source | Exact class | Narrow owner or derivation | Regeneration, validation, and pointer disposition |
| --- | --- | --- | --- |
| [`implementation-matrix.md`](../implementation-matrix.md) | `AUTHORITY` | Concept-to-owner and durable-form mapping doctrine. Subject owners still own object meaning; work-item records own cut status. | The live 269-row index is stateless and points to every record. Its former status-bearing body is preserved at [`implementation-matrix-pre-status-truth-snapshot.md`](../../_archive/change-ledgers/implementation-matrix-pre-status-truth-snapshot.md) as non-operative history. Validate with `npm run check:architecture-docs && npm run check:work-items`. |
| [`execution-horizons.md`](../execution-horizons.md) | `AUTHORITY` | Canonical horizon framing, contract dependency order, and claim horizons. It does not activate cuts. | Keep tracked and canonical. Its fourteen-step contract order feeds the master; it must not become a second live sequencer. |
| [`canon-to-code-delta.md`](../canon-to-code-delta.md) | `AUTHORITY` | Stable object-to-owner/code-anchor crossing identities and contract-dependency pointers to application projections only. Subject docs own doctrine, work-item records own status, and the master owns activation. | Retain bounded owner/code/evidence crossings plus record pointers. Validate with `npm run check:canon-to-code-delta`; that dedicated checker is wired into `npm run check:pre-next-leg`. |
| [`source-of-truth-map.md`](../source-of-truth-map.md) | `AUTHORITY` | Subject-to-canonical-owner routing and conflict precedence. | Keep tracked and canonical. Validate its structural/owner invariants with `npm run check:architecture-docs`. |
| [`start-here.md`](../start-here.md) | `AUTHORITY` | First-read orientation and role-based reading paths only. Its summarized doctrine remains owned by the linked subject files. | Keep tracked and canonical. Document-class metadata and stable claim ceilings are not cut status; any durable cut-state assertion routes to work-item records and the local orientation projection. |
| [`work-items/README.md`](./README.md) | `AUTHORITY` | `ioi.program.work_item.v1` format, validation convention, and rule that each record owns its cut's implementation status. | Keep as the status-layer front door; validate records with `npm run check:work-items`. |
| `work-items/*.v1.json` | `WORK-RECORD` | One record owns exactly one cut's status, claim, anchors, evidence, and nonclaims. This transaction contains the six pre-existing M0/M1 records plus 36 proposed M0-M14 gap records. | Keep one file per cut, named from `work_item_id`; validate all 42 with `npm run check:work-items`. |
| [`m0-m14-plan-gap-audit.md`](./m0-m14-plan-gap-audit.md) | `WORK-RECORD` | Snapshot stage-by-stage demanded/specified/proven/missing audit and proposed-cut rationale only. | Keep with the reconciliation PR. It neither amends the sequencer nor owns the status of any proposed record. |
| [`stateless-master-guide.v1.json`](../reconciliation/stateless-master-guide.v1.json) and [`stateless-master-guide.v1.patch`](../reconciliation/stateless-master-guide.v1.patch) | `WORK-RECORD` | Exact, non-authoritative review representation of the approved stateless change to the ignored sole sequencer, binding the estate base, reviewed result, and full-context unified patch by SHA-256. | Keep with the reconciliation PR. `npm run check:stateless-master-guide` always reconstructs and hash-validates the full base and result from the tracked patch and validates the reconstructed result's stateless semantics; when the ignored guide is present it additionally requires the local bytes to match the reviewed result hash. |
| `scripts/check-work-items.mjs` | `AUTHORITY` | Machine validation rules for work-item records and matrix-pointer coverage; it owns no cut status. | Run through `npm run check:work-items`; keep it in `check:pre-next-leg`. |
| `scripts/check-canon-to-code-delta.mjs` | `AUTHORITY` | Machine validation rules for the delta projection; it owns no architecture or implementation fact. | Run through `npm run check:canon-to-code-delta`; keep it in `check:pre-next-leg`. |
| This report | `WORK-RECORD` | This point-in-time estate inventory only. | Keep with the reconciliation PR. Future status or sequence changes do not occur here. |

## Duplicated facts and collapse disposition

| Duplicate | One owner | Collapse rule |
| --- | --- | --- |
| M0-M14 order in the master, the undeniable-proof guide, refine guide, taxonomy plan, hardening cuts, campaign phases, and low-level pointer | Master for live activation; execution horizons for canonical dependency/claim-horizon doctrine | Older phase/dependency lists are non-executable. Keep their routing tombstones and historical detail. |
| First-proof profile in execution horizons, the undeniable-proof guide, and the master | Canonical profile doctrine in execution horizons/subject owners; implementation activation and proof aggregation in the master | The undeniable-proof guide remains retained detail only. |
| Per-cut status in matrix cells, delta rows, guides, Markdown cut logs, JSON records, and program state | One JSON record per cut; `program-state.json` is only the derived session view | Live guide/matrix prose becomes doctrine, proof definition, evidence, or a pointer. Preserved source bodies remain historical evidence, and the `PG-*` ledger retains its narrower specialized closure role. |
| Product taxonomy and membership in the taxonomy plan, refine guide, start-here, and current code | Canonical Hypervisor owner docs routed by the source map | Taxonomy-plan `UX-00` evidence survives; old names and membership assertions do not. |
| M8 Campaign meaning in the campaign plan and canon | Canonical bounded-improvement/Common Objects owners | The campaign plan owns experiment methodology only. |
| Runtime layout/boundaries in the module map, package-boundary checklist, trust audit, archived kernel records, canon, and code | Current daemon subject owners for doctrine; current code plus checked projections for implementation evidence | Module map/package-boundary bodies are reference history. The trust audit owns only its method classification/proof obligations. |
| Runtime action schema in the ignored and tracked paths | `docs/architecture/_meta/schemas/runtime-action-schema.json` | Ignored file is a byte projection and never a second schema owner. |
| M1.5 status/design in the ignored Markdown log and tracked JSON records | `m1-5-protected-transitions.v1.json` owns the umbrella cut status; `m1-5b-generic-protected-transitions.v1.json` owns the distinct generic operational slice status; Markdown retains cut detail only | Keep the records distinct and the Markdown pointer-only for status; do not strip the log. |

## Conflicts that must not be resolved silently

1. Physical archive versus preservation. The reconciliation prompt says to
   archive superseded or overlapping plans. The master guide's top-level
   preservation rule and sections 2.2/14 instead require every source plan to
   remain unmoved and unstripped. The guide wins. No source was moved, deleted,
   stripped, or physically archived. Changing that requires an explicit
   `SEQUENCER AMENDMENT`.

2. `pending` is a stage state, not a work-item state. The reconciliation
   prompt requests new work-item records with `status: pending`, but master
   section 4.1 and `scripts/check-work-items.mjs` allow only `proposed`,
   `scoped`, `active`, `evidence_ready`, `verified`, `blocked`, `superseded`,
   or `rejected`. Master section 4.4 separately allows a stage to be
   `pending`. The guide wins: a newly identified, unadmitted plan gap uses
   `status: proposed`; writing `pending` would make the required checker fail.

3. Sole sequencer versus canonical build order. The master guide section 2.1
   ranks execution horizons above itself, and section 14.5 says execution
   horizons owns M1-M14 order and horizon claims. Execution horizons contains
   a fourteen-step "ORDER work is pulled in" list. Until amended, the
   non-overlapping reading is: execution horizons owns canonical contract
   dependencies and claim horizons; the master alone activates and sequences
   implementation cuts. If "sole sequencer" is intended to remove the tracked
   order list too, the user must amend the master first.

4. Runtime specialist authority drift. The master guide section 2.3 calls the
   kernel unification guide and migration matrix active canonical
   implementation authorities. At tracked commit `69592149186cb29383a397ad0aa3ad6f5ab4ab7b`, the source map
   and implementation matrix classify both as archived terminal records with
   no current status, doctrine, or sequence. The master's own precedence gives
   the source map priority, so current daemon owners/code win and the master's
   specialist list is stale.

5. Source-coverage ledger drift. Master section 14 inventories the original
   twelve sources and the later trust audit, but not the subsequently added
   `runtime-kernel-namespace-residual.v1.json`,
   `work-item-m1-5-protected-transitions.md`, `program-state.json`, or its
   checker. This report records them but cannot amend the master's disposition
   ledger.

The approved stateless-guide slice is already applied and is not an open
conflict: the guide now declares the Status Truth Rule at its front door,
replaces its dated baseline and live stage narratives with record/projection
pointers, and routes section 13.3 status updates to the owning record. The
hardening plan's `PG-*` gate-closure ledger is an explicit, narrower specialist
exception, not a second owner of cut status. Likewise, document-class metadata,
durable-form doctrine, stable claim ceilings, preserved old-plan prose, and
append-only work logs are not all removable "status": the preservation rule
keeps source detail, while routing tombstones prevent it from becoming live
truth.

## Validation findings

- The program-state transaction targets the 42-record status layer, the
  deduplicated set of ongoing records discovered across the workspace and
  refs, and the committed M0 exit artifact. Final regeneration and local
  validation follow the rebased M0 evidence refresh; neither step can close a
  stage without its committed literal exit proof.
- The ignored runtime action schema was byte-identical to its tracked canonical
  owner under the `cmp -s` command above.
- `node scripts/internal/verify-runtime-kernel-trust-audit.mjs` passed the
  198-method baseline, four exact service allowlists, 52-module residual ledger,
  and full Rust-source inherent-implementation scan.
- `npm run check:work-items` structurally covers all 42 records and their
  matrix pointers; the 36 new records are `proposed`, as the guide requires.
  The final all-green run follows refresh of the M0 literal wrapper against the
  rebased exit-report hash.
- `npm run check:stateless-master-guide` verified the tracked `WORK-RECORD`
  manifest and full-context patch hash, reconstructed and hash-validated both
  estate base and reviewed result, matched the local ignored guide to that
  result, and validated all 15 stateless stage definitions. Clean checkouts
  run the same semantic validation over the reconstructed result rather than
  skipping it. `npm run check:canon-to-code-delta` passed 50 rows with 54
  explicit implementation-or-precedent anchors.
- `npm run check:architecture-docs` passed after its matrix integrity checks
  were retargeted from deleted live-status cells to the stateless four-column
  concept-owner contract and direct source audits.
- Every Markdown link authored in this report targets a tracked file in the
  reconciliation checkout. Ignored-estate sources are intentionally written as
  repository-relative code paths rather than GitHub links, because they do not
  exist in a fresh tracked worktree.

These checks validate inventory mechanics only. They do not close a stage,
verify a product claim, or replace a literal exit line in retained evidence.
