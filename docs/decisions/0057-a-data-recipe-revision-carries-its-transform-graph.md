# ADR 0057: A DataRecipe Revision Carries Its Transform Graph, Over A Registered Operator Catalog

Status: Proposed (awaiting owner decision)

Date: 2026-09-27

Relates to: [ADR 0056](./0056-organize-the-hypervisor-application-estate-by-four-axes-and-retire-missions.md)
(Amendment 1, plane 4: change sets — the patch branch a recipe draft lives on), the
semantic plane's `DataRecipeEnvelope` (docs/architecture/foundations/objects/semantic-plane.md),
and R-241 (the UX seed depth phase: adopt the reference Pipeline Builder, never recreate it).

## Context

The adopted Pipeline Builder now lists DataRecipe families as pipelines, creates one as a founding
change set, and opens a pipeline's editor read-only (ledger CXCV–CXCVII). The next step is the
editor's writes: a person adds a transform, wires it, sets its arguments, and saves. A save should
become a draft on the pipeline's change set, validated by DataRecipe admission and merged as the
family's next revision.

That cannot round-trip today. A DataRecipe revision declares its transformations as
`transformation_steps`: at most eight coarse phase names (`extract`, `redact`, `normalize`, `dedupe`,
`validate`, `map`, `link`, `export`), a set with no order, no arguments and no edges. The reference
editor's unit of work is a GRAPH: transforms (an operator id and version, typed arguments — column
references, expressions, literals), edges from one transform's output to another's input, and targets
bound to outputs. Admission builds the record from its named fields only, so any graph a draft carried
would vanish at merge. The mapped wire (`.artifacts/mvp-finish-line/cut2d-editor-write-wire-2026-09-27.md`)
confirms there is no lossless mapping: every reference transform carries arguments the step set cannot hold.

Canon already says a recipe "declares transformations and output contracts" and that a released
revision is immutable and content-addressed. What it declares today is too coarse to execute or to edit.

## Decision (proposed)

1. **DataRecipe v3 adds `transform_graph`**, committed in the revision's `content_hash`:
   - `nodes[]`: `{ node_id, operator_ref (an exact revision in the operator catalog), phase (one of the
     eight canon steps), arguments (typed: column_ref | expression | literal | node_output_ref) }`;
   - `edges[]`: `{ from: node_id#output, to: node_id#input }` (acyclic; admission refuses a cycle);
   - `outputs[]`: `{ node_id#output → output_dataset_contract_ref | output_object_model_ref }`.
   `transformation_steps` becomes DERIVED — the set of the graph's node phases — so v2 readers and
   the step-level policy that keys on phases keep working. A v2 revision (no graph) stays valid and
   readable; a successor may add a graph.
2. **A registered operator catalog** (a family of immutable operator revisions: id, version, typed
   input/output ports, argument schema, the phase it belongs to, and whether the TransformationRun
   executor implements it). The editor's transform picker reads THIS catalog — not the reference's —
   so the adopted builder can only draft what the Hypervisor can execute. Its first members are the
   operators the executor already performs for the canon steps.
3. **The editor's writes then map losslessly**: a save is a draft whose body is the v3 admission
   request (graph included); validation is admission's own check (graph well-formed, every operator
   revision exact and executable, every output bound to a declared contract); merge admits the next
   revision; Deploy admits a TransformationRun of it. Layout (node positions) is presentation, not
   recipe content — kept on the change set's draft as an uncommitted display member, never in the
   revision's hash.

## Alternatives

- **A separate `RecipeGraph` family bound by exact revision from the recipe.** Rejected as proposed:
  a second family and a second binding for content the recipe already claims to declare, with no
  independent lifecycle.
- **Keep the step set; the editor refuses graph edits.** The status quo: the adopted editor stays
  read-only for anything but naming, and a pipeline can never be built in the product.
- **Store the reference's snapshot verbatim in the draft.** Rejected: it would admit the reference
  vendor's operator vocabulary as ours, which the executor cannot run and canon does not define.

## Consequences

- A contract revision (`data-recipe/v3`), admission changes, and a new operator-catalog plane; the
  TransformationRun executor must implement the catalog's first operators.
- The adopted editor's transform picker binds to the operator catalog (the `transformations/all` read
  that still passes through to the local mirror is then answered from it).
- Until decided, cut 2d binds only what needs no graph: edit mode for naming and outputs that name
  declared contracts, Proposals (proposed change sets), History (revisions), and a named gap on the
  graph (as today).

## Cost of being wrong and reversal

The graph member is additive and versioned: v2 recipes are unaffected, and a v3 revision that proves
wrong is superseded by a successor, never rewritten. The operator catalog is a registry of immutable
revisions; retiring an operator deprecates it without invalidating recipes already admitted over it.
