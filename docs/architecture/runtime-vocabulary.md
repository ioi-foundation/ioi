# Runtime Vocabulary

The agent harness uses behavior-first names in runtime code and reserves
compliance acronyms for hidden audit material.

## Runtime Terms

- `intent`: the semantic operation the user is asking the harness to perform.
- `lane`: a durable runtime capability family such as weather, sports, places,
  recipes, messaging, user input, visualizer, artifact, or inline answer.
- `source`: the origin of information used to answer or act.
- `adapter`: the concrete runtime implementation that executes an action.
- `connector`: a user- or workspace-connected service that may supply private
  context or perform authenticated work.
- `policy`: versioned decision logic for permission, risk, priority, or
  feasibility.
- `constraint`: a typed requirement that must hold before a decision or action
  is valid.
- `evidence`: typed proof that a runtime stage happened or a requirement was
  satisfied.
- `observation`: measured runtime state collected during execution.
- `decision_record`: hidden structured evidence describing a selected lane,
  source, adapter, or outcome.
- `ledger`: authoritative append-only execution attempt state.
- `completion_gate`: the shared API that decides whether a terminal path may
  complete.
- `verification`: typed checks or observations proving the requested outcome.

## Audit Terms

- `receipt`: an immutable audit event emitted for hidden traces or bundles.
- `contract`: a spec-level requirement set, not product UI copy.
- `CIRC`: the intent-resolution compliance specification label.
- `CEC`: the execution-completion compliance specification label.

`CIRC` and `CEC` may appear in specs, trace schema values, evidence bundle
paths, and architecture guard tests. They should not appear in ordinary runtime
type names, helper names, Chat/Spotlight UI copy, or product-facing summaries.
