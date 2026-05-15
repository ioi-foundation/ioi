# ADR 0005: Make Domain Ontologies And Data Recipes The Semantic Data Plane

- Status: Accepted
- Date: 2026-05-14
- Owners: Autopilot Foundry / Agentgres / connectors / Worker Training

## Context

Reliable workers need durable domain meaning. Raw documents, traces, schemas,
and connector payloads are useful source material, but they are not enough for
repeatable training, evaluation, policy enforcement, provenance, or
ontology-aware projections.

Serious worker training needs domain meaning.

## Decision

Domain Ontologies and Data Recipes are the semantic data plane for IOI.

Canonical flow:

```text
raw sources
→ ConnectorMapping
→ DataRecipe
→ TransformationRun
→ ontology-bound canonical objects
→ PolicyBoundDataView
→ DistilledOntologyDataset / EvaluationDataset / WorkerTraining / OntologyProjection
→ WorkerManifest, MoW routing, service outcomes
```

Raw source material may seed training, but it does not become durable domain
truth until it is mapped, transformed, authorized, receipted, and projected.

## Consequences

- Workers train on ontology-bound data and policy-bound data views, not raw
  blobs or ambient connector payloads.
- Efficient specialist workers may train from distilled ontology-bound
  datasets: compact high-signal examples, counterexamples, tool traces,
  verifier assertions, rubric judgments, canonical object transitions, and
  failure regressions derived from ontology-bound source truth.
- Distillation does not erase provenance. Distilled datasets bind source
  commitments, recipe versions, policy-bound views, transformation receipts,
  and teacher/verifier refs when used.
- Connector payloads are source material until ConnectorMapping and DataRecipe
  boundaries bind them into canonical domain objects.
- Evaluation datasets bind ontology refs, rubric refs, benchmark refs, source
  commitments, policy, distilled dataset refs when used, and receipt roots.
- Autopilot Foundry should expose ontology, recipe, mapping, data-view,
  transformation, evaluation dataset, and projection controls.
- Agentgres owns ontology and recipe lifecycle state; Filecoin/CAS stores large
  payload bytes; wallet.network controls data-use authority.

## Canonical References

- `docs/architecture/foundations/domain-ontologies-and-data-recipes.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/components/agentgres/api-object-model.md`
- `docs/architecture/components/connectors-tools/contracts.md`
