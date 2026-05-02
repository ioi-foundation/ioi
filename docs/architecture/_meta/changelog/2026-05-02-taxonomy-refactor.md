# Architecture Taxonomy Refactor

Status: refactor report.
Canonical owner: this file for the 2026-05-02 architecture taxonomy pass.
Supersedes: `docs/architecture/operations/` as a mixed metadata, roadmap, and generated-reference home.
Superseded by: future documentation refactor reports.
Last alignment pass: 2026-05-02.

## Executive Verdict

The architecture corpus now separates stable architecture authority from implementation plans, conformance contracts, product context, protocol references, and generated formal outputs.

## New Documentation Structure

```text
docs/architecture/
  README.md
  _meta/
  foundations/
  components/
  products/
  domains/
  protocols/

docs/implementation/
  roadmap-and-dependencies.md
  low-level-implementation-milestones.md
  runtime-module-map.md
  runtime-package-boundaries.md
  runtime-action-schema.json

docs/conformance/
  agentic-runtime/

docs/formal-artifacts/aft/
  generated/
  traces/
  states/
```

## Boundary Decisions

- Architecture keeps canonical doctrine, low-level component references, protocol source, and formal source.
- Implementation keeps roadmaps, source-tree maps, package boundaries, and generated-contract schema inputs.
- Conformance keeps CIRC/CEC outside the architecture tree.
- `docs/formal-artifacts/aft/` keeps TLC traces, state dumps, and compiled yellow paper outputs.

## Validation

Required validation for this refactor:

```text
npm run check:architecture-docs
npm run check:pre-next-leg
```
