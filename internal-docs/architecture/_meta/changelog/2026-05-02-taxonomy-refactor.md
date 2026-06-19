# Architecture Taxonomy Refactor

Status: refactor report.
Authority: historical report only; `docs/architecture/` and accepted ADRs are canonical.
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
  refine-architecture.md
  low-level-implementation-milestones.md
  runtime-module-map.md
  runtime-package-boundaries.md
  runtime-action-schema.json

docs/conformance/
  agentic-runtime/

internal-docs/formal/aft/
  generated/
  traces/
  states/
```

Note: the legacy `roadmap-and-dependencies.md` sequencing document was later
retired into `internal-docs/implementation/refine-architecture.md` so the
Hypervisor implementation roadmap has one active owner.

## Boundary Decisions

- Architecture keeps canonical doctrine, low-level component references, protocol source, and formal source.
- Implementation keeps roadmaps, source-tree maps, package boundaries, and generated-contract schema inputs.
- Conformance keeps CIRC/CEC outside the architecture tree.
- `internal-docs/formal/aft/` keeps curated TLC traces, state dumps, and compiled yellow paper outputs.

## Validation

Required validation for this refactor:

```text
npm run check:architecture-docs
npm run check:pre-next-leg
```
