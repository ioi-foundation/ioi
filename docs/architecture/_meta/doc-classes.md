# Architecture Documentation Classes

Status: canonical metadata vocabulary.
Canonical owner: this file for architecture documentation class names and placement rules.
Supersedes: ad hoc document-type labels in architecture headers.
Superseded by: none.
Last alignment pass: 2026-06-23.
Doctrine status: canonical
Implementation status: mixed (documentation metadata vocabulary)
Last implementation audit: 2026-07-05

## Purpose

This register names the document classes used to keep architecture doctrine, reference material, implementation plans, conformance contracts, and generated evidence from drifting back into one mixed corpus.

## Classes

| Class | Meaning | Primary Home |
| --- | --- | --- |
| `canonical-index` | Navigation and ownership index. | `docs/architecture/README.md`, `docs/architecture/_meta/` |
| `canonical-digest` | Current cross-owner architecture defaults that help readers orient before opening subject owners. Digest docs summarize; they do not override owner docs. | `docs/architecture/_meta/` |
| `canonical-doctrine` | Stable architecture authority prose. | `docs/architecture/foundations/`, `docs/architecture/components/`, `docs/architecture/domains/` |
| `canonical-reference` | Low-level APIs, object models, endpoint references, and contracts. | `docs/architecture/components/`, selected endpoint references under `docs/architecture/domains/` |
| `canonical-schema` | Shared schemas that drive generated contracts. | `docs/architecture/_meta/schemas/` until schema generation is split into a package |
| `conformance-contract` | Hidden or public invariant contracts used for conformance checks. | `docs/conformance/` |
| `implementation-plan` | Sequencing, package maps, milestones, and source-tree guidance. Internal master guides are private execution scaffolding and do not own doctrine. | `internal-docs/implementation/` and local ignored plans under `.internal/plans/` |
| `product-context` | Product-surface reference material and UX intent that follows canonical doctrine. | `internal-docs/architecture/products/` |
| `decision-history` | Resolved historical decisions retained only when future maintainers need the reason. | Nearest owning component or `_meta/changelog/` |
| `formal-source` | TLA+, configs, proof source, and formal-model READMEs. | `internal-docs/architecture/protocols/aft/formal/` |
| `formal-generated` | TLC traces, generated trace modules, state dumps, and model-checker byproducts. | `internal-docs/formal/aft/` |
| `evidence-artifact` | Validation outputs, scorecards, screenshots, bundles, and run reports. | `docs/evidence/` |

## Status Axis (Doctrine vs Implementation)

Every canon file carries two orthogonal status fields in its front matter,
plus an audit date and optional code refs:

```text
Doctrine status: canonical | draft | reference | archived
Implementation status: built | partial | planned | speculative | mixed
Implementation refs:            # only when built or partial
  - path/or/route/ref
Last implementation audit: YYYY-MM-DD
```

Rules:

- `Doctrine status` says whether the architecture prose is authoritative.
  `reference` marks low-level listings whose source of truth is (or should
  become) code; `archived` marks history that no longer binds anyone.
- `Implementation status` says whether the described system exists today.
  `built` and `partial` name their code anchors in `Implementation refs`;
  `speculative` is a maturity statement, never a scope cut.
- The axes are independent: a file may be canonical **and** speculative
  (future doctrine is still doctrine), or reference **and** built. Never
  demote doctrine because implementation is future.
- A short parenthetical after the implementation value states what exactly is
  built/missing — prefer one honest clause over a bare label.
- When implementation state changes, update the file's status line and
  `Last implementation audit` in the same change that lands the code, or in
  the next alignment pass.

Horizon framing for the whole corpus lives in
[`execution-horizons.md`](./execution-horizons.md); per-concept durable-form
status lives in [`implementation-matrix.md`](./implementation-matrix.md).

## Placement Rule

`docs/architecture/` should not contain `implementation-plan`,
`product-context`, `formal-source`, `formal-generated`, `evidence-artifact`,
`.st`, `.fp`, `.bin`, `.aux`, `.log`, `.out`, generated trace modules, or
`states/` directories. Architecture docs may reference those artifact classes
only when the generated output is necessary public evidence.

`docs/architecture/_archive/` is the exception lane: verbatim historical
extractions (change ledgers, build logs, former specs) live there with
`Doctrine status: archived` and are never authority. The two `_meta`
migration artifacts (the non-doctrinal migration/evidence guide and
implementation ledger) remain in place as reference and status artifacts;
their per-slice history has been moved to `_archive/change-ledgers/`.

## Canonical Owner Shape

Major owner docs should converge toward this reader shape when edited:

```text
Definition
Owns
Does Not Own
Core Objects
Lifecycle / State Transitions
Interfaces / APIs / Surfaces
Receipts / Proof / Audit
Related Owners
Implementation Anchors
Supporting Context / Appendix
```

Do not force every file into every heading. Use the shape where it reduces
split-brain, clarifies implementation ownership, or keeps long supporting
context from competing with current doctrine.
