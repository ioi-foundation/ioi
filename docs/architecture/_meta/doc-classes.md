# Architecture Documentation Classes

Status: canonical metadata vocabulary.
Canonical owner: this file for architecture documentation class names and placement rules.
Supersedes: ad hoc document-type labels in architecture headers.
Superseded by: none.
Last alignment pass: 2026-05-02.

## Purpose

This register names the document classes used to keep architecture doctrine, reference material, implementation plans, conformance contracts, and generated evidence from drifting back into one mixed corpus.

## Classes

| Class | Meaning | Primary Home |
| --- | --- | --- |
| `canonical-index` | Navigation and ownership index. | `docs/architecture/README.md`, `docs/architecture/_meta/` |
| `canonical-doctrine` | Stable architecture authority prose. | `docs/architecture/foundations/`, `docs/architecture/components/`, `docs/architecture/domains/`, `docs/architecture/products/`, `docs/architecture/protocols/` |
| `canonical-reference` | Low-level APIs, object models, endpoint references, and contracts. | `docs/architecture/components/`, `docs/architecture/protocols/` |
| `canonical-schema` | Shared schemas that drive generated contracts. | `docs/implementation/` until schema generation is split into a package |
| `conformance-contract` | Hidden or public invariant contracts used for conformance checks. | `docs/conformance/` |
| `implementation-plan` | Sequencing, package maps, milestones, and source-tree guidance. | `docs/implementation/` |
| `product-context` | Product-surface reference material and preserved UX intent. | `docs/architecture/products/` |
| `preserved-context` | Historical or whitepaper context retained as non-primary authority. | Nearest owning component or `_meta/changelog/` |
| `formal-source` | TLA+, configs, proof source, and formal-model READMEs. | `docs/architecture/protocols/aft/formal/` |
| `formal-generated` | TLC traces, generated trace modules, state dumps, and model-checker byproducts. | `docs/formal-artifacts/aft/` |
| `evidence-artifact` | Validation outputs, scorecards, screenshots, bundles, and run reports. | `docs/evidence/` |

## Placement Rule

`docs/architecture/` should not contain `formal-generated`, `evidence-artifact`, `.st`, `.fp`, `.bin`, `.aux`, `.log`, `.out`, generated trace modules, or `states/` directories. Architecture docs may link to those artifacts when the generated output is useful evidence.
