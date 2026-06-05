# Canon Readability Audit

Status: canonical readability workplan.
Canonical owner: this file for tracking architecture-doc enterability, implementation-grade gaps, and reader-path cleanup.
Supersedes: informal readability notes in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Purpose

The canon already contains the right deep architecture. The readability problem
is that new implementers can still encounter the system as scattered doctrine
instead of a guided build map.

This audit tracks the cleanup needed to make the canon:

- easy to enter;
- precise about ownership boundaries;
- implementation-grade;
- explicit about durable forms;
- honest about supporting/historical context;
- resistant to stale terminology.

## Current Top-Level Findings

| Finding | Impact | Fix |
| --- | --- | --- |
| Reader path was implicit | New readers had to reconstruct the stack from doctrine docs | Added [`start-here.md`](./start-here.md) |
| Concept-to-durable-form mapping was scattered | Implementers could not quickly tell event vs receipt vs object vs projection | Added [`implementation-matrix.md`](./implementation-matrix.md) |
| Runtime profile naming was too easy to overread as a peer runtime | Risk of reintroducing a runtime beside the daemon | Canonicalized `Default Harness Profile` |
| Older docs mix canon and long former-spec modules | Correctness is high, but first-read clarity suffers | Mark supporting context clearly and keep top canon sections crisp |
| Anti-patterns are uneven | Boundary mistakes are harder to remember | Add explicit anti-pattern sections to major docs |
| Some docs have good ownership but weak implementation hooks | Builders need current durable form and conformance anchor | Use implementation matrix and add "Minimal Implementation Objects" where needed |

## Audit Table

| Doc | Primary reader | Current strength | Gap | Priority fix |
| --- | --- | --- | --- | --- |
| [`start-here.md`](./start-here.md) | everyone | guided entry point | new file; keep synchronized with source map | maintain as first-read map |
| [`_meta/source-of-truth-map.md`](./source-of-truth-map.md) | architects, implementers | strong owner table | must include new profile and matrix docs | keep owner rows complete |
| [`_meta/vocabulary.md`](./vocabulary.md) | everyone | strong naming reference | stale terms must remain qualified only | keep `DefaultHarnessProfile`, `AgentWiki`, `ioi-memory` current |
| [`_meta/implementation-matrix.md`](./implementation-matrix.md) | implementers | maps concept to durable form | new file; needs code anchors maintained | update whenever objects promote |
| [`daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | runtime implementers | implementation-grade lifecycle and schemas | long but intentionally buildable | keep as canonical profile owner |
| [`daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md) | runtime/product/CLI | clear daemon ownership | long CLI appendix competes for attention | keep top canon crisp; label appendix as support |
| [`daemon-runtime/api.md`](../components/daemon-runtime/api.md) | API/runtime implementers | concrete endpoints and non-negotiables | should expose profile metadata | done; keep profile field current |
| [`daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | runtime/evidence implementers | strong event/receipt owner | anti-pattern section useful | add if stale completion/proof confusion returns |
| [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | Agentgres, memory, state implementers | excellent ownership doctrine | very long supporting module after canon | add anti-patterns; eventually split support appendix |
| [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md) | Agentgres implementers | concrete object shapes | should cross-link implementation matrix | add when object promotion accelerates |
| [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | authority implementers | clear owns/does-not-own | anti-patterns help prevent wallet-as-runtime drift | add anti-patterns |
| [`foundations/aiip.md`](../foundations/aiip.md) | interop implementers | clear interop semantics | anti-patterns should call out bespoke app protocols | add anti-patterns |
| [`foundations/ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | settlement implementers | clear L1 boundary | anti-patterns should emphasize trigger-based settlement | add when touched next |
| [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | Agentgres/artifact implementers | canonical artifact-ref and restore boundary | new file; keep synchronized with object model and delivery docs | maintain as artifact-ref owner |
| [`storage-backends/doctrine.md`](../components/storage-backends/doctrine.md) | storage implementers | clear byte-plane boundary | new file; backend profiles should not drift into authority | keep backend docs byte-only |
| [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | API/schema implementers | strong shared vocabulary | long envelope list can overwhelm | use matrix for first-read object status |
| [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) | marketplace/routing implementers | clear anti-cannibalization | now should use `Default Harness Profile` consistently | done |
| [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | worker marketplace implementers | clear worker package vs instance | long product context appendix | label as supporting context; keep anti-patterns |
| [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | service marketplace implementers | clear service package/outcome boundary | long product context appendix | ensure local/managed/service-package distinctions stay canonical |

## Standard Shape Target

Major docs should converge toward:

```text
Canonical Definition
Owns
Does Not Own
Lifecycle
Minimal Implementation Objects
Admission / Settlement Boundary
Events and Receipts
Conformance Checks
Anti-Patterns
Related Canon
Supporting Context / Appendix
```

Do not force every doc to use every heading. Use the shape where it clarifies
implementation ownership.

## Terminology Watchlist

Allowed only when qualified:

```text
Default Harness Runtime
  deprecated wording; use Default Harness Profile

SCS
  historical terminology; use Agent Wiki / ioi-memory for live architecture

CAS/Filecoin as runtime substrate
  wrong; storage backend / payload availability plane only

capability as authority
  wrong when it means permission; use prim:* for primitive capabilities and
  scope:* for authority scopes
```

## Refactor Backlog

1. Keep [`start-here.md`](./start-here.md) as the primary entry link from
   `README.md`.
2. Add explicit anti-pattern sections to Agentgres, daemon runtime,
   wallet.network, AIIP, and marketplace docs.
3. Keep former product/spec modules clearly labeled as supporting context.
4. As implementation lands, update code anchors in
   [`implementation-matrix.md`](./implementation-matrix.md).
5. When a projection/event/receipt is promoted to a canonical object, update
   the canonical owner doc first, then this audit and the implementation matrix.

## Acceptance Checklist

- A new reader can explain the core stack in under five minutes.
- A runtime implementer can find the Default Harness Profile without mistaking
  it for a peer daemon.
- An Agentgres implementer can tell refs/state/projections/bytes apart.
- A memory implementer can tell Agent Wiki / `ioi-memory` from Agentgres truth.
- An authority implementer can tell `prim:*` from `scope:*`.
- A marketplace implementer can tell worker packages, service packages, and
  marketplace surfaces apart.
- An interop implementer can find AIIP as the shared protocol instead of
  inventing bespoke per-app protocols.
- Stale terms appear only as explicitly deprecated or historical wording.
