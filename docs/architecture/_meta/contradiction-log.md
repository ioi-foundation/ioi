# Architecture Documentation Contradiction Log

Status: canonical contradiction and decision-history log.
Canonical owner: this file for resolved architecture documentation conflicts.
Supersedes: silent drift between architecture, plans, specs, and evidence.
Superseded by: none.
Last alignment pass: 2026-05-02.

## Purpose

This log records contradictions that were resolved during documentation
refactors. It preserves context without letting older wording remain canonical.

## Resolved Contradictions

| Area | Older Wording | Canonical Resolution | Canonical Docs |
| --- | --- | --- | --- |
| Capability tiers | Domain operations used `cap:*` and generic capability grants. | Split into primitive execution capabilities (`prim:*`) and authority scopes (`scope:*`) with explicit authority grants. | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) |
| Agentgres/Filecoin split | Agentgres could be misread as storing state as opaque Filecoin blobs. | Agentgres owns canonical domain-local state, operation logs, object heads, constraints, indexes, projections, subscriptions, receipt metadata, delivery state, and artifact refs. Filecoin/CAS stores immutable payloads, evidence bundles, trace bundles, checkpoints, snapshots, packages, and archives referenced by hash/CID. | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`filecoin-cas-artifact-plane.md`](../components/filecoin-cas/doctrine.md), [`filecoin-cas-api-and-artifact-refs.md`](../components/filecoin-cas/api-artifact-refs.md) |
| CLI vs daemon | Some prose blurred “CLI/daemon” as one runtime owner. | Daemon owns execution semantics; CLI/TUI is a client over daemon/public runtime APIs. | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) |
| SDK/local runtime | SDK local or mock behavior risked reading as canonical execution. | SDK is a developer client over daemon/substrate; mock/local projection paths are explicit test/dev surfaces and non-authoritative. | [`runtime-package-boundaries.md`](../../implementation/runtime-package-boundaries.md), [`runtime-module-map.md`](../../implementation/runtime-module-map.md) |
| Agentgres role | Agentgres was sometimes described as generic app storage only. | Agentgres owns canonical operational truth for serious runs through operation logs, task state, receipts, scorecards, stop conditions, and projections. | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) |
| Events as truth | Event streams risked being treated as canonical state. | Events are replayable observation streams; Agentgres operation logs plus receipts/artifacts are canonical for serious runs. | [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) |
| Swarm naming | `swarm` and older adaptive work graph wording appeared as if they could be product/runtime surfaces. | `swarm` is legacy/historical vocabulary; public architecture uses execution strategy, work graph, or `adaptive_work_graph`. | [`runtime-vocabulary.md`](./vocabulary.md), [`runtime-package-boundaries.md`](../../implementation/runtime-package-boundaries.md) |
| Tool authority | Tool contracts used a flattened capability bag. | RuntimeToolContract declares primitive capabilities separately from authority scope requirements. | [`connectors-tools-and-authority-registry.md`](../components/connectors-tools/doctrine.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) |
| Smarter-agent records | Better-agent behavior risked being treated as evidence-only plumbing. | Task state, uncertainty, probes, postconditions, semantic impact, stop conditions, handoff quality, and scorecards are runtime records that must influence execution. | [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`low-level-implementation-milestones.md`](../../implementation/low-level-implementation-milestones.md) |

## Open Watchlist

- Historical plans under `docs/plans/` may still mention `adaptive work graph` as legacy
  execution-strategy vocabulary. That context is allowed when historical, but
  new public/runtime docs should use `adaptive_work_graph`.
- Evidence directories describe what was validated at a moment in time. They
  are not architecture authority when they conflict with `docs/architecture/`.
- CIRC/CEC may use `Capability` as the primitive ontology term. That is
  intentional; it must not be confused with wallet authority scopes.
