# Architecture Documentation Contradiction Log

Status: canonical contradiction and decision-history log.
Canonical owner: this file for resolved architecture documentation conflicts.
Supersedes: silent drift between architecture, plans, specs, and evidence.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This log records contradictions that were resolved during documentation
refactors. It preserves context without letting older wording remain canonical.

## Resolved Contradictions

| Area | Older Wording | Canonical Resolution | Canonical Docs |
| --- | --- | --- | --- |
| Capability tiers | Domain operations used `cap:*` and generic capability grants. | Split into primitive execution capabilities (`prim:*`) and authority scopes (`scope:*`) with explicit authority grants. | [`common-objects-and-envelopes.md`](../runtime/common-objects-and-envelopes.md), [`wallet-network-api-and-authority-scopes.md`](../authority/wallet-network-api-and-authority-scopes.md), [`connector-and-tool-contracts.md`](../tools/connector-and-tool-contracts.md) |
| CLI vs daemon | Some prose blurred “CLI/daemon” as one runtime owner. | Daemon owns execution semantics; CLI/TUI is a client over daemon/public runtime APIs. | [`ioi-cli-daemon-runtime.md`](../runtime/ioi-cli-daemon-runtime.md), [`ioi-daemon-runtime-api.md`](../runtime/ioi-daemon-runtime-api.md) |
| SDK/local runtime | SDK local or mock behavior risked reading as canonical execution. | SDK is a developer client over daemon/substrate; mock/local projection paths are explicit test/dev surfaces and non-authoritative. | [`runtime-package-boundaries.md`](./runtime-package-boundaries.md), [`runtime-module-map.md`](./runtime-module-map.md) |
| Agentgres role | Agentgres was sometimes described as generic app storage only. | Agentgres owns canonical operational truth for serious runs through operation logs, task state, receipts, scorecards, stop conditions, and projections. | [`agentgres-state-substrate.md`](../state/agentgres-state-substrate.md), [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md) |
| Events as truth | Event streams risked being treated as canonical state. | Events are replayable observation streams; Agentgres operation logs plus receipts/artifacts are canonical for serious runs. | [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md) |
| Swarm naming | `swarm` and older adaptive work graph wording appeared as if they could be product/runtime surfaces. | `swarm` is legacy/historical vocabulary; public architecture uses execution strategy, work graph, or `adaptive_work_graph`. | [`runtime-vocabulary.md`](./runtime-vocabulary.md), [`runtime-package-boundaries.md`](./runtime-package-boundaries.md) |
| Tool authority | Tool contracts used a flattened capability bag. | RuntimeToolContract declares primitive capabilities separately from authority scope requirements. | [`connectors-tools-and-authority-registry.md`](../tools/connectors-tools-and-authority-registry.md), [`connector-and-tool-contracts.md`](../tools/connector-and-tool-contracts.md) |
| Smarter-agent records | Better-agent behavior risked being treated as evidence-only plumbing. | Task state, uncertainty, probes, postconditions, semantic impact, stop conditions, handoff quality, and scorecards are runtime records that must influence execution. | [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md), [`low-level-implementation-milestones.md`](../runtime/low-level-implementation-milestones.md) |

## Open Watchlist

- Historical plans under `docs/plans/` may still mention `adaptive work graph` as legacy
  execution-strategy vocabulary. That context is allowed when historical, but
  new public/runtime docs should use `adaptive_work_graph`.
- Evidence directories describe what was validated at a moment in time. They
  are not architecture authority when they conflict with `docs/architecture/`.
- CIRC/CEC may use `Capability` as the primitive ontology term. That is
  intentional; it must not be confused with wallet authority scopes.
