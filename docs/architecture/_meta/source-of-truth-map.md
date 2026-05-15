# Architecture Source Of Truth Map

Status: canonical documentation ownership map.
Canonical owner: this file for where architecture subjects should be edited first.
Supersedes: informal subject ownership scattered across plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-15.

## Purpose

This map prevents split-brain architecture documentation. When a subject appears
in multiple plans, specs, evidence bundles, or implementation guides, edit the
canonical architecture file first and let supporting docs reference it.

Conflict rule:

1. Prefer `docs/architecture/` over plans, specs, and evidence when architecture
   direction conflicts.
2. If two architecture files disagree, prefer the newer aligned direction.
   Current canonical defaults:
   - `prim:*` means primitive execution capability;
   - `scope:*` means wallet/provider authority scope;
   - daemon/public runtime APIs own execution semantics;
   - IOI daemon/runtime nodes are compute-node execution targets;
   - Agentgres is operation-backed domain truth with a Postgres bridge;
   - Filecoin/CAS is payload, evidence, archive-byte, and package availability;
   - IOI kernel is the L0 substrate;
   - IOI L1 is the public settlement, registry, dispute, and governance root;
   - IOI topology is edge-in and fractal;
   - clients are projections or operators, not private runtime truth;
   - Worker is the protocol actor;
   - Model is a cognition backend;
   - MoW is labor routing;
   - Worker Training is the supply-creation lifecycle;
   - TrainingBatchPlan, RawBatchArchive, QualityGateReport,
     ModelCapacityProfile, and TrainingCostLedger are first-class Foundry and
     Agentgres objects when batch-level training mechanics matter;
   - Domain Ontologies and Data Recipes are the semantic data plane;
   - DistilledOntologyDataset is the compact high-signal data substrate for
     efficient specialist training and evaluation when useful;
   - adaptive work graph is execution strategy only.
3. Record resolved contradictions only when the decision history is needed for
   future maintainers; do not keep obsolete variants as parallel doctrine.

## Subject Ownership

| Subject | Canonical Owner | Low-Level Reference | Supporting Context |
| --- | --- | --- | --- |
| Web4 category and IOI stack | [`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | architectural-improvements plans |
| Mixture of Workers and worker routing | [`mixture-of-workers.md`](../foundations/mixture-of-workers.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | aiagent/sas routing docs |
| Worker Training lifecycle and training profiles | [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | Autopilot Foundry, aiagent categories, sas worker-training contracts |
| Domain Ontologies and Data Recipes | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | Autopilot Foundry, Worker Training, connector mappings, distilled ontology datasets, ontology-aware projections |
| IOI L1, L0/L1 boundary, and settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`ioi-l1-smart-contract-interfaces.md`](../foundations/ioi-l1-contract-interfaces.md) | sas/aiagent marketplace docs |
| Kernel/domain architecture and edge-in topology | [`domain-kernels.md`](../foundations/domain-kernels.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime package boundaries |
| Agentgres canonical state and Postgres bridge | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md) | detailed Agentgres reference module inside canonical owner, evidence/architectural-improvements-broad |
| Autopilot, shared builder substrate, and workflow compositor | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | internal product context and workflow-compositor specs |
| Daemon and public runtime API | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | Cursor SDK parity guide |
| SDK, CLI, GUI, harness, benchmark, compositor boundaries | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | internal package-boundary docs |
| wallet.network authority | [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md) | [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | CIRC/CEC |
| Capability and authority ontology | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | agent tool vocabulary plan |
| aiagent.xyz worker marketplace and managed instances | [`aiagent-xyz-worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](../domains/aiagent/worker-endpoints.md) | product context module inside canonical owner, marketplace neutrality doc |
| sas.xyz service marketplace | [`sas-xyz-service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas-xyz-service-endpoints.md`](../domains/sas/service-endpoints.md) | product context module inside canonical owner, service settlement docs |
| ioi.ai control plane | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md) | [`runtime-nodes-depin-tee-and-execution-privacy.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | product context in marketplace/CLI/litepaper docs |
| Filecoin/CAS artifacts | [`filecoin-cas-artifact-plane.md`](../components/filecoin-cas/doctrine.md) | [`filecoin-cas-api-and-artifact-refs.md`](../components/filecoin-cas/api-artifact-refs.md) | delivery/evidence docs |
| Runtime nodes, hosted workers, TEE, DePIN | [`runtime-nodes-depin-tee-and-execution-privacy.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) | [`runtime-node-and-task-capsule-protocol.md`](../components/daemon-runtime/task-capsule-protocol.md) | hosted/self-hosted proof plans |
| Model routing, BYOK, run-to-idle | [`model-router-byok-run-to-idle.md`](../components/model-router/doctrine.md) | [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | model-router specs |
| Connectors, tools, MCP | [`connectors-tools-and-authority-registry.md`](../components/connectors-tools/doctrine.md) | [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | MCP/skills/hooks guides |
| Events, receipts, traces, replay | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime evidence specs |
| Smarter-agent runtime loop | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | internal runtime loop plans |
| Marketplace neutrality and contribution accounting | [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | aiagent/sas docs |
| Security/privacy/policy invariants | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) | [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md), [`conformance/CEC.md`](../../conformance/agentic-runtime/CEC.md) | runtime invariant specs |

## Edit Rules

- Add new runtime/client/package ownership language to the public daemon,
  event, and common-object contracts first. Internal package-boundary plans may
  track implementation sequencing, but they do not own canonical doctrine.
- Add new MoW, worker-routing, Sparse Worker Category, Worker Training, batch
  planning, generation-batch, quality-gate, model-capacity, or training-cost
  doctrine to [`mixture-of-workers.md`](../foundations/mixture-of-workers.md)
  and [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md)
  before product/domain docs rely on it.
- Add new ontology, DataRecipe, CanonicalObjectModel, ConnectorMapping,
  PolicyBoundDataView, DistilledOntologyDataset, EvaluationDataset,
  OntologyProjection, or
  ontology-to-worker doctrine to
  [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
  before product, connector, Agentgres, or Worker Training docs rely on it.
- Add new operator-facing TUI control or SDK client behavior to
  [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) and
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before product-surface docs rely on it.
- Add new shared object fields to
  [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before copying examples into endpoint docs.
- Add new Agentgres durability, consistency, SQL bridge, migration, index, or
  database-readiness doctrine to
  [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md)
  before product or implementation docs rely on it.
- Add new event, trace, receipt, scorecard, or replay fields to
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before referencing them in daemon, Agentgres, GUI, harness, or benchmark docs.
- Add new low-level proof gates to canonical runtime/event/conformance docs
  before adding them to internal implementation prompts.

## Decision History Policy

Accepted architecture decision history belongs in
[`docs/decisions`](../../decisions/README.md). Do not recreate contradiction
logs as parallel doctrine; port durable rationale into ADRs and keep current
architecture prose clean.

Older plans may keep historical terms such as `adaptive work graph`, former artifact names, or
pre-split capability language only when they are clearly describing decision history.
New canonical architecture must use:

```text
adaptive_work_graph for public delegated execution strategy
prim:* for primitive execution capabilities
scope:* for wallet/provider authority scopes
grant:// or authority_grant_id for authority grants/leases
projection/cache/checkpoint for non-canonical client state
```
