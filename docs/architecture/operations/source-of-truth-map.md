# Architecture Source Of Truth Map

Status: canonical documentation ownership map.
Canonical owner: this file for where architecture subjects should be edited first.
Supersedes: informal subject ownership scattered across plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This map prevents split-brain architecture documentation. When a subject appears
in multiple plans, specs, evidence bundles, or implementation guides, edit the
canonical architecture file first and let supporting docs reference it.

Conflict rule:

1. Prefer `docs/architecture/` over plans, specs, and evidence when architecture
   direction conflicts.
2. If two architecture files disagree, prefer the newer aligned direction:
   `prim:*` primitive execution capabilities, `scope:*` authority scopes,
   daemon/public runtime API as execution authority, Agentgres as canonical
   operation-log state, clients as projections, and adaptive work graph as strategy only.
3. Preserve older context as legacy/decision history; do not silently delete it.

## Subject Ownership

| Subject | Canonical Owner | Low-Level Reference | Supporting Context |
| --- | --- | --- | --- |
| Web4 category and IOI stack | [`canonical-web4-and-ioi-stack.md`](../foundations/canonical-web4-and-ioi-stack.md) | [`common-objects-and-envelopes.md`](../runtime/common-objects-and-envelopes.md) | architectural-improvements plans |
| IOI L1 and settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`ioi-l1-smart-contract-interfaces.md`](../foundations/ioi-l1-smart-contract-interfaces.md) | sas/aiagent marketplace docs |
| Consensus and AFT protocol corpus | [`consensus/README.md`](../consensus/README.md) | [`aft/specs/README.md`](../consensus/aft/specs/README.md), [`aft/formal/README.md`](../consensus/aft/formal/README.md) | consensus crate docs |
| Kernel/domain architecture | [`fractal-kernel-and-domain-kernels.md`](../foundations/fractal-kernel-and-domain-kernels.md) | [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md) | runtime package boundaries |
| Agentgres canonical state | [`agentgres-state-substrate.md`](../state/agentgres-state-substrate.md) | [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md), [`canonical-state-and-projection-system-whitepaper.md`](../state/canonical-state-and-projection-system-whitepaper.md) | preserved detailed Agentgres module inside canonical owner, evidence/architectural-improvements-broad |
| Autopilot and workflow canvas | [`autopilot-local-app-and-workflow-canvas.md`](../surfaces/autopilot-local-app-and-workflow-canvas.md) | [`autopilot-internal-product-spec.md`](../surfaces/autopilot-internal-product-spec.md), [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md) | chat UX/runtime specs |
| Daemon and public runtime API | [`ioi-cli-daemon-runtime.md`](../runtime/ioi-cli-daemon-runtime.md) | [`ioi-daemon-runtime-api.md`](../runtime/ioi-daemon-runtime-api.md) | Cursor SDK parity guide |
| SDK, CLI, GUI, harness, benchmark, compositor boundaries | [`runtime-package-boundaries.md`](./runtime-package-boundaries.md) | [`runtime-module-map.md`](./runtime-module-map.md) | pre-next-leg checklist |
| wallet.network authority | [`wallet-network-authority-layer.md`](../authority/wallet-network-authority-layer.md) | [`wallet-network-api-and-authority-scopes.md`](../authority/wallet-network-api-and-authority-scopes.md) | CIRC/CEC |
| Capability and authority ontology | [`common-objects-and-envelopes.md`](../runtime/common-objects-and-envelopes.md) | [`runtime-package-boundaries.md`](./runtime-package-boundaries.md), [`conformance/CIRC.md`](../conformance/CIRC.md) | agent tool vocabulary plan |
| aiagent.xyz worker marketplace | [`aiagent-xyz-worker-marketplace.md`](../marketplaces/aiagent-xyz-worker-marketplace.md) | [`aiagent-xyz-agent-and-worker-endpoints.md`](../marketplaces/aiagent-xyz-agent-and-worker-endpoints.md) | preserved product-context module inside canonical owner, marketplace neutrality doc |
| sas.xyz service marketplace | [`sas-xyz-service-marketplace.md`](../marketplaces/sas-xyz-service-marketplace.md) | [`sas-xyz-service-endpoints.md`](../marketplaces/sas-xyz-service-endpoints.md) | preserved product-context module inside canonical owner, service settlement docs |
| `ai://` manifests | [`ai-url-registry-and-manifests.md`](../surfaces/ai-url-registry-and-manifests.md) | [`ai-url-manifest-schemas.md`](../surfaces/ai-url-manifest-schemas.md) | L1 namespace docs |
| Filecoin/CAS artifacts | [`filecoin-cas-artifact-plane.md`](../artifacts/filecoin-cas-artifact-plane.md) | [`filecoin-cas-api-and-artifact-refs.md`](../artifacts/filecoin-cas-api-and-artifact-refs.md) | delivery/evidence docs |
| Runtime nodes, hosted workers, TEE, DePIN | [`runtime-nodes-depin-tee-and-execution-privacy.md`](../runtime/runtime-nodes-depin-tee-and-execution-privacy.md) | [`runtime-node-and-task-capsule-protocol.md`](../runtime/runtime-node-and-task-capsule-protocol.md) | hosted/self-hosted proof plans |
| Model routing, BYOK, run-to-idle | [`model-router-byok-run-to-idle.md`](../runtime/model-router-byok-run-to-idle.md) | [`model-router-api-byok-and-mounting.md`](../runtime/model-router-api-byok-and-mounting.md) | model-router specs |
| Connectors, tools, MCP | [`connectors-tools-and-authority-registry.md`](../tools/connectors-tools-and-authority-registry.md) | [`connector-and-tool-contracts.md`](../tools/connector-and-tool-contracts.md) | MCP/skills/hooks guides |
| Events, receipts, traces, replay | [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../runtime/ioi-daemon-runtime-api.md), [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md) | runtime evidence specs |
| Marketplace neutrality and contribution accounting | [`marketplace-neutrality-and-contribution-accounting.md`](../marketplaces/marketplace-neutrality-and-contribution-accounting.md) | [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md) | aiagent/sas docs |
| Security/privacy/policy invariants | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-and-policy-invariants.md) | [`conformance/CIRC.md`](../conformance/CIRC.md), [`conformance/CEC.md`](../conformance/CEC.md) | runtime invariant specs |
| Smarter-agent runtime loop | [`low-level-implementation-milestones.md`](../runtime/low-level-implementation-milestones.md) | [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../state/agentgres-api-and-object-model.md) | live superiority proof plan |
| Implementation sequencing | [`implementation-roadmap-and-dependencies.md`](./implementation-roadmap-and-dependencies.md) | [`low-level-implementation-milestones.md`](../runtime/low-level-implementation-milestones.md) | architectural-improvements master guide |

## Edit Rules

- Add new runtime/client/package ownership language to
  [`runtime-package-boundaries.md`](./runtime-package-boundaries.md) first.
- Add new source-tree placement rules to
  [`runtime-module-map.md`](./runtime-module-map.md) first.
- Add new shared object fields to
  [`common-objects-and-envelopes.md`](../runtime/common-objects-and-envelopes.md)
  before copying examples into endpoint docs.
- Add new event, trace, receipt, scorecard, or replay fields to
  [`events-receipts-and-delivery-bundles.md`](../runtime/events-receipts-and-delivery-bundles.md)
  before referencing them in daemon, Agentgres, GUI, harness, or benchmark docs.
- Add new low-level proof gates to
  [`low-level-implementation-milestones.md`](../runtime/low-level-implementation-milestones.md)
  before adding them to implementation prompts.

## Legacy Context Policy

Older plans may keep historical terms such as `adaptive work graph`, former artifact names, or
pre-split capability language when they are clearly describing historical state.
New canonical architecture must use:

```text
adaptive_work_graph for public delegated execution strategy
prim:* for primitive execution capabilities
scope:* for wallet/provider authority scopes
grant:// or authority_grant_id for authority grants/leases
projection/cache/checkpoint for non-canonical client state
```
