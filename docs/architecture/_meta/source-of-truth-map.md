# Architecture Source Of Truth Map

Status: canonical documentation ownership map.
Canonical owner: this file for where architecture subjects should be edited first.
Supersedes: informal subject ownership scattered across plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-02.

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
   operation-log state, Filecoin/CAS as payload/evidence availability rather
   than state authority, clients as projections, and adaptive work graph as strategy only.
3. Preserve older context as legacy/decision history; do not silently delete it.

## Subject Ownership

| Subject | Canonical Owner | Low-Level Reference | Supporting Context |
| --- | --- | --- | --- |
| Web4 category and IOI stack | [`canonical-web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | architectural-improvements plans |
| IOI L1 and settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`ioi-l1-smart-contract-interfaces.md`](../foundations/ioi-l1-contract-interfaces.md) | sas/aiagent marketplace docs |
| Consensus and AFT protocol corpus | [`consensus/README.md`](../protocols/aft/README.md) | [`aft/specs/README.md`](../protocols/aft/specs/README.md), [`aft/formal/README.md`](../protocols/aft/formal/README.md) | consensus crate docs |
| Kernel/domain architecture | [`fractal-kernel-and-domain-kernels.md`](../foundations/domain-kernels.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime package boundaries |
| Agentgres canonical state | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md) | preserved detailed Agentgres module inside canonical owner, evidence/architectural-improvements-broad |
| Autopilot and workflow canvas | [`autopilot-local-app-and-workflow-canvas.md`](../products/autopilot/local-app-workflow-canvas.md) | [`autopilot-internal-product-spec.md`](../products/autopilot/internal-product-spec.md), [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | chat UX/runtime specs |
| Daemon and public runtime API | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | Cursor SDK parity guide |
| SDK, CLI, GUI, harness, benchmark, compositor boundaries | [`runtime-package-boundaries.md`](../../implementation/runtime-package-boundaries.md) | [`runtime-module-map.md`](../../implementation/runtime-module-map.md), [`harness-change-workflow.md`](../../specs/runtime/harness-change-workflow.md) | pre-next-leg checklist |
| wallet.network authority | [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md) | [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | CIRC/CEC |
| Capability and authority ontology | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`runtime-package-boundaries.md`](../../implementation/runtime-package-boundaries.md), [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md) | agent tool vocabulary plan |
| aiagent.xyz worker marketplace | [`aiagent-xyz-worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent-xyz-agent-and-worker-endpoints.md`](../domains/aiagent/worker-endpoints.md) | preserved product-context module inside canonical owner, marketplace neutrality doc |
| sas.xyz service marketplace | [`sas-xyz-service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas-xyz-service-endpoints.md`](../domains/sas/service-endpoints.md) | preserved product-context module inside canonical owner, service settlement docs |
| `ai://` manifests | [`ai-url-registry-and-manifests.md`](../protocols/ai-url/registry-and-manifests.md) | [`ai-url-manifest-schemas.md`](../protocols/ai-url/manifest-schemas.md) | L1 namespace docs |
| Filecoin/CAS artifacts | [`filecoin-cas-artifact-plane.md`](../components/filecoin-cas/doctrine.md) | [`filecoin-cas-api-and-artifact-refs.md`](../components/filecoin-cas/api-artifact-refs.md) | delivery/evidence docs |
| Runtime nodes, hosted workers, TEE, DePIN | [`runtime-nodes-depin-tee-and-execution-privacy.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) | [`runtime-node-and-task-capsule-protocol.md`](../components/daemon-runtime/task-capsule-protocol.md) | hosted/self-hosted proof plans |
| Model routing, BYOK, run-to-idle | [`model-router-byok-run-to-idle.md`](../components/model-router/doctrine.md) | [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | model-router specs |
| Connectors, tools, MCP | [`connectors-tools-and-authority-registry.md`](../components/connectors-tools/doctrine.md) | [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | MCP/skills/hooks guides |
| Events, receipts, traces, replay | [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime evidence specs |
| Marketplace neutrality and contribution accounting | [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | aiagent/sas docs |
| Security/privacy/policy invariants | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) | [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md), [`conformance/CEC.md`](../../conformance/agentic-runtime/CEC.md) | runtime invariant specs |
| Smarter-agent runtime loop | [`low-level-implementation-milestones.md`](../../implementation/low-level-implementation-milestones.md) | [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | live superiority proof plan |
| Implementation sequencing | [`implementation-roadmap-and-dependencies.md`](../../implementation/roadmap-and-dependencies.md) | [`low-level-implementation-milestones.md`](../../implementation/low-level-implementation-milestones.md) | architectural-improvements master guide |

## Edit Rules

- Add new runtime/client/package ownership language to
  [`runtime-package-boundaries.md`](../../implementation/runtime-package-boundaries.md) first.
- Add new source-tree placement rules to
  [`runtime-module-map.md`](../../implementation/runtime-module-map.md) first.
- Add new shared object fields to
  [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before copying examples into endpoint docs.
- Add new event, trace, receipt, scorecard, or replay fields to
  [`events-receipts-and-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before referencing them in daemon, Agentgres, GUI, harness, or benchmark docs.
- Add new low-level proof gates to
  [`low-level-implementation-milestones.md`](../../implementation/low-level-implementation-milestones.md)
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
