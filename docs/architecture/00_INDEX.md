# IOI Canonical Architecture Spec Pack

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate authority documents so each facet has a clear role, boundary, and dependency surface.

The core doctrine is:

> **IOI L1 settles rights and trust. Agentgres remembers operational truth. Autopilot executes work. wallet.network authorizes power. Filecoin/CAS stores payloads. aiagent.xyz discovers workers. sas.xyz sells outcomes.**

These documents should be treated as architectural authority prose. They are not implementation tickets, but they should constrain implementation choices, naming, product boundaries, and future specs.

## Spec Files

1. [`01_CANONICAL_WEB4_AND_IOI_STACK.md`](01_CANONICAL_WEB4_AND_IOI_STACK.md) — category definition and stack map.
2. [`02_IOI_L1_MAINNET.md`](02_IOI_L1_MAINNET.md) — IOI L1 duties, smart contracts, gas boundaries.
3. [`03_FRACTAL_L0_KERNEL_AND_DOMAIN_KERNELS.md`](03_FRACTAL_L0_KERNEL_AND_DOMAIN_KERNELS.md) — root kernel, application-domain kernels, and Agentgres hosting.
4. [`04_AGENTGRES_STATE_SUBSTRATE.md`](04_AGENTGRES_STATE_SUBSTRATE.md) — per-domain state substrate for canonical operational truth.
5. [`05_AUTOPILOT_LOCAL_APP_AND_WORKFLOW_CANVAS.md`](05_AUTOPILOT_LOCAL_APP_AND_WORKFLOW_CANVAS.md) — local app, workflow builder, harness-as-workflow.
6. [`06_IOI_CLI_DAEMON_RUNTIME.md`](06_IOI_CLI_DAEMON_RUNTIME.md) — universal execution endpoint for local, hosted, and DePIN nodes.
7. [`07_WALLET_NETWORK_AUTHORITY_LAYER.md`](07_WALLET_NETWORK_AUTHORITY_LAYER.md) — identity, secrets, capability grants, approvals, payments.
8. [`08_AIAGENT_XYZ_WORKER_MARKETPLACE.md`](08_AIAGENT_XYZ_WORKER_MARKETPLACE.md) — worker marketplace application domain.
9. [`09_SAS_XYZ_SERVICE_MARKETPLACE.md`](09_SAS_XYZ_SERVICE_MARKETPLACE.md) — Service-as-Software outcome marketplace application domain.
10. [`10_AI_URL_REGISTRY_AND_MANIFESTS.md`](10_AI_URL_REGISTRY_AND_MANIFESTS.md) — `ai://` naming, manifests, resolver metadata.
11. [`11_FILECOIN_CAS_ARTIFACT_PLANE.md`](11_FILECOIN_CAS_ARTIFACT_PLANE.md) — package, artifact, evidence, checkpoint availability.
12. [`12_RUNTIME_NODES_DEPIN_TEE_AND_EXECUTION_PRIVACY.md`](12_RUNTIME_NODES_DEPIN_TEE_AND_EXECUTION_PRIVACY.md) — local/hosted/DePIN/TEE execution modes.
13. [`13_MODEL_ROUTER_BYOK_RUN_TO_IDLE.md`](13_MODEL_ROUTER_BYOK_RUN_TO_IDLE.md) — model registry, BYOK, local mounting, run-to-idle compute.
14. [`14_CONNECTORS_TOOLS_AND_CAPABILITY_REGISTRY.md`](14_CONNECTORS_TOOLS_AND_CAPABILITY_REGISTRY.md) — typed tools, connector capabilities, risk classes.
15. [`15_MARKETPLACE_NEUTRALITY_CONTRIBUTION_ACCOUNTING.md`](15_MARKETPLACE_NEUTRALITY_CONTRIBUTION_ACCOUNTING.md) — anti-cannibalization doctrine, contribution receipts, attribution.
16. [`16_SECURITY_PRIVACY_AND_POLICY_INVARIANTS.md`](16_SECURITY_PRIVACY_AND_POLICY_INVARIANTS.md) — non-negotiable security and authority invariants.
17. [`17_IMPLEMENTATION_ROADMAP_AND_DEPENDENCIES.md`](17_IMPLEMENTATION_ROADMAP_AND_DEPENDENCIES.md) — recommended chronological implementation path.

## One-Sentence Boundary Summary

| Facet | Canonical Role |
|---|---|
| IOI L1 | Registry, rights, settlement, governance, bonds, disputes, and public trust commitments. |
| Domain Kernel | Application-domain authority/runtime deployment for Agentgres and routing. |
| Agentgres | Per-domain canonical operational state, receipts, projections, quality, and contribution accounting. |
| Autopilot | Local user application, workflow canvas, harness, and desktop execution/runtime control surface. |
| IOI CLI/Daemon | Universal execution endpoint for workflows, workers, tools, models, connectors, and artifacts. |
| wallet.network | Sovereign authority layer for identity, secrets, keys, capability grants, approvals, payments, and revocation. |
| aiagent.xyz | Canonical Web4 marketplace for portable digital workers. |
| sas.xyz | Canonical Web4 marketplace for autonomous service outcomes. |
| ai:// | Naming and manifest resolution protocol for intelligence, workers, services, apps, and domains. |
| Filecoin/CAS | Immutable payload availability for packages, artifacts, evidence, receipts, and checkpoints. |
| DePIN/TEE Nodes | Execution venues that run IOI daemon profiles, not the Web4 apps themselves. |

## Core Layering

```text
IOI L1
  registry, rights, settlement, governance, bonds, disputes, roots

Application Domains
  aiagent.xyz, sas.xyz, Autopilot domains, enterprise domains
  each runs kernel/runtime deployment + Agentgres domain

Execution Nodes
  local Autopilot, hosted IOI daemon, provider daemon, DePIN node, TEE node, customer VPC

Storage Plane
  Filecoin/CAS/CDN for packages, artifacts, evidence bundles, checkpoints

Authority Plane
  wallet.network for identity, secrets, capability grants, payments, approvals, revocation
```

## Key Non-Negotiables

1. Agentgres does not run on IOI L1. It runs per application/domain.
2. aiagent.xyz and sas.xyz are not separate chains by default. They are canonical Web4 application domains with their own Agentgres backends and IOI L1 smart-contract settlement rails.
3. IOI L1 is not the operational notebook. It stores registry, rights, economic commitments, disputes, and sparse roots.
4. IOI gas is consumed at coordination and settlement boundaries, not per model thought, tool call, or workflow node.
5. The default harness must be marketplace-neutral and must not cannibalize worker/service markets through silent appropriation.
6. wallet.network is the authority plane. Agents and runtimes receive scoped capabilities, not raw secrets.
7. DePIN nodes are execution venues; Web4 apps define state, rights, UX, contracts, and outcomes.
8. Filecoin/CAS stores payloads; trust comes from manifests, hashes, signatures, receipts, and settlement roots.

