# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./operations/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate authority documents so each facet has a clear role, boundary, and dependency surface.

The core doctrine is:

> **IOI L1 settles rights and trust. Agentgres remembers operational truth. The daemon executes work. Autopilot, agent-ide, CLI/TUI, SDK, workflow compositor, harnesses, and benchmarks are clients. wallet.network authorizes power. Filecoin/CAS stores payloads. aiagent.xyz discovers workers. sas.xyz sells outcomes.**

These documents should be treated as architectural authority prose. They are not implementation tickets, but they should constrain implementation choices, naming, product boundaries, and future specs.

## Navigation And Ownership

- [`source-of-truth-map.md`](./operations/source-of-truth-map.md) — canonical subject ownership, edit rules, and conflict policy.
- [`documentation-contradiction-log.md`](./operations/documentation-contradiction-log.md) — resolved contradictions and legacy-context policy.
- [`documentation-refactor-report.md`](./operations/documentation-refactor-report.md) — latest documentation refactor report.

## High-Level Canonical Spec Files

- [`canonical-web4-and-ioi-stack.md`](./foundations/canonical-web4-and-ioi-stack.md) — category definition and stack map.
- [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md) — IOI L1 duties, smart contracts, gas boundaries.
- [`fractal-kernel-and-domain-kernels.md`](./foundations/fractal-kernel-and-domain-kernels.md) — root kernel, application-domain kernels, and Agentgres hosting.
- [`agentgres-state-substrate.md`](./state/agentgres-state-substrate.md) — per-domain state substrate for canonical operational truth.
- [`autopilot-local-app-and-workflow-canvas.md`](./surfaces/autopilot-local-app-and-workflow-canvas.md) — local app, workflow builder, harness-as-workflow.
- [`autopilot-internal-product-spec.md`](./surfaces/autopilot-internal-product-spec.md) — Autopilot product definition, UX surface intent, and operator-shell direction.
- [`ioi-cli-daemon-runtime.md`](./runtime/ioi-cli-daemon-runtime.md) — universal execution endpoint for local, hosted, and DePIN nodes.
- [`wallet-network-authority-layer.md`](./authority/wallet-network-authority-layer.md) — identity, secrets, authority scopes, approvals, payments.
- [`aiagent-xyz-worker-marketplace.md`](./marketplaces/aiagent-xyz-worker-marketplace.md) — worker marketplace application domain.
- [`sas-xyz-service-marketplace.md`](./marketplaces/sas-xyz-service-marketplace.md) — Service-as-Software outcome marketplace application domain.
- [`ai-url-registry-and-manifests.md`](./surfaces/ai-url-registry-and-manifests.md) — `ai://` naming, manifests, resolver metadata.
- [`filecoin-cas-artifact-plane.md`](./artifacts/filecoin-cas-artifact-plane.md) — package, artifact, evidence, checkpoint availability.
- [`runtime-nodes-depin-tee-and-execution-privacy.md`](./runtime/runtime-nodes-depin-tee-and-execution-privacy.md) — local/hosted/DePIN/TEE execution modes.
- [`model-router-byok-run-to-idle.md`](./runtime/model-router-byok-run-to-idle.md) — model registry, BYOK, local mounting, run-to-idle compute.
- [`connectors-tools-and-authority-registry.md`](./tools/connectors-tools-and-authority-registry.md) — typed tools, connector authority, risk classes.
- [`marketplace-neutrality-and-contribution-accounting.md`](./marketplaces/marketplace-neutrality-and-contribution-accounting.md) — anti-cannibalization doctrine, contribution receipts, attribution.
- [`security-privacy-and-policy-invariants.md`](./foundations/security-privacy-and-policy-invariants.md) — non-negotiable security and authority invariants.
- [`implementation-roadmap-and-dependencies.md`](./operations/implementation-roadmap-and-dependencies.md) — recommended chronological implementation path.
- [`consensus/README.md`](./consensus/README.md) — consensus architecture corpus index; AFT protocol material lives under `consensus/aft/`.

## Low-Level Reference Files

- [`common-objects-and-envelopes.md`](./runtime/common-objects-and-envelopes.md) — shared envelopes, ID namespaces, primitive capabilities, authority scopes.
- [`aiagent-xyz-agent-and-worker-endpoints.md`](./marketplaces/aiagent-xyz-agent-and-worker-endpoints.md) — aiagent.xyz worker and inter-agent endpoints.
- [`sas-xyz-service-endpoints.md`](./marketplaces/sas-xyz-service-endpoints.md) — sas.xyz order, delivery, provider, and dispute endpoints.
- [`ioi-daemon-runtime-api.md`](./runtime/ioi-daemon-runtime-api.md) — public daemon runtime API, event streaming, inspect, scorecard, replay.
- [`agentgres-api-and-object-model.md`](./state/agentgres-api-and-object-model.md) — Agentgres APIs, object classes, operation log, runtime v0 state.
- [`canonical-state-and-projection-system-whitepaper.md`](./state/canonical-state-and-projection-system-whitepaper.md) — preserved CSPS taxonomy context for projection-native state systems.
- [`wallet-network-api-and-authority-scopes.md`](./authority/wallet-network-api-and-authority-scopes.md) — wallet.network authority scopes, grants, approvals, brokerage, revocation.
- [`ioi-l1-smart-contract-interfaces.md`](./foundations/ioi-l1-smart-contract-interfaces.md) — IOI L1 contract interfaces.
- [`ai-url-manifest-schemas.md`](./surfaces/ai-url-manifest-schemas.md) — `ai://` manifest schemas and resolution flow.
- [`runtime-node-and-task-capsule-protocol.md`](./runtime/runtime-node-and-task-capsule-protocol.md) — runtime assignment, task capsules, privacy modes, attestation.
- [`filecoin-cas-api-and-artifact-refs.md`](./artifacts/filecoin-cas-api-and-artifact-refs.md) — artifact/package refs, bundles, verification.
- [`model-router-api-byok-and-mounting.md`](./runtime/model-router-api-byok-and-mounting.md) — model provider, endpoint, route, invocation, BYOK, mounting.
- [`connector-and-tool-contracts.md`](./tools/connector-and-tool-contracts.md) — RuntimeToolContract, connector/tool APIs, risk classes.
- [`events-receipts-and-delivery-bundles.md`](./runtime/events-receipts-and-delivery-bundles.md) — runtime events, receipts, delivery bundles, traces, quality.
- [`low-level-implementation-milestones.md`](./runtime/low-level-implementation-milestones.md) — low-level milestones and cross-surface proof gates.

## Boundary And Generated References

- [`runtime-vocabulary.md`](./operations/runtime-vocabulary.md) — runtime, audit, substrate, projection, and legacy naming vocabulary.
- [`runtime-package-boundaries.md`](./operations/runtime-package-boundaries.md) — ownership map for daemon, CLI, SDK, agent-ide, harness, benchmarks, adaptive work graph strategy, and local projections.
- [`runtime-module-map.md`](./operations/runtime-module-map.md) — concrete source-tree map for runtime, clients, projections, validation, and legacy naming.
- [`runtime-action-schema.json`](./operations/runtime-action-schema.json) — shared action-kind source for generated Rust and TypeScript runtime/workflow contracts.
- [`conformance/CIRC.md`](./conformance/CIRC.md) — hidden intent-resolution conformance invariant.
- [`conformance/CEC.md`](./conformance/CEC.md) — hidden completion-evidence conformance invariant.
- [`consensus/aft/specs/README.md`](./consensus/aft/specs/README.md) — AFT spec corpus, yellow paper, runbooks, and protocol references.
- [`consensus/aft/formal/README.md`](./consensus/aft/formal/README.md) — AFT formal models and proof artifacts.

## Source Of Truth By Subject

The edit-first source of truth for each subject is
[`source-of-truth-map.md`](./operations/source-of-truth-map.md). Plans, specs, prompts, and
evidence files are supporting references. When they conflict with
`docs/architecture/`, update the architecture owner first and then reconcile the
supporting file.

## One-Sentence Boundary Summary

| Facet | Canonical Role |
|---|---|
| IOI L1 | Registry, rights, settlement, governance, bonds, disputes, and public trust commitments. |
| Domain Kernel | Application-domain authority/runtime deployment for Agentgres and routing. |
| Agentgres | Per-domain canonical operational state, receipts, projections, quality, and contribution accounting. |
| Autopilot | Local user application, workflow canvas, harness, and desktop execution/runtime control surface. |
| IOI CLI/Daemon | Universal execution endpoint for workflows, workers, tools, models, connectors, and artifacts. |
| wallet.network | Sovereign authority layer for identity, secrets, keys, authority scopes, approvals, payments, and revocation. |
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
  wallet.network for identity, secrets, authority scopes, payments, approvals, revocation
```

## Key Non-Negotiables

1. Agentgres does not run on IOI L1. It runs per application/domain.
2. aiagent.xyz and sas.xyz are not separate chains by default. They are canonical Web4 application domains with their own Agentgres backends and IOI L1 smart-contract settlement rails.
3. IOI L1 is not the operational notebook. It stores registry, rights, economic commitments, disputes, and sparse roots.
4. IOI gas is consumed at coordination and settlement boundaries, not per model thought, tool call, or workflow node.
5. The default harness must be marketplace-neutral and must not cannibalize worker/service markets through silent appropriation.
6. wallet.network is the authority plane. Agents and runtimes receive authority scopes, not raw secrets.
7. DePIN nodes are execution venues; Web4 apps define state, rights, UX, contracts, and outcomes.
8. Filecoin/CAS stores payloads; trust comes from manifests, hashes, signatures, receipts, and settlement roots.
