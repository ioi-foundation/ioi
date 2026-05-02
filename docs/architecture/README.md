# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-05-02.

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate authority documents so each facet has a clear role, boundary, and dependency surface.

The core doctrine is:

> **IOI L1 settles rights and trust. Agentgres remembers operational truth. The daemon executes work. Autopilot, agent-ide, CLI/TUI, SDK, workflow compositor, harnesses, and benchmarks are clients. wallet.network authorizes power. Filecoin/CAS stores payloads. aiagent.xyz discovers workers. sas.xyz sells outcomes.**

Agentgres should not be read as "state stored as Filecoin blobs." Agentgres is
the state machine and query substrate; Filecoin/CAS is the content-addressed
payload and evidence availability layer.

These documents should be treated as architectural authority prose. They are not implementation tickets, but they should constrain implementation choices, naming, product boundaries, and future specs.

## Taxonomy

Architecture contains stable authority prose, protocol references, and low-level component references. Implementation plans live in [`docs/implementation`](../implementation/). Conformance contracts live in [`docs/conformance`](../conformance/). Generated formal outputs live in [`docs/formal-artifacts`](../formal-artifacts/).

## Navigation And Ownership

- [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) — canonical subject ownership, edit rules, and conflict policy.
- [`contradiction-log.md`](./_meta/contradiction-log.md) — resolved contradictions and legacy-context policy.
- [`doc-classes.md`](./_meta/doc-classes.md) — documentation class vocabulary for future metadata/linting.
- [`2026-05-02-taxonomy-refactor.md`](./_meta/changelog/2026-05-02-taxonomy-refactor.md) — latest documentation refactor report.

## High-Level Canonical Spec Files

- [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md) — category definition and stack map.
- [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md) — IOI L1 duties, smart contracts, gas boundaries.
- [`domain-kernels.md`](./foundations/domain-kernels.md) — root kernel, application-domain kernels, and Agentgres hosting.
- [`agentgres/doctrine.md`](./components/agentgres/doctrine.md) — per-domain state substrate for canonical operational truth.
- [`autopilot/local-app-workflow-canvas.md`](./products/autopilot/local-app-workflow-canvas.md) — local app, workflow builder, harness-as-workflow.
- [`autopilot/internal-product-spec.md`](./products/autopilot/internal-product-spec.md) — Autopilot product definition, UX surface intent, and operator-shell direction.
- [`daemon-runtime/doctrine.md`](./components/daemon-runtime/doctrine.md) — universal execution endpoint for local, hosted, and DePIN nodes.
- [`wallet-network/doctrine.md`](./components/wallet-network/doctrine.md) — identity, secrets, authority scopes, approvals, payments.
- [`domains/aiagent/worker-marketplace.md`](./domains/aiagent/worker-marketplace.md) — worker marketplace application domain.
- [`domains/sas/service-marketplace.md`](./domains/sas/service-marketplace.md) — Service-as-Software outcome marketplace application domain.
- [`protocols/ai-url/registry-and-manifests.md`](./protocols/ai-url/registry-and-manifests.md) — `ai://` naming, manifests, resolver metadata.
- [`filecoin-cas/doctrine.md`](./components/filecoin-cas/doctrine.md) — package, artifact, evidence, checkpoint availability.
- [`daemon-runtime/runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md) — local/hosted/DePIN/TEE execution modes.
- [`model-router/doctrine.md`](./components/model-router/doctrine.md) — model registry, BYOK, local mounting, run-to-idle compute.
- [`connectors-tools/doctrine.md`](./components/connectors-tools/doctrine.md) — typed tools, connector authority, risk classes.
- [`domains/marketplace-neutrality.md`](./domains/marketplace-neutrality.md) — anti-cannibalization doctrine, contribution receipts, attribution.
- [`security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md) — non-negotiable security and authority invariants.
- [`protocols/aft/README.md`](./protocols/aft/README.md) — AFT protocol corpus index.

## Low-Level Reference Files

- [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md) — shared envelopes, ID namespaces, primitive capabilities, authority scopes.
- [`aiagent-xyz-agent-and-worker-endpoints.md`](./domains/aiagent/worker-endpoints.md) — aiagent.xyz worker and inter-agent endpoints.
- [`sas-xyz-service-endpoints.md`](./domains/sas/service-endpoints.md) — sas.xyz order, delivery, provider, and dispute endpoints.
- [`daemon-runtime/api.md`](./components/daemon-runtime/api.md) — public daemon runtime API, event streaming, inspect, scorecard, replay.
- [`agentgres/api-object-model.md`](./components/agentgres/api-object-model.md) — Agentgres APIs, object classes, operation log, runtime v0 state.
- [`agentgres/projection-system-reference.md`](./components/agentgres/projection-system-reference.md) — preserved CSPS taxonomy context for projection-native state systems.
- [`wallet-network/api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md) — wallet.network authority scopes, grants, approvals, brokerage, revocation.
- [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) — IOI L1 contract interfaces.
- [`protocols/ai-url/manifest-schemas.md`](./protocols/ai-url/manifest-schemas.md) — `ai://` manifest schemas and resolution flow.
- [`daemon-runtime/task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md) — runtime assignment, task capsules, privacy modes, attestation.
- [`filecoin-cas/api-artifact-refs.md`](./components/filecoin-cas/api-artifact-refs.md) — artifact/package refs, bundles, verification.
- [`model-router/api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) — model provider, endpoint, route, invocation, BYOK, mounting.
- [`connectors-tools/contracts.md`](./components/connectors-tools/contracts.md) — RuntimeToolContract, connector/tool APIs, risk classes.
- [`daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md) — runtime events, receipts, delivery bundles, traces, quality.

## Boundary And Generated References

- [`vocabulary.md`](./_meta/vocabulary.md) — runtime, audit, substrate, projection, and legacy naming vocabulary.
- [`roadmap-and-dependencies.md`](../implementation/roadmap-and-dependencies.md) — recommended chronological implementation path.
- [`low-level-implementation-milestones.md`](../implementation/low-level-implementation-milestones.md) — low-level milestones and cross-surface proof gates.
- [`runtime-package-boundaries.md`](../implementation/runtime-package-boundaries.md) — implementation ownership map for daemon, CLI, SDK, agent-ide, harness, benchmarks, adaptive work graph strategy, and local projections.
- [`runtime-module-map.md`](../implementation/runtime-module-map.md) — concrete source-tree map for runtime, clients, projections, validation, and legacy naming.
- [`runtime-action-schema.json`](../implementation/runtime-action-schema.json) — shared action-kind source for generated Rust and TypeScript runtime/workflow contracts.
- [`CIRC.md`](../conformance/agentic-runtime/CIRC.md) — hidden intent-resolution conformance invariant.
- [`CEC.md`](../conformance/agentic-runtime/CEC.md) — hidden completion-evidence conformance invariant.
- [`protocols/aft/specs/README.md`](./protocols/aft/specs/README.md) — AFT spec corpus, yellow paper, runbooks, and protocol references.
- [`protocols/aft/formal/README.md`](./protocols/aft/formal/README.md) — AFT formal source and proof material. Generated traces and TLC state dumps live under [`docs/formal-artifacts/aft`](../formal-artifacts/aft/).

## Source Of Truth By Subject

The edit-first source of truth for each subject is
[`source-of-truth-map.md`](./_meta/source-of-truth-map.md). Plans, specs, prompts, and
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
9. Agentgres state MUST NOT be reduced to opaque Filecoin blobs. Agentgres owns canonical operations, object heads, indexes, constraints, projections, subscriptions, delivery state, receipt metadata, and artifact refs.
