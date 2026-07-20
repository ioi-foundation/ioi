# Conformance Contracts

Status: canonical conformance index.
Canonical owner: this file for the conformance tree and contract ownership.
Supersedes: product or architecture prose that treats conformance as tied to one
agent runtime, IDE, or harness.
Superseded by: none.
Last alignment pass: 2026-07-19.

## Purpose

Conformance contracts define the testable invariants for bounded autonomous
work. They are not product surfaces and they are not a separate runtime.

The current architecture is heterogeneous:

```text
Hypervisor Core coordinates.
Harness profiles, agent harnesses, modules, tools, workers, and AIIP peers
execute under daemon/domain gates.
wallet.network authorizes.
Agentgres records admitted truth.
Receipts and observations decide completion.
```

Conformance keeps that architecture from collapsing into hidden shortcuts.

## Active Contract Families

| Family | Owner | Purpose |
| --- | --- | --- |
| [`hypervisor-core/intent-resolution.md`](./hypervisor-core/intent-resolution.md) | Hypervisor Core | Deterministic intent collapse, primitive capability ontology, provider/harness shortcut bans. |
| [`hypervisor-core/effect-execution.md`](./hypervisor-core/effect-execution.md) | Hypervisor Core | Effect execution, receipt-driven verification, terminal-state gates, remediation boundaries. |
| [`hypervisor-core/harness-profile-adapter.md`](./hypervisor-core/harness-profile-adapter.md) | Hypervisor Core | Minimum adapter contract for third-party harnesses, model runtimes, modules, and worker profiles. |
| [`hypervisor-core/information-flow-propagation.md`](./hypervisor-core/information-flow-propagation.md) | Security/privacy/policy owners | Target Cut 3B1 label propagation and exact-effect declassification contract; registered schemas and fixtures do not imply live pre-invoker enforcement. |
| [`hypervisor-core/institutional-learning-boundary.md`](./hypervisor-core/institutional-learning-boundary.md) | Cross-plane enterprise learning owners | Target end-to-end grades for institution-controlled learning, egress, lineage, provider substitution, revocation, and export/import. |
| [`hypervisor-core/work-lifecycle.md`](./hypervisor-core/work-lifecycle.md) | Domain work owners plus daemon runtime | Target shared kind-specific lifecycle, exact-head, cancellation, replay, and archival contract; current owner planes retain their own lifecycles. |
| [`hypervisor-core/managed-work-billing.md`](./hypervisor-core/managed-work-billing.md) | Economic, metering, and receipt owners | Registered fixed-point bundle contract and target quote/hold/usage/debit lifecycle; no current accounting kernel or billing service. |
| [`hypervisor-core/dispute-rails.md`](./hypervisor-core/dispute-rails.md) | Marketplace, AIIP, settlement, and receipt owners | Registered rail-bundle contract and target case/default/remedy/allocation behavior; no current adjudication kernel or settlement effect. |
| [`hypervisor-core/attestation-assurance.md`](./hypervisor-core/attestation-assurance.md) | Runtime assurance and deployment-policy owners | Target structured attestation, startup narrowing, and deployment-obligation contract; no dedicated evaluator or live evidence owner. |
| [`hypervisor-core/physical-action-safety.md`](./hypervisor-core/physical-action-safety.md) | Physical safety and Embodied Runtime | Current declaration-level intent admission plus target final-invoker, interrupted-effect, and execution-receipt contract. |
| [`hypervisor-core/platform-operability.md`](./hypervisor-core/platform-operability.md) | Platform Operability | Target cross-plane operation disposition, recovery, version/key transition, and protected observability contract. |
| [`hypervisor-core/platform-fault-matrix.v1.json`](./hypervisor-core/platform-fault-matrix.v1.json) | Platform Operability | Canonical machine-readable target scenarios; fixture evidence only, with no current operability evaluator or live fault injection. |
| [`hypervisor-core/sovereign-local-completeness.md`](./hypervisor-core/sovereign-local-completeness.md) | Hypervisor Core and deployment owners | Target claim-scoped standalone, self-hosted, managed attach/detach, portability, and honest-capability contract; no current end-to-end evaluator. |
| [`hypervisor-core/sovereign-local-completeness-matrix.v1.json`](./hypervisor-core/sovereign-local-completeness-matrix.v1.json) | Hypervisor Core and deployment owners | Canonical machine-readable target scenarios; fixture evidence only, with no current local-completeness runner or isolation evaluator. |

## Compatibility Labels

`CIRC` and `CEC` remain stable labels for traces, receipts, evidence bundles,
legacy specs, and tests:

```text
CIRC = Intent Resolution Contract
CEC  = Effect Execution Contract
```

The active documents now live under `docs/conformance/hypervisor-core/` because
the invariants apply across Hypervisor Core and heterogeneous harnesses, not one
desktop-agent runtime.

## Boundary

Conformance contracts may define:

- required typed objects;
- receipt fields;
- replay material;
- profile-specific tests;
- forbidden shortcuts;
- failure classes;
- migration obligations.

They do not define:

- product IA;
- model prompts;
- a single blessed harness;
- Agentgres schema ownership;
- wallet.network policy ownership;
- IOI L1 settlement triggers.

## Anti-Patterns

- Treating conformance as optional because a third-party harness is used.
- Treating a model reply, UI toast, or debug string as completion truth.
- Embedding provider, model, or harness shortcuts in intent resolution.
- Retrying effects invisibly inside one admitted operation instead of opening a
  new proposal, gate, receipt, and observation path.
- Letting product clients bypass Hypervisor Core/domain APIs for consequential
  work.
