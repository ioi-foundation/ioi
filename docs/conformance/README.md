# Conformance Contracts

Status: canonical conformance index.
Canonical owner: this file for the conformance tree, contract ownership, the conformance state vocabulary, and the claim coverage index.
Supersedes: product or architecture prose that treats conformance as tied to one
agent runtime, IDE, or harness; per-document ad hoc status wording as the only
statement of a contract's maturity.
Superseded by: none.
Last alignment pass: 2026-07-25.

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

## Conformance States

Every contract in this tree, and every major canon claim in the coverage index
below, carries exactly one of these states. The vocabulary exists because two
different situations were previously indistinguishable: a claim nobody can yet
prove because the substrate to prove it does not exist, and a claim that is
fully provable but has never been proven. Those are different risks and they
must read differently.

| State | Meaning |
| --- | --- |
| `active_invariant` | Runtime-adjudicated today; violations fail real gates. |
| `target_runnable` | Contract written and a real runnable substrate exists (registered schemas/fixtures/matrices or partial runners); the end-to-end claim has not passed. **Provable-but-unproven.** |
| `target_defined` | Contract written; no runner, fixture executor, or evaluator exists yet. Provable in principle once the named evaluator is built. |
| `named_target` | The claim has a named future contract (a path in this index) but the contract itself is not yet written. **Not yet provable** — the definition is the missing substrate. |
| `out_of_scope_nonclaim` | Deliberately ineligible in the current claim profile; cannot pass vacuously. |
| `deprecated_stub` | Compatibility pointer only. |

A canon claim with no row in the coverage index is a defect in this file, not
evidence of coverage.

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
| [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | Daemon runtime and goal-pursuit owners | Target unified GoalRun admission contract (profile resolution, resolved admission evidence per INV-37, retained state root, typed receipt obligations) and the `GoalRunActivation` product-crossing contract; no current evaluator. |

## Claim Coverage Index

Every major canon claim, its conformance target, and its state. `named_target`
paths are commitments to write that contract, not evidence it exists.

| Canon claim | Target | State |
| --- | --- | --- |
| Intent resolution (CIRC) | [`hypervisor-core/intent-resolution.md`](./hypervisor-core/intent-resolution.md) | `active_invariant` |
| Effect execution (CEC) | [`hypervisor-core/effect-execution.md`](./hypervisor-core/effect-execution.md) | `active_invariant` |
| Third-party harness/adapter minimum contract | [`hypervisor-core/harness-profile-adapter.md`](./hypervisor-core/harness-profile-adapter.md) | `target_defined` |
| Sovereign local completeness / standalone product journey | [`hypervisor-core/sovereign-local-completeness.md`](./hypervisor-core/sovereign-local-completeness.md) | `target_runnable` (matrix fixtures only; **the selected first proof** per [`execution-horizons.md`](../architecture/_meta/execution-horizons.md)) |
| Platform operability / cross-plane disposition | [`hypervisor-core/platform-operability.md`](./hypervisor-core/platform-operability.md) | `target_runnable` (fault matrix fixtures only) |
| Institutional learning boundary | [`hypervisor-core/institutional-learning-boundary.md`](./hypervisor-core/institutional-learning-boundary.md) | `target_defined` |
| Information-flow propagation / declassification | [`hypervisor-core/information-flow-propagation.md`](./hypervisor-core/information-flow-propagation.md) | `target_runnable` (registered schemas/fixtures) |
| Shared work lifecycle | [`hypervisor-core/work-lifecycle.md`](./hypervisor-core/work-lifecycle.md) | `target_defined` |
| Managed work billing / Work Credits | [`hypervisor-core/managed-work-billing.md`](./hypervisor-core/managed-work-billing.md) | `target_runnable` (registered bundle contract) |
| Dispute rails | [`hypervisor-core/dispute-rails.md`](./hypervisor-core/dispute-rails.md) | `target_runnable` (registered bundle contract) |
| Attestation assurance | [`hypervisor-core/attestation-assurance.md`](./hypervisor-core/attestation-assurance.md) | `target_defined` |
| Physical action safety | [`hypervisor-core/physical-action-safety.md`](./hypervisor-core/physical-action-safety.md) | `target_runnable` (declaration-level planner + registered receipt schema) |
| GoalRun admission + `GoalRunActivation` product crossing | [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | `target_defined` |
| Authority Gateway attach lane (`ActionRequestEnvelope`, gateway receipts, `AuthorityGatewayProfile`, graduation) | `hypervisor-core/authority-gateway-attach-lane.md` | `named_target` |
| Two-sovereign-DAS AIIP proof (Horizon 3) | `hypervisor-core/aiip-two-sovereign-das.md` | `named_target` |
| OutcomeRoom `federated_admission` | `hypervisor-core/outcome-room-federated-admission.md` | `named_target` |
| Portable authority (`AuthorityGrantEnvelope` v3 chain) | `hypervisor-core/portable-authority-v3.md` | `named_target` |
| Model-route rights enforcement (standalone) | covered inside [`institutional-learning-boundary.md`](./hypervisor-core/institutional-learning-boundary.md) route cases; standalone target `hypervisor-core/model-route-rights.md` | `named_target` |
| Bounded improvement campaign (Horizon 1B) | `hypervisor-core/bounded-improvement-campaign.md` | `named_target` |
| Improvement assurance profiles (executable ladder incl. protected build / threshold recovery) | `hypervisor-core/improvement-assurance-profiles.md` | `named_target` |
| Improvement control-protocol subversion resistance (intentional subversion, evaluator gaming, monitor collusion) — gates claims above `bounded_optimization` | `hypervisor-core/improvement-control-evaluation.md` | `named_target` |
| Receipt checkpoints / offline proof export | `hypervisor-core/receipt-checkpoints-offline-proofs.md` | `named_target` |
| Portable memory (MemorySpace vault export/import) | `hypervisor-core/portable-memory-vault.md` | `named_target` |
| Marketplace neutrality / routing receipts | `hypervisor-core/marketplace-neutrality.md` | `named_target` |
| Temporal verification (INV-36) | covered as sub-criteria in [`platform-operability.md`](./hypervisor-core/platform-operability.md) (CPO-11) and [`attestation-assurance.md`](./hypervisor-core/attestation-assurance.md) (CAA-10) | `target_defined` |
| IOI L1 settlement triggers | none — explicitly outside this tree's boundary (below) | `out_of_scope_nonclaim` |
| HA / managed hosting / portable secret export (within SLC) | [`sovereign-local-completeness-matrix.v1.json`](./hypervisor-core/sovereign-local-completeness-matrix.v1.json) `external_conditional_nonclaims` | `out_of_scope_nonclaim` |
| Legacy CIRC/CEC stubs | [`../conformance/agentic-runtime/CIRC.md`](./agentic-runtime/CIRC.md), [`CEC.md`](./agentic-runtime/CEC.md) | `deprecated_stub` |

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
