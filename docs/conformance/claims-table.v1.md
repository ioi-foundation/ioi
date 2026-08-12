# Conformance Claims Table

Status: generated projection; do not edit by hand.
Canonical owner: [`README.md`](./README.md) — this file is a generated projection of its status-bearing tables (§ Conformance States, § Claim Coverage Index) and owns no claim of its own.
Supersedes: any hand-written public maturity or claims table.
Superseded by: none.
Last alignment pass: 2026-07-25 (inherited from the source header).

> **GENERATED — edit `docs/conformance/README.md` and regenerate.**
> Generator: `scripts/generate-conformance-claims.mjs`
> (`npm run generate:conformance-claims`). Source: `docs/conformance/README.md`.
> Freshness is CI-gated by `npm run check:conformance-claims`, which fails
> unless this file matches a fresh regeneration byte-for-byte.

## Claim counts

| State | Claims |
| --- | ---: |
| `active_invariant` | 4 |
| `target_runnable` | 7 |
| `target_defined` | 10 |
| `named_target` | 11 |
| `out_of_scope_nonclaim` | 2 |
| `deprecated_stub` | 1 |
| **Total** | **35** |

## `active_invariant` (4)

Runtime-adjudicated today; violations fail real gates.

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| Intent resolution (CIRC) | [`hypervisor-core/intent-resolution.md`](./hypervisor-core/intent-resolution.md) | — |
| Effect execution (CEC) | [`hypervisor-core/effect-execution.md`](./hypervisor-core/effect-execution.md) | — |
| GoalRun activation — selected M4 `create` + `ioi_goal_draft` slice | [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | count-pinned fresh-process gate; the claim closes through GRA-1..GRA-9 in the linked suite |
| OutcomeRoom hosted M4 admission, reciprocal membership, and graph/discussion projections | [`hypervisor-core/outcome-room-admission.md`](./hypervisor-core/outcome-room-admission.md) | count-pinned fresh bounded-System/owner-plane gates; the claim closes through ORA-1..ORA-8 in the linked suite |

## `target_runnable` (7)

Contract written and a real runnable substrate exists (registered schemas/fixtures/matrices or partial runners); the end-to-end claim has not passed. **Provable-but-unproven.**

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| Sovereign local completeness / standalone product journey | [`hypervisor-core/sovereign-local-completeness.md`](./hypervisor-core/sovereign-local-completeness.md) | matrix fixtures only; **the selected first proof** per [`execution-horizons.md`](../architecture/_meta/execution-horizons.md) |
| Platform operability / cross-plane disposition | [`hypervisor-core/platform-operability.md`](./hypervisor-core/platform-operability.md) | fault matrix fixtures only |
| Information-flow propagation / declassification | [`hypervisor-core/information-flow-propagation.md`](./hypervisor-core/information-flow-propagation.md) | registered schemas/fixtures |
| Managed work billing / Work Credits | [`hypervisor-core/managed-work-billing.md`](./hypervisor-core/managed-work-billing.md) | registered bundle contract |
| Dispute rails | [`hypervisor-core/dispute-rails.md`](./hypervisor-core/dispute-rails.md) | registered bundle contract |
| Physical action safety | [`hypervisor-core/physical-action-safety.md`](./hypervisor-core/physical-action-safety.md) | declaration-level planner + registered receipt schema |
| GoalRun unified admission — `join_existing` and remaining source kinds | [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | selected create-mode substrate only; the broader cases remain open |

## `target_defined` (10)

Contract written; no runner, fixture executor, or evaluator exists yet. Provable in principle once the named evaluator is built.

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| Third-party harness/adapter minimum contract | [`hypervisor-core/harness-profile-adapter.md`](./hypervisor-core/harness-profile-adapter.md) | — |
| Institutional learning boundary | [`hypervisor-core/institutional-learning-boundary.md`](./hypervisor-core/institutional-learning-boundary.md) | — |
| Shared work lifecycle | [`hypervisor-core/work-lifecycle.md`](./hypervisor-core/work-lifecycle.md) | — |
| Attestation assurance | [`hypervisor-core/attestation-assurance.md`](./hypervisor-core/attestation-assurance.md) | — |
| OutcomeRoom current participant/frontier/claim/attempt/finding/challenge lifecycles | [`hypervisor-core/outcome-room-admission.md`](./hypervisor-core/outcome-room-admission.md) | M4 proves honest-empty and predecessor refusal only; positive current-generation lifecycle admission remains M5 |
| Temporal verification (INV-36) | covered as sub-criteria in [`platform-operability.md`](./hypervisor-core/platform-operability.md) (CPO-11) and [`attestation-assurance.md`](./hypervisor-core/attestation-assurance.md) (CAA-10) | — |
| Outsider-runnable public conformance profile (`ioi_public_conformance_profile_v1`) | this file, § The Public Conformance Profile | admission rule, entitlements, and boundary defined; membership uncomputed and no outside runner exists |
| Two-client independence, recorded by ADR 0032 axes | this file, § The two-client claim, expressed by axes | vocabulary defined; no client has asserted axes |
| Reference-implementation designation and third-party parity | [`../architecture/foundations/web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md) § The Reference-Implementation Contract | contract written; no release is designated and no parity claim exists |
| Protocol-governance neutrality (change process, capture resistance, versioning rights) | [`../architecture/foundations/protocol-governance-neutrality.md`](../architecture/foundations/protocol-governance-neutrality.md) | contract written; no proposal registry, objection record, or designation record exists |

## `named_target` (11)

The claim has a named future contract (a path in this index) but the contract itself is not yet written. **Not yet provable** — the definition is the missing substrate.

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| Authority Gateway attach lane (`ActionRequestEnvelope`, gateway receipts, `AuthorityGatewayProfile`, graduation) | `hypervisor-core/authority-gateway-attach-lane.md` | — |
| Two-sovereign-DAS AIIP proof (Horizon 3) | `hypervisor-core/aiip-two-sovereign-das.md` | — |
| OutcomeRoom `federated_admission` | `hypervisor-core/outcome-room-federated-admission.md` | — |
| Portable authority (`AuthorityGrantEnvelope` v3 chain) | `hypervisor-core/portable-authority-v3.md` | — |
| Model-route rights enforcement (standalone) | covered inside [`institutional-learning-boundary.md`](./hypervisor-core/institutional-learning-boundary.md) route cases; standalone target `hypervisor-core/model-route-rights.md` | — |
| Bounded improvement campaign (Horizon 1B) | `hypervisor-core/bounded-improvement-campaign.md` | — |
| Improvement assurance profiles (executable ladder incl. protected build / threshold recovery) | `hypervisor-core/improvement-assurance-profiles.md` | — |
| Improvement control-protocol subversion resistance (intentional subversion, evaluator gaming, monitor collusion) — gates claims above `bounded_optimization` | `hypervisor-core/improvement-control-evaluation.md` | — |
| Receipt checkpoints / offline proof export | `hypervisor-core/receipt-checkpoints-offline-proofs.md` | — |
| Portable memory (MemorySpace vault export/import) | `hypervisor-core/portable-memory-vault.md` | — |
| Marketplace neutrality / routing receipts | `hypervisor-core/marketplace-neutrality.md` | — |

## `out_of_scope_nonclaim` (2)

Deliberately ineligible in the current claim profile; cannot pass vacuously.

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| IOI L1 settlement triggers | none — explicitly outside this tree's boundary (below) | — |
| HA / managed hosting / portable secret export (within SLC) | [`sovereign-local-completeness-matrix.v1.json`](./hypervisor-core/sovereign-local-completeness-matrix.v1.json) `external_conditional_nonclaims` | — |

## `deprecated_stub` (1)

Compatibility pointer only.

| Canon claim | Target | Honesty note |
| --- | --- | --- |
| Legacy CIRC/CEC stubs | [`../conformance/agentic-runtime/CIRC.md`](./agentic-runtime/CIRC.md), [`CEC.md`](./agentic-runtime/CEC.md) | — |
