---
module_id: stage-future
module_class: stage
title: Conditional Future Work
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [FUTURE]
canon_owners:
  - docs/architecture/_meta/execution-horizons.md
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/foundations/physical-action-safety.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/ioi-l1-mainnet.md
  - docs/architecture/components/daemon-runtime/embodied-runtime.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
  - docs/architecture/components/agentgres/artifact-ref-plane.md
  - docs/architecture/components/hypervisor/foundry.md
  - docs/conformance/hypervisor-core/physical-action-safety.md
  - docs/conformance/hypervisor-core/platform-fault-matrix.v1.json
  - docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md
---

# FUTURE — Conditional Future Work

Hold canonically required work whose activation depends on a named external condition rather than on a stage predecessor.

## Why this is next

FUTURE is never "next" by position: [`sequence.v1.json`](../program/sequence.v1.json) gives it `depends_on: []`, `canonical_build_step: null`, and an activation rule requiring both a satisfied external condition and a newly added explicit `depends_on` edge. Its records carry their own work-item dependencies instead — `m11-selected-profile-exit-proof` for the embodied and contract-registry records, `m14-selected-profile-aggregate-exit` for the correlated-fault record — so what M11 establishes non-live (`M11.5`–`M11.10`) and what M14 establishes across optional service planes (`M14.1`–`M14.6`) are the predecessors these records extend. FUTURE adds the three things those stages deliberately refuse: a live actuator promotion, an estate-wide contract-registry and reference migration, and correlated failure injection across the actually selected shared planes. It pulls the `embodied` (legacy `WP-EMBODIED`) and `network-and-l1` (legacy `WP-NET`) modules named in `sequence.v1.json`, and advances `R-CONTRACT`, `R-RUNTIME`, `R-TRUTH`, `R-AUTH`, `R-PRODUCT`, and `R-OPS` inside itself.

## Canon owners

| Canon owner | Obligation this stage must satisfy |
| --- | --- |
| `docs/architecture/_meta/execution-horizons.md` | Horizon 5 enterprise/embodied and Horizon 6 public-commitment placement; promotion is pulled by evidence, never elapsed time. |
| `docs/architecture/_meta/source-of-truth-map.md` | Single-owner resolution for every embodied, physical, operability, service, and settlement family these records name. |
| `docs/architecture/foundations/physical-action-safety.md` | `PhysicalActionIntent` meaning, the `E0..E3` evidence ladder, e-stop and final-veto authority, fail-closed live admission when the exact deployment-bound bundle is absent. |
| `docs/architecture/components/daemon-runtime/embodied-runtime.md` | Native graph/profile/stream/activation machinery, `LocalControlSupervisor` as deterministic local execution and final veto, `FleetMissionAllocationLease`, `micro`/`edge`/`site` profile identity. |
| `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md` | `PhysicalActionExecutionReceipt` and `AuthorityEffectAdmissionReceipt` field schemas and receipt linkage. |
| `docs/architecture/foundations/common-objects-and-envelopes.md` | Shape ownership for `ReceiptEnvelope`, `GoalRunProfile`/`GoalRun`/`GoalGroundingLoop`, `RuntimeAssignment`, `HarnessInvocationEnvelope`, `NativeEmbodiedRuntimeProfile`, `EmbodiedRuntimeGraphManifestEnvelope`, `PhysicalStreamContract`, `EmbodiedDeploymentAssuranceCase`, `SpacetimeReservationLease`, `AuthorityGrantEnvelope`, `ManagedWorkBillingLedgerBundle`, `DisputeRailBundle`, `NetworkServiceInvocationEnvelope`, `DeliveryUpdateEnvelope`, `SettlementIntentEnvelope`, `SettlementEnvelope`, `IOINetworkEnrollment`. |
| `docs/architecture/foundations/ecosystem-assurance-certification-liability.md` | Interpretation of assurance cases and certification claims for any `E1+` promotion. |
| `docs/architecture/components/hypervisor/foundry.md` | Backend-neutral simulation/SIL/HIL/shadow execution and candidate artifacts; Foundry holds no promotion or live-runtime authority. |
| `docs/architecture/components/agentgres/artifact-ref-plane.md`, `docs/architecture/components/agentgres/api-object-model.md`, `docs/architecture/components/agentgres/doctrine.md`, `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md`, `docs/architecture/components/agentgres/projection-system-reference.md` | `ArtifactRef`, `ArtifactAvailabilityIncident`, `ArtifactRepairReceipt`, `OperationLogEntry`, exact head/root, readiness and projection parity under reference migration and correlated fault. |
| `docs/architecture/components/daemon-runtime/api.md`, `docs/architecture/components/daemon-runtime/doctrine.md`, `docs/architecture/components/daemon-runtime/default-harness-profile.md`, `docs/architecture/components/daemon-runtime/hypervisoros.md`, `docs/architecture/components/daemon-runtime/platform-operability.md`, `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`, `docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md`, `docs/architecture/components/daemon-runtime/task-capsule-protocol.md` | Rust-owned admission path, harness invocation shape, `EnforcementCoverageDeclaration`/`NodeEnforcementProfile`, `TemporalVerificationProfile`/`TemporalValidityEvaluation`, node/TEE posture, plane fault contract. |
| `docs/architecture/foundations/invariants.md`, `docs/architecture/foundations/domain-kernels.md`, `docs/architecture/foundations/governed-autonomous-systems.md`, `docs/architecture/foundations/security-privacy-policy-invariants.md` | Invariant set, `RuntimeAssignment` semantics inside one `system_id`, and the authority/information-flow boundary correlated faults may not erode. |
| `docs/architecture/components/connectors-tools/contracts.md` | `RuntimeToolContract` registered shape and its consumer binding. |
| `docs/architecture/components/hypervisor/providers-and-environments.md`, `docs/architecture/components/hypervisor/byo-provider-plane.md` | `HypervisorEnvironmentLifecycleObservation`, `HypervisorChangePlan`, `HypervisorResourceCleanupObligation` under provider-plane fault and exit. |
| `docs/architecture/components/storage-backends/doctrine.md`, `docs/architecture/components/storage-backends/filecoin-cas.md` | Durability and custody posture during correlated storage/artifact loss. |
| `docs/architecture/components/wallet-network/api-authority-scopes.md`, `docs/architecture/components/wallet-network/doctrine.md`, `docs/architecture/components/wallet-network/product-exchange-risk.md` | Authority scope, revocation, and exchange-risk boundaries during authority-plane fault. |
| `docs/architecture/domains/marketplace-neutrality.md`, `docs/architecture/domains/sas/service-endpoints.md`, `docs/architecture/domains/sas/service-marketplace.md` | Neutrality, service delivery, acceptance, and service-dispute obligations that must survive injected faults. |
| `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md`, `docs/architecture/foundations/ioi-l1-contract-interfaces.md`, `docs/architecture/foundations/ioi-l1-mainnet.md` | Settlement and optional-L1 plane semantics and the preserved valid no-L1 branch. |
| `docs/conformance/hypervisor-core/physical-action-safety.md` | Conformance obligations for physical-action admission and refusal. |
| `docs/conformance/hypervisor-core/platform-fault-matrix.v1.json`, `docs/conformance/hypervisor-core/platform-operability.md`, `docs/conformance/hypervisor-core/attestation-assurance.md` | The checked fault matrix and attestation expectations that actual states and obligations are compared against. |
| ADR `docs/decisions/0002-execution-authority-and-client-boundaries.md` (accepted) | The daemon remains the canonical execution endpoint for any promoted effect. |
| ADR `docs/decisions/0003-agentgres-operation-backed-domain-truth.md` (accepted) | Migrated references and injected-fault evidence remain operation-backed domain truth. |
| ADR `docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md` (accepted) | Bounded agency is execution-boundary alignment; a live actuator effect is an execution-boundary crossing. |
| ADR `docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md` (accepted) | Enrollment, network posture, and the demand gate on public commitments. |

## In scope

FUTURE carries no substage identifiers of its own; scope is anchored by record id.

- `live-embodied-promotion` — approved plan-level gap closure covering `PHYSICAL`, `ASSURANCE`, `FOUNDRY`: native executor/supervisor/controller, physical receipt, deployment assurance, and `E1+` promotion; the physical execution/promotion plan and its declared literal exit contract.
- `m11-canonical-contract-registry-and-legacy-ref-migration` — own PG-0.3 across every persisted legacy-reference family with an exact owner/family census, explicit read aliases, canonical new writes, collision fixtures, migration residual, and rollback rule; own PG-1.1 across `GoalRun`, grounding, runtime assignment/harness invocation, and the remaining non-live physical-action envelope families without treating schema registration as runtime integration proof; retain per-family owner approvals, generated projections, real consumer anchors, and positive/adversarial fixtures. Scope tags `SYSTEM` `DAEMON` `AGENTGRES` `PHYSICAL`.
- `m14-cross-plane-correlated-failure-injection` — freeze the selected-plane matrix and explicitly disposition every unselected plane, including the valid no-L1 branch, before scheduling correlated faults; define expected degraded, denied, ambiguous, recovery, reconciliation, and safe-exit states across daemon, Agentgres, authority, storage, clock, provider, fleet, attestation, billing, dispute, service, and settlement owners; retain actual-state/obligation comparison evidence. Scope tags `DAEMON` `AGENTGRES` `WALLET` `STORAGE` `ENVIRONMENTS` `MEASURED` `ECON` `SERVICES` `L1`.
- Every record also scopes positive, adversarial, stale-state, substitution, fault, recovery, product/operator-state, and retained-evidence planning for its bounded claim, including the eight enumerated states from `loading_or_pending` through `completed`, plus its compatibility and migration obligations.
- Shared thresholds each record freezes before observation: `generic.unauthorized_final_invoker_calls` = 0, `generic.duplicate_or_status_inferred_effects` = 0, `generic.unresolved_required_owner_dependency_mappings` = 0, `generic.exact_retained_successful_literal_exit_lines` = 1, and `future.effects_before_explicit_amendment` = 0.
- Each record's rollback/stop rule: stop before implementation or claim widening on unknown owner/contract, missing dependency, uncontrolled final invoker, absent authority/receipt path, stale canon digest, mutable threshold, or a failed branch; roll back only through the affected owner's explicit successor/compensation path.

## Out of scope

- Any actuator path before the named amendment, and the M11 non-live embodied proof itself (`M11.5`–`M11.10`), which M11 owns.
- The M14 demand, service-family, and L1-decision records (`M14.1`–`M14.6`), and forcing optional billing, fleet, settlement, or L1 planes into an earlier stage.
- Registration or projection without its actual runtime consumer and adversarial fixtures; accepting a collision; omitting an owner family; any new write to a persisted legacy reference.
- Fault injection against unselected or production targets, or without isolation.
- Turning unknown or ambiguous evidence into authority, delivery, payment, settlement, or success.

## Work items

| `hypervisoros-ctee-task-capsule-attestation` | conditional_future | Reusable physical cTEE/task-capsule assurance; not a backend-neutral M9 prerequisite. |
| `hypervisoros-appliance-install-update-recovery` | conditional_future | Signed image, installer, update/rollback, break-glass, support, and recovery. |
| `hypervisoros-single-node-virtualization-journey` | conditional_future | Exact supported physical single-node machine lifecycle. |
| `hypervisoros-appliance-profile-claim-gate` | conditional_future | Single-node node-root claim only; clustered replacement remains separate. |

`sequence.v1.json` declares `exit_gate: null` for FUTURE. **There is no aggregate_exit work item for this stage, and none may be inferred.**

| Work item id | Role | What it owns |
| --- | --- | --- |
| `live-embodied-promotion` | `conditional_future` | Physical execution/promotion plan, owner integration, product/operator states, and proof bundle; literal exit `LIVE_EMBODIED_PROMOTION_EXIT=0`; PG-5.2, PG-5.3, PG-5.4, PG-5.5 with closure stage FUTURE; final invoker is the native `LocalControlSupervisor`/controller. |
| `m11-canonical-contract-registry-and-legacy-ref-migration` | `conditional_future` | Estate-wide read-old/write-new migration of persisted legacy references and the owner-approved registration, projection, consumer adoption, and adversarial proof of every remaining consequential pilot contract family; literal exit `M11_CANONICAL_CONTRACT_REGISTRY_MIGRATION_EXIT=0`; PG-0.3 and PG-1.1 with closure stage M11. |
| `m14-cross-plane-correlated-failure-injection` | `conditional_future` | PG-7.2 planning at the latest selected-profile boundary, the frozen fault schedule, the expected state/obligation matrix, and the safe no-L1 exclusions; literal exit `M14_CROSS_PLANE_CORRELATED_FAILURE_EXIT=0`; the record itself carries no applicable PG id. |
| `chain-depth-latency-scaling-diagnosis` | `conditional_future` | Candidate diagnostic leg deferred from the proof-infrastructure work: measure committed-transaction latency against chain depth on the selected profile under both build profiles, and attribute the dominant cost to a named code path before proposing any change; literal exit `CHAIN_DEPTH_LATENCY_SCALING_DIAGNOSIS_EXIT=0`; carries no applicable PG id and closes no stage or claim. Activation condition: owner decides the question is worth answering — a flat release-profile curve closes it as a harness artifact, while a super-linear one is re-filed as a defect record against its owning plane. |
| `standing-authority-clause-composition-v3` | `conditional_future` | Dormant v3 standing-envelope profile preserving clause-local associations and explicit disjunction-of-conjunction composition. Activates only on an owner-approved v3 freeze or selected heterogeneous-authority profile and never blocks exact-effect-only P2. |

## Code surfaces likely affected

- `crates/services/src/agentic/runtime/kernel/runtime_physical_action_intent_admission.rs` — adjacent precedent named by two records; precedent only.
- `crates/types/src/app/generated/architecture_contracts.rs` — generated projection parity for newly registered families.
- `crates/agentgres/` — `ArtifactRef` read-alias and canonical-write path; head/root and projection behavior under injected fault.
- `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`, `docs/architecture/_meta/schemas/physical-action-execution-receipt.v1.schema.json`.
- Per-family `docs/architecture/_meta/schemas/*.schema.json` for families holding no registered revision (to be created).
- `scripts/generate-architecture-contracts.mjs`, `scripts/check-architecture-contracts.mjs`.
- `docs/conformance/hypervisor-core/platform-fault-matrix.v1.json` — expected-vs-actual comparison target.
- `apps/hypervisor/` — policy-filtered product/operator states, including the conditional Embodied Systems surface.
- `internal-docs/implementation/evidence/FUTURE/` (to be created) — the three declared exit files.
- A correlated-fault harness and a physical/embodied conformance runner (to be created); no existing `hypervisor-conformance` tier covers them.

## Focused checks during development

```text
git diff --check
npm run check:architecture-docs
npm run check:conformance-docs
npm run check:architecture-contracts
npm run check:architecture-contract-bar
npm run check:artifact-availability-incident
npm run check:work-items
npm run check:pre-next-leg
npm run hypervisor-conformance:docs
npm run hypervisor-conformance:receipts
npm run hypervisor-conformance:negative
node internal-docs/implementation/tools/check-work-item-shape.mjs
node internal-docs/implementation/tools/certify-stage.mjs
node internal-docs/implementation/tools/check-estate.mjs
node internal-docs/implementation/tools/check-estate.mjs
```

A green command proves only its actual scope. Record the exact selected command set in the owning work item.

## Exit proof

FUTURE has no stage-level aggregate exit to bind. Each record closes only against its own content-bound literal exit, retained at the path its `evidence_index` declares under `internal-docs/implementation/evidence/FUTURE/`: `LIVE_EMBODIED_PROMOTION_EXIT=0`, `M11_CANONICAL_CONTRACT_REGISTRY_MIGRATION_EXIT=0`, and `M14_CROSS_PLANE_CORRELATED_FAILURE_EXIT=0`.

For any one of them to hold, all of the following must be true: the selected profile completes its bounded journey through the declared owner path and produces the exact expected truth/effect/evidence outputs; restart/replay or independent reconstruction preserves the same owner refs, heads/roots, receipts, and nonclaims; every adversarial, substitution, stale-state, denial, dependency-loss, retry/ambiguity, restart, recovery, product/operator-state, compatibility, and migration obligation passes; negative and inconclusive results are retained; the producer is independent of the claim; and the retained evidence contains exactly one standalone matching line. Claim level `P6` closes at FUTURE only through the `live-embodied-promotion` bundle; the other two records close no claim level.

## Blocks advancement

- The external gate `later-explicit-sequencer-amendment` on all three records: a user-approved amendment must assign and activate the candidate after every named prerequisite, and the sequence graph must gain the explicit `depends_on` edge.
- Unmet work-item dependencies `m11-selected-profile-exit-proof` and `m14-selected-profile-aggregate-exit`.
- Open gates: PG-0.3 and PG-1.1 (closure stage M11), PG-5.2 through PG-5.5 (closure stage FUTURE), and PG-7.2, which the correlated-fault record plans for without owning.
- An `E1+` assertion lacking the exact deployment-bound assurance bundle or hash; emergency-stop, fence, or recovery failure; any actuator call before approval.
- Absence of an owner-approved selected-plane matrix, or an unselected plane left without an explicit disposition.
- The unresolved canon gaps below.

## Nonclaims

- Simulation/SIL/HIL/shadow or a planned record proves no live actuator path or `E1+` claim.
- These docs-and-orchestration records close no work item, stage, runtime capability, application, or public claim.
- The registry/migration candidate is inert planning: it proves no consumer integration, product write, physical action, or live embodied capability.
- The correlated-failure candidate injects no fault and proves no selected service, demand, settlement, L1, recovery, or stage exit.
- The valid no-L1 branch remains available; planning proves no demand, mainnet, native asset, or recurring external cohort.
- Creating or holding a record does not implement behavior, activate work, close a literal exit, or change a stage.
- Named code anchors are adjacent implementation precedent only, never proof of these work items.

## Canon gaps

- **Persisted legacy-reference migration rule (PG-0.3).** No canon text under `docs/architecture/` defines the persisted legacy reference scheme, its read aliases, alias duration, mixed-version refusal, or collision rule. Canon owner to resolve: `docs/architecture/components/agentgres/artifact-ref-plane.md` with `docs/architecture/foundations/common-objects-and-envelopes.md`.
- **Which families must hold a registry-canonical owner ref (PG-1.1).** `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json` carries `PhysicalActionExecutionReceipt` among the embodied set, while `NativeEmbodiedRuntimeProfile`, `EmbodiedRuntimeGraphManifestEnvelope`, `PhysicalStreamContract`, `LocalControlSupervisor`, `EmbodiedDeploymentAssuranceCase`, `SpacetimeReservationLease`, `FleetMissionAllocationLease`, `GoalRunProfile`, `GoalRun`, `GoalGroundingLoop`, `RuntimeAssignment`, and `HarnessInvocationEnvelope` resolve only as reviewed owner locators. Canon does not state which are required to register. Canon owner to resolve: `docs/architecture/_meta/source-of-truth-map.md` with `docs/architecture/components/daemon-runtime/embodied-runtime.md`.
- **Registration owner for split-owner embodied families.** The records name `docs/architecture/foundations/common-objects-and-envelopes.md` as reviewed shape owner for several families that `docs/architecture/_meta/source-of-truth-map.md` assigns to `docs/architecture/components/daemon-runtime/embodied-runtime.md`; which doc is the registration owner is not stated. Canon owner to resolve: `docs/architecture/_meta/source-of-truth-map.md`.
- **Per-profile plane selection for correlated fault injection (PG-7.2).** `docs/architecture/components/daemon-runtime/platform-operability.md` explicitly does not claim scheduled correlated-failure injection across a deployed estate, and `docs/conformance/hypervisor-core/platform-fault-matrix.v1.json` records required dispositions without a per-profile rule for which shared planes count as selected, or where an unselected plane's disposition (including the no-L1 branch) is recorded. Canon owner to resolve: `docs/architecture/components/daemon-runtime/platform-operability.md` with `docs/architecture/_meta/execution-horizons.md` and `docs/architecture/foundations/ioi-l1-mainnet.md`.
