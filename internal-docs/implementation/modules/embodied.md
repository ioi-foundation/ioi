---
module_id: embodied
module_class: method
title: Native embodied stack
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M11, FUTURE]
canon_owners:
  - docs/architecture/components/daemon-runtime/embodied-runtime.md
  - docs/architecture/foundations/physical-action-safety.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/hypervisor/foundry.md
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/architecture/_meta/execution-horizons.md
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/conformance/hypervisor-core/physical-action-safety.md
---

# Native Embodied Stack

## What this module owns

This module owns the reusable method for building and proving a **native** IOI embodied compiler/runtime/supervisor stack: how a work item freezes the embodied contract surface, how it earns non-live graph evidence, how that evidence is labeled, and what a live release overlay would additionally require. It is a method only — it never orders work, never carries status, and is never a sequencer; stage placement and dependencies belong to [`sequence.v1.json`](../program/sequence.v1.json), durable status belongs to the owning work-item record, and architecture doctrine belongs to the canon owners below.

## Pulled by

`sequence.v1.json` `modules[].applies_to_stages` binds this module to **`M11`** and **`FUTURE`**. No other binding exists, and this file creates none.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| `docs/architecture/components/daemon-runtime/embodied-runtime.md` | Native graph/profile/executor/supervisor contract family, `EmbodiedRuntimeGraphManifest`, `micro`/`edge`/`site` profiles, execution strata, activation transactions, fleet allocation and `SpacetimeReservationLease`, `SimToRealPromotionGate`, the reference proof matrix, and the conformance checks. |
| `docs/architecture/foundations/physical-action-safety.md` | Physical-action safety invariants, supervision, emergency-stop authority, sensor evidence, actuator receipts, and physical-action incidents. |
| `docs/conformance/hypervisor-core/physical-action-safety.md` | The CPAS criteria evidence is labeled against: exact deployment binding, evidence-level honesty, assured safety inputs, restart/exclusive-writer behavior, real-invoker choke point, interrupted-execution proof. |
| `docs/architecture/foundations/objects/embodied-systems.md` | Wire shapes for `EmbodimentAdapter`, `EmbodiedActionPolicyContract`, `PhysicalStreamContract`, `EmbodiedActionChunk`, `EmbodiedGraphActivationTransaction`, `SpacetimeReservationLease`, and the embodied envelope family. |
| `docs/architecture/foundations/ecosystem-assurance-certification-liability.md` | `EmbodiedDeploymentAssuranceCase` interpretation and the boundary against generic certification claims. |
| `docs/architecture/components/daemon-runtime/doctrine.md`, `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md` | Daemon-runtime admission/execution ownership and the receipt/evidence field schemas embodied effects bind to. |
| `docs/architecture/components/hypervisor/foundry.md` | Backend-neutral simulation/SIL/HIL/shadow experiment execution and candidate artifacts, which activate no graph and authorize no actuator. |
| `docs/architecture/components/hypervisor/core-clients-surfaces.md` | The Systems, Operations, Provenance, Sessions, Governance, Studio, and Foundry owner jobs plus the conditional Embodied Systems `owner_application` registration. |
| `docs/architecture/_meta/execution-horizons.md` | The canonical contract-freeze list, embodied proof-matrix breadth, and promotion-gate composition for embodied work. |
| `docs/architecture/_meta/source-of-truth-map.md` | Single-owner resolution across the embodied, safety, assurance, and receipt families when two owners appear to speak. |

## Retained obligations

### Native stack, not a partner bridge

- The target is a native state-of-the-art compiler/runtime/supervisor stack, **not a partner bridge as architecture**. A cut that makes an external robotics runtime, simulator, or vendor cloud the semantic, authority, evidence, or safety owner has not applied this method.
- `EmbodimentAdapter` and `LocalControlBridge` are **compatibility surfaces**. They translate semantics; they never grant authority, select work, bypass the supervisor, or prove that current physical state is safe. Each one carried in a cut is an explicit residual with a named stop condition.
- The native `LocalControlSupervisor` remains the **deterministic execution and assurance root**: final local veto, command arbitration, exclusive fenced actuator writer, watchdog, recovery/minimum-risk switching, and emergency stop. It may admit, clip, delay, interrupt, reject, or transfer, but it cannot create or widen authority.
- Robots with their own runtimes may join through bounded adapters. IOI does **not** require HypervisorOS on every servo, sensor, controller, drone, robot, or certified local safety loop; HypervisorOS remains one optional substrate.
- Native-versus-adapter semantic equivalence is proven, never assumed — adapter non-equivalence is a required row of the canonical reference proof matrix.

### Three separable contributions

The method contributes in three separable forms. Which stage each attaches to is owned by [`sequence.v1.json`](../program/sequence.v1.json), not by this file.

1. **Contract freeze.** Freeze the native Embodied Runtime contract surface before implementation: immutable `EmbodiedRuntimeGraphManifest`, composable `micro`/`edge`/`site` profiles, isolated local execution strata, `PhysicalStreamContract`, `EmbodimentAdapter`, `EmbodiedActionPolicyContract`, non-authoritative `EmbodiedActionChunk`, native `LocalControlSupervisor` versus compatibility `LocalControlBridge`, `EmbodiedGraphActivationTransaction`, `SpacetimeReservationLease`, and deployment-bound assurance-case refs. Freezing and registering this surface makes the compiler, executor, supervisor, adapters, and Embodied Systems application **no more implemented than before**.
2. **Non-live proof.** Compile one exact manifest across the declared profiles without changing graph semantics or authority; activate transactionally as prepare/validate/commit-or-abort that leaves every local target inactive and unarmed on abort or restart; keep action chunks proposal-only; exercise epoch-fenced allocation and space-time reservations while determinism, veto, recovery, and emergency stop stay local; and inject the stream, deadline/freshness, clock, liveliness, autonomy/GPU, coordinator-loss, partition/rejoin, conflicting-reservation, stale-allocation, standby-takeover, and ambiguous-effect faults canon requires.
3. **Live release overlay.** Applies only after the non-live exit and the applicable safety and production gates. It binds the graph, hardware and software revisions, operational design domain, hazards, timing and fault assumptions, tests, and evidence through the deployment assurance case, and promotes only through the target owner's ordinary transfer plus the Physical Action Safety, Embodied Runtime, assurance, and governance gates.

### Evidence-level honesty

- A simulated, SIL, HIL, or shadow result is evidence **at its declared stage**, never a completed physical mission and never a generic certification of hardware, a system, or a supplier.
- The asserted evidence level never exceeds the evidence actually bound to the deployment. Foundry evidence does not activate a graph or authorize an actuator.
- Passing one robot body, one vendor stack, one simulator, or one network topology does not satisfy the canonical reference proof matrix; breadth plus the required latency/jitter, missed-deadline, safe-state-time, intervention, replay-fidelity, resource and space-time conflict, partition/rejoin, and promotion/rollback measures are reported with the claim.

### Conditional-future boundary

- `live-embodied-promotion` remains a **conditional-future** record outside the active M0–M14 closure path. It may be assigned and activated only by a later explicit sequencer amendment after the non-live exit.
- Non-live evidence cannot prove live physical action. A cut applying this method states that limit rather than inferring readiness from green non-live results.
- This module adds no stop rule, rail, or claim level of its own; those live in [`program/rules.md`](../program/rules.md) and [`sequence.v1.json`](../program/sequence.v1.json).

## Applying it in a work item

- `contract_families` names each frozen embodied family with its `owner_path`, `contract_ids`, `schema_versions`, and `registry_resolution`; an unregistered family a cut depends on is a blocker, not a footnote.
- `consequential_effects_and_final_invokers` names the native `LocalControlSupervisor`/controller as `final_invoker` for any actuator-bearing effect, with its `authority_source`, its receipt (`PhysicalActionExecutionReceipt` or the applicable receipt family), and its `negative_behavior` on denial.
- `positive_proof` and `adversarial_or_fault_proof` carry the compile/admission, restart-unarmed, single-writer/fence, safe-takeover, supervisor-veto, stream/clock/liveliness, partition/rejoin, and ambiguous-effect cases; run literals belong in `adversarial_or_fault_proof`, while `evidence_refs` and `evidence_index.retained_refs` carry repo paths.
- Every promotion-stage artifact is labeled `simulation`, `sil`, `hil`, `shadow`, or `limited_live` at its actual stage, and `metrics_and_frozen_thresholds` freezes the timing, safe-state, intervention, and replay-fidelity thresholds before observation.
- `remaining_nonclaims` states the live-actuator, generic-certification, single-body/single-vendor, and evidence-level limits that survive the cut; `external_gates` names any adapter residual with its retirement condition and any later sequencer amendment the live overlay would depend on.

## Terminal evidence

The method's contribution closes when the frozen embodied contract families are registered and projected, one exact graph compiles and activates across the declared profiles with commit-or-abort and restart-unarmed behavior proven, the supervisor's independent veto/recovery/emergency-stop and single-writer fencing hold under the injected fault set, every artifact is labeled at its actual promotion stage, adapter residuals are named with stop conditions, and the owning work-item record's declared literal exit contract is satisfied with its retained evidence. Green non-live evidence closes the method's non-live contribution only; it never closes a live release overlay.

## Canon gaps

- Canon requires native-versus-adapter semantic equivalence proof and treats `EmbodimentAdapter`/`LocalControlBridge` as compatibility surfaces, but does not state the admission bar a compatibility surface must clear nor the condition under which its residual must be retired rather than carried indefinitely — owner to resolve: `docs/architecture/components/daemon-runtime/embodied-runtime.md`.
- CPAS-6 requires at least one current assured non-learned safety input, but canon does not state whether — or on what admission evidence — an externally certified local safety loop that does not run HypervisorOS may serve as that assured input — owner to resolve: `docs/architecture/foundations/physical-action-safety.md`.
- Canon names the contract-freeze list and the non-live proof obligations, but does not state whether a frozen embodied contract family may be revised after non-live evidence is retained, or whether such a revision invalidates that evidence — owner to resolve: `docs/architecture/components/daemon-runtime/embodied-runtime.md`.
