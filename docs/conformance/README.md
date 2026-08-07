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
| [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | Daemon runtime and goal-pursuit owners | Active selected-slice invariant for M4 `create` + `ioi_goal_draft`; unified admission, `join_existing`, and all other source kinds remain target behavior. |
| [`hypervisor-core/outcome-room-admission.md`](./hypervisor-core/outcome-room-admission.md) | OutcomeRoom, Agentgres, daemon, and product-projection owners | Active selected hosted-M4 room/System, reciprocal-membership, child-admission, graph/discussion, denial, replay, and non-overclaim invariant; current M5 lifecycles remain target behavior. |

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
| GoalRun activation — selected M4 `create` + `ioi_goal_draft` slice | [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | `active_invariant` (count-pinned fresh-process gate; the claim closes through GRA-1..GRA-9 in the linked suite) |
| GoalRun unified admission — `join_existing` and remaining source kinds | [`hypervisor-core/goal-run-admission-and-activation.md`](./hypervisor-core/goal-run-admission-and-activation.md) | `target_runnable` (selected create-mode substrate only; the broader cases remain open) |
| OutcomeRoom hosted M4 admission, reciprocal membership, and graph/discussion projections | [`hypervisor-core/outcome-room-admission.md`](./hypervisor-core/outcome-room-admission.md) | `active_invariant` (count-pinned fresh bounded-System/owner-plane gates; the claim closes through ORA-1..ORA-8 in the linked suite) |
| OutcomeRoom current participant/frontier/claim/attempt/finding/challenge lifecycles | [`hypervisor-core/outcome-room-admission.md`](./hypervisor-core/outcome-room-admission.md) | `target_defined` (M4 proves honest-empty and predecessor refusal only; positive current-generation lifecycle admission remains M5) |
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
| Outsider-runnable public conformance profile (`ioi_public_conformance_profile_v1`) | this file, § The Public Conformance Profile | `target_defined` (admission rule, entitlements, and boundary defined; membership uncomputed and no outside runner exists) |
| Two-client independence, recorded by ADR 0032 axes | this file, § The two-client claim, expressed by axes | `target_defined` (vocabulary defined; no client has asserted axes) |
| Reference-implementation designation and third-party parity | [`../architecture/foundations/web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md) § The Reference-Implementation Contract | `target_defined` (contract written; no release is designated and no parity claim exists) |
| Protocol-governance neutrality (change process, capture resistance, versioning rights) | [`../architecture/foundations/protocol-governance-neutrality.md`](../architecture/foundations/protocol-governance-neutrality.md) | `target_defined` (contract written; no proposal registry, objection record, or designation record exists) |
| Legacy CIRC/CEC stubs | [`../conformance/agentic-runtime/CIRC.md`](./agentic-runtime/CIRC.md), [`CEC.md`](./agentic-runtime/CEC.md) | `deprecated_stub` |

## The Public Conformance Profile

The index above is complete about what IOI claims and useless to an outsider who
wants to check any of it: every row names a target and a state, and none says
what an adopter *runs*. This section defines that — the definition and its
contract surface, not new proof machinery. **No runner is built by this
section, and none is claimed to exist.**

### What the profile is

**`ioi_public_conformance_profile_v1` is the named, versioned set of claims an
outside adopter can check for themselves, together with what passing each one
entitles them to say.** It is a *subset* of the index above, and being a subset
is the point: a public profile that promised everything would be unrunnable, and
an adopter would learn nothing from a bar nobody can clear.

Admission to the profile is mechanical, not editorial. A claim is in
`ioi_public_conformance_profile_v1` if and only if:

1. its state is `active_invariant` or `target_runnable` — a claim whose contract
   is unwritten or whose substrate does not exist cannot be run by anyone,
   including us;
2. its check runs against **published artifacts only** — registered schemas,
   published fixtures, canonical matrices — with no dependency on a hosted IOI
   service, an IOI-issued credential, network access to IOI, or non-public
   material;
3. its **negative cases are published alongside its positive ones**. A profile
   entry that only demonstrates acceptance lets an adopter prove they can say
   yes, which is the easy half and the wrong half; and
4. its passing statement is written in the entitlement vocabulary below.

A claim meeting all four is in the profile whether or not it flatters the
implementation. A claim failing any is out, with the failing condition named —
which makes the profile's *boundary* checkable too, rather than a curated list.

### What passing entitles an adopter to say

Passing is a statement about a checked surface, never about a system. Three
levels, and the distinctions are the substance:

| Entitlement | Earned by | Explicitly not |
| --- | --- | --- |
| `schema_conformant` | positive **and** negative fixture parity over the named registered contracts | that the implementation behaves correctly at runtime; a schema is a shape |
| `behavior_conformant` | the above, plus matching typed refusals on every published negative case for the named claim | certification; that untested surfaces behave; that the implementation is secure |
| `surface_complete` | the above across every claim in the profile, with a published manifest of what is implemented and what is declared unimplemented | that IOI endorses, certifies, supports, or has reviewed the implementation |

**Refusal parity is the load-bearing half.** Agreeing about what to accept is
cheap; agreeing about what to *refuse*, with the same typed reason, is what
makes two implementations substitutable. An implementation that accepts what the
reference refuses is more permissive, not more compatible.

### What the profile is not

- **Not certification.** A `CertificationClaim` is issued by an accredited
  issuer under
  [`../architecture/foundations/ecosystem-assurance-certification-liability.md`](../architecture/foundations/ecosystem-assurance-certification-liability.md).
  Self-checking the public profile is a self-report and reads as one; passing it
  is the *input* an issuer may consider, never a substitute for the issuer.
- **Not a security claim.** Nothing here establishes that an implementation is
  safe, correct, or fit for a purpose. The profile checks agreement with a
  contract; a contract can be agreed with and badly implemented underneath.
- **Not permission to use IOI's names.** Marks and naming are licensed
  separately (see the licensing ADR); passing a public profile grants no naming
  right, and claiming one is a marks violation regardless of the conformance
  result.
- **Not evidence of a passing north-star or first proof.** Those remain what the
  index says they are.
- **Not a gate on anything.** No release, admission, routing, or authority
  decision depends on this profile. It is a self-service check, which is the
  only kind an adopter can trust without trusting us.

### The two-client claim, expressed by axes

A conformance claim of "two independently implemented clients" is recorded as
the **set of axes** each client asserts under
[ADR 0032](../decisions/0032-independently-implemented-client-definition.md) —
`separate_binary`, `separate_codegen`, `separate_transport`,
`separate_authoring_party` — never as a boolean. A boolean would force a partial
claim to overstate; the axis set lets a true partial claim be stated truthfully,
and lets a reader see whether it demonstrates contract sufficiency, party
adoption, or only packaging.

### Honest state of this profile

`ioi_public_conformance_profile_v1` is **defined and unpopulated.** Its admission
rule, entitlement vocabulary, and boundary exist as of this section; no runner,
harness, or published fixture bundle for outside execution exists on current
master, and the profile's membership list has not been computed. Its own state
in the index below is therefore `target_defined`, and it is listed there like
every other claim — a profile exempt from the index would be exactly the
unfalsifiable surface this file exists to prevent.

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

## Claim-scoped Hypervisor compute conformance

This tree covers both bounded autonomous work and independently closable,
claim-scoped compute profiles. WorkRun isolation, Workstation, attached
Infrastructure, and HypervisorOS node-root have separate matrices, evidence
freshness, compatibility scope, negative reachability, and withdrawal rules.
Passing one never implies another. Contract or UI presence is not operational
conformance, and simulated evidence cannot close a live claim.
