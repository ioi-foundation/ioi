# ADR 0023: Generalize Improvement Campaigns To Typed Work Subjects And Make Assurance Executable

- Status: Accepted
- Date: 2026-07-26
- Owners: bounded recursive improvement / improvement objects / platform operability / canonical enums / conformance
- Refines: ADR 0018, ADR 0022
- Confidence: settled for the decoupling (it resolves ADR 0022's first named
  untangling in the direction that preserves the stronger guarantee);
  working_ruling for the exact assurance-tier member set and the
  operational-assurance contract's field-level shape, both free to evolve
  until schema registration.

## Context

Three defects sat between the improvement doctrine and the claim it protects:

1. **A foundations safety spine required an application object.** Campaign
   admission mandated "one coordinating `GoalRunProfile` revision," and the
   campaign diagram made GoalRuns the execution children — while ADR 0022
   allocated the GoalRun family to the ioi.ai orchestration application. A
   bounded institution without that application could not use the adaptive
   improvement spine at all. ADR 0022 had already registered this as its
   first named untangling with the choice (generalize vs. bind) left open.
2. **"Assurance class" was load-bearing prose.** Search/Judgment/Authority
   separation strength was gated on "the declared assurance class" — a phrase
   with no member set, no profile object, and nothing to declare against.
3. **Nothing reconciled continuously.** Pipelines terminate; the decision
   invariants of platform operability assumed current evidence (anchors,
   attestations, coverage declarations, route posture) with no standing
   contract that revalidates them, detects invalidation, fences, recovers,
   and feeds findings back. The estate's own history supplied the proof of
   need: verification bases went stale twice in one convergence day.

An external comparative analysis (retained under
`internal-docs/prompts/architecture-relative-comparison/`) reached the same
three findings independently; this ADR records the owner-approved resolution.

## Decision

1. **Campaign coordination generalizes to typed work subjects.** Campaign
   children are Sessions and WorkRuns generically, and GoalRuns/OutcomeRooms
   optionally where the goal-orchestration application is present. Admission
   requires one coordinating-work declaration: a coordinating pursuit (exact
   `GoalRunProfile` revision + resolution snapshot) where the application is
   present, or the Campaign's declared Session/WorkRun coordination profile.
   The flagship Horizon 1B proof remains pursuit-coordinated; the spine never
   requires the application. Envelope fields follow
   (`coordinating_work_subject_ref`, `child_work_subject_refs`, optional
   `coordinating_pursuit`).
2. **`improvement_assurance_profile` replaces assurance-class prose.** A
   cumulative executable ladder — `local_lightweight | independent_review |
   protected_build | adversarial_control | threshold_recovery |
   failure_domain_independent` — declared at admission, member set owned by
   `canonical-enums.md`, tier requirements owned by
   `bounded-recursive-improvement.md`. SLSA-shaped review/build provenance
   and TUF-shaped threshold recovery roots satisfy tiers as admission-bound
   **evidence, never authority** (the same composition rule every external
   standard obeys here); an undeclarable profile fails closed.
3. **Continuous operational assurance is a named target contract.** A
   standing owner-specific `AutomationSpec` family (no new runtime,
   controller layer, or council) owned by `platform-operability.md`:
   reconcile desired-vs-observed, revalidate rot-prone evidence, detect
   invalidation as typed findings, fence via the decision invariants, recover
   exclusively through owning admitted paths, and feed findings to
   improvement intake as ordinary gated evidence.
4. **Adversarial control evaluation gates stronger claims.** Improvement
   claims above `bounded_optimization` require a passing control-protocol
   evaluation under intentional subversion, selective attacks, evaluator
   gaming, prompt injection, and monitor collusion — named conformance
   targets `improvement-assurance-profiles.md` and
   `improvement-control-evaluation.md` in the claim coverage index. Benign
   quality evaluation alone is insufficient.
5. **No new machinery and no new claims.** No swarm, council, consensus
   layer, or RSI engine; the "bounded recursively self-improving institution"
   claim remains unshipped until the ladder's own evidence exists. The
   M0/M1 platform sequence is unchanged.

## Rejected Alternatives

- **Binding the Campaign spine to the application's objects explicitly** (the
  other branch of ADR 0022's untangling): makes every improving institution
  depend on one application; fails sovereign deployments that never install
  it.
- **A separate assurance-object family** beside `EcosystemAssuranceProfile`:
  the ladder is an admission field plus tier requirements, not a new peer
  certification system.
- **An operational-assurance runtime/controller plane**: the daemon and the
  owning admitted paths already exist; only the standing Automation contract
  was missing.

## Consequences

- `bounded-recursive-improvement.md`, `objects/bounded-improvement.md`,
  `canonical-enums.md`, `platform-operability.md`, `execution-horizons.md`
  (H1B wording), the canon-to-code delta row, and the conformance claim
  coverage index carry the changes; ADRs 0018 and 0022 carry dated
  refinements.
- The m8 improvement work items must rescope their coordination and
  assurance language before activation (annotated in the program records).
- Implementation waits for its stages; nothing here is claimed built.

## Cost Of Being Wrong And Reversal

All three moves are additive target contracts over unimplemented substrate.
Reversal before schema registration is editing the owner sections and this
ADR; after registration, ordinary successor-revision rules apply. The
decoupling preserves the previous behavior as one profile (pursuit-
coordinated), so nothing existing is orphaned by being wrong.

## Canonical References

- [`../architecture/foundations/bounded-recursive-improvement.md`](../architecture/foundations/bounded-recursive-improvement.md)
- [`../architecture/foundations/objects/bounded-improvement.md`](../architecture/foundations/objects/bounded-improvement.md)
- [`../architecture/foundations/canonical-enums.md`](../architecture/foundations/canonical-enums.md)
- [`../architecture/components/daemon-runtime/platform-operability.md`](../architecture/components/daemon-runtime/platform-operability.md)
- [`../conformance/README.md`](../conformance/README.md)
