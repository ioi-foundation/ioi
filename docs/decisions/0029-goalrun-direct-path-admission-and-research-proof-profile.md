# ADR 0029: Admit Direct GoalRun Paths Explicitly And Use Research For Non-Software Proof

- Status: Accepted
- Date: 2026-07-30
- Owners: Hypervisor Daemon / Goal Kernel / ioi.ai goal orchestration
- Refines: ADR 0017, ADR 0020, and ADR 0022

## Context

Canon already requires every GoalRun to freeze one exact GoalRunProfile and
preserves a direct non-System path. It did not name a decidable admission
predicate or the owner that chooses between that path and System-bound work.
It also named several valid non-software WorkResult profiles without selecting
one for the first generic-result conformance proof. Those omissions made M3
entry ambiguous and invited either client-selected routing or a proof chosen
after observing results.

## Decision

The Hypervisor Daemon is the sole admission-path owner. It resolves an exact
`GoalRunAdmissionPathDecision` from admitted policy and live runtime facts.
Direct non-System admission requires one bounded work subject; no required
System membership, constitutional state, shared frontier, OutcomeRoom,
collective scheduler, or multi-party admission; capability, authority,
resource, budget, risk, isolation, and receipt requirements that fit one
admitted execution; no unresolved System-owned dependency; and no policy that
requires the System-bound path.

False or unknown direct-path predicates fail closed. The decision is
`system_bound_required` when that path is available and `refused` when its
prerequisites are unavailable. A request, UI selection, correlation ref,
profile, harness, workflow, or model output cannot be the admission owner.

Direct work remains a fully admitted GoalRun. It freezes the built-in
generic-adaptive GoalRunProfile revision and hash, effective constraints,
policy, authority, resolved components, selected result profile, and decision
receipt. It is not a profileless exception and grants no authority by being
direct.

The first canonical non-software M3 proof profile is `research`. Its proof must
exercise a generic WorkResult and retain positive, negative, inconclusive,
challenged, and superseded outcomes as applicable. Research is a selected
conformance profile, not the owner of the generic result seam and not the only
valid non-software profile.

## Consequences

- M3 direct-path work can proceed without claiming that M1 or M2 System-bound
  prerequisites are satisfied.
- System-bound M3 work remains blocked until its exact predecessor and runtime
  prerequisites are current and unqualified.
- Clients may request a path but must render the daemon's typed decision and
  reason codes.
- Runtime and conformance tests must reject unknown predicates, requested-path
  substitution, silent downgrade, and receipt-free decisions.
- This decision changes neither IOI's category, Hypervisor topology, primitive
  ownership, nor GoalRun placement in the ioi.ai orchestration application.

## Canonical References

- `docs/architecture/components/daemon-runtime/default-harness-profile.md`
- `../architecture/domains/ioi-ai/goal-pursuit.md`
- `../architecture/domains/ioi-ai/goal-run-execution.md`
- `docs/architecture/foundations/objects/work-results-and-lifecycle.md`
- `docs/decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md`
- `docs/decisions/0020-unified-goal-run-admission-and-resolved-evidence.md`
- `docs/decisions/0022-goal-orchestration-application-layer-and-clean-slate.md`
