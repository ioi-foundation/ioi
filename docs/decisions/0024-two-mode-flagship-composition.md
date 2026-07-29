# ADR 0024: Compose The Flagship Institution From Two Activation Modes On One Spine

- Status: Accepted
- Date: 2026-07-29
- Owners: execution horizons / conformance / ioi.ai orchestration application / automations machinery
- Refines: ADR 0021, ADR 0022
- Unaffected: ADR 0019, ADR 0020 (the second mode uses `GoalRunActivation` and
  the unified admission contract exactly as written; neither changes)
- Confidence: settled for the two-mode composition and for the protection of
  the generic external-proof claim text (both owner-ruled); working_ruling for
  which selected profile carries the continuous lane, which the owner can
  re-select from this record alone without unwinding a contract.

## Context

ADR 0021 selected sovereign-local completeness as the first flagship proof and
`execution-horizons.md` describes the proof as one visible journey: an operator
verifies a release, reaches genesis, states a bounded goal, and the institution
converges on it once. That journey is correct, and it is what the terminal
internal product-proof rung (P1, `docs/evidence/m0-program-control/release-ladder.json`)
closes.

It is also, by construction, a product used once per goal. The selected profile
for the next rung — external design-partner proof (P2) — is not a one-shot
engagement; it is a maintenance relationship, in which a product signal appears
on the operator's own estate, something must be done about it, and only some of
those things need adaptive convergence. Canon had no place for that behavior,
which left two bad options available by default.

The first was to treat maintenance as a second product: a second activation
path with its own runtime, authority route, and evidence chain. That forks the
institution and reintroduces exactly the substrate/application overreach ADR
0022 ruled out. The second was to promote maintenance to the definition of the
external-proof rung. That silently rewrites a claim which must stay generic
across every future profile that rung will ever admit.

A third defect sat beside these: the terminal journey was described in canon as
an unnumbered flow, so no step of it was citable, gate-referenceable, or
individually checkable. The sequencing owner (`execution-horizons.md`) held
that gap.

## Decision

1. **The flagship institution has two activation modes, not two products.**
   Mode A, **goal-initiated**, is the terminal journey exactly as already
   specified: an operator states one bounded goal and the institution converges
   on it once. Mode B, **continuous maintenance**, is
   `product signal -> AutomationRun -> work item -> optional GoalRun
   escalation`: a standing `AutomationSpec` activation observes a signal on the
   operator's estate, its `AutomationRun` opens or updates a typed
   `HypervisorWorkItem`, and only an item that needs adaptive convergence
   escalates into a `GoalRun`.

2. **Both modes converge on one spine.** Same admission, same evaluation, same
   exact-effect authority ceremony, same receipt and state-root chain, same
   recovery and cleanup obligations, same evidence export. Mode B's escalation
   is an ordinary `GoalRunActivation` from a typed source context that ADR 0019
   already enumerates (work item, automation step); it is not a new crossing.
   There is no second runtime, plane, rail, authority path, or truth owner. A
   mode that cannot reach the spine is not a mode of this institution.

3. **Mode A closes the terminal rung.** The internal product-proof rung is
   closed by the goal-initiated journey and by nothing else. Mode B is not a
   prerequisite for it and does not extend it.

4. **Mode B is a selected-profile obligation of the next rung, not its
   definition.** The continuous lane is what the selected external
   design-partner profile must additionally demonstrate — it is that profile's
   differentiator. **The generic claim text of that rung is correct and does
   not change.** It reads, and continues to read: *"Independent users complete
   the journey on their data with disclosed support and limits."* A future
   profile at the same rung that has no maintenance surface is not thereby
   deficient.

5. **No new vocabulary.** "Continuous maintenance lane" is an owner-qualified
   profile term in the sense ADR 0022 and `term-boundaries.md` already require
   of `Profile` and `Recipe`. It creates no primitive, plane, rail, runtime, or
   bare noun, and it adds no Protected Core Terms row.

6. **Binding is bounded and enumerated.** This composition binds only through:
   `_meta/execution-horizons.md`; this ADR; the external design-partner gate
   and work-item record authored by the program estate; the amended claim-lock
   metrics; and the eventual permitted-claim publication manifest. It proposes
   no claim-ladder edit and no dependency-edge change.

7. **The terminal journey is enumerated.** `execution-horizons.md` renders the
   undeniable-product journey as an ordered, numbered sequence of checkable
   product/operator states, so a step can be cited, evidenced, and failed
   individually. Numbering discharges the canon gap; it changes no step.

## What This ADR Does Not Decide

- **It does not reorder the flagship proofs.** ADR 0021's order — sovereign-local
  completeness, then two-failure-domain continuity, then distributed work, then
  the two-sovereign AIIP proof — stands unchanged.
- **It does not re-place any object.** GoalRun, OutcomeRoom, AutomationRun,
  WorkItem, and WorkRun keep the layering ADR 0022 assigned them; nothing moves
  between substrate, application, and protocol.
- **It does not change any claim text, ladder rung, or dependency edge**, and it
  authorizes no new claim of any kind.
- **It does not specify the maintenance profile's signal taxonomy, triggering
  policy, escalation heuristics, or backpressure.** Those belong to the
  automations and work-queue owners when a profile pulls them.
- **It does not decide surface-truth obligations for claimed journeys.** The
  external-surface integrity rule is canon doctrine owned by
  `execution-horizons.md` under the same owner ruling; it is not an ADR
  decision and is not scoped to this composition.
- **It does not make Mode B implemented.** Neither mode is claimed built; both
  wait on their conformance evidence like everything else.

## Rejected Alternatives

- **Maintenance as a second product or second spine.** Rejected: it duplicates
  admission, authority, and evidence, and it is the same overreach ADR 0022
  removed. Two activation modes over one spine cost nothing structurally; two
  spines cost everything twice and make no claim stronger.
- **Promoting the continuous lane to the generic definition of the
  external-proof rung.** Rejected: the rung must admit profiles that have no
  standing signal source at all. Redefining it to require maintenance would
  narrow a claim that is deliberately general, and would do it by drift rather
  than by ruling.
- **Deferring the continuous lane until after the external-proof rung closes.**
  Rejected: the selected profile's value is the maintenance relationship, so
  deferring it would leave the selected proof demonstrating a one-shot product
  and calling it a design-partner engagement.
- **A dedicated `MaintenanceRun` or maintenance plane.** Rejected under ADR
  0022's clean-slate posture and the no-new-noun rule: `AutomationRun`,
  `HypervisorWorkItem`, and `GoalRunActivation` already carry every step.

## Consequences

- `_meta/execution-horizons.md` carries the numbered terminal journey, the
  continuous-lane composition bound to the selected external design-partner
  profile, and the explicit statement that the generic claim text is unchanged.
- The external design-partner gate and its work-item record (program estate,
  single-sequencer rule) carry the continuous lane as a selected-profile
  obligation; the claim-lock metrics are amended to measure it.
- The conformance claim coverage index gains nothing new from this ADR: no
  claim is created, and no existing claim's evidence requirement is relaxed.
- Mode B's first implementation pull is ordinary contract work under the
  existing build sequence; it opens no new step.

## Cost Of Being Wrong And Reversal

This is a composition ruling over contracts that already exist. If Mode B turns
out to be the wrong differentiator for the selected profile, reversal is
deleting the continuous-lane section and this ADR's status line: no envelope,
schema, route, identifier, or claim depends on it, because the lane is
assembled entirely from `AutomationRun`, `HypervisorWorkItem`, and
`GoalRunActivation` as already specified. If instead the lane turns out to be
universal rather than profile-selected, the generic claim text is widened by a
later ADR and an owner ruling — never by drift. The cost of being wrong is a
deleted section, not a lost guarantee.

## Canonical References

- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`../architecture/foundations/objects/goal-run-execution.md`](../architecture/foundations/objects/goal-run-execution.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/foundations/term-boundaries.md`](../architecture/foundations/term-boundaries.md)
- [`../conformance/hypervisor-core/sovereign-local-completeness.md`](../conformance/hypervisor-core/sovereign-local-completeness.md)
- [`../conformance/README.md`](../conformance/README.md)
