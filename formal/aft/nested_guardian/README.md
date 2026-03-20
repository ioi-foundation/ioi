# NestedGuardian Formal Model

This directory holds the formal artifacts for `NestedGuardian`.

The canonical prose spec lives at
[`docs/consensus/aft/specs/nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/nested_guardian.md).

The model includes the witness-layer mechanics that are absent from the
production-only baseline:

- deterministic slot assignment to witness committees
- witness certificate issuance as a prerequisite for validator votes
- witness outage and checkpoint rollback faults
- bounded reassignment depth for witness replacement
- conflicting finalization checks over the combined validator and witness path
- an exploratory threshold recovery-or-missingness kernel for witness-coded
  slot recovery

As with `GuardianMajority`, the proof surface is split:

- `NestedGuardianProof.tla` is the proof-kernel module used for unbounded TLAPS
  safety proofs over the witness-augmented protocol core.
- TLC explores the richer bounded composed model in `NestedGuardian.cfg`
- `NestedGuardian.tla` remains the executable model for assignment,
  reassignment, outage, and checkpoint-admissibility scenarios.
- `NestedGuardianLiveness.tla` is the first bounded obligation-5 churn harness:
  it forces one reassignment/outage/rotation/checkpoint plus
  continuation-boundary churn sequence, then checks post-stabilization
  eventual target finalization plus continuation bootstrap under weak fairness
  for the minimal progress actions.
- `NestedGuardianRecurringLiveness.tla` is the first bounded recurring harness:
  it is now cycle-count parameterized, with the default executable instance
  executing three such churn/stabilize/finalize/bootstrap cycles in sequence
  and checking that later cycles cannot be reached without completing earlier
  ones and that all three cycles eventually fetch their named continuation. It
  also carries an explicit cycle-transfer property: completion of cycle `c`
  must eventually land in the normalized churn-start state for cycle `c + 1`.
- `NestedGuardianRecurringLivenessCore.tla` is the reusable recurring-liveness
  core that the default three-cycle wrapper instantiates.
- `NestedGuardianRecurringLivenessFourCycle.tla` is a second executable wrapper
  over the same recurring core, instantiated at four cycles to demonstrate
  bounded reuse without rewriting the core.
- `NestedGuardianRecoveryRecurringLivenessCore.tla` is the reusable
  recovery-inclusive recurring core: it composes the recurring liveness core
  with the recovery kernel and exports the recovery-transfer landing
  soundness condition plus an explicit recovery-recurring recurrence contract
  and bounded closed-prefix recurrence properties.
- `NestedGuardianRecoveryRecurringInductionCore.tla` packages the first
  induction-shaped layer over that recovery-inclusive recurring core: it
  binds the base closed-prefix obligation together with the bounded step
  obligations up to cycle `c` and checks that those premises suffice to close
  the prefix at cycle `c`.
- `NestedGuardianRecoveryRecurringProof.tla` packages the next proof-oriented
  layer: it lifts the bounded induction kernel into a parameterized
  recurrence theorem surface over arbitrary `TotalCycles`.
- `NestedGuardianRecoveryClassicalAgreementReduction.tla` packages the first
  reduction-oriented layer: it maps those same closed prefixes into finite
  classical-agreement decision prefixes and states the corresponding first
  reduction theorem surface.
- `NestedGuardianRecoveryClassicalAgreementTotality.tla` packages the next
  totality-oriented layer: it lifts that finite reduction into a total
  classical-agreement history object over the model's arbitrary `TotalCycles`
  horizon, states the corresponding total reduction and recurrence-kernel
  corollaries, and is now directly discharged under `tlapm`.
- `NestedGuardianRecoveryClassicalAgreementCollapse.tla` packages the final
  semantic-collapse wrapper: it turns that discharged totality witness into the
  final stronger classical sentence as an explicit ordinary-history claim, and
  is now directly discharged under `tlapm` as well.
- `NestedGuardianRecoveryRecurringLiveness.tla` is the default bounded wrapper
  over that recovery-inclusive recurring core: its executable instance
  composes three recurring cycles while requiring each cycle's continuation
  publication and fetch to wait on recovery resolution of the current target
  slot.
- the validator/runtime side now mirrors that bounded target with a
  three-cycle historical-continuation restart harness under archived profile
  rotation and index-free continuation discovery, and now also with a single
  persistent historical-continuation churn/restart simulator over one evolving
  runtime state.
- the remaining follow-on is therefore no longer collapse-proof completion, but
  cleanup, doctrine promotion, and any broader runtime stress coverage we want
  to add on top of the finished formal bridge.
- `NestedGuardianRecovery.tla` is the exploratory executable model for the
  first constructive follow-on: assigned witness share receipts, deterministic
  recovery-window close, explicit dual-receipt conflict objects, and
  threshold-missingness certificates once recovery becomes impossible.
  The bounded `NestedGuardianRecovery.cfg` instance is intentionally kept to a
  bounded seven-slot `2-of-3` recovered-only prefix with a single candidate
  block per slot so TLC stays proportional to the current recursive
  overlap-stitched restart-ancestry slice; recovered close/abort composition
  remains exercised on the runtime side and in the unconstrained model
  semantics, but the executable bounded config now intentionally freezes
  missingness and abort churn because this slice is about recovered
  certified-header overlap composition rather than re-exploring omission
  branches. The runtime/tests now exercise the configurable bounded composer
  at its default five-window / seventeen-step branch and now also exercise a
  live recursive exact-overlap segment-of-segments composition of two
  overlapping four-segment folds into an eighty-nine-step recovered
  certified branch, plus a stronger three-fold / one-hundred-twenty-five-step
  runtime proof point and a bounded conformance harness across one, two, and
  three stitched segment folds. The runtime/tests now also exercise an
  overlap-checked paged cursor over older exact-overlap segment folds into a
  longer two-hundred-thirty-three-step recovered certified branch with direct
  registry parity plus explicit duplicate-page, missing-gap, and late-page
  overlap rejection while keeping only the bounded recent suffix plus the
  current streamed page live in engine caches. `NestedGuardianRecovery.tla`
  now abstracts the index-free historical replay rule with
  `RecoveredHistoricalBootstrapClosure`,
  `RecoveredHistoricalIntervalComposition`, and
  `RecoveredHistoricalIndexFreeReplay`; there is intentionally no mutable
  latest-activation index in that executable slice. This TLC instance remains
  the smaller executable abstraction of that recursive exact-overlap shape
  rather than a literal 233-step paging model. The live runtime now treats
  deeper recovered history as ordinary endogenous AFT history: canonical
  collapse / replay history names the historical continuation root, the AFT
  recovered-state contract carries the same continuation bundle, and the
  continuation objects are historically self-describing through profile-hash /
  activation-hash bindings plus predecessor/checkpoint validation rather than
  any latest-activation side index. This package note records that runtime
  theorem boundary,
even though the bounded TLC instance
  still abstracts the archival lane rather than modeling every archival object
  directly.
  That bounded config now also freezes witness availability via
  `NoAvailabilityChurn`, because this follow-on is about recovered surface /
  abort prefix composition rather than outage churn and the base
  `NestedGuardian.tla` package already covers assignment and outage behavior.
  It also serializes slot work via `RecoveredPrefixSeriality`, because this
  bounded follow-on is about recovered prefix extraction / ancestry
  composition rather than cross-slot recovery interleavings, and TLC now also
  uses witness symmetry reduction because this slice is about bounded prefix
  structure rather than witness identity.
  The recovery model now stores at most one threshold-missingness certificate
  per slot, because the runtime only needs one objective impossibility witness
  to force abort and enumerating every supporter subset adds state explosion
  without changing the close-or-abort semantics.

The current runtime now lands three honest engineering steps for that lane:
`DeterministicScaffoldV1`, a single-witness threshold-1 capsule and binding
producer on ordinary `ExperimentalNestedGuardian` finalization, including
publication of the matching signed scaffold share receipt, plus a
bounded abstract coded recovery-family contract over a publication-oriented
slot payload with ordered transaction bytes and canonical publication-bundle
bytes, currently realized by a `SystematicXorKOfKPlus1V1` cold-path parity
family and a parametric true non-parity `SystematicGf256KOfNV1` family with
bounded exercised instances at `2-of-4`, `3-of-5`, `3-of-7`, `4-of-6`, and
`4-of-7`. The runtime now also has a bounded conformance harness that checks
every threshold-sized reveal subset reconstructs and every below-threshold
subset fails across the admitted coded-family realizations of that contract.
The
runtime now also has bounded recovered-only harnesses for both adjacent
positive-slot frontier composition and a close/abort/close bulletin window
with a recovered omission-dominated middle slot, and those same recovered-only
bounded harnesses now also materialize the authoritative
`CanonicalCollapseObject` predecessor chain. The runtime now also has a bounded
read-side replay-prefix extractor over that recovered chain plus a bounded
recovered canonical-header extractor, and the execution module now verifies
the bounded replay-prefix tip as the same restart anchor that the ordinary
durable lane uses, retains both recovered prefixes in execution state, and
uses the recovered canonical-header ancestry for bounded anchored reads plus
parent-block / parent-state-root continuity after restart when ordinary recent
blocks are absent. Validator consensus orchestration now also uses the same
bounded recovered canonical-header / collapse surface to derive a recovered
restart parent anchor when the ordinary committed block is absent, and the
live `GuardianMajority` engine now also consumes that bounded recovered
canonical-header prefix as restart-time parent/QC context for synthetic
parent-height QC continuity when the full committed block is absent. That
same recovered surface now also yields a bounded recovered certified-header
window plus a restart-only recovered `BlockHeader` / QC cache window for
restart-time header / QC lookup plus bounded QC-certified recovered branch
reconciliation over the configured local five-entry window, and the runtime
can now also fold recovered windows by exact overlap with a configurable
budget, exercised today at five windows into a longer seventeen-step
recovered certified branch without falling back to ordinary committed-header
availability, and the runtime/tests now also recurse one level further by
composing two overlapping four-segment folds into an eighty-nine-step
recovered certified branch plus a three-fold one-hundred-twenty-five-step
proof point. The live restart cache is now complemented by bounded-memory
paging beneath that suffix, so broader restart-time recovered QC-certified
ancestry can stream until target height or recovered-history exhaustion. The
TLA+
recovery model now
mirrors that mixed-window sequencing rule and the same recursive
overlap-composition shape in a bounded seven-slot `2-of-3` instance:
threshold-many support can recover positively, threshold-many missingness can
force abort only after predecessor resolution, later recovered surfaces can
continue after that predecessor abort, and recovered surfaces / aborts respect
the same collapse-prefix continuity across the stitched recovered-only prefix.
The coded
lanes now also have distinct per-witness signed carriage and sealed-finality
publication of the shared capsule plus derived per-witness receipts, plus
off-chain assigned-share delivery-before-sign with guardian-local durable
custody of the exact share material. They can now also reload those stored
shares by signed binding, publish verified public `RecoveryShareMaterial`
reveals, reconstruct the publication-oriented payload from threshold-many
public reveals, and publish a compact `RecoveredPublicationBundle` object for
the recovered verifying publication bundle. That recovered publication payload
can now also be lifted deterministically first into the explicit positive
close-extraction surface and then into the explicit extractable
bulletin-surface payload by deriving and hashing the verifying canonical
bulletin-close bytes, bulletin-availability bytes, and sorted bulletin
entries. The registry can therefore materialize the ordinary positive
canonical close surface plus the same extracted bulletin surface from that
object, fail closed to a deterministic recovery-impossible canonical abort
from published missingness evidence, and fail closed to canonical abort from
objective recovered-support conflict. The bounded formal slice now also checks
that extracted recovered surfaces and aborts form a predecessor-respecting
seven-slot recovered-only prefix and the same authoritative collapse-prefix
chain. The live runtime no longer has an unresolved theorem-side recovery
scope gap here: close-or-abort integration, recovered closed-slot extraction,
authoritative collapse / replay / header extraction, restart continuation,
and deeper historical continuation are now part of one singular AFT theorem
surface. That singular theorem surface is now also promoted repository-wide to
unconditional classical `99% Byzantine agreement`. What remains here is package
hygiene, proof maintenance, and any broader stress coverage we want on top of
that finished bridge.

Its job is to keep the runtime’s witness-assignment, reassignment, and
witness-admissibility rules aligned with the implementation.

## Files

- `NestedGuardian.tla`: executable TLC model
- `NestedGuardianLiveness.tla`: executable TLC liveness harness for bounded
  churn followed by eventual target finalization
- `NestedGuardianRecurringLiveness.tla`: executable TLC liveness harness for
  a cycle-count-parameterized recurring bridge; the default executable
  instance uses three bounded churn/finalization/continuation cycles plus an
  explicit recurrence-transfer property
- `NestedGuardianRecurringLivenessCore.tla`: reusable parameterized
  recurring-liveness core used by the default wrapper
- `NestedGuardianRecurringLivenessFourCycle.tla`: second executable wrapper
  over the same core, instantiated at four cycles
- `NestedGuardianRecurringLivenessFourCycle.cfg`: bounded TLC configuration for
  the four-cycle wrapper
- `NestedGuardianRecoveryRecurringLivenessCore.tla`: reusable
  recovery-inclusive recurring core
- `NestedGuardianRecoveryRecurringLiveness.tla`: executable TLC wrapper over
  the recovery-inclusive recurring core
- `NestedGuardianRecoveryRecurringLiveness.cfg`: bounded TLC configuration for
  the recovery-recurring bridge
- `NestedGuardianRecoveryClassicalAgreementCollapse.tla`: first semantic
  collapse wrapper from discharged totality into the final stronger classical
  sentence
- `NestedGuardianRecovery.tla`: executable TLC model for threshold recovery or
  deterministic missingness with explicit conflict and threshold objects
- `NestedGuardianProof.tla`: proof-kernel module for TLAPS work
- `NestedGuardian.cfg`: bounded TLC configuration
- `NestedGuardianLiveness.cfg`: bounded TLC configuration for the first churn
  liveness harness
- `NestedGuardianRecurringLiveness.cfg`: bounded TLC configuration for the
  first recurring liveness harness
- `NestedGuardianRecovery.cfg`: bounded TLC configuration for the recovery
  kernel

## Running locally

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

The script discharges both proof kernels and then runs TLC over the executable
models. The verifier-kernel conformance tests that back the log/certificate
predicates live in:

- [`guardian_committee.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_committee.rs)
- [`guardian_log.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_log.rs)
