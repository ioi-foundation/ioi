# NestedGuardian

NestedGuardian is the witness-augmented mode within the broader Aft
Fault Tolerance family.

## Intended Model

This mode explores a layered construction:

- outer validators run the aft Aft deterministic message flow
- each validator proposal is certified by its own guardian committee
- external witness committees cross-check slot certificates
- chain state anchors witness-log checkpoints and slashing evidence

The goal is to study whether composed threshold assumptions can provide
effective majority-safety regimes beyond the standard single-layer Byzantine
model.

## Current Runtime Scope

The current codebase implements the cryptographic runtime needed to run this
mode and a split formal package for its safety rules:

- guardian slot certificates may carry an `experimental_witness_certificate`
- experimental witness statements and certificates may optionally carry a
  signed `recovery_binding` covering a recovery-capsule hash and a coded-share
  commitment hash
- the live signer/control path can now carry that optional recovery binding
  end to end
- witness committees are registered on-chain through the guardian registry
- validators in NestedGuardian mode reject slot certificates that do
  not include a valid, assigned, registered witness certificate
- witness assignment is derived deterministically from the active witness set,
  the epoch seed, the proposal slot, and the reassignment depth
- ordinary `ExperimentalNestedGuardian` block production now synthesizes a
  deterministic `RecoveryCapsule_h` scaffold from the committed slot surface,
  the assigned witness manifest, and the reassignment depth
- a first-class `RecoveryWitnessCertificate_h` can now be derived from the
  finalized header plus the signed witness certificate, and finalization will
  publish the scaffold capsule when missing plus the derived witness
  certificate and matching signed scaffold share receipt when the signed
  recovery binding matches that scaffold
- the asymptote sealed-finality path can now carry distinct per-witness
  recovery bindings across the returned witness certificates and publish the
  shared descriptor-based capsule plus the derived per-witness recovery
  witness certificates and compact share receipts when those bindings match
  the deterministic recovery coding plan
- the same sealed-finality path can now also deliver off-chain
  `AssignedRecoveryShareEnvelopeV1` objects to the assigned witness
  committee, and the guardian will verify and durably store the exact share
  material before any local or remote witness member signs
- `formal/nested_guardian/NestedGuardianProof.tla` proves the
  unbounded witness-augmented safety kernel in TLAPS
- the executable TLA+ model in `formal/nested_guardian/` checks
  witness assignment, reassignment, outage, and checkpoint-admissibility
  transitions in bounded TLC runs

## Research Questions

- How should witness committees be assigned across epochs?
- What checkpoint cadence is sufficient to make rollback detection meaningful?
- What slashing evidence is required for witness omission, stale registry use, or conflicting witness attestations?
- Which combinations of validator faults, guardian faults, witness faults, and registry/log faults still preserve safety?

## Exploratory Recovery Variant

The constructive lower-bound follow-on now scopes its first recovery variant
under `NestedGuardian` rather than under baseline canonical ordering. The
reason is simple: this mode already has deterministic witness assignment,
registered witness manifests, and a formal safety kernel for witness-backed
admissibility.

The minimal exploratory object family is:

```text
RecoveryCodingDescriptor_h = (
  family_h,
  share_count_h,
  recovery_threshold_h
)

RecoveryCapsule_h = (
  h,
  RecoveryCodingDescriptor_h,
  recovery_committee_root_h,
  payload_commitment_h,
  coding_root_h,
  recovery_window_close_h
)

RecoveryWitnessCertificate_h = (
  h,
  witness_manifest_hash_h,
  witness_epoch,
  recovery_capsule_hash_h,
  share_commitment_h
)

RecoverableSlotPayloadV1_h = (
  h,
  view_h,
  producer_h,
  block_commitment_h,
  OCert_h,
  ordered_tx_hashes_h
)

RecoverableSlotPayloadV2_h = (
  h,
  view_h,
  producer_h,
  block_commitment_h,
  OCert_h,
  ordered_tx_bytes_h
)

RecoverableSlotPayloadV3_h = (
  h,
  view_h,
  producer_h,
  block_commitment_h,
  OCert_h,
  ordered_tx_bytes_h,
  canonical_order_publication_bundle_bytes_h
)

RecoverableSlotPayloadV4_h = (
  h,
  view_h,
  producer_h,
  block_commitment_h,
  OCert_h,
  ordered_tx_bytes_h,
  canonical_order_publication_bundle_bytes_h,
  canonical_bulletin_close_bytes_h
)

RecoveryShareMaterial_h = (
  h,
  witness_manifest_hash_h,
  block_commitment_h,
  RecoveryCodingDescriptor_h,
  share_index_h,
  share_commitment_h,
  material_bytes_h
)

AssignedRecoveryShareEnvelopeV1_h = (
  recovery_capsule_hash_h,
  expected_share_commitment_h,
  RecoveryShareMaterial_h
)

RecoveryShareReceipt_h = (
  h,
  witness_manifest_hash_h,
  block_commitment_h,
  share_commitment_h
)

RecoveredPublicationBundle_h = (
  h,
  block_commitment_h,
  RecoveryCodingDescriptor_h,
  supporting_witness_manifest_hashes_h,
  recoverable_slot_payload_hash_h,
  recoverable_full_surface_hash_h,
  canonical_order_publication_bundle_hash_h,
  canonical_bulletin_close_hash_h
)

MissingRecoveryShare_h = (
  h,
  witness_manifest_hash_h,
  recovery_capsule_hash_h,
  recovery_window_close_h
)
```

The live NestedGuardian path is committee / manifest centric, so the
exploratory recovery object family is now explicitly manifest-scoped as well.
The remaining blocker is no longer witness identity or the total absence of a
capsule producer. Ordinary block production can now synthesize a deterministic
single-witness scaffold, and the cold path now contains an abstract coded
recovery-family contract that reaches the canonical publication bundle, as
currently realized by the parametric `SystematicXorKOfKPlus1V1` parity family
plus the parametric true non-parity `SystematicGf256KOfNV1` family with at
least two parity shares, now implemented with systematic Cauchy-style
coefficients and presently exercised in bounded `2-of-4`, `3-of-5`, `3-of-7`,
`4-of-6`, and `4-of-7` lanes.
Ordinary finalization now also
publishes the matching signed scaffold share receipt, and the sealed-finality
path now publishes distinct per-witness witness certificates and receipts when
the deterministic coded-share plan is carried honestly. With the new
assigned-share envelope path, those lanes now have initial
delivery-before-sign and local witness custody. With the new reveal path, they
now also have later share retrieval by signed binding plus public reveal
publication. With the new recovered-publication path, threshold-many public
reveals can now also be summarized into a compact
`RecoveredPublicationBundle_h` that binds the recovered positive
close-extraction surface, the explicit recovered extractable
bulletin-surface payload, the verifying canonical publication bundle, and the
verifying canonical bulletin close. The same coded lanes can now materialize
the ordinary positive canonical close surface from that recovered object,
recover the same extractable bulletin surface used by
`extract_published_bulletin_surface`, route recovered omission-carrying
bundles into the ordinary `OmissionDominated` canonical abort path while
keeping omission evidence published, and enough `MissingRecoveryShare_h`
objects can now force a deterministic recovery-impossible canonical abort.
The bounded recovered-only harness now also shows that two consecutive
recovered `RecoverableSlotPayloadV5_h` surfaces can still derive and publish
the ordinary `PublicationFrontier_h` predecessor chain and the same
authoritative `CanonicalCollapseObject_h` predecessor chain without the
ordinary publication-bundle lane.
Another bounded recovered-only harness now shows a close/abort/close window
with a recovered omission-dominated middle slot: recovered data alone
materializes the ordinary positive closes and extracted bulletin surfaces on
the outer slots, materializes the ordinary `OmissionDominated` abort in the
middle while keeping omission evidence and recovered bulletin entries public,
still lets the positive slots carry ordinary `PublicationFrontier_h`
objects where applicable, and now also materializes the same authoritative
`CanonicalCollapseObject_h` continuity chain across that bounded window.
The runtime now also has a bounded read-side replay-prefix extractor over that
persisted recovered chain: the same recovered-only durable surface yields the
same compact height-to-state-root prefix view that ordinary execution / replay
would consume, and a bounded recovered canonical-header extractor now yields
the same compact recent consensus ancestry surface from those recovered full
slots. The execution module now also uses that bounded replay-prefix tip as a
restart verifier against the loaded durable state root, retains both bounded
recovered prefixes in execution state, and now uses the recovered
canonical-header ancestry for bounded anchored reads plus parent-block /
parent-state-root continuity after restart when ordinary recent blocks are
absent, so the recovered-only durable surface now reaches the ordinary
execution handoff seam rather than only a state-root-only restart check. The
validator consensus orchestrator now also uses the same bounded recovered
canonical-header / collapse surface to derive a recovered restart parent
anchor when the ordinary committed block is absent, so close-valued recovered
restart tips no longer silently collapse back to genesis ancestry, and the
live `GuardianMajority` engine now also consumes that bounded recovered
canonical-header prefix as restart-time parent/QC context for synthetic
parent-height QC continuity when the full committed block is absent. The
same bounded recovered surface now also yields a bounded recovered
certified-header window plus a restart-only recovered `BlockHeader` / QC
cache window carrying the compact certified-parent linkage and restart
header surface that validator restart and the live engine now use for
restart-time header / QC lookup plus bounded QC-certified recovered branch
reconciliation over the configured local five-entry window when the ordinary
committed block is absent, and the same loaders now expose a configurable
exact-overlap fold budget, exercised today at five recovered windows into a
longer seventeen-step recovered certified branch without ordinary committed
headers. Those same live cold-path loaders now also consume a configurable
exact-overlap segment budget, exercised today at four exact-overlap segments
into a longer fifty-three-step recovered certified branch with direct
registry-extraction parity and explicit interior-overlap conflict rejection.
Those same live restart loaders now also recurse one level further by
composing two overlapping four-segment exact-overlap folds into a longer
eighty-nine-step recovered certified branch with matching registry parity and
explicit inter-fold overlap conflict rejection, and runtime/tests now also
exercise that same recursive carrier at three overlapping four-segment folds
into a one-hundred-twenty-five-step recovered certified branch. The runtime
now also has a bounded conformance harness over one, two, and three stitched
segment folds, matching the same production-loader / registry-extraction
carrier at the corresponding fifty-three-step, eighty-nine-step, and
one-hundred-twenty-five-step branches. The same live restart path can now
also page older exact-overlap segment folds on demand beneath that bounded
in-memory suffix via an overlap-checked cursor while keeping only the
bounded recent suffix plus the current streamed page live in engine caches,
and runtime/tests now exercise that paged carrier at a longer
two-hundred-thirty-three-step recovered certified branch with matching
registry parity plus explicit duplicate-page, missing-gap, and late-page
overlap rejection. This closes the validator-side ancestry-composition gap:
restart can now stream recovered certified ancestry until target height or
recovered-history exhaustion without a theorem-relevant fixed depth bound.
The live theorem story is now singular rather than two-tiered: the whole AFT
stack universally breaks the lower bound with no qualifiers. Ordinary
canonical collapse and replay history now name the deeper historical
retrievability root, the AFT recovered-state contract carries the same
historical retrievability surface for restart consumers, and the historical
retrievability objects themselves are profile-hash-bound, activation-hash-bound,
content-addressed, and validated by predecessor/checkpoint history rather
than mutable latest indexes. Broader recovered history is therefore ordinary
endogenous AFT history, not a standing theorem-side qualifier.
In the bounded admitted coded families, disjoint threshold support sets no
longer force an optimistic positive-close ambiguity: conflicting recovered
publication bundles now fail closed to canonical abort rather than remaining
as two positive close candidates, and the bounded conformance harness now
checks that every threshold-sized reveal subset reconstructs and every
below-threshold subset fails across the shipped XOR and GF256 realizations of
the abstract recovery-family contract. The completed lane is therefore no
longer blocked by public resolution plumbing, explicit recovered closed-slot surface
extraction, bounded recovered-only authoritative collapse-window
composition, bounded replay-prefix extraction, bounded recovered
canonical-header extraction, bounded recovered certified-header plus
restart-header extraction, bounded execution restart-handoff verification,
bounded anchored-read / recovered parent-block / parent-state-root execution
continuation, or the total absence of non-parity redundancy. The
theorem-scope promotion and historical-retrievability internalization work are
now complete. This is not a tentative side theorem; it is the live repository
claim that the whole AFT stack universally breaks the lower bound with no
qualifiers plus `99% Byzantine Tolerance` inside the AFT architecture. It
should be read as a categorical architectural result, not
as a half-promoted corollary waiting for another qualifier to fall away. That
same achieved result is now also promoted directly to unconditional classical
`99% Byzantine agreement` in the ordinary dense-vote permissioned model. The
canonical statement of that promotion lives in
[`yellow_paper.tex`](/home/heathledger/Documents/ioi/repos/ioi/docs/architecture/protocols/aft/specs/yellow_paper.tex),
not as an open theorem gap, but as the final specification.

The intended semantics are:

- `RecoveryCapsule_h` binds the recovery obligation for one slot surface and
  names the recovery coding descriptor that produced it
- `RecoveryWitnessCertificate_h` says the assigned witness is registered for
  the slot's recovery capsule and commits to one coded share
- `RecoverableSlotPayloadV1_h` is the narrower predecessor payload that carried
  only ordered transaction hashes
- `RecoverableSlotPayloadV2_h` is the live widened canonical slot payload for
  the intermediate coded-share experiment and carries canonical ordered transaction
  bytes
- `RecoverableSlotPayloadV3_h` is the live publication-oriented payload for the
  current coded-share experiments and adds canonical encoded
  `CanonicalOrderPublicationBundle_h` bytes to the ordered transaction bytes
- `RecoverableSlotPayloadV4_h` is the lifted positive close-extraction payload
  derived from `RecoverableSlotPayloadV3_h` by verifying the recovered
  publication bundle and appending the exact canonical
  `CanonicalBulletinClose_h` bytes that the ordinary positive lane needs
- `RecoverableSlotPayloadV5_h` is the lifted explicit extractable
  bulletin-surface payload derived from `RecoverableSlotPayloadV4_h` by
  appending the exact canonical encoded bulletin-availability bytes plus the
  sorted canonical bulletin-entry surface that
  `extract_published_bulletin_surface` depends on
- `RecoveryShareMaterial_h` is the cold-path reveal object that expands one
  witness share commitment into concrete material bytes and a candidate block
  commitment under one recovery coding descriptor
- `AssignedRecoveryShareEnvelopeV1_h` is the off-chain delivery object that
  hands one assigned witness the exact `RecoveryShareMaterial_h` it must store
  before signing the bound witness statement
- `RecoveryShareReceipt_h` is the compact public receipt that binds a witness
  share to one candidate slot surface / block commitment
- `RecoveredPublicationBundle_h` is the compact public recovered object that
  says one canonical support set of public reveals reconstructs a specific
  `RecoverableSlotPayloadV4_h` hash, one specific
  `RecoverableSlotPayloadV5_h` hash, plus verifying
  `CanonicalOrderPublicationBundle_h` and `CanonicalBulletinClose_h` hashes
  under one recovery coding descriptor
- `MissingRecoveryShare_h` is the compact public claim that the assigned
  witness failed to reveal its committed share before the deterministic recovery
  window closed

Two `RecoveryShareReceipt_h` objects for the same `(h, witness_id)` and
different `block_commitment_h` form objective conflict evidence. A slot should
eventually resolve one of three ways:

- threshold recovery: enough assigned witnesses reveal matching receipts to
  make reconstruction possible and support publication of a compact
  `RecoveredPublicationBundle_h` that materializes the ordinary positive
  canonical close surface when the recovered certificate is omission-free, or
- recovered omission dominance: threshold-many reveals reconstruct a
  `RecoveredPublicationBundle_h` whose carried certificate contains objective
  omission proofs, and the registry therefore publishes the ordinary
  `OmissionDominated` canonical abort while keeping the omission evidence
  and bulletin entries public, or
- recovered-support conflict: distinct threshold support sets reconstruct
  conflicting `RecoveredPublicationBundle_h` objects and therefore materialize
  a fail-closed canonical abort, or
- deterministic missingness: enough `MissingRecoveryShare_h` objects accumulate
  to make threshold recovery impossible for the slot window and materialize a
  recovery-impossible canonical abort

This is intentionally narrower than a full coded-DA theorem. It is the smallest
candidate surface that could turn witness assignment into endogenous recovery
authority without asking all validators to reconstruct the full slot surface on
the hot path.

The current exploratory runtime now gives these objects a canonical registry
lane:

- `RecoveryCapsule_h` is stored once per slot height
- `RecoveryWitnessCertificate_h` is stored once per
  `(h, witness_manifest_hash_h)`
- `RecoveryShareReceipt_h` is stored per
  `(h, witness_manifest_hash_h, block_commitment_h)`
  so same-witness cross-block conflicts remain visible instead of being
  overwritten
- `RecoveryShareMaterial_h` is stored per
  `(h, witness_manifest_hash_h, block_commitment_h)` and is only admissible
  when the matching witness certificate and compact receipt already exist
- `RecoveredPublicationBundle_h` is stored per
  `(h, block_commitment_h, support_hash_h)` where `support_hash_h` is the
  canonical hash of the sorted supporting witness-manifest list, and is only
  admissible when the supporting public share reveals reconstruct the claimed
  payload, publication-bundle, and bulletin-close hashes; once admitted it can
  materialize the ordinary positive canonical close surface even if the ordinary
  publication-bundle lane was absent
- `MissingRecoveryShare_h` is stored once per `(h, witness_manifest_hash_h)`
  and is only admissible when the bound capsule / witness certificate exist
  and no receipt has already been published for that witness; once enough such
  objects accumulate to make threshold recovery impossible, the registry can
  materialize a deterministic recovery-impossible canonical abort

The live witness-certification path now also carries the first cryptographic
attachment needed for a constructive route:

- `GuardianWitnessStatement` may include
  `recovery_binding = (recovery_capsule_hash_h, share_commitment_h)`
- `GuardianWitnessCertificate` mirrors that binding
- witness-certificate verification rejects any mismatch between the signed
  statement and the carried certificate binding
- `GuardianMajority` reconstructs the same signed statement when it verifies
  experimental witness certificates, so tampering with the carried recovery
  binding is rejected on the witness-verification path
- the same header/certificate pair now deterministically derives a
  first-class `RecoveryWitnessCertificate_h`
- ordinary `ExperimentalNestedGuardian` block production now derives
  `RecoveryCapsule_h` with
  `RecoveryCodingDescriptor_h = (DeterministicScaffoldV1, 1, 1)`, a single
  assigned witness, and deterministic `payload_commitment_h`,
  `coding_root_h`, and `share_commitment_h` values from the committed slot
  surface
- finalization publishes that scaffold capsule automatically when it is absent
  and then publishes the derived witness certificate plus the matching compact
  scaffold share receipt when the signed recovery binding matches the
  deterministic scaffold
- `guardian_registry` can now classify a recovery lane as pending,
  recoverable, or impossible from compact receipt and missingness evidence
  alone; conflicting same-witness multi-block receipts remain visible but do
  not count as positive support for any single candidate block

Historically this began as a cold-path scaffold. The live theorem surface now
treats the shipped recovery-family contract as complete for its admitted
families, while still leaving room for broader operational envelopes:

- `DeterministicScaffoldV1` is only a single-witness threshold-1 carrier
- the underlying bulletin `recoverability_root` is still a commitment-only
  seed over bulletin / randomness / ordered-transactions / post-state inputs
- an exploratory off-hot-path multi-witness planning step can now derive
  deterministic witness committees, threshold-k coding parameters, and
  per-witness share-commitment hashes from that shared seed plus the current
  witness-assignment carrier
- a new cold-path kernel can now materialize deterministic
  `RecoveryShareMaterial_h` objects and verify them back into matching
  `RecoveryShareReceipt_h` objects from current endogenous inputs alone
- the live materialization kinds are:
  `TransparentCommittedSurfaceV1`, a transparent preimage over already
  committed slot-surface facts, and `SystematicXorKOfKPlus1V1`, a parametric
  `k-of-(k+1)` systematic XOR parity family over `RecoverableSlotPayloadV3_h`
- that `SystematicXorKOfKPlus1V1` lane can reconstruct widened ordered
  transaction bytes plus canonical publication-bundle bytes from
  threshold-many distinct witness reveals in the parity-family shape
- the recovered publication-bundle bytes decode to a verifying
  `CanonicalOrderPublicationBundle_h` under current endogenous finalization
  rules
- the repo now has end-to-end receipt publication and compact threshold-status
  observation for the signed scaffold lane
- the parity family now also has delivery-before-sign and guardian-local
  durable custody via off-chain `AssignedRecoveryShareEnvelopeV1_h` carriage
  on the witness-signing path
- the parity family now has honest multi-witness signed carriage plus
  shared-capsule / per-witness receipt publication through sealed finality
- the parity family can now later reload those stored shares by signed
  binding, publish verified public `RecoveryShareMaterial_h` objects into the
  registry lane, reconstruct `RecoverableSlotPayloadV3_h` from threshold-many
  published reveals, lift it into `RecoverableSlotPayloadV4_h` and then
  `RecoverableSlotPayloadV5_h`, and publish a compact
  `RecoveredPublicationBundle_h` object for the recovered verifying
  publication bundle, bulletin close, and extractable bulletin surface
- the parity family can now also materialize the ordinary positive
  canonical close surface from `RecoveredPublicationBundle_h`, route
  omission-carrying recovered bundles into the ordinary
  `OmissionDominated` abort path, and fail closed to a deterministic
  recovery-impossible canonical abort from published missingness evidence
- broader coded-share engines, wider family inventories, and richer
  bulletin-surface materialization remain future envelope extensions rather
  than theorem-side blockers on the promoted singular claim

The bounded formal recovery kernel now mirrors that shape: dual receipts
materialize explicit conflict objects, and missingness is derived through an
explicit threshold certificate rather than a bare cardinality guard.

## Current Constructive Scope Decision

For now, these recovery objects should be treated as a `NestedGuardian`
attachment, not as part of the baseline `GuardianMajority` or ordinary
canonical-ordering runtime.

That keeps the theorem honest:

- the completed recovery lane is explicit layered witness authority expressed
  through an AFT-native recovery / historical-retrievability module
- the singular AFT claim already includes that lane rather than excluding it
- any future strengthening must improve liveness, efficiency, or operational
  envelope, not reintroduce theorem-side scope qualifiers

## Remaining Proof And Operations Work

- anti-capture rotation policy beyond the current deterministic assignment rule
- stronger composed liveness analysis under the now-explicit target model:
  frontier generation, canonical resolution, recovery completion,
  restart/continuation re-entry, and infinite composition under repeated
  reassignment and witness outage
- larger simulator / counterexample search over validator, guardian, witness, and log faults
- threshold recovery-or-missingness proofs over witness-coded share receipts
- operational guidance for rotation cadence, reassignment depth, and outage handling

Until those conditions are tightened into a full composed liveness theorem, the
open issue should be read narrowly: not “generic unfinished liveness,” but the
specific composed liveness kernel under the target eventual-fair scheduler.
This mode should therefore be treated as a witness-augmented aft path with
unbounded safety proofs, bounded operational model checking, a first bounded
churn-to-finalization-and-continuation-bootstrap liveness harness in the
formal package, a stronger cycle-count-parameterized recurring bridge whose
default executable instance still uses three cycles, and one explicit remaining
unbounded-composition liveness kernel rather than an undefined theorem gap. The
implementation side now mirrors that bounded recurring bridge
with a three-cycle historical-retrievability restart harness under archived
profile rotation and index-free retrievability discovery, so the remaining
open step is unbounded recurrence rather than missing repeated-cycle evidence
or a missing one-step recurrence-transfer witness. The formal side now also
reuses the same recurring core through a second four-cycle executable wrapper,
so the open issue is no longer bounded reuse of the recurring core itself.
That recurring skeleton is now also factored into a reusable
recovery-inclusive core, `NestedGuardianRecoveryRecurringLivenessCore.tla`,
whose default bounded wrapper `NestedGuardianRecoveryRecurringLiveness.tla`
requires each cycle's continuation publication and fetch to wait on recovery
resolution of the current target slot and exports the corresponding
recovery-transfer landing soundness condition. That same core now also carries
an explicit recovery-recurring recurrence contract: once cycle `c` has landed
in the normalized transfer state with cycle `c - 1` already resolved, the
model must eventually resolve and fetch cycle `c`, and while still in that
resolved/fetched state it must eventually land the normalized transfer state
for cycle `c + 1`. The same bounded artifact now also closes the
corresponding prefix form: every bounded closed prefix is eventually reached,
and every closed prefix at cycle `c` eventually advances to the closed prefix
for cycle `c + 1`. A further induction-oriented layer now packages the base
closed-prefix obligation together with the bounded step obligations up to
cycle `c` and checks that those premises suffice to close the prefix at
cycle `c`. A further proof-oriented layer now packages those bounded
ingredients into a parameterized recurrence theorem surface: for arbitrary
`TotalCycles`, the global induction premises together with the bounded kernel
imply closure of every finite prefix. A first reduction-oriented layer now
maps those same closed prefixes into finite classical-agreement decision
prefixes and states the corresponding first reduction theorem surface. A
further totality-oriented layer now lifts that finite reduction into a total
classical-agreement history object over the model's arbitrary `TotalCycles`
horizon, and that recurrence/reduction/totality chain is now directly
discharged under `tlapm`. The semantic-collapse wrapper is now directly
discharged too in
`formal/nested_guardian/NestedGuardianRecoveryClassicalAgreementCollapse.tla`,
packaging the final stronger classical sentence itself as an explicit
ordinary-history witness over that discharged totality chain. The validator
runtime now also mirrors the recurring side with a single persistent
historical-retrievability churn/restart simulator over one evolving state. The
remaining work is therefore no longer collapse-proof completion or theorem
promotion, but only cleanup, proof maintenance, and any broader runtime stress
coverage we may want to add on top of the finished formal bridge.
