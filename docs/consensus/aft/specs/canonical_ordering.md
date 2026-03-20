# Canonical Ordering

This document is the normative protocol model for AFT's proof-carrying
equal-authority ordering path. It is the ordering-specific component of the
repository's broader `99% Byzantine Tolerance` claim over an explicit
public-state-continuity substrate.

Consensus is obtained because the ordered set is accepted when it is uniquely
and recoverably *proved*, not because it wins a dense validator vote.

## Objective

For each slot `h`, define a unique canonical ordered set `O_h` and a certificate
`OCert_h` such that:

- every honest verifier can check `OCert_h` cheaply,
- any omission is objectively provable,
- the ordered set is recoverable from public data,
- conflicting valid certificates for the same slot are impossible, and
- arbitrary behavior by almost all validators cannot create a conflicting valid
  ordering outcome, and every honest validator that observes the same closed
  bulletin surface derives the same positive order object or decisive abort.

## Public State Continuity Instance

Canonical ordering is the ordering-specific instance of AFT's broader
`public state continuity with extractable obstructions` target.

For the closed ordering boundary

```text
∂_h^ord = (root_{h-1}, bulletin_commitment_h, cutoff_certificate_h, R_h, verifier_id)
```

define the ordering language

```text
L_ord(∂_h^ord) = { X | ∃π : Accept(∂_h^ord, X, π) = 1 }
```

where `X` is the normalized public ordering object for slot `h`.

The target theorem shape is:

```text
1. |L_ord(∂_h^ord)| <= 1
2. any fully specified conflicting candidate admits a short public rejection witness
3. the protocol-defined bulletin extractor deterministically reconstructs the
   closed bulletin surface from CanonicalBulletinClose_h, and every honest
   verifier that observes the same closed boundary derives the same
   admissible order object or decisive abort
```

In canonical ordering, the positive witness is the succinct order-certificate
proof and the negative witness is an omission proof.

## Canonical Objects

For slot `h`:

```text
B_h   = bulletin surface certified recoverable by BulletinAvailabilityCertificate_h
        and sealed by CanonicalBulletinClose_h
R_h   = public randomness beacon for slot h
E_h   = { tx | Included(tx, B_h) ∧ Eligible(tx, root_{h-1}) }
O_h   = CanonicalOrder(R_h, E_h)
root_h = Execute(root_{h-1}, O_h)
```

The certifying object is:

```text
OCert_h = (
  h,
  root_{h-1},
  cutoff_certificate_h,
  bulletin_commitment_h,
  bulletin_availability_certificate_h,
  canonical_set_commitment_h,
  resulting_state_root_h,
  succinct_witness_h
)
```

The slot also exports a first-class public close artifact:

```text
CanonicalBulletinClose_h = (
  h,
  cutoff_timestamp_h,
  bulletin_commitment_hash_h,
  bulletin_availability_certificate_hash_h,
  entry_count_h
)
```

`CanonicalBulletinClose_h` is not inlined into `OCert_h` in the current
runtime. It is derived from the proof-carried bulletin objects and persisted
into the registry as the unique closed bulletin object for slot `h`.

The current runtime also exports a first-class negative ordering artifact:

```text
CanonicalOrderAbort_h = (
  h,
  reason_h,
  details_h,
  bulletin_commitment_hash_h?,
  bulletin_availability_certificate_hash_h?,
  bulletin_close_hash_h?,
  canonical_order_certificate_hash_h?
)
```

`CanonicalOrderAbort_h` is published when deterministic local extraction of the
proof-carried ordering surface fails closed for slot `h`. It is not yet the
final universal collapse object for the whole protocol, but it is the
ordering-specific negative artifact that mirrors `CanonicalBulletinClose_h` on
the positive side. In the live engine, a published `CanonicalOrderAbort_h`
already acts as consensus-visible negative authority for ordering enrichment:
it dominates any positive canonical-order certificate for the same slot and the
engine rejects parent state that mixes an ordering abort with positive
published ordering artifacts. In the current Phase 3 runtime slice, execution
also folds the ordering close-or-abort result into a protocol-wide
`CanonicalCollapseObject_h`. Validator finalization now publishes that object
through `publish_aft_canonical_collapse_object@v1` after local post-commit
header enrichment, `guardian_registry` stores the published copy under the slot
height, and `GuardianMajority` cross-checks it against the proof-carried header
surface when parent-state data is available. The externally finalized AFT
commit path persists the same object alongside the committed state root, so
ordering collapse now participates directly in durable AFT state wherever the
decisive proof surface is already present at commit time. In the current
recursive-continuity slice, `CanonicalCollapseObject_h` also carries a rolling
`previous_canonical_collapse_commitment_hash`, so the slot-local ordering
outcome is bound not just to its own closed boundary but to the previously
persisted or published collapse object as well. In the current clean-break runtime slice,
`CanonicalCollapseObject_h` also carries `continuity_accumulator_hash` plus
`continuity_recursive_proof`, and the newest proposal-surface slice pushes
that continuity rule into the signed block itself: `BlockHeader_h` now carries
`previous_canonical_collapse_commitment_hash` in its signed preimage and now
also carries `CanonicalCollapseExtensionCertificate` as the proof-carrying
continuity certificate. In the newest succinct live-carrier slice, that
certificate no longer carries the full predecessor proof chain. Instead it
carries only the predecessor commitment plus the predecessor recursive-proof
hash for slot `h-1`, while the public `CanonicalCollapseObject_{h-1}` carries a
single recursive proof step plus its recursive public inputs. The shared proof
system surface now distinguishes the reference `HashPcdV1` carrier from a
backend slot `SuccinctSp1V1`, and `ioi-api` plus `zk-driver-succinct` now
expose a continuity-verifier seam for those same public inputs. That seam is
now exercised on the live runtime path too: `GuardianMajority` uses it when a
carried or anchored continuity proof step advertises `SuccinctSp1V1`, and
validator durable-state gating also uses the same backend check before a
persisted canonical collapse object is treated as authoritative. The rolling
`continuity_accumulator_hash` still compresses the same chain. `Asymptote`
leaders stall rather than propose when the required extension certificate or
its anchored predecessor collapse object is unavailable, proposal verification
checks that the carried predecessor commitment hash matches the signed
predecessor link, checks that the predecessor commitment's resulting state root
matches the signed parent-state root, and checks that the carried predecessor proof hash
matches the anchored predecessor collapse object. QC progress now therefore
treats the anchored predecessor collapse object plus the succinct extension
certificate as the live continuity authority and only treats
continuity-linked headers as proposal-authoritative. The formal package now
mirrors that runtime relation with
`formal/aft/canonical_ordering/CanonicalCollapseRecursiveContinuity.tla`, a
bounded TLC model of deterministic proof steps, predecessor-proof hashing,
extension-certificate carriage, and header-admission dependence on the
anchored predecessor proof relation. The formal model still covers the
reference `HashPcdV1` carrier; the landed `SuccinctSp1V1` backend is the
runtime upgrade path beyond that model and is now active on both live
consensus verification and durable persisted-collapse verification.

## Succinct Witness

The witness must be *succinct*: all validators verify a small object instead of
replaying the full bulletin or recomputing the ordering search.

The abstract witness shape is:

```text
succinct_witness_h = (
  verifier_id,
  proof_bytes,
  bulletin_root_h,
  bulletin_availability_certificate_hash_h,
  eligibility_root_h,
  canonical_order_root_h,
  omission_commitment_h
)
```

The witness proves:

```text
1. bulletin_root_h commits the public bulletin / DA surface B_h
2. cutoff_certificate_h defines the unique admissible cutoff τ_h
3. bulletin_availability_certificate_hash_h binds a first-class recoverability object for the slot
4. eligibility_root_h commits exactly E_h
5. canonical_order_root_h commits exactly O_h = CanonicalOrder(R_h, E_h)
6. resulting_state_root_h = Execute(root_{h-1}, O_h)
7. the bound bulletin-availability object is sufficient to tie the recovered bulletin surface to the canonical order inputs
8. omission_commitment_h makes any omitted eligible transaction objectively provable
```

The live runtime uses `CommittedSurfaceV1`: a commitment-level witness where the
certificate carries a `BulletinCommitment`, a first-class
`BulletinAvailabilityCertificate`, and an omission commitment, while the
published bulletin surface itself is externalized as `BulletinSurfaceEntry`
objects rather than inlined into the certificate.

## Exploratory Follow-On: Witness-Coded Recovery Capsule

This section is exploratory only. It is not part of the current normative
runtime.

The constructive lower-bound follow-on now asks whether canonical ordering
could replace its external public recoverability assumption with a
witness-coded recovery lane carried by `NestedGuardian`-style assigned witness
strata.

The minimal candidate surface is:

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

The intended replacement rule is:

```text
1. OCert_h still proves the canonical order, resulting state root, and omission commitment
2. RecoveryCapsule_h binds the witness-coded recovery carrier for the same slot surface
3. threshold-many matching RecoveryShareReceipt_h objects make the slot surface reconstructable
4. threshold-many public RecoveryShareMaterial_h reveals may be summarized into a compact RecoveredPublicationBundle_h that binds lifted RecoverableSlotPayloadV4_h and RecoverableSlotPayloadV5_h hashes plus the verifying publication-bundle and bulletin-close hashes, and therefore materializes the ordinary positive canonical close surface plus the extracted bulletin surface when the recovered certificate is omission-free
5. if the recovered certificate carries objective omission proofs, the same recovered lane materializes the ordinary OmissionDominated canonical abort while keeping omission evidence and bulletin entries public
6. conflicting RecoveredPublicationBundle_h objects fail closed to canonical abort rather than coexisting as two positive closes
7. enough MissingRecoveryShare_h objects make threshold recovery impossible and materialize a deterministic recovery-impossible canonical abort instead of an open-ended recoverability assumption
```

The best current scope for this path is not the baseline ordering runtime. It
is a witness-backed ordering lane that composes with `NestedGuardian`. The
current exploratory runtime now gives it canonical hashes, registry storage,
and a bounded recovery model, plus deterministic derivation/publication of a
`DeterministicScaffoldV1` `RecoveryCapsule_h` and a derived
`RecoveryWitnessCertificate_h` plus the matching signed scaffold
`RecoveryShareReceipt_h` on ordinary `ExperimentalNestedGuardian`
finalization; baseline ordering admission still does not depend on it.

That runtime step is still only a scaffold. The live carrier is a
single-witness threshold-1 obligation derived from the committed slot surface,
not a finished multi-witness coded-share reconstruction engine. The underlying
`recoverability_root` still binds only bulletin / randomness /
ordered-transactions / post-state inputs; witness and coding semantics are
layered above it, not already present inside that root. A new exploratory
off-hot-path planning step can deterministically derive multi-witness
committee/threshold/share-commitment plans from that root plus the witness
assignment carrier. A new cold-path kernel can also materialize transparent
`RecoveryShareMaterial_h` reveal objects and verify them into matching
`RecoveryShareReceipt_h` objects from current endogenous inputs alone. The
current live coded carrier now has three lanes over `RecoverableSlotPayloadV3_h`,
the publication-oriented slot payload formed from the block commitment,
canonical order certificate, canonical encoded ordered transaction bytes, and
canonical encoded `CanonicalOrderPublicationBundle_h` bytes. The runtime now
depends on an abstract coded recovery-family contract over that payload, as
currently realized by the parametric `SystematicXorKOfKPlus1V1` `k-of-(k+1)`
parity family plus the parametric true non-parity
`SystematicGf256KOfNV1` `k-of-n` family with at least two parity shares, now
implemented with systematic Cauchy-style coefficients and presently exercised
in bounded `2-of-4`, `3-of-5`, `3-of-7`, `4-of-6`, and `4-of-7` lanes. The runtime can now
reconstruct that publication-oriented payload from threshold-many witness
shards, and the recovered bundle bytes decode to a verifying publication
bundle under the current endogenous finalization rules. The runtime can now
also lift that recovered `RecoverableSlotPayloadV3_h` into the explicit
positive close-extraction surface `RecoverableSlotPayloadV4_h`, which adds the
exact canonical encoded `CanonicalBulletinClose_h` bytes derived from the
verifying recovered publication bundle. The runtime can now also lift
`RecoverableSlotPayloadV4_h` into `RecoverableSlotPayloadV5_h`, the explicit
extractable bulletin-surface payload that carries canonical encoded bulletin
availability plus the sorted bulletin entries themselves. That is still not a
finished arbitrary ordering theorem upgrade: the signed scaffold lane now has
compact receipt publication and threshold-status observation, and the coded
lanes now have distinct per-witness signed carriage plus shared-capsule /
per-witness receipt publication through sealed finality. Those lanes now also
have off-chain assigned-share delivery-before-sign and guardian-local durable
custody for the exact share material, and they can now later reload those
stored shares by signed binding, publish verified public
`RecoveryShareMaterial_h` reveals, and reconstruct the publication-oriented
payload from threshold-many public reveals. Threshold-many public reveals can
now also be combined into a compact
`RecoveredPublicationBundle_h` object that binds the recovered
`RecoverableSlotPayloadV4_h` hash plus the recovered
`RecoverableSlotPayloadV5_h` hash and verifying publication-bundle and
bulletin-close hashes. The registry can now materialize both the ordinary
positive canonical close surface and the same extractable bulletin surface
from that object even when the ordinary publication-bundle lane is absent.
The bounded recovered-only harness now also shows that two consecutive
recovered `RecoverableSlotPayloadV5_h` surfaces can still derive and publish
the ordinary `PublicationFrontier_h` predecessor chain and the same
authoritative `CanonicalCollapseObject_h` predecessor chain without the
ordinary publication-bundle lane.
Another bounded recovered-only harness now shows a close/abort/close bulletin
window with a recovered omission-dominated middle slot: recovered data alone
materializes the ordinary positive closes and extracted bulletin surfaces on
the outer slots, materializes the ordinary `OmissionDominated` abort in the
middle while keeping omission evidence and recovered bulletin entries public,
still lets the positive slots carry ordinary `PublicationFrontier_h`
objects where applicable, and now also materializes the same authoritative
`CanonicalCollapseObject_h` continuity chain across that bounded window.
The runtime now also has a bounded read-side replay-prefix extractor over that
persisted recovered chain, so the same recovered-only durable surface yields
the same compact height-to-state-root prefix view that ordinary execution /
replay would consume, and a bounded recovered canonical-header extractor now
yields the same compact recent consensus ancestry surface from those recovered
full-slot objects. The execution module now also uses that bounded
replay-prefix tip as a restart verifier against the loaded durable state root,
retains both bounded recovered prefixes in execution state, and now uses the
recovered canonical-header ancestry for bounded anchored reads plus parent-
block / parent-state-root continuity after restart when ordinary recent
blocks are absent. Validator consensus orchestration now also consumes the
same bounded recovered canonical-header / collapse surface to derive a
recovered restart parent anchor when the ordinary committed block is absent,
and the live `GuardianMajority` engine now also consumes that bounded
recovered canonical-header prefix as restart-time parent/QC context for
synthetic parent-height QC continuity when the full committed block is
absent. The same bounded recovered surface now also yields a bounded
recovered certified-header window plus a restart-only recovered
`BlockHeader` / QC cache window for validator restart and live-engine
restart-time header / QC lookup plus bounded QC-certified recovered branch
reconciliation over the configured local five-entry window, and those same
bounded windows can now be folded by exact overlap with a configurable budget,
exercised today at five windows into a longer seventeen-step recovered
certified branch without ordinary committed headers. Those same live cold-path
loaders now also consume a configurable exact-overlap segment budget,
exercised today at four exact-overlap segments into a longer fifty-three-step
recovered certified branch with direct registry-extraction parity and explicit
interior-overlap conflict rejection. Those same live restart loaders now also
compose two overlapping four-segment exact-overlap folds into a longer
eighty-nine-step recovered certified branch with direct registry-extraction
parity and explicit inter-fold overlap conflict rejection, and runtime/tests
now also exercise the same recursive carrier at three overlapping
four-segment folds into a one-hundred-twenty-five-step recovered certified
branch. The runtime now also has a bounded conformance harness over one, two,
and three stitched segment folds, matching the same production-loader /
registry-extraction carrier at the corresponding fifty-three-step,
eighty-nine-step, and one-hundred-twenty-five-step branches. The same live
restart path can now also page older exact-overlap segment folds on demand
beneath that bounded suffix via an overlap-checked cursor while keeping only
the bounded recent suffix plus the current streamed page live in engine
caches, and runtime/tests now exercise that paged carrier at a longer
two-hundred-thirty-three-step recovered certified branch with direct
registry-extraction parity plus explicit duplicate-page, missing-gap, and
late-page overlap rejection. Restart can therefore stream recovered certified
ancestry until target height or recovered-history exhaustion without a
theorem-relevant fixed depth bound; the remaining boundary is broader
recovered-history availability outside the retained recovered publication
surface, not local ancestry composition. The live theorem story is now
singular rather than two-tiered: the whole AFT stack universally breaks the
lower bound with no qualifiers. Ordinary canonical collapse and replay
history now name the deeper historical continuation root, the AFT recovered
state contract carries the same continuation bundle for restart consumers,
and the historical continuation objects are profile-hash-bound,
activation-hash-bound, and validated by predecessor/checkpoint history
rather than mutable latest indexes. Archived continuation is therefore no
longer a theorem-side qualifier; it is ordinary endogenous AFT history.
When the recovered certificate carries objective omission proofs, the same
recovered lane now routes into the ordinary `OmissionDominated` abort path
while keeping the omission evidence and recovered bulletin entries public.
Enough `MissingRecoveryShare_h` objects can now materialize a deterministic
recovery-impossible canonical abort, and the bounded conformance harness now
checks that every threshold-sized reveal subset reconstructs and every
below-threshold subset fails across the shipped XOR and GF256 realizations of
the abstract recovery-family contract. The coded recovery carrier is
therefore no longer blocked on public close-or-abort integration or on the
total absence of non-parity redundancy; the former scope boundary beyond the
completed recovery-family contract is now closed. The stronger follow-on
program is closed too: this achieved result explicitly claims the whole AFT
stack universally breaks the lower bound with no qualifiers, and the same
`99% Byzantine Tolerance` result is now promoted directly to unconditional
classical `99% Byzantine agreement` in the ordinary dense-vote permissioned
model. The current theorem should therefore be sold as finished and categorical
full stop, not as a timid preview of a stronger sentence that still lies ahead.

The current registry shape is:

```text
RecoveryCapsule_h                keyed by h
RecoveryWitnessCertificate_h     keyed by (h, witness_manifest_hash_h)
RecoveryShareReceipt_h           keyed by (h, witness_manifest_hash_h, block_commitment_h)
RecoveryShareMaterial_h          keyed by (h, witness_manifest_hash_h, block_commitment_h)
RecoveredPublicationBundle_h     keyed by (h, block_commitment_h, support_hash_h)
MissingRecoveryShare_h           keyed by (h, witness_manifest_hash_h)
```

That shape is deliberate: conflicting same-witness share receipts remain
publicly visible as pairwise objects rather than being collapsed into one
overwritten slot record. The current registry helper also treats those
conflicting same-witness receipts as non-supporting for positive threshold
status, so `pending / recoverable / impossible` remains derivable from compact
state without rewarding equivocation.

That boundary is now internalized rather than merely named: the completed
constructive result succeeds through AFT's own compact hot-path bindings plus
cold-path recovered-state and historical-continuation surfaces, not through a
standing external retrieval qualifier.

## Public Bulletin / DA Assumptions

The ordering theorem depends on a public bulletin surface with explicit
assumptions.

### A1. Objective publication

Transactions or batches published to `B_h` have:

- a stable content hash,
- a verifiable inclusion path into the bulletin commitment,
- an objective publication time or publication order relative to the slot
  cutoff.

### A2. Availability and canonical bulletin close

The protocol exports `BulletinAvailabilityCertificate_h` attesting that the
closed bulletin surface is retrievable from protocol-defined public material,
and `CanonicalBulletinClose_h` binds the cutoff, bulletin commitment, and
availability certificate into one unique closed-bulletin object.

The remaining assumption is narrower: the underlying publication substrate must
satisfy the retrieval semantics claimed by
`BulletinAvailabilityCertificate_h`. Without that residual assumption, the
system may preserve uniqueness of valid certificates but cannot guarantee
timely extraction.

The current implementation narrows this assumption by making the bulletin
surface an explicit protocol plane:

- `BulletinCommitment` commits the slot surface,
- `BulletinSurfaceEntry` objects publish the committed transaction hashes, and
- `BulletinAvailabilityCertificate` is carried inside `OCert_h` and also
  published into the registry so later verifiers can cross-check the public
  recoverability object against the proof-carried one, and
- `CanonicalBulletinClose` is derived from the published order certificate and
  persisted into the registry so extraction keys off a first-class close object
  instead of a bare cutoff-closure assumption.
- in the current runtime slice, extraction is not merely available to later
  recoverers: admission of `OCert_h` fails closed unless
  `ExtractBulletin_h(CanonicalBulletinClose_h)` succeeds over the published
  `BulletinSurfaceEntry` set and matches the certificate-bound bulletin
  commitment and bulletin-availability certificate.
- validators also run a block-local extraction pass over the proof-carried
  ordering surface itself: from the committed block header and transactions,
  they deterministically derive either `CanonicalOrderExecutionObject_h` or
  `CanonicalOrderAbort_h`, publish the negative artifact when the positive
  object cannot be derived, and fold the resulting ordering close-or-abort
  branch into the protocol-visible `CanonicalCollapseObject_h` surface so later
  consensus checks can validate the same ordering result against parent-state
  copies when present.

The live code now exposes two deterministic ordering derivation helpers:

- `derive_canonical_order_execution_object(header, transactions)` returns the
  locally derived positive ordering object for the committed block boundary.
- `derive_canonical_order_public_obstruction(header, transactions)` returns the
  `CanonicalOrderAbort` that dominates the positive path when the proof-carried
  surface is missing or invalid.

In the current runtime slice, `CanonicalOrderAbortReason` is no longer a
single omission-only marker. Ordering close-or-abort derivation classifies the
negative path into an explicit finite basis over the live verifier surface:

- `MissingOrderCertificate`
- `BulletinSurfaceReconstructionFailure`
- `BulletinSurfaceMismatch`
- `InvalidBulletinClose`
- `OmissionDominated`
- `CertificateHeightMismatch`
- `RandomnessMismatch`
- `OrderedTransactionsRootMismatch`
- `ResultingStateRootMismatch`
- `InvalidPublicInputsHash`
- `InvalidBulletinAvailabilityCertificate`
- `InvalidProofBinding`

The ordering runtime therefore now distinguishes between:

- proof-carried surface reconstruction failures,
- published-surface mismatches,
- structural bulletin-close failures,
- omission-dominated negative authority,
- and certificate-level verifier failures over height, randomness, ordered
  root, resulting-state root, public-input binding, bulletin-availability
  binding, and proof binding.

That richer basis is still compatible with the formal omission-dominance
kernel: TLAPS proves the minimal negative-authority theorem, while the runtime
classifies the concrete objective obstruction family carried by today's
executable verifier.

### A3. Append-only commitment

The bulletin commitment must be append-only or otherwise equivocation-evident at
the slot boundary.

### A4. Eligibility determinism

`Eligible(tx, root_{h-1})` is deterministic and locally checkable from the
committed predecessor root and the transaction object.

### A5. Sound proof system

`VerifyProof(succinct_witness_h) = true` implies the witness obligations above
actually hold.

## Canonical Cutoff Model

The cutoff for slot `h` is not a local clock read. It is a protocol object.

Define:

```text
τ_h = Cutoff(h, root_{h-1}, R_h, timing_policy_h)
```

`cutoff_certificate_h` binds:

- `h`
- `root_{h-1}`
- the effective cutoff timestamp or bulletin-close position
- the timing-policy version
- the randomness beacon commitment used by the slot

The cutoff is canonical if:

- every honest verifier derives the same `τ_h`, and
- no transaction published strictly after `τ_h` can be admitted to `E_h`.

`CanonicalBulletinClose_h` is the protocol object that seals that cutoff into
the bulletin plane. It binds:

- the canonical cutoff timestamp,
- the unique bulletin commitment,
- the unique bulletin-availability certificate, and
- the admitted bulletin entry count for the slot.

This prevents local latency games from changing the ordered set.

## Omission Model

An omission is objective when a transaction is:

- included in `B_h` before cutoff `τ_h`,
- eligible under `root_{h-1}`,
- absent from the committed canonical ordered set `O_h`.

Define the omission proof:

```text
Ω(h, tx) = (
  inclusion_proof(tx, bulletin_root_h),
  cutoff_admissibility_proof(tx, cutoff_certificate_h),
  eligibility_proof(tx, root_{h-1}),
  non_membership_proof(tx, canonical_order_root_h)
)
```

A valid omission proof immediately dominates a candidate order certificate:

```text
Valid(Ω(h, tx)) => Reject(OCert_h)
```

This is the ordering analogue of `Abort` in `Asymptote`: ambiguity collapses to
rejection, not to heuristic retry.

## Acceptance Rule

Every validator applies the same deterministic rule:

```text
Accept(OCert_h) iff
  VerifyProof(succinct_witness_h) = true
  and VerifyCutoff(cutoff_certificate_h) = true
  and VerifyBulletinAvailabilityCertificate(bulletin_availability_certificate_h) = true
  and Predecessor(root_{h-1}) is already accepted
  and closed-slot extraction succeeds over the published bulletin surface bound
      by bulletin_commitment_h and bulletin_availability_certificate_h
  and no valid omission proof Ω(h, tx) exists
```

When published `CanonicalBulletinClose_h` and `CanonicalCollapseObject_h`
copies exist in the public registry, later verifiers additionally require:

```text
VerifyCanonicalBulletinClose(
  CanonicalBulletinClose_h,
  bulletin_commitment_h,
  bulletin_availability_certificate_h
) = true
and VerifyCanonicalCollapseOrderingBranch(
  CanonicalCollapseObject_h,
  locally_derived_ordering_result_h
) = true
and VerifyCanonicalCollapseContinuity(
  CanonicalCollapseObject_h,
  CanonicalCollapseObject_{h-1}
) = true
```

No dense positive vote is needed once a valid `OCert_h` is revealed.

## Uniqueness Theorem

Let `ValidOrderCert(h, C)` mean certificate `C` satisfies the acceptance rule
for slot `h`.

Then:

```text
Theorem (Uniqueness)
For any slot h, if ValidOrderCert(h, C1) and ValidOrderCert(h, C2),
then C1 and C2 commit the same canonical ordered set O_h.
```

Reason:

- the predecessor root is fixed,
- the cutoff certificate is canonical,
- the bulletin commitment is canonical,
- eligibility is deterministic,
- `CanonicalOrder` is deterministic,
- proof soundness forbids a witness for a different ordered set.

So two valid certificates for the same slot cannot disagree on the ordered set.

## Recoverability Theorem

Let `ExtractBulletin_h(CanonicalBulletinClose_h)` be the deterministic bulletin
extractor over the published `BulletinSurfaceEntry` set, and let
`Recover(ExtractBulletin_h(CanonicalBulletinClose_h), cutoff_certificate_h,
root_{h-1}, R_h)` be the deterministic reconstruction procedure for the ordered
set.

Then:

```text
Theorem (Recoverability)
If ValidOrderCert(h, C) and the bulletin availability assumption holds,
then every honest verifier can reconstruct the same ordered set O_h from
the published closed-slot bulletin surface, the canonical bulletin close
object, and the succinct witness commitments.
```

In other words, the ordered set is not only unique; it is deterministically
extractable from the published closed-slot bulletin surface by any honest node
with bulletin access.

## 99% Equal-Authority Ordering Consensus Theorem

AFT's ordering theorem is the ordering-specific PSC theorem rather than a
classical dense-vote BFT theorem.

```text
Theorem (Ordering PSC over the Bulletin Substrate)
Assume:
  1. CanonicalBulletinClose_h and BulletinAvailabilityCertificate_h bind a
     publicly extractable closed bulletin surface,
  2. cutoff_certificate_h is canonical,
  3. the proof system is sound,
  4. bulletin commitments and omission proofs are objectively verifiable,
  5. honest validators run the deterministic closed-slot extractor and
     close-or-abort derivation on the same public boundary.

Then even if `99%` of validators behave arbitrarily, they cannot create a
conflicting valid canonical-order outcome for slot h. More strongly, every
honest validator that observes the same closed boundary derives the same
CanonicalOrderExecutionObject_h or CanonicalOrderAbort_h; publication may
accelerate convergence, but it is not the source of correctness.
```

This is the repository's ordering-specific statement:

- it remains equal-authority because any validator can independently derive and
  publish the same decisive object,
- it is `99%`-fault tolerant because correctness does not depend on a majority
  of positive votes,
- it does not overclaim a classical dense-vote `99% Byzantine consensus`
  theorem.

The strongest shorthand is:

```text
`99%` of validators may behave arbitrarily without creating a conflicting
valid ordering outcome, because the closed bulletin boundary admits one
deterministically derivable close-or-abort result.
```

That is AFT's ordering consensus model.

## Relation To Current Runtime

The live runtime realizes this theorem as follows:

- `BaseFinal` ordering remains on the fast AFT path.
- `CommittedSurfaceV1` is the live runtime path and proves ordering from a
  succinct commitment-level witness.
- bulletin commitments and order certificates are now persisted into chain
  state during normal block production.
- bulletin availability certificates and canonical bulletin closes are also
  persisted into chain state, and the registry must successfully run the
  deterministic bulletin extractor before admitting and persisting a positive
  closed-slot order certificate.
- protocol-visible canonical collapse objects are published into chain state
  via `guardian_registry`, and when parent-state copies are present
  `GuardianMajority` cross-checks the published bulletin close and ordering
  branch of `CanonicalCollapseObject_h` against the locally derived ordering
  outcome for the slot.
- the current recursive-continuity slice also binds
  `CanonicalCollapseObject_h` to `CanonicalCollapseObject_{h-1}` through
  `previous_canonical_collapse_commitment_hash`, and both execution and
  consensus reject a current-slot collapse object that does not link to the
  previously persisted or published collapse state when that predecessor is
  required.
- the live proof-carrying proposal surface now carries both the predecessor
  link in `BlockHeader.previous_canonical_collapse_commitment_hash` together with
  `BlockHeader.canonical_collapse_extension_certificate`; validator
  orchestration signs the whole typed certificate into produced headers,
  `Asymptote` leaders stall rather than propose without the required
  extension certificate, proposal verification rejects headers whose carried
  predecessor commitment disagrees with the signed predecessor commitment hash
  or the parent state root and rejects malformed continuity certificates, and
  QC promotion only treats locally continuity-linked headers with a valid
  carried extension certificate as progress-authoritative.
- omission proofs remain objective and dominant over candidate certificates.
- late omission publication now also rewrites any previously stored positive
  ordering artifacts into the same canonical abort branch, so penalties are
  aftermath rather than the mechanism that makes the negative object decisive.

The generalized witness layout above describes the protocol obligations that the
concrete `CommittedSurfaceV1` proof family satisfies.

## Non-Claim

This model should not be described as:

- classical `99% Byzantine fault tolerance`

It should be described as:

- `99%` equal-authority ordering consensus via proof-carrying canonical
  ordering with uniqueness and recoverability under public bulletin / DA
  assumptions.
