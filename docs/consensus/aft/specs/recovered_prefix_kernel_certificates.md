# Recovered Prefix Kernel Certificates

Status: exploratory future-work note, not a current protocol claim.

This document defines one plausible lightweight proof family for the bounded
recovered-prefix lane that the repository now exercises in runtime and bounded
TLA form. The intended outcome is not "generic zk for everything." The
intended outcome is a much smaller fixed-function validity layer that can be
wrapped in succinct or privacy-preserving machinery later if that ever becomes
worth the cost.

## Honest Framing

- The first target should be a public validity certificate, not a zero-knowledge
  proof.
- Most of the interesting recovered-prefix data are already public.
- The repo's throughput guardrails strongly prefer cold-path fixed-function
  verification over hot-path generic proving.
- If a cryptographic wrapper is added later, it should likely be a
  non-zk succinct proof first and a zk wrapper only if there is a clear reason
  to hide share material or committee-local structure.

## Mechanism Name

The proposed family is:

- `RecoveredPrefixKernelV1`: canonical bounded recovered-prefix object
- `RecoveredPrefixCertificateV1`: deterministic public validity certificate for
  that kernel
- `RecoveredPrefixSuccinctSealV1`: optional outer succinct proof over the fixed
  verifier
- `RecoveredPrefixPrivateSealV1`: optional later zk wrapper, only if privacy is
  actually needed

The core idea is that the cryptographic surface should prove only a tiny,
closed, canonical kernel. Symmetry reduction, slot-seriality, and other
canonicalization steps should be treated as deterministic preprocessing lemmas,
not as expensive arithmetic constraints inside the proof core.

## Target Object

`RecoveredPrefixKernelV1` should capture a bounded consecutive recovered window,
for example width `W = 4`, over one already-canonical recovery family such as
`SystematicGf256KOfNV1`.

Minimal fields:

- `window_start_height`
- `window_len`
- `recovered_slot_surfaces`
- `recovered_publication_bundle_hashes`
- `recovered_bulletin_surface_hashes`
- `canonical_collapse_commitment_hashes`
- `recovered_replay_prefix_entries`
- `recovered_canonical_header_entries`
- `recovered_certified_header_entries`
- `recovered_restart_header_entries`
- `recovery_support_summary`
- `missing_threshold_summary`
- `abort_reason_summary`
- `coding_descriptor`
- `kernel_domain_separator`

The object must be canonical and replayable from public recovered artifacts
alone. If two honest nodes start from the same recovered slot window, they must
derive byte-identical `RecoveredPrefixKernelV1`.

## Fixed Verifier

The verifier for `RecoveredPrefixCertificateV1` should be fixed-function and
closed-form. It should not interpret arbitrary programs or circuits.

Verifier checks:

1. The recovered window is consecutive and width-bounded.
2. Every slot resolves to exactly one of:
   - recovered positive surface
   - omission-dominated abort
   - recovery-impossible abort
   - recovered-support-conflict abort
3. Positive recovered slots have threshold support under the declared coding
   descriptor.
4. Missingness certificates objectively exceed the recovery threshold bound
   needed to force abort.
5. Abort and positive-close surfaces are mutually exclusive per slot.
6. Predecessor linkage is canonical across recovered slot surfaces.
7. `CanonicalCollapseObject` continuity holds across the bounded window.
8. Replay-prefix extraction is deterministic and matches the recovered durable
   surface.
9. Canonical-header ancestry is deterministic and parent-linked.
10. Certified-header and restart-header ancestry are parent/QC consistent.
11. No conflicting recovered branch can satisfy the same bounded kernel under
    the same domain separator.

The important design goal is that the verifier's rule list is closed and short.
There should be no user-extensible gadgets and no generic VM.

## Canonicalization Boundary

The certificate should prove facts about the canonicalized kernel, not about
all raw equivalent presentations.

Outside the cryptographic core:

- witness renaming is quotiented away by canonical witness ordering
- irrelevant receipt interleavings are quotiented away by canonical slot-local
  ordering
- bounded prefix seriality is treated as a deterministic extraction rule for
  the kernel slice
- sorted summaries replace dense receipt bags whenever only threshold support or
  impossibility counts matter

Inside the cryptographic core:

- the canonical kernel bytes
- the fixed-function verifier
- the domain-separated hash commitments over the kernel

This separation is where most of the expected cost savings come from.

## Why This Could Be Much Cheaper Than Generic zkVM Proving

The bounded recovered-prefix lane has unusually favorable structure:

- fixed-width local state rather than open-ended execution traces
- public data rather than secret witnesses
- a closed list of invariants rather than arbitrary program semantics
- deterministic canonicalization rather than many equivalent encodings
- cold-path use rather than per-slot hot-path proving

That means the system can avoid:

- full VM trace arithmetization
- large generic memory tables
- general control-flow proving
- proving hidden witness data that no one needs hidden
- per-slot commodity-validator proving requirements

If this works, the "proof" is less like a general SNARK over a protocol and
more like a compact cryptographic check over a tiny normalized protocol kernel.

## Suggested Certificate Layout

`RecoveredPrefixCertificateV1` should be a compact public object:

```text
RecoveredPrefixCertificateV1 {
  version,
  kernel_hash,
  window_start_height,
  window_len,
  coding_descriptor,
  recovered_tip_height,
  recovered_tip_block_hash,
  recovered_tip_state_root,
  collapse_tip_hash,
  certificate_hash,
  verifier_commitment,
  support_commitment,
  abort_commitment,
  optional_signature_or_multisig
}
```

The certificate should be sufficient for fast screening. Full kernel bytes can
be fetched only when deeper verification or checkpointing is needed.

## Proof Ladder

Recommended exploration order:

1. `RecoveredPrefixKernelV1`
   Deterministic byte-level kernel definition.
2. `RecoveredPrefixCertificateV1`
   Public fixed-function verifier over the kernel.
3. `RecoveredPrefixSuccinctSealV1`
   Optional succinct proof that the fixed verifier accepted the kernel.
4. `RecoveredPrefixPrivateSealV1`
   Optional zk wrapper only if there is a concrete privacy requirement.

This ordering keeps the repo honest. It avoids claiming "zk" before the kernel
and certificate language are even stable.

## Soundness Obligations

Before any cryptographic instantiation, the following need explicit arguments:

- canonicalization uniqueness
- soundness of witness-symmetry quotienting
- soundness of slot-serial recovered-prefix extraction
- threshold-support soundness under each admitted coding family
- soundness of conflict-abort and recovery-impossible abort derivation
- soundness of collapse continuity derivation
- soundness of replay/header/certified-header/restart-header extraction
- domain separation across coding families and kernel versions

If any of those rely on hidden side conditions that are not themselves
certificate-verifiable, the mechanism should be treated as unsound until fixed.

## Where This Would Run

This should remain a cold-path object.

Good uses:

- checkpoint publication
- restart / replay anchoring
- external auditability
- recovered-branch attestation
- later optional compression into succinct checkpoint proofs

Bad uses:

- per-slot hot-path proving
- forcing ordinary validators to generate heavy proofs every round
- replacing compact runtime recovery objects with large proof payloads

## Kill Criteria

This path should be abandoned if any of the following become true:

- the kernel cannot be canonicalized without importing hidden assumptions
- quotienting steps are not soundly checkable
- the certificate is not materially smaller or cheaper than shipping the raw
  recovered prefix itself
- proving cost approaches generic zkVM or general-purpose SNARK costs
- verification cost stops being clearly bounded and fixed-function

## Minimal Exploration Program

If this is revisited later, the smallest honest program is:

1. Define exact bytes for `RecoveredPrefixKernelV1`.
2. Write a pure deterministic verifier over that kernel.
3. Prove by tests and formal correspondence that the verifier matches the
   bounded recovered-prefix invariants already exercised in runtime and TLA.
4. Benchmark `RecoveredPrefixCertificateV1` generation and verification.
5. Only then evaluate whether an outer succinct or zk wrapper is worthwhile.

## Non-Claim

This document does not claim that such a proof system exists today in the
repository, or that it would automatically beat mature succinct proof systems.
It claims only that the repo now has a bounded recovered-prefix kernel whose
shape makes a specialized, likely cheaper proof family plausible enough to
deserve later exploration.
