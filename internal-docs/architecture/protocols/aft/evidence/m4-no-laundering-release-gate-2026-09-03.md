# M4 no-laundering theorem/runtime release gate — 2026-09-03

Status: **PASS for the certificate-only verifier and runtime-v3 receipt
boundary**. This closes M4. It does not establish any future strengthening
transformation: every non-empty transformation trace remains default-deny
until its coordinate-specific verifier and independent evidence land.

## Claim under test

Given verified constituent guarantee vectors `g_1 .. g_k`, a verifier that
observes only those certificates can soundly report only their exact
coordinate-wise evidence meet. Re-signing or nesting the same evidence cannot
strengthen the result. A coordinate may differ only when a named,
versioned rule verifies new evidence for that coordinate and commits to its
inputs, theorem, verifier profile and output.

This is the executable T6/L-M boundary. Requirements joins and evidence meets
are distinct types and operations; policy evaluation accepts only the opaque
`VerifiedGuaranteeV1` returned by the verifier.

## Runtime boundary

`RuntimeFinalityCertificateV2` now carries `RuntimeAssuranceV1`, separating:

- the effect's `GuaranteeRequirementsV1`;
- the evidence-derived `GuaranteeVectorV1`;
- its canonical commitment; and
- a coordinate-specific transformation trace.

The issuer derives this body from native or hash-async evidence. The portable
runtime verifier independently derives it again, exact-compares the
requirements, transformation trace and commitment, recomputes the meet, and
only then evaluates policy against the opaque verified result. The outer
issuer signature is therefore authentication, not authority to invent an
assurance coordinate.

The hash-async profile truthfully reports post-quantum consensus and randomized
asynchronous termination while leaving `channel_pq` and `end_to_end_pq` false:
the receipt declares the PQ-channel requirement but does not yet carry a
portable channel transcript proof.

## Negative and mutation corpus

The type-level corpus proves that:

- a PQ terminal seal cannot launder classical BLS ordering into PQ consensus;
- conflict safety cannot become publication availability;
- collateral cannot become BFT safety;
- timeout-labelled transforms cannot downgrade or replace certificate class;
- a classical endpoint prevents end-to-end PQ;
- cross-domain composition loses exact domain identity and keeps the weakest
  availability coordinate; and
- incomplete, mismatched, unknown and unverified transforms fail closed.

The runtime mutation reissues a valid outer issuer signature after changing
the embedded achieved vector's `channel_pq` coordinate. Independent
verification rejects the bundle.

Mutation calibration temporarily disabled the exact-meet comparison in
`CertificateOnlyGuaranteeVerifierV1::verify_claim`. The focused forged-wrapper
test then failed with exit 101 because the mutant accepted the amplified
claim. The comparison was restored before every clean run below.

## Formal evidence

`formal/no_laundering/GuaranteeMeet.tla` exhaustively explores a bounded
two-coordinate, three-level guarantee lattice. It checks that a certificate-
only report is accepted exactly when it equals the evidence meet, and that a
verified transform may alter only its named coordinate.

Reproduction:

```text
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC \
  -cleanup -deadlock -config GuaranteeMeet.cfg GuaranteeMeet.tla
```

Result: **PASS**, 11,666 generated states, 5,833 distinct states, complete
depth 3, no errors.

This bounded model does not prove a cryptographic proof system or pre-approve
a future transform. The Rust registry deliberately supports no strengthening
rule at M4.

## Clean verification

```text
cargo test -p ioi-types app::consensus::tests:: --lib
cargo test -p ioi-types --lib
cargo test -p ioi-finality --lib
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
git diff --check
```

Observed results:

- consensus/type subset: **106 passed / 0 failed**;
- complete types library: **447 passed / 0 failed** in 808.09 seconds;
- complete finality library: **51 passed / 0 failed** in 234.15 seconds;
- formal census: **37 modules = 24 executed + 13 explicitly manual**;
- theorem-assumption, claim-discipline and whitespace gates: **PASS**.

## Honest boundary

- M4 prevents evidence amplification; it does not itself prove PQ channels,
  external occurrence, at-most-once effects, or economic collateral.
- A valid new-evidence transform needs its own theorem, verifier, negative
  corpus and portable proof before leaving default-deny.
- Runtime-v3 assurance is integrated into emission and independent
  verification. Estate-wide production effect authorization consuming these
  vectors remains a later release gate.
- Historical M4-time status: T5d and T8 were then recorded as two open
  lower-bound rows. The M9 reconciliation later paired T5d with L-S after the
  already-existing responsive-impossibility/scheduled-safety adjudication;
  T8 is the remaining open lower-bound row. This does not change M4 evidence.
