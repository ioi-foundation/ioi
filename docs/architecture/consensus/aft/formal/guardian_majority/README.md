# GuardianMajority Formal Model

This directory contains the formal artifacts for the production
`GuardianMajority` mode of Aft Fault Tolerance.

The canonical prose spec lives at
[`docs/architecture/consensus/aft/specs/guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/architecture/consensus/aft/specs/guardian_majority.md).

The proof surface is split into three layers:

- `GuardianMajority.tla` models slot voting, guardian admissibility, epoch state,
  and checkpoint admissibility.
- `GuardianMajorityProof.tla` is the proof-kernel module used for unbounded TLAPS
  safety proofs over the protocol core.
- TLC model checking explores the richer bounded state space in
  `GuardianMajority.cfg`.

The model covers the protocol inputs that matter for the production safety
claim:

- validator votes are slot-scoped and epoch-scoped
- guardian readiness is a precondition for admissible votes
- registry epoch and manifest epoch mismatches can block finalization
- checkpoint rollback is modeled as a loss of admissibility
- finalized tuples retain their certifying voter set so safety is proved from
  recorded quorum witnesses rather than current registry state

The formal package is still safety-focused. It proves the unbounded safety core
and model-checks richer bounded executions, but it does not attempt a full
asynchronous liveness proof.

## Files

- `GuardianMajority.tla`: executable TLC model
- `GuardianMajorityProof.tla`: proof-kernel module for TLAPS work
- `GuardianMajority.cfg`: bounded TLC configuration

## Running locally

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

The script currently:

- discharges the unbounded TLAPS proof kernel in `GuardianMajorityProof.tla`
- discharges the unbounded TLAPS proof kernel in `NestedGuardianProof.tla`
- runs TLC over the bounded `GuardianMajority` and `NestedGuardian` models

The verifier-kernel conformance tests live in the Rust tree:

- [`guardian_committee.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_committee.rs)
- [`guardian_log.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_log.rs)
