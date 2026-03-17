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

As with `GuardianMajority`, the proof surface is split:

- `NestedGuardianProof.tla` is the proof-kernel module used for unbounded TLAPS
  safety proofs over the witness-augmented protocol core.
- TLC explores the richer bounded composed model in `NestedGuardian.cfg`
- `NestedGuardian.tla` remains the executable model for assignment,
  reassignment, outage, and checkpoint-admissibility scenarios.

Its job is to keep the runtime’s witness-assignment, reassignment, and
witness-admissibility rules aligned with the implementation.

## Files

- `NestedGuardian.tla`: executable TLC model
- `NestedGuardianProof.tla`: proof-kernel module for TLAPS work
- `NestedGuardian.cfg`: bounded TLC configuration

## Running locally

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

The script discharges both proof kernels and then runs TLC over the executable
models. The verifier-kernel conformance tests that back the log/certificate
predicates live in:

- [`guardian_committee.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_committee.rs)
- [`guardian_log.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/crypto/src/sign/guardian_log.rs)
