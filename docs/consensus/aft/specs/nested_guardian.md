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
- witness committees are registered on-chain through the guardian registry
- validators in NestedGuardian mode reject slot certificates that do
  not include a valid, assigned, registered witness certificate
- witness assignment is derived deterministically from the active witness set,
  the epoch seed, the proposal slot, and the reassignment depth
- `formal/aft/nested_guardian/NestedGuardianProof.tla` proves the
  unbounded witness-augmented safety kernel in TLAPS
- the executable TLA+ model in `formal/aft/nested_guardian/` checks
  witness assignment, reassignment, outage, and checkpoint-admissibility
  transitions in bounded TLC runs

## Research Questions

- How should witness committees be assigned across epochs?
- What checkpoint cadence is sufficient to make rollback detection meaningful?
- What slashing evidence is required for witness omission, stale registry use, or conflicting witness attestations?
- Which combinations of validator faults, guardian faults, witness faults, and registry/log faults still preserve safety?

## Remaining Proof And Operations Work

- anti-capture rotation policy beyond the current deterministic assignment rule
- stronger composed liveness analysis under repeated reassignment and witness outage
- larger simulator / counterexample search over validator, guardian, witness, and log faults
- operational guidance for rotation cadence, reassignment depth, and outage handling

Until those conditions are tightened into a full composed liveness theorem, this
mode should be treated as a witness-augmented aft path with unbounded
safety proofs plus bounded operational model checking, not as a finished
non-classical theorem.
