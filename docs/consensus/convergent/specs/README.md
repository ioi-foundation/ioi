# Convergent Specs

This directory is the canonical prose-spec surface for Convergent Fault
Tolerance.

- [`guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/convergent/specs/guardian_majority.md): production GuardianMajority fault model and safety assumptions
- [`nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/convergent/specs/nested_guardian.md): witness-augmented NestedGuardian protocol scope

The formal artifacts live under
[`formal/convergent/`](/home/heathledger/Documents/ioi/repos/ioi/formal/convergent),
including the discharged proof-kernel modules and the richer bounded TLC
models, and the runtime implementation lives under
[`crates/consensus/src/convergent/`](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus/src/convergent).
