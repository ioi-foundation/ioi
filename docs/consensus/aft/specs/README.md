# Aft Specs

This directory is the canonical prose-spec surface for Aft Fault
Tolerance.

- [`guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/guardian_majority.md): production GuardianMajority fault model and safety assumptions
- [`asymptote.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/asymptote.md): two-tier finality with asynchronous sealing, equal-authority observer veto-collapse, and sealed-only effects
- [`yellow_paper.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/yellow_paper.md): markdown+LaTeX yellow paper for Asymptote Fault Tolerance, including the benchmark-positioning section against HotStuff-, Narwhal-, and Bullshark-style baselines
- [`canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md): succinct witness model, bulletin / DA assumptions, canonical cutoff, omission proofs, recoverability, and the high-fault equal-authority ordering theorem
- [`equal_authority_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/equal_authority_ordering.md): proof-carrying canonical ordering as the final-mile route toward a 99%-class equal-authority ordering story
- [`nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/nested_guardian.md): witness-augmented NestedGuardian protocol scope

The formal artifacts live under
[`formal/aft/`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft),
including the discharged proof-kernel modules and the richer bounded TLC
models for `GuardianMajority`, `NestedGuardian`, `Asymptote`, and
`CanonicalOrdering`, and the runtime implementation lives under
[`crates/consensus/src/aft/`](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus/src/aft).
