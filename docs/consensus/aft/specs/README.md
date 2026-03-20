# Aft Specs

This directory is the canonical prose-spec surface for Asymptote Fault
Tolerance (AFT).

Canonical theorem/protocol specification:

- [`yellow_paper.tex`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/yellow_paper.tex): standalone LaTeX yellow paper for Asymptote Fault Tolerance (AFT), including the final theorem surface, self-contained protocol coverage, embedded formal-artifact context, and implementation correspondence

- [`guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/guardian_majority.md): production GuardianMajority fault model, now scoped as transport / tentative progress under PSC-gated durability
- [`asymptote.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/asymptote.md): two-tier finality with asynchronous sealing, equal-authority observer veto-collapse, and sealed-only effects under the repository's broader PSC-based `99%` Byzantine-tolerance claim
- [`deterministic_observer_sealing.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/deterministic_observer_sealing.md): normative `CanonicalChallengeV1` observer-sealing spec: deterministic transcript/challenge surfaces, close-or-abort exclusivity, challenge dominance, and sealed-effect binding
- [`canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md): normative ordering-specific PSC theorem surface: `99%` equal-authority canonical ordering, deterministic extraction, omission-dominant aborts, and bulletin / DA assumptions
- [`equal_authority_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/equal_authority_ordering.md): architectural framing for AFT's `99%` equal-authority ordering consensus claim and its separation of revelation from dense positive voting
- [`nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/nested_guardian.md): witness-augmented NestedGuardian protocol scope
- [`recovered_prefix_kernel_certificates.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/recovered_prefix_kernel_certificates.md): exploratory future-work note for a bounded recovered-prefix certificate family, starting from a public fixed-function validity certificate and only later considering succinct or zk wrappers

The formal artifacts live under
[`formal/aft/`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft),
including the discharged proof-kernel modules and the richer bounded TLC
models for `GuardianMajority`, `NestedGuardian`, `Asymptote`, and
`CanonicalOrdering`, and the runtime implementation lives under
[`crates/consensus/src/aft/`](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus/src/aft).
