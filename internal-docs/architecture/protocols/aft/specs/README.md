# Aft Specs

Status: internal protocol spec index (AFT corpus); non-canonical.

This directory is the internal prose/spec workspace for Asymptote Fault
Tolerance (AFT). It is supporting protocol context; `docs/architecture/` and
accepted ADRs remain canonical.

Current theorem/protocol reference:

- [`yellow_paper.tex`](./yellow_paper.tex): standalone LaTeX yellow paper for Asymptote Fault Tolerance (AFT), including the final theorem surface, self-contained protocol coverage, embedded formal-artifact context, and implementation correspondence
- [`common_boundary_theorems.md`](./common_boundary_theorems.md): AFT-CB P1.2 paper theorems — T1–T9 with lower bounds L1/L2/L9 + L-E/L-H/L-LR/L-M, machine-checked `Assumes:` discipline (A5→T4a/T4b only, A9→T5b/T5d only, A10→T5d only; T8 probabilistic and quarantined), and the lower-bound pairing table (three named L-OPEN rows; T5d's claim withdrawn to design-open after four adversarial review rounds); conditional on the AFT model delta
- [`common_boundary.md`](./common_boundary.md): AFT-CB P1.1 protocol specification — Boundary Ring + Unanimous Boundary Close: the nineteen-section normative spec (ack state machine, ack journal, oracle-free cutoffs, validate-and-hold, live-tier-only ejection, custody succession, bootstrap, receipt-or-silence, handover ceremony, proof-of-silence prohibition, batch-seal cadence, attribution-preserving encoding, per-seal key evolution, anchored re-genesis, VDF chain, pre-consented succession, sortition + watchtowers, the `pq` bit, the finality menu), every rule citing the A1–A9 ledger entries it consumes; conditional on the AFT model delta

Current follow-on design program:

- Endogenous retrievability: design program for finishing the protocol-native retrievability plane rooted in canonical close, custody, challenge, extraction, and deterministic abort. No standalone program file is present in this snapshot.

- [`guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/guardian_majority.md): production GuardianMajority fault model, now scoped as transport / tentative progress under PSC-gated durability
- [`asymptote.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/asymptote.md): two-tier finality with asynchronous sealing, equal-authority observer veto-collapse, and sealed-only effects under the repository's broader PSC-based all-but-one (`n-1` of `n`) Byzantine-safety claim, conditional on the AFT model delta
- [`deterministic_observer_sealing.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/deterministic_observer_sealing.md): normative `CanonicalChallengeV1` observer-sealing spec: deterministic transcript/challenge surfaces, close-or-abort exclusivity, challenge dominance, and sealed-effect binding
- [`canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/canonical_ordering.md): normative ordering-specific PSC theorem surface: all-but-one (`n-1` of `n`) equal-authority canonical ordering in the AFT model delta, deterministic extraction-or-abort, omission-dominant aborts, compact publication frontiers, and the endogenous retrievability plane
- [`equal_authority_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/equal_authority_ordering.md): architectural framing for AFT's all-but-one (`n-1` of `n`) equal-authority ordering consensus claim (conditional on the AFT model delta) and its separation of revelation from dense positive voting
- [`nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/nested_guardian.md): witness-augmented NestedGuardian protocol scope
- [`recovered_prefix_kernel_certificates.md`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/specs/recovered_prefix_kernel_certificates.md): exploratory future-work note for a bounded recovered-prefix certificate family, starting from a public fixed-function validity certificate and only later considering succinct or zk wrappers

The formal artifacts live under
[`internal-docs/architecture/protocols/aft/formal/`](/home/heathledger/Documents/ioi/repos/ioi/internal-docs/architecture/protocols/aft/formal),
including the discharged proof-kernel modules and the richer bounded TLC
models for `GuardianMajority`, `NestedGuardian`, `Asymptote`, and
`CanonicalOrdering`, and the runtime implementation lives under
[`crates/consensus/src/aft/`](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus/src/aft).
