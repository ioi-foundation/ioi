# AFT Formal Models

This directory is the top-level home for the formal artifacts backing the Aft
protocol family.

The canonical prose specifications live under
[`docs/consensus/aft/specs/`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs).

Layout:

- `AsymptoteProof.tla`, `Asymptote.tla`, and `Asymptote.cfg` define the
  scalable two-tier finality model directly at the Aft root, including the
  equal-authority observer close/veto kernel used for sealed-effect collapse.
- [`canonical_ordering/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/canonical_ordering/README.md)
  covers the proof-carrying equal-authority canonical-ordering model: succinct
  witness commitments, omission dominance, uniqueness, and recoverability.
- [`guardian_majority/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/guardian_majority/README.md)
  covers the guardian-majority proof kernel and executable model.
- [`nested_guardian/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/nested_guardian/README.md)
  covers the witness-augmented nested-guardian model.

Run all formal checks locally with:

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

The `Asymptote` proof kernel proves the deterministic part of the protocol at
the admitted-object boundary:

- base-certificate uniqueness
- close-certificate anchoring to an already admitted base certificate
- sealed-certificate uniqueness
- abort dominance from admissible observer vetoes

The richer TLC model carries the per-observer sample/accounting state. The TLAPS
kernel intentionally abstracts that to already admitted base, close, and abort
objects so the proof stays tractable while still matching the runtime collapse
boundary.

The separate `99%+` sampling story in the prose spec remains an analytical
probability bound over honest observer sampling; it is not encoded as a TLAPS
probability theorem.

The canonical-ordering package carries the parallel deterministic ordering
story: once bulletin availability, cutoff closure, and proof soundness are
assumed, uniqueness, omission dominance, and recoverability are proved at the
admitted-object boundary.
