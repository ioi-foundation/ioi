# M13Q QUV theorem local evidence

Status: local theorem/mechanization evidence; M17Q independent review remains
release-blocking.

Date: 2026-09-03.

## Result

The M13Q theorem surface is fixed in
`specs/query_unanimity_theorems.md`. It proves, under Q-A1 through Q-A10:

- arbitrary-set non-conflict among accepted non-`Abort` outcomes for owned and
  unowned slots;
- external validity and typed candidate/`Abort` outcomes;
- one-`delta_rt` typed operation termination; and
- singleton-candidate progress for every honest operation despite Byzantine
  silence.

The result is explicitly not classical exact-decision agreement: an earlier
accepted candidate can coexist with a later `Abort` after valid equivocation.
It is also not portable or asynchronous. This classification is part of the
theorem, not a documentation caveat applied afterward.

## Mechanization

Command:

```text
bash .github/scripts/run_aft_formal_checks.sh --quv-theorem-only
```

Result:

```text
census OK: 45 modules = 32 executed + 13 manifest-marked (manual)
All 75 obligations proved.
```

The TLAPS kernel quantifies over arbitrary member, correct-member, candidate,
and operation sets; it does not fix `n`. It derives pairwise accepted-value
non-conflict from self-inclusion, per-correct-member serialization disclosure,
and a nonempty correct set. The operational bridge from Q-A3 supplies every
correct snapshot before the decision deadline. R4 separately mutation-tests
that weakening the bridge to different timely witnesses is unsafe.

Pre-commit artifact hashes:

```text
4ba8dd71491fc98d525016f88c9b7d6e3aed01148f89f717da363dd7aea005e5  formal/maximal_visibility/QueryUnanimityProof.tla
ba37e6e0e2ce5ab22a1067ceb88253fc03c37f68c219eb2534938c952d3be7d6  specs/query_unanimity_theorems.md
de19f6f878423e51143475ea5998555c212e2acb54510d38668900bb6e938f19  .github/scripts/run_aft_formal_checks.sh
```

## Gate effect and remaining work

This closes the local M13Q theorem/mechanization gate and opens M14Q. It does
not admit production, a public consensus headline, or M14Q-M18Q. M14Q must
prove predecessor-bound ordering, durable recovery/reconfiguration, and
executor-side QUV immediately before irreversible effects. M17Q must
independently review this theorem and its operational bridge.
