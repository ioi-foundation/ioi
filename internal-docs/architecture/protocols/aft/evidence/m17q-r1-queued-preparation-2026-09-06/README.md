# Scoped queued preparation evidence

Selected dirty-worktree source is bound by started.json and sources/; it is not
an immutable qualified checkout. completed.json reports all nine scoped checks
passing and no selected source changes. Tests: 33 consequence, 15 runtime-finality,
23 QUV runtime, 2 executor. Formal: 9 TLAPS obligations, 16 reachable states,
three expected counterexamples. The production inspection-write omission fails
the exact regression; mutations.json records restoration. Initial noninductive
proof failures remain in development/.

Executable preparation owns admission through own live QUV and continuation.
The proof remains conditional on actual validation, finality, custody and live
interaction antecedents. Terminal/reconciliation fairness, aggregate bounds,
retention, full refinement and exact-source process qualification remain open.
No whole finding closed; R2 unqualified; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.
Reproduce the scoped checks using python3 run_checks.py from this directory.
