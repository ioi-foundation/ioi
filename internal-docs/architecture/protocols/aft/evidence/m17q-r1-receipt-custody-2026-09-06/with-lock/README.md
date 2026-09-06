# Scoped receipt leaf custody evidence

### Receipt leaf custody guards (2026-09-06)

Directory-entry absence now uses symlink_metadata: dangling active links and
metadata errors cannot become fresh authorization. On Unix, initial receipt
staging and the consequence lock use the existing no-follow, regular-file,
single-link guard before truncation or locking. Existing generic non-Unix
adapters remain outside the Linux reserved profile.

**Assumes:** exclusive nonrollback custody of the store and its parent namespace;
ordinary Unix no-follow/open/lock semantics. These leaf checks do not establish
parent-directory custody, adversarial namespace race protection, aggregate
physical resources, or full transition refinement. Invalid active state maps
to refusal, never the Absent case of QuvEffectPreparation. The existing reserved
receipt proof's private-file antecedent remains conditional on these OS/custody
assumptions. No stored bytes create live authority.

Evidence: `evidence/m17q-r1-receipt-custody-2026-09-06/with-lock/`. Thirty-three
consequence, 15 runtime-finality, 22 QUV runtime and two executor tests, CLI
compile, formatting, formal guard checks and receipt syscall controls pass.
Original failing dangling-active/lock-alias regressions are retained. Removing
existence, staging, or lock validation produces the expected test failure;
original source is restored. Previous process evidence predates this change.
All whole findings remain OPEN; R2 unqualified; M18Q NOT_ADMITTED.

Reproduce: run_checks.py and run_mutations.py. Selected worktree source is not
an immutable qualification checkout.
