# Scoped terminal storage evidence


### Terminal readmission storage (2026-09-06; scoped)

After exact committed admission rederivation, Executed/Reconciled result
readmission skips receipt-pair allocation and reinitialization. It still performs
an exact current resource lookup. InFlight/Unknown retains preparation because
lookup reconciliation can durably change the receipt. No state is promoted to
executable and no terminal transcript authorizes an invocation.

**Assumes:** exact receipt-state/admission validation and the existing exclusive
nonrollback custody and resource contract. QuvEffectPreparation now distinguishes
validated preparation from storage preparation and proves TerminalReadOnly;
the removed rule produces its expected countermodel. The production regression
checks both file contents and active inode, expired retrieval and exact result;
restoring unconditional preparation fails that regression. Source is restored.
This does not bound lookup request rate, startup writes, global contention or
aggregate storage, and does not close terminal/reconciliation fairness.

Evidence: `evidence/m17q-r1-terminal-readonly-2026-09-06/`. All scoped checks pass
on the recorded selected dirty-worktree sources: 33 consequence, 15
runtime-finality, 23 QUV runtime, two executor tests, CLI compilation, format,
syntax, nine proof obligations, four countermodels and receipt syscall controls.
The M16Q reservation-test assertion was corrected to its actual quv::tests
namespace; the preceding campaign's assertion used admission::tests and would
have failed the full runner. Its scoped component passes never represented full
M16Q execution. R2 remains unqualified; all whole findings remain OPEN.

started.json records source hashes; completed.json records no selected source changes.
This is not an immutable qualified checkout. Reproduce with python3 run_checks.py.
