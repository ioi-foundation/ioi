# Exact pre-live handoff storage reservation

Scoped R1 remediation only: all 13 whole findings OPEN; M15Q reopened,
M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED.

Production validates the exact handoff envelope and reserves its encoded state
rounded to a 4096-byte data charge, plus two fixed raw authenticated anchors,
before the successor begins its own live QUV. Preparation never activates the
successor. The sole prepared identity is fixed for the handle. Install checks
exact identity/size and intact allocation before its final continuation check,
writes/syncs/renames the already reserved state inode, and commits the reserved
anchor before memory publication. No live state/anchor allocation or truncation
is required. Recovery retains schema-3 authentication, the one-shot reachable
state shape, exact pending-head extension, and no grant reconstruction.

84 core tests, 21 runtime tests, CLI compilation, formatting/syntax, the focused
record/anchor/lifetime/continuation proofs and models, and record/anchor trace
gate pass. `started.json`, `sources/`, `results.json`, `completed.json` bind the
unchanged selected dirty-worktree source during that collector. The separate
`handoff-trace/` command passes on the identical production/test sources and
rejects removed state/anchor syncs. Its fixture proves no-preparation refusal,
preparation without authority, lost-allocation refusal before final consumption,
exact inode/allocated-charge reuse, and authenticated reopen. Existing pending
anchor failure cases retain their original recovery assertions through a
post-state-durability test hook.

The M16Q runner subsequently gained this passing handoff trace gate and its
source hash. `runner-followup/` retains the before/after runner binding and
syntax checks. `source-followup.json` confirms the runner is the only changed
selected source since the collector; all production, tests and proofs remain
identical. This is not an immutable qualified checkout. Reproduce the collector
with `python3 run_checks.py` from its retained repository location, then run
`python3 .github/scripts/check_aft_quv_handoff_reservation.py --output <directory>`.

`core-development.log` retains the preceding 83-test integration run; it predates
the new exact reservation regression. Earlier fence/mutation evidence is in
`../m17q-r1-handoff-final-fence-2026-09-06/`, with its own older source bindings.
The benchmark was not repeated; fresh performance remains mandatory at full R2.

The existing record/anchor ordering kernels apply conditionally to one-shot
handoff state staging: reserved file write, durable rename, inactive anchor sync,
exchange, parent sync, then memory. The continuation kernel checks consumption
and recovery. These are not full protocol refinement or a filesystem timing
proof. Metadata, decoded memory, consequence resources, cross-configuration
retention, transport/authentication/fair service and aggregate recovery bounds
remain open. No refusal is inclusion, canonical progress or completed effects.
M12a/M12b and portable_final_receipt=false remain fixed.
