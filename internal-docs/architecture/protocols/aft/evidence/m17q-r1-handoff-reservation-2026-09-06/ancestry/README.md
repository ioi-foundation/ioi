# Custody ancestry follow-up — incomplete collector

Production now syncs the handoff anchor directory's complete ancestry before
returning prepared capacity. This campaign passed 84 core/21 runtime tests, CLI,
format/syntax, four focused formal gates and the handoff trace, but its final
record-trace invocation contained an extra script argument and exited 2.
The full collector is failed; retain results.json and trace.log honestly.

The initial separate-directory fixture and removed-common-ancestor control
were then strengthened to custody/nested/state.anchor with removal of only the
intermediate custody sync. The corrected collector is running in deep-custody/.
Its production code is unchanged from this ancestry run; test/checker and collector
changes have separate source bindings. Neither campaign establishes full R2,
complete resource/refinement obligations, independent review or M18Q admission.
