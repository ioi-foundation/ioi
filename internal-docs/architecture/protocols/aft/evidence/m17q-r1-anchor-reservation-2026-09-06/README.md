# Integrated member record and anchor reservation evidence

Scoped R1 remediation only. All 13 whole findings remain OPEN; M15Q reopened,
M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED.

`run_checks.py`, `started.json`, `results.json`, and `completed.json` bind the
selected dirty-worktree source copies and commands. All selected source hashes
were unchanged during this run. This is not a clean immutable candidate.
The next handoff-fence edit postdates this campaign.

Passed: 81 QUV core tests (the separately required benchmark remains ignored),
21 runtime tests, CLI compilation, formatting/syntax, 9 record-reservation,
10 anchor-ordering and 36 lifetime TLAPS obligations with positive models and
required negative models. The anchor model has 36 distinct positive states.
The production trace checks seven record commits and nine anchor exchanges
(startup, seven live updates, reopen), record/anchor sync order and removed
sync/truncation controls. Two anchor inodes retain 4096 allocated bytes each
and the raw 114-byte authenticated format throughout the complete fixture.

`core-development.log` retains 80 pass/1 failure: the last preparation fixture
removed the anchor to simulate an uncertain post-record write. New preflight
correctly refused before that write. The fixture now injects an error after
record and inactive-anchor durability, preserving all original quarantine,
pending-record authentication and recovery assertions. No deadline was relaxed.
`trace-development/` retains the initial checker failure: strace annotated
AT_FDCWD with its directory; the corrected parser accepts that annotation.
The fresh `trace/` run and all its negative controls pass.

The models condition on durable filesystem primitives, exclusive nonrollback
custody and complete authenticated semantic replay. The trace observes issued
syscalls, not power loss or worst-case latency. Data-file allocation does not
reserve metadata or bound RAM, handoff/consequence state, recovery, retention,
transport/authentication or fair service. Full refinement, final full R2,
performance on that exact source, independent review and M18Q remain mandatory.
Historical schema-7 process evidence and the earlier member-reservation
benchmark are not current-source qualification. M12a/M12b and
portable_final_receipt=false remain fixed.
