# QUV payload arena and capacity-error isolation

The final source-bound campaign is `normal-capacity/`. It follows the initial
arena-only campaign in this directory; the earlier source snapshot is retained
but is stale for the subsequent normal-capacity repair. Both are scoped dirty
worktree evidence at HEAD `24a9888e3b88383c18dfbfea0f2e7fa44b99fa64`, not an
immutable clean R2 qualification. Commands and source hashes are in each
started.json/results.json, and copied sources are under sources/.

Final results: 36 channel tests, 21 runtime tests, CLI compile, formatting and
runner syntax pass. All 6 arena numerical/frame TLAPS obligations pass, the
113-state slot model passes, and the three-slot/overwrite-retained mutations
fail as expected. The reserved-index kernel passes 9 obligations and 10 states;
the payload/index kernel (including PrecommitCapacityRefusal) passes 9 obligations
and 79 states. Their four paired mutations fail as expected. Ancestry and index
reservation syscall gates pass. The index syscall fixture now includes its
additional startup-only AFTPQI05 conversion exchange; the sixteen live commits
retain the same no-allocation and synchronization requirements.

Arena tests stage two maximum-size replacements while retaining both old lanes,
exercise errors before index exchange and before directory sync, reopen the
correct queue, check stable arena inode/allocation, and reject active corruption
even with an intact retired payload copy. Normal capacity tests inject ENOSPC,
EDQUOT and EIO before/after unreferenced file rename, plus failed cleanup. Only
capacity failures with durable cleanup preserve usability; existing QUV retirement
and new reply enqueue then succeed. Other/uncertain failures remain quarantined.
The failed normal operation is refused, not counted as inclusion or progress.

AFTPQI04 allocated envelopes now carry AFTPQI05 arena-backed indices. AFTPQA01
reserves 4096+N*4*20480 bytes and binds scope/rooted accounts. Logical entries
remain v2, member custody remains schema 9, and policy roots remain v5. Retired
arena bytes are non-authoritative; recovery follows the validated index only.

These tests use local storage-boundary fault injection, not a real disk-full
process campaign or power-loss test. Arithmetic/finite-model evidence does not
prove the full production transition mapping, physical metadata/RAM availability
or worst-case service timing. Member/consequence allocation, rate/fair scheduling,
retention across configurations and complete transition refinement remain open.
Every whole R1 finding remains open. Clean full R2, immutable candidate, fresh
authorized independent review and M18Q admission remain outstanding.

Reproduce with `python3 normal-capacity/run_checks.py` in this directory (the
collector overwrites its own outputs). No reviewer, commit, tag or public owner
action was invoked. No live jobs remain after the final campaign exited 0.
