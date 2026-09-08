# Rooted member record-data reservation

The final tested production source is bound by `allocation-charge/started.json`.
Its unchanged-source campaign passes 75 core tests (one benchmark excluded),
21 runtime tests, CLI compile, formatting/syntax, 9 record-reservation TLAPS
obligations with a 15-state positive model and two expected countermodels,
the 36-obligation finite-lifetime gate, and the reserved-record syscall gate.

The parent campaign is the preceding exact source: 74 core/21 runtime tests,
the same formal/trace gates, and the explicitly run 256-sample benchmark passed.
The subsequent repair classifies excessive existing physical allocation as a
quarantining storage fault. Its focused regression first failed against the old
behavior (overallocated-control-before-fix.log), then passed in the final campaign.
The parent benchmark is retained for its own source; it is not final-source M16Q
performance qualification after that repair. Full clean R2 remains mandatory.

Parent benchmark microsecond arrays [samples,min,p50,p95,p99,max]:
- ML-DSA signing: [256,1581210,1628257,1666395,1690981,1839445]
- durable handling with test hash signer: [256,32009,34298,37723,48147,51387]
- durable handling with ML-DSA: [256,1591114,1667380,1710862,1719029,1725661]
The benchmark ran for 849.31 seconds. These are finite measured samples; they do
not establish a worst-case scheduler/device bound and exclude startup from the
per-operation samples. Its existing handle was observed until exit 0.

Production derives the complete record count from independently provisioned
H/A domain lifetimes. Future raw record files use KEEP_SIZE preallocation in a
scope-authenticated sibling pool. Live append reuses a reserved inode and syncs
both directories before independent anchor persistence, memory publication or
reply. Old schema-9 payloads/AFTQJ001 record bytes remain unchanged. Pool contents
never enter semantic replay. The 4096-byte rounded allocation charge is checked
against reported allocated blocks, separately from encoded-length accounting.

Retained failures: initial-core.log contains the initial Rust error-comparison
compile failure. core-development.log records 70 passes/four failures: two stale
write-error staging fixtures and two fixtures spanning costly reopen inside a
live interval or grant lifetime. core-batched-development.log retains the two
timing failures after staging fixes. Allocation now precedes the per-inode sync
pass, avoiding repeated reallocation of healthy empty files. Fixtures initialize
the correct member before starting the live interval and acquire a fresh own
interaction after restart. Deadlines, continuation/capacity assertions and
quarantine requirements remain unchanged. These changes do not qualify process
restart/reconfiguration timing; those gates remain open.

All evidence is a selected dirty-worktree subset at HEAD
24a9888e3b88383c18dfbfea0f2e7fa44b99fa64, not an immutable clean candidate.
Use each results.json for commands and sources/ for captured inputs. Reproduce
with `python3 allocation-charge/run_checks.py` (overwrites that collector's files).
The final collector explicitly excludes the unlinked anchor_reservation.rs draft.
That next-step module and its tests are prepared but have not compiled or run;
it is not a production repair or qualified evidence yet.

All 13 whole R1 findings remain open. Metadata/journal capacity, fixed anchor,
handoff/consequence allocation, RAM/rate/fair service, cross-configuration retention,
complete transition refinement, clean R2, immutable freezing, fresh independent
review and M18Q admission remain required. No reviewer, commit, tag or owner-only
public action was invoked. No live jobs remain.
