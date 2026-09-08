# Allocated PQ queue-index remediation

Scope: selected dirty-worktree sources at HEAD
`24a9888e3b88383c18dfbfea0f2e7fa44b99fa64`, not an immutable qualified checkout.
`started.json` binds the source copies; `completed.json` confirms no selected
source changed during the final run. `results.json` retains exact commands and
exit codes. Run `python3 run_checks.py` from this directory or its repository
path to reproduce the scoped campaign (it overwrites campaign outputs).

Final results: 33 channel tests, 21 runtime tests, CLI compile, formatting and
runner syntax pass. The reserved-index proof discharges 9 TLAPS obligations;
its complete positive graph has 10 distinct states and both early-exchange and
truncate mutations fail as required. The existing payload/index proof also
passes 9 obligations, 79 states and both ordering mutations. Both ancestry and
reserved-index production syscall gates pass their removed-rule controls.

The initial network failure is retained in initial-network.log: the old
prepublication-error fixture made a directory at the obsolete temporary index
path. It no longer caused the intended fault after switching to inactive-file
exchange. The fixture now fails opening the actual inactive file, and the
postpublication branch uses the real production writer. No quarantine or
non-mutation assertion was removed. Development logs are intermediate evidence;
use final logs and the final source snapshot for exact binding.

AFTPQI04 reserves two index inodes and checks reported allocated bytes. The
production profile currently requires Linux posix_fallocate and RENAME_EXCHANGE;
startup refuses unsupported allocation/exchange. The checks do not establish
physical power-loss semantics, device timing, filesystem metadata headroom,
payload reservation, memory bounds or the integrated service theorem. The
storage proof is conditional on its primitive assumptions and is not complete
transition refinement. All 13 whole R1 findings remain open; full clean R2,
immutable freezing, fresh independent review and M18Q admission are outstanding.

Next production dependency: reserve QUV payload storage without consuming the
normal-traffic budget or deleting anything referenced by an uncommitted index.
A four-slot-per-rooted-recipient layout can retain the two active lanes and stage
both replacement lanes atomically; prove that allocation and integrate recovery
before treating it as implemented. Include physical metadata, pending copies,
normal-traffic failure isolation, RAM and worst-case service costs in the full
profile. No agent/reviewer or owner-only public action was invoked.
