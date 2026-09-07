# Flood campaign active-service budget under host contention (2026-09-07)

Scope: the third clean M16Q R2 run (`20260907T100107Z-6ee42fd7f0a0`, on
`6ee42fd7f`) passed 52 phases and failed `quv_byzantine_flood` after 557 s
with

```
Error: status: FailedPrecondition, message: "QUV operation active service deadline exceeded; inspect durable history"
```

This is a measured-cost finding about the flood fixture's rooted active
service budget on this host, not an R1 finding. No runtime code, theorem,
premise, interval (`delta_rt` 5000 ms), reply envelope (4500 ms) or checker
rule changes. The failed phase is retained here (`failed-clean-run-phase/`,
gzipped, with `phase-results.tsv`, `commit.txt`, `environment.txt`); the run
directory itself is kept outside the candidate as history.

## What happened

The failing operation (`eaa7d7d6…`, executor validator 20000, the
beyond-horizon / historical-replay step after horizon slot 4) started at
11:18:05.270, published its admitted effect at 11:18:08.2, received all
member replies by 11:18:09.5 and logged `operation_accepted_audit` at
11:18:10.275 (the 5 s interval). It then logged nothing for 5.3 s until
`operation_service_expired` (`phase=finalization` and
`phase=admission_release`) at 11:18:15.567: `elapsed_micros=13009511`,
9.5 ms past the 13 s budget (5 s interval + 8 s continuation). The evidence
checker and the fixture rightly treat a late release as a declared failure.

During that window the chain on the executor stalled: its last finalized
height before the operation was 162 at 11:18:04.6; height 163 finalized on
other nodes at 11:18:10–11; the height-164 leader logged
`workload_client.process_block() is slow` at 11:18:04.985 (the only such
warning in the three retained flood campaigns) and height 165 was still
being decided at 11:18:14.7. The post-acceptance tail is the executor's
runtime-finality critical section (committed-admission revalidation, the
synchronous claim/call path, receipt durability), which the verification
specification already records as an unqualified R2 cost; it waits on
committed admission and therefore stretches with block finality.

Host condition: `host-load-snapshot-after-failure.txt`, taken 100 s after
the failure, shows load averages 7.8 / 10.1 / 9.5 (1/5/15 min) on 24 cores
with unrelated CPU-heavy processes (a rendering job and a Python job at
100 %+ CPU, the hypervisor daemon at 31 %, several editor and browser
processes). The previous two clean runs on this host ran at load averages
around 3.

## Measurements (budgeted `operation_admission_released`, all nodes)

| campaign | n | max | p90 |
|---|---|---|---|
| flood, run `20260907T014928Z-5ae464c1146e` | 58 | 10.25 s | 8.27 s |
| flood, run `20260907T074926Z-f41ba3b416ac` | 56 | 10.20 s | 7.84 s |
| flood, run `20260907T100107Z-6ee42fd7f0a0` (this) | 44 | 13.01 s | 9.35 s |
| single-correct, same three runs | 58/61/58 | 8.28 / 9.81 / 9.09 s | 6.93 / 6.64 / 7.50 s |
| consecutive readiness, same three runs | 17/19/19 | 8.62 / 7.62 / 9.54 s | 7.54 / 7.38 / 8.58 s |

Post-acceptance tails (audit to finish) in the flood campaigns: maxima
2.46 s, 2.69 s and 5.29 s (this run also had 3.67 s and 3.44 s). Every
process phase in this run was 10–15 % slower at p90 than the two earlier
runs, consistent with the host contention above rather than with any
change between `f41ba3b41` and `6ee42fd7f` (the only change is a fixture
assertion in the PQ timeout drill).

## Repair (fixture bound sized from measurement)

`crates/cli/tests/aft_e2e_parts/quv_flood.rs`: `CONTINUATION` 8 000 ms →
11 000 ms, so the flood profile's active service budget is 16 s. This is the
same rule the previous resize applied (10 s → 13 s after 10.25 s releases):
the budget covers the measured maximum with a comparable margin. The
readiness fixture's 10 s budget (5 s + 5 s) is unchanged; its measured maxima
are below 9.6 s. The interval, the reply envelope, every deadline assertion
in the checkers and the rule that a late release is a failure are unchanged.
The fixture comment and the M18Q packet's cost section record the numbers.

Also recorded: qualification campaigns on this host must not share it with
CPU-heavy work; the relaunch of the clean run is gated on a quiet host
(1-minute load below 4 for five consecutive minutes and no build, TLC or
rendering process), and the load trace during the run is retained beside it
(`../m16q-runs/<run>/` is the runner's output; the gate's own trace is kept
in the session record).

## Preflight on the resized fixture (`preflight-process/`)

The flood campaign ran standalone on `2080d09d6` after the host had been
quiet for five minutes (`wait-trace.txt`; launch load 2.5 / 3.5 / 5.6). It
passed (exit 0, 637.62 s) and the flood evidence checker passed
(`flood-evidence-check.txt`). 63 budgeted operations were released with
maximum 10.78 s and p90 8.03 s against the 16 s budget; flood-phase valid
reply maxima 977, 3009 and 1122 ms against the 4500 ms envelope; recovery
5284 ms against 120 000 ms. `load-trace.txt` shows the campaign's own load
(1-minute average up to 19.8 on 24 cores while four validators and the
fixture run), which is the ordinary cost of the campaign, not contention.

## What this does and does not establish

It sizes one fixture budget from three campaigns' measurements and records
the host-contention cost. It does not make the executor's runtime-finality
critical section a timing guarantee, does not change the service-failure
semantics, and does not qualify anything by itself; the clean run on the
committed fixture remains the qualification evidence.
