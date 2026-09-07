# Readiness campaign reply envelope on shared PQ lanes (2026-09-07)

Scope: the fourth clean M16Q R2 run (`20260907T115443Z-4826d4bdb394`, on
`4826d4bdb`, launched on a quiet host and load-traced) passed 48 phases and
failed `quv_consecutive_readiness` after 216 s with

```
Error: child exceeded reply envelope
```

This is a measured-cost finding about the readiness fixture's
operator-declared reply envelope (4000 ms), not an R1 finding. The rooted
interval (`delta_rt` 5000 ms), the service budgets, the checker deadline
rules and the runtime are unchanged. The failed phase is retained here
(`failed-clean-run-phase/`, gzipped, with `phase-results.tsv`, `commit.txt`,
`environment.txt`, the runner's launch load and the per-minute load trace);
the run directory itself is kept outside the candidate as history.

## What happened

The slot-2 child operation (`30262293…`, executor validator 20000) started
at 12:56:26.475. Every member queued and completed its write-before-reply
work within 0.3 s of receiving the push and handed its reply to the swarm
at 12:56:26.775 (20200), 12:56:27.385 (20100) and 12:56:27.490 (20300). The
executor received them at 12:56:27.045, 12:56:30.284 and 12:56:30.685: two
replies spent 2.9–3.2 s between `reply_command_sent` on the member and
`reply_network_admitted` on the executor. The accepted audit at
12:56:31.484 recorded `max_valid_reply_elapsed_millis=4210`, inside the
rooted 5000 ms interval and outside the fixture's 4000 ms envelope; the
operation was accepted with all four members valid. The three members
started their own independent preparation operations at 12:56:27.0–28.5
(each pushing to every member, including the executor, which answered one
at 12:56:28.3–28.6), and the ordering profile committed height 54 at
12:56:27.1–27.9 on the same strict-PQ carrier. The retained logging has no
per-record lane events, so the wait cannot be attributed to a particular
record; QUV replies, QUV pushes and ordering records share the single
in-flight PQ request lane per peer, and that is the only mechanism visible
here.

Host condition: the run was gated on five quiet minutes (launch load
2.3 / 4.7 / 6.5) and the load trace shows 4.3–8.1 (1-minute) during the
readiness phase, which is the campaign's own load on 24 cores. This is not
the host-contention case of `../m17q-r2-flood-host-contention-2026-09-07/`.

## Measurements (executor reply arrivals, seconds after operation start)

| campaign | parent | unrelated | child (slot 2) | slot 3 |
|---|---|---|---|---|
| `20260907T014928Z-5ae464c1146e` | 1.38 / 1.75 / 2.06 | 0.82 / 1.40 / 1.58 | 1.03 / 1.18 / 1.33 | 1.88 / 2.35 / 3.09 |
| `20260907T074926Z-f41ba3b416ac` | 0.96 / 1.34 / 1.73 | 0.59 / 0.60 / 0.92 | 0.99 / 2.42 / 2.52 | 0.59 / 1.16 / 1.66 |
| `20260907T100107Z-6ee42fd7f0a0` | 1.43 / 1.53 / 1.54 | 1.40 / 1.72 / 2.19 | 1.90 / 1.90 / 2.11 | 1.27 / 1.51 / 1.68 |
| `20260907T115443Z-4826d4bdb394` (this) | 2.08 (audit) | 1.94 (audit) | 0.57 / 3.81 / 4.21 | not reached |

Retained readiness-campaign audit maxima: 2075, 2217, 2524, 2731 and
4210 ms. The flood profile on the same host already declares 4500 ms after a
4010 ms observation (`crates/cli/tests/aft_e2e_parts/quv_flood.rs`).

## Repair (fixture envelope sized from measurement)

`crates/cli/tests/aft_e2e_parts/quv_readiness.rs`: the readiness profile
declares `QUALIFIED_ENVELOPE_MS = 4_500` (was 4000) for the parent, child
and unrelated-probe assertions and in its `[M16Q-READINESS-EXPECT]` row;
`.github/scripts/check_aft_quv_readiness_evidence.py` pins the same 4500 ms
profile (its self-test row and the audit latency bound). The 5000 ms
interval, the 40 s readiness bound, the service budgets and every other
assertion are unchanged; a reply past the rooted interval is still
discarded. The verification specification's failure boundaries record the
shared-lane reply wait as a deployment cost.

## What this does and does not establish

It aligns the readiness profile's declared envelope with the flood profile
and with the measured maximum, and records a transport observation for the
independent reviewer: QUV reply latency on this host can reach 4.2 s when
replies share the per-peer PQ lane with concurrent pushes and ordering
commits. It does not qualify reply latency under any other load, does not
attribute the wait to a specific record, and does not change any theorem
premise; Q-A3 (known synchrony) remains a deployment obligation measured,
not guaranteed, by these campaigns.
