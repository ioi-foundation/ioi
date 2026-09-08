# Late-joining validator frozen by a duplicate opportunistic sync batch (2026-09-06)

Scope: orchestration sync liveness defect found while requalifying the
integrated R2 tree. It is not one of the thirteen R1 findings and it changes
no QUV theorem, assumption, authority rule or policy root. It is retained
because it made the M16Q single-correct process campaign fail on the
integrated tree and because the same frozen-member state is visible in an
earlier retained passing campaign, where it only slowed the cluster.

## Observation

`failed-c1/`: the integrated-tree single-correct campaign
(`test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation`,
`quv=debug,network=debug`) failed with
`Timeout waiting for tx ... to commit` during effect-manifest registration
after 1118 s. The first validator's workload log shows 65 commits with a
periodic pattern: three blocks a few seconds apart, then a stall of 31.6–39.3
seconds, repeating (median 2.6 s, p90 32.2 s, max 39.3 s). Registration
transactions are submitted sequentially to validator 0 and each waits at most
60 s to commit (`IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS` default), so one long
stall plus a leader rotation exceeded the wait.

`diagnostic-info-level/`: the same fixture re-run with
`info,quv=debug,network=debug,consensus=debug` and a 480 s bound (exit 124 is
the bound, not an assertion). The fourth validator (port 21300) starts about
65–80 s after the third because the fixture serializes key encryption per
validator; the first three already satisfy the AFT bootstrap peer set and
produce blocks 1–6. The fourth then:

1. syncs blocks 1–6 from one peer (`Block sync complete!`, catch-up vote for
   H=6), leaving the workload executed cursor at 6 while the Agentgres-admitted
   floor is still 0;
2. receives a second, duplicate opportunistic blocks response starting at
   height 1 from another peer and adopts it because the adoption cursor used
   the admitted floor (0), not the executed cursor;
3. attempts to apply height 1 with the workload at 6; the execution-equivalence
   check cannot see the not-yet-admitted speculative block, so the reconciler
   reports `Committed sync history disagrees outside the bounded unadmitted AFT
   projection window; node frozen` (`applying_height=1, workload_height=6,
   admitted_height=0`) and quarantines the node.

A quarantined validator never votes or proposes. Every fourth height is its
round-robin turn, which the others wait out for the view timeout: the 32 s
stall. Its QUV member path still answers, which is why earlier campaigns with
this state could pass their participation assertions while running slowly.

The retained passing readiness campaign
`../m17q-r1-receipt-admission-2026-09-06/pressure-process/components/validator-20300-orch.log`
shows the same 51 `node frozen` lines; the retained passing single-correct
campaign `../m17q-r1-continuation-admission-2026-09-06/process-recovery/admission-diagnostic/components/`
shows no frozen validator (its launch stagger was 42–61 s, so the fourth
validator joined before the first proposal). The defect is therefore
pre-existing and timing-dependent, not introduced by the R2 wave.

## Repair

`crates/validator/src/standard/orchestration/sync.rs`: in the unsolicited
(opportunistic) response path, `already_executed_prefix_len` skips exactly the
response prefix that ends in a block whose height equals the locally executed
speculative height and whose header hash equals the locally executed tip
hash; hash linkage makes the skipped prefix the same chain. Adoption then
resumes from the executed cursor. A differing hash at that height skips
nothing, so a genuine fork still reaches the fail-closed replacement checks.
Nothing skipped or retained gains ordering or finality authority; every
retained block passes the unchanged signature, QC, execution and finality
checks. Genesis-only nodes and empty tip hashes never skip.

Regression: `standard::orchestration::sync::tests::already_executed_prefix_is_skipped_only_on_exact_tip_hash_match`
(duplicate prefix skipped through the executed height; different tip hash
skips nothing; response beyond the executed height skips nothing; unhashable
block never matches; genesis or empty tip never skips). Registered as the
mandatory `sync_executed_prefix` M16Q phase.

## What this does and does not establish

It removes one reproduced cause of a quarantined late joiner. It does not
qualify sync liveness in general, does not change the Agentgres floor
semantics, and does not make any process campaign pass by itself; the
requalified campaigns on the fixed tree are recorded separately in
`../m17q-r2-process-fixtures-2026-09-06/` and in the clean R2 run.
Binary failed-admission state captures were not copied into this directory; the fixture agent's copy remains under ../m17q-r2-process-fixtures-2026-09-06/.

## Second mechanism (same run family, c2)

With the prefix skip in place the late validator synced 1–5 and skipped four
duplicate batches, then executed height 6 through live consensus while the
Agentgres floor stood at 3. The ordinary in-progress sync loop, which fetches
from the admitted floor, then tried to apply height 4 with the workload at 6;
`stage_execution_equivalent_candidate` cannot look up a not-yet-admitted
speculative block, so height 4 became `node frozen`
(`applying_height=4, workload_height=6, admitted_height=3`).

Repair: `MainLoopContext::recent_executed_headers` keeps a bounded ring
(`RECENT_EXECUTED_HEADERS = 256`) of the header hashes this node itself
executed, recorded at every executed-tip update (sync, gossip, QUV boundary).
In the sync apply loop a fetched block at a height at or below the executed
cursor is skipped only when its header hash equals this node's own executed
hash at that height (`executed_exactly`); the sync cursor advances and the
block's admission still follows the unchanged finality path. Unknown heights
and differing hashes keep the fail-closed reconciliation. Regression:
`standard::orchestration::sync::tests::executed_header_ring_is_bounded_and_matches_only_exact_hashes`,
required by the `sync_executed_prefix` M16Q phase together with the prefix test.
