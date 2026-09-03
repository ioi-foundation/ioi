# M3 hash-only fallback adversarial release gate — 2026-09-03

Status: **PASS for M3's declared static-adversary profile**. This evidence
closes RES-R10 for the normative hash-only fallback. It does not claim
adaptive security, favorable latency, or progress with more than `f` Byzantine
members.

## Profile under test

- exact unit-weight geometry `n = 3f + 1`, `q = 2f + 1`;
- static Byzantine adversary and randomized asynchronous termination;
- private authenticated channels at the construction boundary, carried by
  AFT's mutually authenticated PQ channel in the production drill;
- no private threshold setup or DKG;
- ML-DSA availability, ordering, and executed-block certificates;
- randomness selects and schedules; it never authorizes a block;
- a durable cross-path fence prevents an optimistic and hash-async signer from
  authorizing different block roots at the same height.

## Adversarial matrix

| Obligation | Exercised boundary | Result |
|---|---|---|
| delay and reordering | alternating front/back delivery in `asynchronous_schedule_tolerates_one_silent_byzantine_loss_reordering_and_duplicates` and the production network | PASS |
| loss and retry | first-transmission loss in the adverse scheduler; durable account-addressed strict-PQ outbox and ACK retirement in production | PASS |
| duplication | duplicate protocol deliveries, start triggers, certificates, runtime admission, and post-terminal traffic | PASS; duplicate/rejected traffic does not grow the WAL |
| Byzantine silence/messages | one permanently silent member at `n=4`; malformed envelopes, wrong sender/index, equivocation, conflicting proposals, and signature mutations | PASS; three honest nodes converge and malformed traffic fails closed |
| crash/restart | repeated nonterminal reopen at delivery boundaries 50, 200, and 400; torn WAL tail; schema-2 migration; terminal checkpoint reopen; full process cold restart | PASS |
| trigger races | byte-distinct exact-`q` timeout witnesses with identical safe state, duplicate trigger adoption, and different-safe-state conflict | PASS; semantic equality is idempotent and conflict is refused |
| optimistic/fallback race | a real same-height optimistic workload projection is staged before view-3 fallback; only certified fallback may replace it above the Agentgres floor | PASS in the four-validator production drill |
| late cross-path traffic | delayed optimistic votes/QCs after durable fallback and late async carriers after terminal retirement | PASS; neither regains authority |

The crash boundary between signer-fence state and external-anchor persistence
has its own test,
`crash_after_state_commit_heals_one_generation_stale_anchor`. It restores a
one-generation-stale anchor, proves reopen completes that exact pending
commit, accepts same-root replay only idempotently, and refuses a conflicting
root. Larger gaps, rollback, mutation, and concurrent clones remain refused.

## Mutation calibration

Two temporary source mutants were compiled and run against focused tests, then
removed before the clean suites and process drill:

1. Replacing the proposal fallback-lock comparison in
   `AftAsyncProposalRefV1::validate_for` with an unconditional false guard made
   `proposal_and_instance_are_bound_to_fallback_lock` fail (exit 101) because
   the mutated implementation accepted the wrong lock.
2. Removing both the nested timeout-certificate shape validation and expected
   view check from `AftFallbackTriggerCertificateV1::validate_shape` made
   `mutations_of_scope_trigger_and_lock_fail_closed` fail (exit 101).

A narrower trigger mutant that removed only the outer view comparison stayed
green because nested certificate validation independently enforces the same
view. That redundant check is therefore not credited as mutation coverage.
After exact restoration, `cargo test -p ioi-types --lib` passed 442/442.

## Production drill

Reproduction:

```text
RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
```

Result: **PASS, 1 passed / 0 failed in 621.34 seconds**.

The clean restored-source run:

1. brought four rooted ML-DSA validators to a shared height;
2. staged an actual optimistic projection at height 4 with hash
   `a76755135f66576a6dad50623dac51fc14da931214f2e7877f4a8db5e6f70097`;
3. formed the exact-`q` timeout chain through view 3 and activated one semantic
   fallback instance;
4. made all validators availability-certify, agree, deterministically execute,
   and certify the same replacement block;
5. admitted the block through the runtime receipt/finality boundary, installed
   its typed async-parent proof, and retired the active session;
6. rejected delayed carriers after retirement rather than reopening authority;
7. cold-restarted the four processes, converged at height 5 with zero retained
   active async sessions, and resumed native PQ progress.

The independently reloaded receipt test accepts the original disk receipt and
rejects a mutation to an embedded timeout signature even after the outer
certificate is reissued.

## Production cost attribution

The clean drill exported the following production counters. These are
observations from one adverse process run, not latency distributions:

| Evidence class | messages in/out | bytes in/out |
|---|---:|---:|
| proposal payload | 3 / 3 | 666 / 666 |
| availability vote | 12 / 12 | 31,620 / 31,620 |
| availability certificate | 24 / 24 | 182,976 / 182,976 |
| protocol message | 229 / 228 | 35,923 / 35,670 |
| ordering vote | 3 / 3 | 7,587 / 7,587 |
| ordering certificate | 6 / 6 | 758,034 / 758,034 |
| executed-block vote | 3 / 3 | 7,587 / 7,587 |
| executed-block certificate | 3 / 3 | 756,540 / 756,540 |

| Production stage | observations | accumulated seconds |
|---|---:|---:|
| ingress | 276 | 63.057118951 |
| dispatch | 280 | 135.992624904 |
| execution prepare | 1 | 0.006476235 |
| workload execution | 1 | 0.031097992 |
| runtime stage | 1 | 0.016481343 |
| runtime admission | 1 | 106.307948350 |
| parent-proof install | 1 | 9.419630696 |

These production metrics complement, rather than blend, the retained component
benchmarks:

- `m1-pq-benchmarks-2026-09-02.md` separates ML-DSA, SLH-DSA, and PQ-channel
  primitive sizes and latency distributions;
- `m3-hash-async-core-benchmark-2026-09-02.md` publishes messages, encoded
  bytes, CPU, memory, iterations, and latency observations through exact
  `n=130`;
- `m3-hash-async-journal-benchmark-2026-09-02.md` isolates encrypted WAL,
  per-event fsync, external-anchor update, compaction, and recovery.

Socket scheduling and production admission dominate this particular drill,
while the journal benchmark shows synchronous durability dominating the local
component run. The evidence does not support an optimal-latency claim.

## Formal and executable composition evidence

`OptimisticFallbackComposition.tla` exhaustively checks the bounded one-height
seam: captured committed state is preserved, fallback fences later optimistic
authority, and random scheduling cannot select a conflicting root. TLC reports
24 generated / 11 distinct states, depth 4, with no invariant violation. The
Rust fence, transition journal, exact-`q` certificate checks, same-height
replacement limit, Agentgres floor, and production race drill implement the
same boundary.

## Honest limitations

- The adversary is static, not adaptive.
- Randomized asynchronous progress requires the declared reliable private
  authenticated-channel abstraction and at most `f < n/3` Byzantine members.
- “No setup” means no private threshold setup or DKG; ordinary public
  parameters, enrolled identity keys, and custody roots still exist.
- The hash path is intentionally expensive and is the pessimistic fallback.
- This closes M3/RES-R10. It does not resolve M1's independent cryptographic
  review, prove end-to-end externalization, or authorize the final headline.
