# ADR 0038: Split Deterministic Merge Verification From Wallet-Authority Soaks

- Status: Accepted
- Date: 2026-08-27
- Owners: verification estate / wallet.network authority / state runtime
- Refines: verifier claim discipline and ADR 0036's M04.8 boundary
- Confidence: accepted from live M04.8 verifier evidence; latency budget remains
  deliberately unset pending the profiling leg.

## Context

M04.8 has two materially different verification mechanisms. Its deterministic
route and architecture matrix executes 111 tests in approximately 8.4 seconds.
Its real wallet-authority journey starts a one-validator AFT chain, records
exact governed approvals, consumes them through the daemon, exercises restart,
and deepens chain state across the complete 15-gate journey. Debug-profile
runs took more than six hours; an optimized release-profile run also remained
minutes-scale at later approvals.

Making both mechanisms one per-iteration gate destroys the development loop.
Reducing the journey until it becomes fast would destroy the state-depth signal
that exposed the defect. Calling the deterministic matrix "end to end" would
instead claim ground it does not walk. The estate's standing rule is that a
label claims only what its checker observes.

The distinction resembles the AFT T5d resolution: a property unavailable on a
responsive path may still have an honest scheduled, mechanized lane. T5d is an
analogy for mechanism placement, not proof that this verifier is correct.

## Decision

M04.8 verification has two named lanes.

1. `check:m4-room-participation-contribution-architecture` is the blocking
   merge lane. It proves the declared deterministic M04.8 lifecycle, authority,
   CAS, lineage, liveness, exclusion, and ownership matrix. "Complete" means
   complete only for that declared matrix. It does not claim a real wallet
   chain, consensus finalization, durable chain restart, or state-depth soak.
2. `soak:m4-room-participation-contribution-wallet-authority` is the full
   release-profile wallet-authority lane. It retains the complete approval
   count and restart/replay ending. It runs nightly, on explicit dispatch, and
   before a release candidate may be promoted; it is not a per-iteration or
   ordinary pull-request blocker. A semantic failure blocks release.

The current minutes-scale approval latency is a tracked defect, not an accepted
wallet-chain property. The soak must eventually emit per-approval measurements
at minimum for chain height, committed state/version depth, submission,
consensus/finalization, state execution, durable persistence, proof/resolution,
CPU time, bytes written, and backend/build profile. The first profiling leg
must distinguish constant overhead from growth with height, state, history, or
version count. A numeric latency tripwire lands only with a reproducible
baseline and a mutation that proves the tripwire can fail; an aspirational
number is not evidence.

### 2026-08-28 measured profiling result

The first complete release-mode profiling leg now separates submission,
AFT finalization, execution preparation and commit, IAVL commitment
materialization, Redb persistence, and post-commit wallet resolution for all 27
authority approvals. It pins the one-validator fixture to readiness lag 1 and
records height, version count, tree depth, node and byte counts, build profile,
and backends. The profile is diagnostic observation, not an authority receipt
or state commitment.

Before repair, AFT finalization grew from 1,503 ms at the low end to 31,056 ms
at the high end over versions 74–215 and tree depths 9–11. IAVL commitment
materialization remained 0.003–0.010 ms and Redb persistence remained
19.875–33.213 ms. This separated the dominant growth from state-tree
materialization and persistence: steady-state AFT paths were repeatedly
re-verifying the full canonical-collapse prefix, producing cumulative
quadratic work.

The repair uses a previously admitted canonical-collapse object as a bounded
warm-path trust anchor, rejects conflicting replacements, and retains complete
verification for cold, gap, and recovery inputs. Production observation does
not re-walk an unchanged already-admitted tip. The profiling run also exposed
a stale batch-collected transaction-ingestion anchor; authoritative validation
now begins at the current watched committed tip and retries only after a
demonstrable non-regressing tip change. IAVL state and block persistence use
the combined atomic commit path while retaining durability ordering.

After repair, AFT finalization was 56–94 ms through version 919 and tree depth
12; execution commit was 27–37 ms, commitment materialization was
0.004–0.009 ms, and persistence was 25.920–36.228 ms. The 27-approval profile
had 27 distinct heights, no attribution anomalies, and retained all original
soak work. A mutation restoring the full warm-path re-walk failed the bounded
depth test, a mutation admitting regressing ingestion tips failed its focused
test, and the parser's missing-field mutations fail closed.

These measurements do not establish a numeric tripwire. They are one host's
pre/post evidence, client wait is polling-quantized, and the M04.8 artifact's
complete semantic soak was 14/15 because its final restarted OutcomeRoom
projection returned the then-unavailable owner-record dependency. Repeated
release-host runs plus a mutation of the selected budget remain prerequisites
for a threshold. The exact aggregate and depth buckets and artifact hashes are
recorded in
[`m04-8-wallet-authority-commit-path-profile.v1.json`](../architecture/_meta/evidence/m04-8-wallet-authority-commit-path-profile.v1.json).

### 2026-08-28 ordering/finality parity follow-on

The next release-mode leg compared the repaired one-validator AFT control with
the existing immediate Solo path through the same wallet admission, execution,
IAVL state, Redb durability, individual receipt, restart, and authority
abstractions. Six runs independently configured ordering profile, scheduler
ticker plus genesis block floor, and polling interval with provenance. Every
run accepted the same 27-operation target-scope sequence, passed 15/15
fail-closed semantic checks, and reprojected
all nine room-child families after restart with status/operations/latest
sequence `200/21/20`. This follow-on does not rewrite the historical 14/15
M04.8 artifact above; the intervening replay/ownership repairs are separately
committed and tested.

The descriptive run-level client medians were Solo/AFT 907/1,481 ms at the
1,000 ms scheduler/block configuration with 25 ms polling, 106/1,324 ms at the
100 ms configuration with 25 ms polling, and an effectively null 1,003/1,004
ms at the 1,000 ms configuration with 500 ms polling. The first pair's
ordering/finalization medians were 48/60 ms. Independent fresh chains produced
different depth/version sample mixes, and depth-matched buckets do not preserve
all aggregate comparisons. Proposal wait and event-driven completion are not
separately instrumented, realized proposal spacing was unavailable, and the
client phase is polling-quantized. These values are descriptive rather than
matched causal estimates. State commitment and Redb persistence remained
similar across profiles, including Solo at version 4,004 and tree depth 10.

The semantic and restart parity—not an uncontrolled latency delta—supports
reviewing Solo as a deployment profile, not deleting or demoting the AFT
control. ADR 0039 records that direction as **Proposed**, with no runtime
authority. It preserves one Agentgres spine, individual receipts, and exact
batch/state bindings while separating inclusion, consistency, freshness,
revocation, admission, and cross-scope adjudication obligations. No numeric
tripwire is set. Exact phase definitions, depth/version buckets, artifact
hashes, fault coverage, and nonclaims are recorded in
[`m04-9-ordering-finality-parity-profile.v1.json`](../architecture/_meta/evidence/m04-9-ordering-finality-parity-profile.v1.json).

The following stop disposition remains historical and specific to the original
quadratic M04.8 defect; the follow-on evaluates Solo separately without
reopening the stopped backend or partition candidates. The ordered ladder stops
after step 1 for this defect. Batching was not needed
to remove the measured dominant growth and individual authority receipts were
not altered. JMT is not benchmark-qualified because current evidence does not
establish incremental-commit, persistence/restart, historical-anchor, pruning,
and proof-surface parity through `StateManager`. Fractal partitioning has no
measured need; fail-closed cross-partition proof consumption and adjudication
remain preconditions rather than deferred cleanup.

The ordered performance ladder is:

1. repair the measured commit/execution/consensus usage defect;
2. batch independent approvals into one block/version while retaining each
   approval's exact request hash, authority record, receipt, and failure
   semantics;
3. benchmark an alternative commitment backend after semantic, proof,
   persistence, restart, pruning, and historical-anchor parity; and
4. partition only after measured state-size or contention evidence.

IAVL is the current wallet-chain configuration, not architecture doctrine. The
common `StateManager` capability hierarchy and `StateTreeType` selector are the
backend boundary. The in-tree Jellyfish implementation is the first candidate
to qualify, not a pre-authorized successor: its current full-snapshot commit
behavior and limited persistence evidence must pass the parity gate before a
performance comparison can authorize a default change. External designs such
as NOMT remain research candidates, not dependencies.

The future storage shape preserves the capability split already expressed by
`StateAccess`, `VerifiableState`, and `ProofProvider`: latest-state/projection
reads, cryptographic commitment, historical proofs, and durable block history
must be measurable and replaceable as separate responsibilities even when one
backend currently implements several of them. A backend benchmark that speeds
one responsibility by dropping another is not parity evidence.

Signature ownership does not move for performance. Signing and verification
remain behind `dcrypt`; batch verification or other optimizations may be
benchmarked only through that boundary after profiling attributes meaningful
cost to it.

Fractal child chains are a last scaling lever. Any future child remains a
governed child anchored to the one kernel spine; no topology change may create
a parallel source of truth. Cross-partition proof consumption and adjudication
must be designed fail-closed and mechanized before the first child ships.
Partition budgets bound scope but do not themselves prove a latency bound.

Application reads use rebuildable flat projections. Authority writes may be
shown as pending until a durable receipt exists, but no client may project
pending work as authoritative success. GoalRun continues to own application
state, executable plans, contexts, and invocation references; Session, launch,
thread, HarnessInvocation, and child owners retain kernel truth.

## Consequences

- The ordinary merge loop stays bounded by the deterministic architecture
  matrix without silently dropping real-chain evidence.
- The soak remains capable of detecting depth/history regressions and has an
  explicit release-blocking semantic posture.
- Performance closure requires measured causality; neither release mode nor a
  tree migration may launder the defect.
- Backend work begins with parity and instrumentation, not a feature-flag flip.
- No smaller soak, parallel spine, optimistic authority claim, or third-party
  crypto substitution is authorized by this decision.

## Reversal

The lanes may be recombined only after measured evidence shows the complete
real-chain journey satisfies the repository's bounded merge-loop budget without
weakening its state depth, restart, or authority semantics. A backend candidate
may become the default only through the parity and benchmark evidence above.
