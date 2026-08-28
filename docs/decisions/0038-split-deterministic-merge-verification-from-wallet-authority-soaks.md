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
