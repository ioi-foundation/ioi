# Query-Unanimity Verification theorem surface

Status: M13Q theorem and mechanization candidate; not production admission,
portable finality, asynchronous safety, or a classical Byzantine-agreement
claim.

Date: 2026-09-03.

## 1. Exact task classification

`aft_quv_v0` implements online, conflict-qualified authorization for a rooted
slot. Each honest operation returns either one externally valid candidate or
typed `Abort`/rejection by its rooted deadline. The agreement property is:

> all accepted non-`Abort` outcomes for one slot are equal.

This matches M11's non-conflicting non-`Abort` agreement coordinate after ADR
0050 replaces its offline verifier with an interactive one. It is weaker than
classical exact-decision agreement: an operation that accepted `X` before a
later owner equivocation may coexist with a later operation that returns
`Abort`. QUV must not be called classical Byzantine agreement or used to claim
portable finality on that basis.

For the proof kernel, `ValidCandidates` means the finite set of independently
valid candidates introduced to correct members or disclosed in valid replies
for the rooted slot over the operations being reasoned about. It is not the
unbounded language of all payloads that could theoretically satisfy static
syntax.

## 2. Relational abstraction

Let `Ops` be any set of honest QUV operations and `Correct` any nonempty subset
of the rooted membership. `CandidateOf[o]` is the candidate pushed by operation
`o`; `Snapshots[o][c]` is the complete snapshot signed by correct member `c`
for `o` after durably processing that operation.

The operational assumptions Q-A1 through Q-A10 imply:

1. self-inclusion: `CandidateOf[o]` is in every `Snapshots[o][c]`;
2. serialization disclosure: for any operations `o1,o2` and correct member
   `c`, either `CandidateOf[o1]` is in `Snapshots[o2][c]` or
   `CandidateOf[o2]` is in `Snapshots[o1][c]`; and
3. complete observation: each honest operation waits long enough to receive
   the bound snapshot from every correct member.

The second fact follows because one of two atomic operations linearizes later
at each fixed correct member and correct conflict knowledge is grow-only. The
third fact is exactly the safety-critical content of Q-A3, including request,
admission/queueing, validation, durable processing, response, and clock error.
Byzantine replies are absent from the proof abstraction because they can add a
valid conflict and force rejection but cannot remove a correct snapshot or
turn rejection into acceptance.

## 3. Theorems

### Q-T1: accepted-value non-conflict

**Assumes:** Q-A1 through Q-A10, a fixed rooted configuration/domain/slot and
predecessor, `Correct` nonempty, and every honest executor follows the complete-
deadline algorithm.

For arbitrary membership size, arbitrary nonempty correct subset, and any
number of operations, two owned-mode accepts or two unowned-mode accepts imply
the same candidate.

For owned mode, choose any fixed correct member `c`. Pairwise serialization
disclosure puts one candidate in the other operation's snapshot at `c`; an
accepting singleton union therefore forces equality. For unowned mode, each
accept must equal every correct member's immutable first winner, so choosing
any `c` again forces equality.

Mechanized as `QOwnedNonConflict`, `QUnownedNonConflict`,
`QOwnedOutcomeNonConflict`, and `QUnownedOutcomeNonConflict` in
`QueryUnanimityProof.tla`.

### Q-T2: external validity

**Assumes:** Q-A1, Q-A7, Q-A8, rooted candidate validation, and the Q-T1
relational typing assumptions.

Every non-`Abort` outcome belongs to the independently valid candidate set.
Invalid and forged replies do not enter an acceptance predicate.

Mechanized as `QOwnedExternalValidity`, `QUnownedExternalValidity`,
`QOwnedOutcomeTyped`, and `QUnownedOutcomeTyped`.

### Q-T3: bounded typed termination

**Assumes:** Q-A2, Q-A3, Q-A6, Q-A8, Q-A9, a live honest executor, and a fixed
rooted operation start.

The operation returns a typed candidate or `Abort` after one complete
`delta_rt` decision interval. Byzantine silence cannot extend that interval;
missing the bound invalidates the model rather than producing a lower-assurance
certificate.

The proof kernel mechanizes total outcome typing once the complete snapshots
exist. The timing bridge is definitional from Q-A3 and the executor algorithm:
every correct snapshot exists in the verifier input by the deadline and the
algorithm evaluates a total predicate at that deadline. This is known-
synchronous termination, not asynchronous or eventual-synchronous progress.

### Q-T4: no-conflict progress and all-correct same-input validity

**Assumes:** Q-A1 through Q-A10, exactly one independently valid candidate `s`
is introduced for the slot, and no separately valid conflict is disclosed.

Every honest operation on `s` accepts by its deadline, including with all
Byzantine members permanently silent. If all members are correct and introduce
the same `s`, the same result gives all-correct same-input validity.

Mechanized for arbitrary sets as `QOwnedSingleCandidateProgress` and
`QUnownedSingleCandidateProgress`; the R4 explicit-time model separately
enumerates fresh/pre-populated state and Byzantine silence/non-conflicting
replies for all authority modes.

## 4. Matching lower bounds and necessity witnesses

| Result | Matching boundary | Evidence |
|---|---|---|
| Q-T1/Q-T4 online construction | A different timely correct witness per operation is insufficient | R4 split-witness mutation: conflicts in 2/16 cases for both dishonest-owned and unowned modes |
| Q-T3 bounded termination | A one-way request bound does not guarantee the correct reply is observed | R4 one-way mutation recovers conflicts |
| Q-T1 durable serialization | Reply-before-durable plus crash loses the operation intersection | R4 volatile mutation recovers conflicts |
| Q-T1 context integrity | Unbound cross-slot/configuration replies can be replayed | R4 unbound-replay mutation recovers conflicts |
| Online result | Finite portable byte-only receipts cannot preserve both solo progress and non-conflict at `f=n-1` | M12a/L-MAX, independently upheld within scope |

The positive and negative results therefore meet at a precise boundary: QUV
adds online interactivity plus a complete known-synchronous correct-member
response fact; it does not refute or package around the byte-only lower bound.

## 5. Mechanization and residual obligations

`QueryUnanimityProof.tla` is parameterized by arbitrary sets; its proof does
not enumerate a fixed `n`. TLAPS discharges 75 obligations for the safety,
validity, typed-outcome, and singleton-candidate theorems. The R4 Python model
checks operational timing and mutations in bounded spaces.

M13Q does not lift QUV through multi-slot ordering, restart/reconfiguration,
state availability, or irreversible effects. Those remain M14Q. Query-flood
capacity and actual durable-I/O latency remain production measurements for
M16Q. A later M17Q reviewer must review this proof and its operational bridge;
the M12b construction review did not pre-approve this theorem surface.
