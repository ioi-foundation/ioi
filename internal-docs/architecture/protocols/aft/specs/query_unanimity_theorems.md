# Query-Unanimity Verification theorem surface

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is [the R1 fault/property matrix](query_unanimity_fault_property_matrix.md); no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

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
`o`; `Snapshots[o][c]` denotes the complete logical history at correct member `c`
after processing that operation. The v4 wire representation signs its first-two
distinct projection. `QuvConflictSummaryProof.tla` establishes preservation of
owned singleton equality, nonemptiness and the unowned first entry for this
projection. Self-inclusion below concerns the logical history; a saturated wire
summary may omit the wanted candidate while forcing the same rejection.
The complete runtime transition/refinement obligation remains open.

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
| Q-T4 singleton premise | Prior acceptance does not guarantee fresh acceptance after a later valid owner conflict | `OwnedParentReverification.tla`: admitted invariants pass; stronger `PriorAcceptancePersists` fails on accept/conflict/abort; sequential one-witness abstraction only |
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

### Preparation progress scope (R1 head integration)

The finite QuvHeadProgress model adds a separate conditional temporal check
for the unimplemented head-preparation layer: singleton input, no crashes,
atomic retained state, exact routing and per-action weak fairness. It passes
when accepted grants survive until advancement; removing that guard admits
a fair retry cycle. This is not Q-T4's rooted deadline proof or a replacement
for its assumptions. The distinction and exact witness are recorded in
`query_unanimity_head_state_design.md`; production integration remains open.

### Member provisioning scope refinement boundary

The durable member implementation now authenticates and compares its configured
network/configuration/policy-set commitment before crash recovery advances an
anchor. This supports the fixed-root premise of Q-T1 and retained-knowledge
assumption; it does not discharge accepted-head derivation, history advancement
or handoff continuity.

**Assumes:** Q-A1 through Q-A10, independently provisioned bootstrap-committing
policy roots, collision resistance, authenticated non-rollback state and anchor,
and exact provisioning comparison before recovery writes. The schema 4 local
regressions do not establish the remaining transition-level refinement or
rooted queue/storage timing premises.

Candidate-triggered independent preparation now has a finite temporal design
check: both modes pass 232 states; disabling the trigger produces a required
15-state stalled-history witness. Reception only enables the member's own
query; own live acceptance still gates Advance. **Assumes:** fixed roots,
singleton inputs, no crashes, atomic non-rollback storage, ideal routing,
per-action weak fairness and pending future Capture until admissibility.
Production bounded retries, timers, admission/fairness, expiry and head
advancement remain open; this is not runtime refinement or R1 closure.
Evidence: `evidence/m17q-r1-triggered-preparation-2026-09-05/`.

The accepted-history transition core now derives historical/next predecessors
from a provisioned initial coordinate and retained accepted hashes, and stages
advancement only from a matching unexpired local live grant. **Assumes:** an
independently provisioned bootstrap, authenticated/validated state, the QUV
live-grant construction and a future atomic durable commit before exposure.
The member store and runtime do not yet persist or enforce this primitive;
preparation, recovery and handoff refinement remain open. Positive/negative
transition tests and a removed-predecessor-check control are retained in
`evidence/m17q-r1-accepted-history-core-2026-09-05/`. No whole R1 closure or
production head-history claim is admitted.

Member schema 5 persists explicitly enrolled domain histories and checks Fixed
history coordinates before member insertion and executor start. Runtime commits
the own-live-grant advancement before result delivery while reserving local
admission; exact historical queries/repeats remain supported. **Assumes:** exact
independent domain enrollment, authenticated non-rollback state/anchor, durable
write/rename/directory synchronization, retained snapshots, the complete QUV
live-grant premises and a live continuation at the write boundary. Local tests
cover advance/recovery/headroom and advanced-history corruption. Multi-member
preparation, timing/fairness, incremental storage and successor frontier transfer
remain open, as do all complete R1 findings and fresh process qualification.
Evidence: `evidence/m17q-r1-durable-history-2026-09-05/`.

A preparation-timing design check now pairs bounded child readiness with a
required no-wait failure of CompleteCorrectProcessing and a completion witness.
**Assumes:** prior complete parent processing, independently completed own parent
queries/commits within an explicit preparation bound, timely child delivery,
fixed roots and ideal model time. It does not prove those service/scheduling
premises. A premature child can be refused by a reachable correct member whose
head is not yet ready; this is outside Q-A3, not an interactive impossibility.
Production preparation, readiness budgets, clocks and restart refinement remain
open. Evidence: `evidence/m17q-r1-preparation-timing-2026-09-05/`.

Pending preparation can now be recovered read-only from the next unaccepted
Fixed-domain snapshot, rotating between domains. Selection preserves mode rules
and excludes historical completions and handoffs. **Assumes:** authenticated,
validated, non-rollback member history and snapshots; fresh independent live
queries still supply advancement authority. The selection primitive does not
implement a worker, bounded fairness or child readiness. Positive restart and
rotation tests plus a historical-rescheduling negative control are retained at
`evidence/m17q-r1-preparation-selection-2026-09-05/`. No whole R1 closure is claimed.

Preparation attempt, service and readiness limits are now explicit policy
commitments under the v2-preparation root; handoff domains explicitly select
OneShot. Missing/incompatible policies and overflowing/insufficient local
budgets refuse. **Assumes:** independently provisioned policies and future
durable attempt reservation, bounded fair service, readiness/clock/restart
refinement and qualification. Root commitment and local syntax checks do not
discharge those premises. The worker and runtime enforcement of these limits
remain open; earlier process evidence does not qualify this changed root.
Evidence: `evidence/m17q-r1-rooted-preparation-policy-2026-09-05/`.


### Accepted-history snapshot retention — 2026-09-05

The retained-knowledge Assumes obligation includes keeping the candidate
snapshot underlying every accepted local history entry. Production recovery
cross-checks this relation before recovery writes. The new regression
`recovery_requires_snapshot_for_every_accepted_history_entry` pairs with removal
of that structural check: the regression fails on the removed-check variant.
This is local recovery evidence, not a new theorem or proof of deployed
non-rollback custody. All existing synchrony and reachability assumptions remain.


### Durable preparation-attempt reservation — 2026-09-05

The preparation-service Assumes obligation still needs production scheduling
and aggregate timing evidence. Its finite-retry sub-obligation now has a local
schema-6 durable reservation primitive. Given the existing non-rollback custody
assumption, reservation spends a rooted next-slot attempt before returning;
reopen does not refund it. Only own live accepted-history advancement retires
that slot's count. This is not a proof that every preparation finishes in time.

Lower-bound/removal pairings: removing the rooted maximum or policy-root comparison
fails preparation_attempts_are_rooted_durable_and_retire_only_on_advance;
removing attempt-map MAC coverage fails
preparation_attempts_preflight_authenticate_and_recover_uncertain_write. These
are local implementation regressions, not replacements for transition refinement
or the existing formal preparation timing assumptions.


### Runtime preparation worker — 2026-09-05

The triggered-preparation model now has a production worker counterpart that
starts own live queries from retained pending candidates. The existing bounded
service and readiness Assumes conditions are not discharged: operation-slot
competition, queue work, full storage cost and restart timing remain unqualified.
Durable attempts bound independent retries under non-rollback custody; exhaustion
is a refusal, never a proof of termination with history/effect progress. Runtime
mutation/process pairing for the worker remains pending.


### Queued foreground/preparation admission — 2026-09-05

Production queue-order evidence now supplements the preparation-service Assumes
obligation: one active operation, bounded enrolled-domain waiters, and one queued
worker. Permit ownership spans the accepted-history commit. Unit tests exercise
both queue orderings and cancellation; relaxing the active or waiting cap fails
the paired regression. This establishes neither aggregate wall-clock service nor
the child-readiness premise, and is not a complete transition refinement proof.


### Queued-admission development result — 2026-09-05

The queued-admission process campaign completed with exit 0 on unchanged
recorded sources and no diagnostic-retention failure. The evidence checker
confirmed all four sole-correct placements, four-way workload overlap (4914.504ms),
one conflict acceptance with typed rejection and resource non-mutation, unrelated
effect execution, and unchanged expired terminal-result retrieval. Retained logs
match 13 accepted worker completions across all four endpoints to preceding
reservation, own live-query audit with all four expected members, and completed
runtime outcome. There were 17 worker starts; no completion is claimed for the
four remaining starts at test shutdown.

The worker-observation checker rejects removed reservation diagnostics, portable
claims and incomplete member sets. These are evidence-check mutations, not a
substitute for runtime worker mutation, restart or transition-refinement tests.
Five runtime tests and two actual admission-capacity controls also passed their
required dispositions. Evidence is retained in
`evidence/m17q-r1-queued-admission-2026-09-05/` (relative to the AFT directory).
This is a shared-host development campaign, not clean R2 qualification, a measured
aggregate service bound or child-readiness proof. All whole R1 findings remain open.


### Cancellation-safe dispatch completion — 2026-09-05

The complete-request/processing Assumes obligation now has an additional local
runtime prerequisite: exact-member dispatch completion must be recorded within
the rooted interval before the live decision runs. This is not an implementation
proof of Q-A3, since outbox admission does not imply delivery or a correct reply.

Lower-bound/removal pairings: removing the complete-set guard fails
`dispatch_requires_every_exact_member_before_decision` and
`canceled_dispatch_never_runs_the_live_decision`; removing the interval guard
fails `dispatch_completion_obeys_before_equal_after_deadline`. The tests use a
controlled decision callback to verify the guard, not a remote exploitation
workflow or full transition-refinement proof. Full current-source process and
refinement qualification remain required.


### Rooted active preparation service — 2026-09-05

The service/readiness Assumes obligations distinguish active attempt cost from
aggregate readiness. Runtime enforcement now limits active preparation from
exclusive admission through completion, but selection, waiting, foreground work,
retries, restart and storage bounds remain to be composed and qualified. Expiry
or refusal is not a witness of history/effect progress.

Local pairings: removing the minimum with the original grant expiry or removing
expired-grant rejection fails
`authorization_expiry_cap_never_extends_or_revives_a_grant`; removing late-service
rejection fails `active_service_completion_never_reports_late_success`. These are
local lifetime/completion checks. They do not prove the full scheduler, physical
storage latency or end-to-end readiness theorem.


The expiry-observation campaign terminated with exit 101 on unchanged recorded
sources. Four sole-correct placements and four saturation effects executed;
both conflicting candidates were rejected with resource non-mutation (safety
only). The unrelated effect failed exact four-member audit coverage, so the
new expiry case was not reached. Its missing member completed durable processing,
but the reply was routed approximately 5296.857ms after the operation-start
log, beyond the rooted 5000ms decision interval, and was absent from the audit.
These are same-host diagnostics; they do not isolate transport, queue, lock or
scheduler delay, or qualify the timing premise. The strict process checker
rejects the run. No retry or relaxed coverage is used to turn it into a pass.
Raw logs and the extracted lifecycle are in
`evidence/m17q-r1-expiry-observation-2026-09-05/process/`.
The strengthened expiry fixture remains locally tested but process-unqualified.
All whole R1 findings and aggregate readiness/timing qualification remain open.


The instrumented reply-path development campaign passed on unchanged recorded
sources, including exact process participation, conflict/resource checks,
unrelated effect execution and unchanged expired-result retrieval (admitted
height 70, fence 65). Four-way workload overlap was 4153.826ms; 14 of 17 worker
starts had accepted completions matched to own live-query/service diagnostics.
Evidence: `evidence/m17q-r1-reply-boundary-diagnostics-2026-09-05/process/`.
Observed reply-stage gaps around orchestration context locks exceed one second;
these samples identify a repair target, not a worst-case bound or a causal proof
for the earlier uninstrumented failure. Both earlier failed campaigns remain
failed. This is neither clean R2 nor whole R1 closure, aggregate readiness,
fairness, restart/storage or full-refinement qualification. No theorem assumption
or lower-bound disposition changes.


The member-completion path now captures notification and reply-routing handles
in its initial rooted-context read, avoiding two main-context acquisitions after
durable work. Exact forwarding, notification under backpressure, refusal and
closed-lane regressions pass; removed-notification and substituted-recipient
controls fail. See `evidence/m17q-r1-member-completion-handles-2026-09-05/`.
This changes no theorem assumption or authority rule and proves no timing bound.
Verifier-side contention, process qualification, full refinement and all whole
R1 findings remain open; the predecessor's process pass is historical only.


Reply observation now uses a separately locked live-operation table captured by
the QUV event loop, instead of acquiring the main orchestration context. Startup,
dispatch, abort and finalization use that same table; rooted revalidation and
monotonic reply deadlines remain unchanged. Routing regression and removed
transport-binding/nonce-lookup controls have their expected dispositions.
See `evidence/m17q-r1-verifier-operation-table-2026-09-05/`. A preceding PUSHQUERY
admission can still block the event loop on main-context access. This change is
not a process timing bound, full refinement, whole R1 closure or clean R2; no
Assumes line or lower-bound disposition changes.


The captured-member-handle/separate-operation-table process campaign passed on
unchanged recorded sources: exact participation, conflict/resource isolation,
unrelated execution and unchanged terminal replay beyond expiry. The expiry
fixture observed equality as pending before crossing from admitted height 65 to
66. Four-way workload overlap was 4868.970ms, and 16 of 18 preparation starts had
accepted completions matched to own live-query/service diagnostics. Raw evidence
is in `evidence/m17q-r1-verifier-operation-table-2026-09-05/process/`.
The repaired post-work/handler-lock stages were below 0.030ms in this sample;
event forwarding to handler entry still reached 998.006ms. These observations do
not qualify an aggregate bound or explain the earlier uninstrumented failures.
All whole R1 findings and clean R2 remain open; no theorem premise is weakened.


A single bounded PUSHQUERY-admission worker now lets the event drain observe
replies while admission waits for the main context. Existing rooted/per-account
checks remain; overflow and unexpected worker exit are explicit failures rejected
by the mandatory process evidence checker. Driver controls distinguish this from
serial processing and an enlarged queue. See
`evidence/m17q-r1-bounded-push-admission-2026-09-05/`. Complete member service still
needs the rooted timing bound; this scheduler change proves neither aggregate
readiness/fairness nor lifetime/storage quotas. Process qualification, full
refinement and every whole R1 finding remain open. No theorem premise changes.


The bounded-admission development process campaign passed its strict checks on
unchanged recorded source, with exact participation, 4373.699ms workload overlap,
conflict/resource checks, unrelated execution and unchanged terminal replay at
height 66 beyond fence 65. Thirteen of sixteen worker starts had matched accepted
completions. The largest observed event-queue gap was 36.217ms, not a qualified
bound. See `evidence/m17q-r1-bounded-push-admission-2026-09-05/process/`.
A subsequent forced-abort regression reproduces a detached admission worker;
that boundary remains separate from this pass and is under repair. All whole
R1 findings, restart/refinement, aggregate bounds and clean R2 remain open.


A forced outer-task abort regression reproduced a detached blocked admission
worker after the preceding process pass. The event drain now owns an abort-handle
guard, so dropping it requests cancellation of that worker. Fourteen runtime tests
pass; removing the guard fails the forced-abort regression. See
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`. This is async admission-
callback ownership, not synchronous preemption or cancellation of already-spawned
durable work. Process/restart/refinement qualification and whole R1 closure remain
open; the preceding source's process pass does not qualify this repair.


The scheduler/worker-ownership runtime passed disjoint and overlapping handoff
campaigns with four independent successor acceptances, exact four-old-member
participation, and maximum observed valid replies of 939ms and 911ms. The overlap
fixture also passed local-gate recovery diagnostics, retrieval of a block two
heights beyond the pre-restart tip, and retired-member role-refusal diagnostics. Stronger scheduling/service diagnostic gates
pass the retained logs; the disjoint recheck used a newer checker after runtime
termination, with both hashes retained. Evidence is in
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`. These scoped checks
are not full restart/refinement, worst-case timing, whole R1 closure or clean R2.


### Repeated-slot readiness composition boundary (2026-09-05)

`QuvReadinessComposition.tla` checks completion schedules for a proposed rule,
not production transition refinement. Waiting a fixed bound after every member's
own head commit does not follow from the rooted active-service bounds alone:
with wait 3, fast service 1, slow service 2, and active budget 3, the fifth child
is introduced at time 16 while the slow predecessor completes at 17. Both
services are strictly within budget. The model stops before any acceptance for
that inadmissible child. Equal-service scheduling passes and a separate required
witness reaches five completed slots, preventing a vacuous always-refuse result.

A second positive configuration exempts retained-candidate preparation from the
foreground wait. It passes the same unequal-service five-slot schedule under
ideal immediate selection, no queue/competition/restart and timely complete
correct-member processing whenever the predecessor is ready. It is a design
candidate, not an implemented readiness gate or derived production bound.

The existing one-parent/child timing model assumes aggregate PreparationBound;
its pass does not derive that bound over repeated slots. Selection, fair queueing,
finite retries, durable reservation/commit and restart still need a uniform
composition bound. A per-attempt cap or readiness policy field alone is
insufficient. This witness violates the missing complete-processing premise;
it is not conflicting acceptance or an impossibility under the fixed QUV
assumptions. No timeout/silence grants authority; every relying member still
needs its own live query and non-rollback durable advance.

Evidence: `evidence/m17q-r1-readiness-composition-2026-09-05/`. The focused formal
flag `--quv-readiness-composition-only` requires two positive schedules and two
named negative/reachability witnesses; full and parent-boundary runners include
the same checks and M16Q hashes their sources. All whole R1 findings, complete
refinement, aggregate readiness and clean R2 remain open.


### Conditional readiness bound across arbitrary slots (2026-09-05)

`QuvReadinessBoundProof.tla` discharges all 10 TLAPS obligations for an inductive
completion-schedule invariant, without a finite slot-count premise. **Assumes:**
each correct member receives the singleton candidate, retained-candidate
preparation has no extra own-head wait, aggregate selection/queue delay is at
most Q, its own live query and durable commit take at most S, and foreground
wait W satisfies W >= Q + S. The next foreground introduction then occurs only
after the prior slow completion. This is a conditional arithmetic schedule
lemma, not QUV authorization, runtime transition refinement or a liveness proof.
It assumes completion costs; it does not prove those completions happen.

The bounded TLC instance explores three slots. The paired instance using a
service-only wait (W=2, Q=2, S=2) violates ReadyForNext: first fast completion 3,
slow completion 6, next introduction 5. The failure demonstrates why queue delay
cannot be omitted from the aggregate premise. Evidence and exact hashes are in
`evidence/m17q-r1-readiness-bound-2026-09-05/`. Both the full formal runner and a
new mandatory M16Q phase include the proof/model pair; only the focused phase
was run here. The initial census rejection is retained and resolved by including
the model in the executed harness, without a manual-discharge exemption.

Production audit: `QuvOperationAdmissionV0` permits one active operation and one
waiting foreground operation per enrolled domain; its single preparation worker
joins FIFO. With D enrolled domains, a newly queued worker has at most D queued
foreground operations plus the active predecessor ahead. An elapsed bound of
(D+1)*Smax additionally requires every predecessor to release admission within
Smax, including startup, dispatch, decision, durable commit and cleanup. Current
foreground/handoff operations do not have a rooted active-service cap. Selection,
context/store lock acquisition, scheduling and restart costs also remain unbounded
by that queue-count argument. The current runtime therefore does not discharge Q,
and no foreground readiness wait is installed or qualified by this lemma.
All whole R1 findings, complete transition refinement and clean R2 remain open.


### Required all-operation service contract — implementation in validation (2026-09-05)

AftQuvDomainPolicyV0 now requires operation_service_millis, with no serde default.
The canonical policy root moves to `ioi/aft/quv-policy/v3-operation-service` and
commits this field. The limit must exceed Delta, fit within checked Delta plus
continuation, and cover the independent preparation active limit. Root/config
validation refuses missing, insufficient or overflowing contracts. Existing
provisioning bindings therefore reject old roots; no migration or fallback is
introduced. Fixture policies and candidate roots explicitly supply the new field.

Every admitted operation now gets an active deadline: foreground and handoff use
the all-operation limit, and independent preparation uses its no-wider attempt
limit. The existing startup/dispatch timeout, capped decision timer, non-extending
live-grant expiry cap, pre-write expiry check and final completion check apply to
all roles. Deadlines start after exclusive admission. Queueing and selection are
outside this active interval and still require separate rooted aggregate bounds.
A deadline failure is logged as operation_service_expired. Evidence gates reject
that marker, the prior preparation marker, or any completed operation lacking
explicit service_budgeted=true and service_budget_met=true. No timeout grants
authority or establishes inclusion/effect progress.

**Assumes still unqualified:** actual startup/transport/storage/cleanup completion
within the active service contract, bounded selection/FIFO delay, correct clock
behavior and restart composition. An already-running blocking write retains its
shared admission permit until it returns or unwinds; a timeout cannot make that
write stop or bound its actual duration. Thus finite declared active budgets do
not yet discharge the queue/readiness lemma's elapsed-time premise.

Validation is ongoing in `evidence/m17q-r1-all-operation-service-2026-09-05/`.
Configuration tests and 40 core tests passed (one pre-existing ignored test remains
separate). Runtime, CLI, removed-rule and process qualification must be completed
for this exact root change. Earlier process evidence is historical. All whole
R1 findings, full transition refinement, clean R2 and release admission remain open.


### Shared admission lifetime and final release observation (2026-09-05)

The startup/dispatch future now retains an admission share independently of the
pending-operation table. Deadline removal of pending state cannot open the lane
while that future is still waiting. Its share is released on return or cancellation;
blocking reservation/head-commit closures retain their existing independent shares.
The final shared QuvActiveAdmissionV0 owner releases the actual semaphore before
sampling the release time. This separate operation_admission_released diagnostic
records whether release was strictly before the rooted active deadline; equality
or lateness emits operation_service_expired. Elapsed microseconds are recorded
without narrowing the integer. The earlier operation_finished sample remains a
finalizer/outcome check, not a claim that all admission shares have disappeared.

All 18 runtime tests pass on final source. The new regressions cover pending removal
while dispatch waits, both normal completion and cancellation, actual semaphore
availability at clock observation, and before/equal/after release deadlines.
Removing startup retention, observing before semaphore release, or admitting release
at deadline equality makes its regression fail; restored source passes. The CLI
aft_e2e target compiled before the final private predicate extraction; final runtime
compilation/tests cover that extraction. Exact commands and hashes are retained in
`evidence/m17q-r1-final-admission-release-2026-09-05/`.

Process gates require successful release diagnostics for selected operations and a
matching final release for every recorded completed operation, including unrelated
nonces. They reject late/unbudgeted release, duplicate records and missing releases.
Workload overlap remains capped by the decision interval; delayed release does not
inflate overlap. Main checker self-tests pass 2 positive/26 negative process and
1 positive/38 negative component cases; handoff passes 1 positive/30 negative cases.
Removing either all-completions release gate makes its self-test fail.

This repairs local ownership and conservative release observation. A delayed clock
sample after actual release can produce a conservative overrun; it cannot certify
late actual release as timely. Crashes without a completed/released record are not
qualified by that match. Selection, scheduler resumption, fair queueing, actual
storage completion and restart still need aggregate bounds/refinement. The prior
v3 process pass is historical for its recorded source. Current-source process
qualification, clean R2 and all whole R1 findings remain open. No audit diagnostic
or timeout independently authorizes another executor or constitutes progress.


### Overlapping handoff and admission-order component evidence (2026-09-05)

The post-commit lock repair's overlapping-member campaign passed with unchanged
recorded sources (314.08s). Handoff and final-release evidence gates both passed:
four successors independently accepted with all four expected old-member replies;
maximum valid reply observation was 962ms. Four completed operations matched four
final release records, maximum 30,012,800 microseconds. No preparation operation
was observed in this campaign. The fixture checked the common member's own live
install, its durable-gate recovery after restart, further public block retrieval,
and retired-member rejection after restart. Retrieval is not proof of fully
admitted canonical history at every height. These are finite observations, not
worst-case timing bounds. Earlier failed campaigns remain retained. Raw evidence:
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/overlap-process/`.

`QuvAdmissionOrder` adds a finite component ordering check, with one/two domains
(18/101 states), one queued preparation worker, one waiting foreground per domain,
FIFO starts, foreground cancellation, and weakly fair release/service. It checks
at most D foreground starts before that worker and eventual worker admission.
Removing FIFO violates the bound with one domain. The focused runner passed and
both full formal/M16Q runners require the positives and named control. Evidence:
`evidence/m17q-r1-admission-order-model-2026-09-05/`. This is not an arbitrary-domain
proof, runtime transition refinement, or a wall-clock queue/readiness guarantee.
Selection, domain rotation, scheduler resumption, actual durable completion and
restart costs remain unqualified; worker admission is not inclusion/effect progress.

All whole R1 findings remain OPEN. Complete mutation/refinement, aggregate readiness
and resource bounds, clean full R2, immutable candidate and fresh independent review
remain required. The fixed M12a/M12b, complete-correct-processing, durable nonrollback
and process-local nonportable authorization boundaries remain unchanged.


### Production foreground child-readiness wait (2026-09-05)

The Fixed-domain foreground path now enforces the independently rooted
`readiness_millis` delay before joining the active operation queue. It holds the
single waiting-domain permit across that delay, so preparation can use the active
lane while additional waiting requests for that domain are refused. Cancellation
releases waiting capacity. Independent preparation and one-shot handoff do not
inherit the foreground delay.

Each member records a process-local monotonic observation only after its own
accepted-head state and external anchor are durable. Authenticated reopen starts
a fresh conservative observation; no Instant is serialized or restored from an
audit. The exact next slot/root/predecessor must match local history. Initial and
historical coordinates impose no new delay; an exact historical retry or refused
mutation does not reset the next child's clock. Uncertain persistence requires
reopen. After waiting and active admission, current rooted membership/policy,
current head and the current readiness deadline are rechecked; a replacement or
new observation cannot borrow an elapsed deadline from the earlier store. Early
admission is refused, equality/past is eligible for a fresh live operation. The
observation itself is never authorization.

Evidence `evidence/m17q-r1-foreground-readiness-2026-09-05/` retains 41 passing core
tests (one unrelated ignored measurement), 20 passing runtime tests, CLI test-target
compilation and seven required-failure controls: early commit/reopen clocks, retry
clock reset, omitted waiting, omitted readiness predicate, preparation waiting, and
active admission before readiness. Restored suites pass. M16Q explicitly requires
the new regressions. The first core command used an unsupported feature and is
retained separately; the corrected command uses `--features aft`.

This implements the local waiting premise in the prior conditional readiness
models; it does not discharge their aggregate QueueBound/ServiceBound assumptions,
prove runtime transition refinement, or establish complete correct-member processing.
The existing 1,000,000ms fixture readiness value is preserved and now actually
applies to noninitial foreground children: up to 16m40s after local commit/reopen.
No shorter qualified envelope is asserted. A refusal, cancellation, or expired
caller is not inclusion/effect progress. Process qualification of this repair,
arbitrary-domain scheduling bounds, authority lifetime/rooted quotas/incremental
storage, full refinement/mutations, clean R2 and fresh review remain outstanding.
All whole R1 findings remain OPEN; fixed M12a/M12b, synchrony, nonrollback retention,
own live query and `portable_final_receipt=false` boundaries remain unchanged.


### Consecutive readiness qualification and consequence lock handoff (2026-09-05)

The earlier initial-slot foreground campaign passed on the preceding readiness
snapshot with unchanged recorded sources and all four evidence checks. It covered
four sole-correct placements, four saturation operations, an unrelated execution
and unchanged expired-result retrieval. The conflict pair had zero acceptances
and two typed refusals with nonmutation: safety only, not conflict progress.
That pass does not qualify the subsequent changes described here.

The effect endpoint previously held its process-wide ConsequenceStore lock across
readiness and live QUV waiting. Durable preflight now finishes and releases that
lock before waiting. The endpoint reopens the store afterward, re-derives exact
current committed admission and height, and revalidates the durable receipt.
If another request has completed meanwhile, only the existing result/reconciliation
path is used; the fresh grant does not cause a second mutation. Otherwise the
fresh process-local continuation still undergoes the immediate T10 checks. The
store remains exclusively locked across the synchronous Claim/call transition.
This change does not establish fair completion of all contenders for that lock;
StoreBusy/refusal remains a refusal, never effect progress.

The readiness clock regression now covers a second durable head transition.
Runtime diagnostics bind a positive remaining delay and observed elapsed duration
to the nonce/domain/slot before active operation startup. The new three-slot process
fixture uses a distinct rooted 40,000ms readiness profile, exact four-member live
participation, a restart before slot three, unchanged terminal parent replay, and
an unrelated effect completed on the same executor during the slot-two wait.
Each noninitial slot must have at least 15 seconds of actual remaining wait and
consume the matching fresh live audit. This is a selected finite profile, not a
replacement for existing 1,000,000ms roots or a derived aggregate QueueBound.

Core (41 pass, one ignored measurement), runtime (20 pass), endpoint lock/refusal
(2 pass), and consequence (22 pass) checks passed. Controls retaining the consequence
lock, failing to refresh the second head clock, and accepting a vacuous wait each
failed the intended regression; restored checks passed. The Rust observation
assertion includes malformed/early/wrong-nonce negatives; the retained process
checker self-test has one positive and 22 negative cases. M16Q now requires these
unit/assertion gates, the consecutive process case, and its independent host-log
checks for accepted scope, exact member coverage, wait ordering, unrelated progress
and final operation releases.

Raw evidence is in `evidence/m17q-r1-readiness-process-2026-09-05/`. The consecutive
process campaign is running; no process pass is claimed yet. Aggregate preparation,
selection/queue/scheduler/restart bounds, rooted lifetime/quotas/incremental storage,
full transition refinement, clean R2 and fresh independent review remain open.
All whole R1 findings remain OPEN. The fixed M12a/M12b, complete-correct-processing,
nonrollback retention and `portable_final_receipt=false` boundaries are unchanged.


### Three-slot readiness/restart campaign passed on its recorded snapshot (2026-09-05)

The corrected campaign passed in 295.93s with unchanged recorded sources. Its
recorded-source readiness checker and final-release analyzer both passed. All
three consecutive Fixed-domain effects executed using the relying executor's own
live operations and exactly all four configured correct-member replies. Slot two
required 39.514471166s and observed 39.515012671s before admission; after restart,
slot three required 38.648001013s and observed 38.648667936s. Their maximum valid
reply observations were 793ms and 817ms (parent: 1554ms), within the fixture's
4000ms envelope and rooted 5000ms decision interval.

The same executor returned the unchanged terminal parent result and executed an
unrelated effect while slot two waited. After restart it recovered the exact
parent result through current committed readmission before the third child query;
the checker also matched the second RPC listener between slot-two completion and
slot-three waiting. Fourteen recorded completed operations matched final-release
records (18 releases total). Maximum observed active release was 7,303,766us;
preparation maximum was 6,004,109us. These are finite host observations, not
worst-case time bounds. Neither diagnostic events nor returned parent receipt
bytes authorize a child or another executor.

The two earlier failed campaigns remain failed and retained with their exact
recorded source copies and checker refusals. This pass does not retroactively
waive them, prove full transition refinement, derive aggregate scheduling/queue/
restart costs, or close whole R1 findings. Canonical receipts, commands, toolchain,
source copies and hashes, raw component logs and checked disposition are retained
under `evidence/m17q-r1-readiness-process-2026-09-05/consecutive-process-recovery-probed/`.
The profile remains two configured domains, four correct members, a rooted 40,000ms
readiness delay and a bounded read-only startup probe. General authority lifetime,
rooted byte/rate/slot quotas, incremental authenticated storage/retention, sustained
resource qualification, complete mutation/refinement, clean full R2 and fresh
independent review remain outstanding. All whole R1 findings remain OPEN.

### 2026-09-05 — shared typed member transitions and journal replay

Production member staging now applies `MemberDelta::{InsertCandidate, ReservePreparation, AcceptHead}` before its existing authenticated snapshot and anchor writes. Live candidate validation, rooted preparation limits, exact expected-head checks and the final process-local expiry check remain outside the state delta and remain required. Delta bytes never create an online authorization. The replay path restores retained state only after the journal chain and exact independently provisioned bootstrap authenticate.

The journal component and typed replay are not yet the production persistence format. Production member schema 6 still clones and rewrites full state; handoff schema 3 is unchanged. Rooted byte/rate/slot/lifetime quotas, incremental production persistence, safe retention/compaction, aggregate timing qualification and complete transition-level refinement remain outstanding. These changes do not establish clean R2 or close a whole R1 finding.

[Scoped evidence](../evidence/m17q-r1-journal-replay-2026-09-05/README.md) retains the comparison against the preceding production staging implementation, exact source revisions, restored unit/runtime checks and removed-retained-candidate / removed-counter-sequence controls. The comparison exercises three consecutive slots in each authority mode with local query grants and recovery after every slot. Following the staging refactor, production and replay deliberately share transition code; their agreement is regression evidence, not independent implementation evidence or a refinement proof.

### 2026-09-05 — prepared deltas and incremental backend component

Production staging now validates borrowed typed transitions and projects exact logical byte growth before mutating a staged snapshot. The test-only schema-7 journal backend uses a cached byte count, bounds delta serialization, commits record and anchor, then applies memory changes. Six integration tests cover three-slot parity in both modes, local grant expiry fences, recovery, uncertain-write quarantine and cached SCALE sizes through 65 slots; transition record lengths remain equal between the first and 65th positions in the fixture. The exact revision passes 59 QUV tests (one existing ignored), 20 runtime tests and CLI compilation. Removed-retained-candidate and removed-counter-sequence controls fail by assertion and are restored. Production still uses schema-6 full snapshots; the journal-directory format switch and its production recovery qualification remain required. [Scoped evidence](../evidence/m17q-r1-journal-replay-2026-09-05/README.md) does not close a whole R1 finding, prove complete refinement or admit R2/M17Q/M18Q.

### 2026-09-05 — schema-7 scoped process qualification

The production journal revision passes 60 QUV tests (plus its separately executed 256-sample durability benchmark), 20 runtime tests, CLI compilation and a syscall-order ancestry check. The fresh three-slot process campaign passes unchanged-source checks: exact four-member participation for all three slots, restart before slot 3, unchanged terminal-parent replay and an unrelated same-executor effect during the wait. Strict evidence checkers pass; 13 completed operations and 17 final releases have maximum observed active hold 6,369,893 microseconds against the fixture's 10-second limit. [Retained evidence](../evidence/m17q-r1-journal-production-2026-09-05/README.md) is finite scoped qualification, not a rooted aggregate resource/service bound, full refinement, clean R2, independent review or whole R1 closure.


### Finite representation and record accounting (schema 9)

**Assumes:** exact v4 policy/bootstrap enrollment; positive nonwrapping Fixed
slot horizon H and preparation cap A; at most two distinct retained candidates
per slot; no reuse of a retired slot or preparation counter; encoded transition
records bounded by B = 8192 bytes; authenticated replay and nonrollback custody.
`QuvLifetimeBudgetProof.tla` discharges the abstract event-count induction
`charged <= H*(A+3)*B`. Removing event uniqueness yields the required
`ChargedRecordBytes` counterexample. Handoff's one-shot two-insertion budget is
accounted separately at production enrollment. Bootstrap and one pending
record's headroom are added before journal creation.

`QuvConflictSummaryProof.tla` proves the projection of an arbitrary distinct
logical history to its first two entries preserves owned uniformity and unowned
first selection. A two-entry summary can therefore validly disclose conflict
without containing the current request's candidate. A singleton cannot do so.
Neither theorem establishes the complete runtime-to-model transition bridge,
physical allocation, fair service, recovery latency or cross-configuration
retention. Q-A3/Q-A5/Q-A9 remain unqualified for that integrated profile; all
whole R1 findings remain open. These results do not change M12a, confer live
authority on retained bytes, or count refusal as inclusion or externalization.


PQ durable-admission follow-up: the unchanged 16 MiB record plaintext limit is
now shared with outbox insertion and recovery validation, before hashing or
cloning unsendable entries. Exact-fit/oversized/non-mutation/reopen coverage and
20 channel plus 6 record-layer checks pass. Evidence:
`../evidence/m17q-r1-outbox-plaintext-2026-09-05/`. This preserves the sendable
payload domain; aggregate encoded/physical outbox capacity, bounded recovery
allocation and incremental persistence/service remain open. No whole finding
or release gate is closed by this boundary repair.


Streaming outbox recovery now checks the v2 scope before allocating entries,
uses a fixed reader and an existing-limit per-entry decoder budget, and refuses
truncated/trailing state without changing it. The allocation probe includes a
removed-budget control. Evidence: `../evidence/m17q-r1-outbox-recovery-2026-09-05/`.
This removes the full-file input buffer but does not bound aggregate decoded
state, reserve physical resources or complete recovery/service refinement.


Rooted outbox account scope now comes from the validated old/staged membership,
independently of carrier discovery. Enqueue/enrollment refuse undeclared accounts;
streaming recovery checks recipient scope before payload allocation and bounds
entry count by the declared set and existing per-recipient cap. Evidence:
`../evidence/m17q-r1-rooted-outbox-2026-09-05/`. Root declaration remains the local
membership-validation boundary, not a new authority or honest-member selector.
This finite count does not reserve physical bytes or bound service/rewrite costs.
Full refinement and every whole R1 finding remain open.


Indexed outbox follow-up: production now stores immutable entry files behind an
atomic ordered queue index (`AFTPQI03`, logical v2 entries). Payload durability
precedes index replacement; retirement follows it. Validated startup recovery
cleans orphans and completes v2 conversion before live admission. The nine-obligation
abstract ordering proof, 79-state model, required ordering mutations, commit/crash
regressions and ancestry syscall check are retained in
`../evidence/m17q-r1-indexed-outbox-2026-09-05/`. This improves payload I/O but does
not establish aggregate physical reservations, complete service bounds, Rust
refinement, independent acceptance or any whole finding closure. Message hashes
are not custody MACs, and the queue never authorizes another executor.


The current v5-outbox-budget root binds normal and QUV count/byte ceilings.
One request and one reply lane per recipient share a separate 32 KiB budget;
each QUV frame is at most 16 KiB and normal pending payloads total at most
16 MiB. Live admission, streaming recovery and record framing enforce the profile.
The 17-obligation reserve proof and shared-budget countermodel establish only
logical byte capacity. Source-bound checks are retained in
`../evidence/m17q-r1-quv-byte-profile-2026-09-05/`. Physical reservation, complete
service/rate bounds and transition refinement remain unqualified. Old v4 roots
are not equivalent and old process evidence does not qualify this increment.
No whole finding, clean R2, review or M18Q claim is admitted by these results.

The R1 AFTPQI04 index reservation does not discharge the physical-resource
antecedents of Q-A3/Q-A5/Q-A9. Its conditional primitive model proves two-index
allocation retention and active-image recovery, including either pre-directory-
sync crash outcome. Assumes remain atomic exchange, honored fsync/nonrollback
storage, retained payloads until the directory commit, and separately established
aggregate service/resource bounds. The paired EarlyExchange and TruncateInactive
countermodels remove the corresponding load-bearing rules. No logical QUV
acceptance, reachability, lifetime or portable-receipt premise changes.

The arena adds a four-slot numerical capacity kernel and an exhaustive finite
slot model, with three-slot and retained-slot-overwrite lower-bound pairings.
Assumes for the production theorem still include the rooted two-lane limit,
atomic/durable index selection, no reuse of slots referenced by the old index,
and the complete physical metadata/memory/service profile. A normal-payload
capacity refusal preserves only the already committed queue, after durable
cleanup; it is not transaction inclusion, ordering progress or effect liveness.
These sub-results do not discharge the remaining Q-A3/Q-A5/Q-A9 antecedents.

The member record-data refinement adds the conditional QuvRecordReservation
kernel paired with live-truncation and acknowledged-record-forgetting mutations.
Assumes remain complete startup allocation before admission, successful durable
record publication before independent anchor/reply, nonrollback custody and
retained conflict knowledge. Its arbitrary slot set is supplied by the rooted
finite-lifetime event bound; no slot reuse or horizon reset was introduced.
Reported data-block charges do not discharge filesystem metadata, anchor,
handoff/consequence, RAM or worst-case service antecedents of Q-A3/Q-A5/Q-A9.


Reserved-anchor composition adds `QuvAnchoredReservationProof.tla` and its
early-anchor/early-reply lower-bound pairings. **Assumes:** complete authenticated
semantic replay, exclusive nonrollback custody, durable record/file/directory
sync and atomic exchange on the admitted storage platform. Recovery restores
retained state and never a process-local grant. The 10-obligation kernel and
production boundary/issued-syscall checks in
`../evidence/m17q-r1-anchor-reservation-2026-09-06/` are conditional sub-evidence;
Q-A3/Q-A5/Q-A9 metadata, handoff/consequence, RAM and service antecedents and
complete admission/head/continuation/handoff/T10 refinement remain unqualified.


Handoff continuation follow-up: the install path rechecks its process-local
grant after exact payload validation, hashing and serialization, immediately
before beginning durable persistence. Equality is live; later time refuses
without disk/memory mutation. Authenticated recovery additionally enforces the
one-shot reachable state shape (generation 0/uninstalled/zero predecessor or
generation 1/installed/nonzero predecessor). Matching MACs alone do not prove
transition reachability. `QuvInstallContinuationProof.tla` supplies a conditional
10-obligation, 145-state install/clock/crash/recovery kernel; own exact-root live
QUV and authenticated durable recovery are antecedents, not discharged by the
kernel. Evidence and outcome-based negative controls are retained at
`../evidence/m17q-r1-handoff-final-fence-2026-09-06/`. Complete refinement and
Q-A3/Q-A5/Q-A9 resource/service qualification remain OPEN.


Handoff reservation maps the conditional file/anchor ordering kernels to one
exact prepared install; its capacity check precedes continuation consumption.
**Assumes:** runtime-validated exact envelope before preparation, same-identity
exclusive custody, full authenticated recovery and honored durable allocation,
rename/exchange and sync primitives. The source-bound 84-core/21-runtime and
syscall checks are in `../evidence/m17q-r1-handoff-reservation-2026-09-06/`.
They do not discharge metadata/RAM/consequence, cross-root retention or aggregate
service/recovery antecedents, or full production transition refinement.


Consequence resource follow-up: `ConsequenceTraceLifetimeProof.tla` establishes
at most 4+M trace entries under durable nonrollback lookup reservation and at
most one entry per lookup. Its ReuseLookup countermodel violates that bound.
Additional arithmetic charges for canonical ML-DSA-44 endpoint evidence and
receipt fields are conditional on the stated serializer/type bounds. The typed
receipt-charge lemma requires the already-proved TypeOK invariant; an initial
untyped failed obligation is retained in evidence. Source, tests and restored
negative controls: `../evidence/m17q-r1-consequence-trace-bound-2026-09-06/`.
No encoded-byte result discharges physical storage, heap allocation, fair service,
aggregate lifetime/recovery or full transition-refinement antecedents of
Q-A3/Q-A5/Q-A9. No whole finding or M16Q/M17Q/M18Q admission follows.

Endpoint data reservation does not alter QUV's authority premises. The named
Linux endpoint's allocation and publication ordering is now checked, but atomic
filesystem semantics, nonrollback custody, metadata/service feasibility and
end-to-end timing remain explicit assumptions/undischarged profile obligations.
The one-key mapping to ReservationSafety is conditional as documented in the
end-to-end theorem file; no whole finding is closed.

AFTCR001 receipt storage adds an explicit conditional two-file durability and
allocated-byte primitive. It does not change authority or admit a timing claim.
The end-to-end file records its filesystem, initialization, custody and capacity
antecedents; all remain distinct from the full Q-A3/Q-A5/Q-A9 profile obligation.

The manifest locator fold is conditional derived-state refinement, not QUV
authority. Its source stability, serialized commit/update and complete rebuild
antecedents are explicit in the end-to-end theorem file. Q-A3/Q-A5/Q-A9 aggregate
resource/recovery/service and full transition obligations remain unqualified.

### Effect preparation guard (2026-09-06)

Both executor entry points compare exact manifest binding and run rooted
signature, membership, policy and expected-head preflight before per-effect
allocation. Authorized/Claimed retries require preflight; non-executable
readmission skips it but still rederives committed authorization. Preparation
creates no live grant. Global lock files may precede this guard.

`QuvEffectPreparationProof` proves a conditional guard kernel: nine TLAPS
obligations and 25 states pass. **Assumes:** correct committed admission and
rooted validator predicates, exclusive nonrollback custody, and OwnLive denotes
the executor's own successful exact-root QUV. Complete transition composition
and physical/fair service bounds remain open. SkipBinding/SkipPreflight violate
PreparationChecked; PreparedBearer violates GrantIsOwn.

Evidence: `evidence/m17q-r1-effect-preflight-2026-09-06/` (selected worktree
source, not immutable qualification). 31 consequence, 15 runtime-finality,
21 QUV runtime and two executor tests, CLI compile, formatting and formal checks
pass. Three production omission controls fail as intended; source is restored.
The new sole-correct-placement process negative requires the precise signature
refusal and unchanged per-effect bytes before valid execution; compiled only.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED.

### Continuation admission ownership (2026-09-06)

The runtime completion channel carries a non-cloneable admitted continuation.
Its admission share survives delivery, post-query committed revalidation and
the synchronous T10 consequence call or durable successor install. A cancelled
observer cannot release a started blocking worker's share. Undeliverable or
unused continuations release ownership when dropped. Only the own-live core
grant authorizes execution; the admission wrapper supplies no authority.

`QuvContinuationAdmissionProof` proves the conditional ownership kernel (nine
TLAPS obligations, eight states). Early delivery release and worker-observation
cancellation countermodels violate Ownership. **Assumes:** every relying call
keeps the wrapper through its synchronous transition and every started worker
owns it until return/unwind. Mapping: completion send is Deliver, consuming
callback is Start/Finish, failed delivery is CancelDelivery, dropped join handle
is CancelObservation. This is not a fairness or worst-case service proof;
pre-allocation admission and aggregate physical bounds still need integration.

Scoped evidence: `evidence/m17q-r1-continuation-admission-2026-09-06/`. Fifteen
runtime-finality, 22 QUV runtime and two executor tests, CLI compile, formatting,
syntax and formal checks pass. The early-release production control fails as
intended; original source is restored. Process campaign is running; it has not
been claimed passing. All whole findings remain OPEN; no clean R2 or M18Q
admission.

### Receipt leaf custody guards (2026-09-06)

Directory-entry absence now uses symlink_metadata: dangling active links and
metadata errors cannot become fresh authorization. On Unix, initial receipt
staging and the consequence lock use the existing no-follow, regular-file,
single-link guard before truncation or locking. Existing generic non-Unix
adapters remain outside the Linux reserved profile.

**Assumes:** exclusive nonrollback custody of the store and its parent namespace;
ordinary Unix no-follow/open/lock semantics. These leaf checks do not establish
parent-directory custody, adversarial namespace race protection, aggregate
physical resources, or full transition refinement. Invalid active state maps
to refusal, never the Absent case of QuvEffectPreparation. The existing reserved
receipt proof's private-file antecedent remains conditional on these OS/custody
assumptions. No stored bytes create live authority.

Evidence: `evidence/m17q-r1-receipt-custody-2026-09-06/with-lock/`. Thirty-three
consequence, 15 runtime-finality, 22 QUV runtime and two executor tests, CLI
compile, formatting, formal guard checks and receipt syscall controls pass.
Original failing dangling-active/lock-alias regressions are retained. Removing
existence, staging, or lock validation produces the expected test failure;
original source is restored. Previous process evidence predates this change.
All whole findings remain OPEN; R2 unqualified; M18Q NOT_ADMITTED.


2026-09-06 queued preparation update: executable effect and handoff allocation
now runs under operation admission, with store release before waiting and
committed admission rederivation afterward. Conditional proof, deadline/ownership
regression and inspection-write negative evidence are indexed in
`evidence/m17q-r1-queued-preparation-2026-09-06/`. See the specification's Queued
preparation refinement Assumes and limitations. Terminal/reconciliation fairness,
aggregate resource/retention bounds and complete refinement remain outstanding.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED. This supersedes no prior failed evidence or immutable-source
requirements.


2026-09-06 terminal readmission: final outcomes skip receipt-pair preparation
while retaining committed validation and exact resource lookup; ambiguous states
retain preparation for reconciliation. Scoped tests, the extended preparation
proof/countermodel and restored production omission are retained in
`evidence/m17q-r1-terminal-readonly-2026-09-06/`. See the protocol/end-to-end
Assumes and limitations. The mandatory reservation-test namespace is corrected.
No whole finding closure, R2 qualification, M17Q acceptance or M18Q admission.


2026-09-06 receipt admission/profile v7: both executor entries serialize initial,
terminal and live-owner receipt access through bounded FIFO admission, release
storage before operation/network waits, and rederive after queueing. Protected
owner capacity is separate from current and historical result waiters. Queue
coefficients enter policy-root v7; current schema formats are unchanged and old
provisioning roots cannot silently migrate. Conditional mapping, service debt
and exact root vector are in the protocol/end-to-end specification. Evidence:
`evidence/m17q-r1-receipt-admission-2026-09-06/`; collector status is authoritative.
All whole findings remain OPEN and M15Q-M18Q remain unadmitted.


Post-query model extension: QuvQueuedEffectPreparation now exposes receipt
reopening and finality-lock acquisition separately, allowing context changes
while the receipt lock is held before finality is acquired. Nine obligations and
four countermodels pass, including removed final revalidation producing an
unauthorized-call trace. Evidence: receipt-admission campaign's
`post-query-model/`. Production Rust is unchanged from the passing pressure run;
this later formal/harness source is separately bound. Validation, custody,
continuation timing and full service/refinement antecedents remain conditional.


2026-09-06 candidate decode boundary: the public effect entry uses
`decode_quv_candidate`, which checks the existing rooted 4096-byte cap before
canonical SCALE decoding. Exact-fit input parses; oversized canonical and
undecodable inputs return the capacity error; empty input retains codec refusal.
Parsing grants no authority. Removing the pre-decode guard fails the existing
mandatory capacity regression, and exact source is restored. Evidence:
`evidence/m17q-r1-candidate-decode-2026-09-06/` (one capacity regression, two
executor regressions, CLI compilation, format and syntax pass on unchanged
selected sources). The earlier pressure process predates this production change.

Proof obligation: this establishes the input-length antecedent at this decoder
entry; it does not establish SCALE heap/allocation amplification, already decoded
protobuf storage, total in-flight requests, authentication service, or the full
resource/transition refinement. Those antecedents remain OPEN under Q-A3/Q-A9.
The policy-root value is unchanged because the capacity was already rooted.
All whole findings remain OPEN; no clean R2, independent acceptance or M18Q
admission follows.

Registry identity preservation pairs the v2 identity guard with a substituted-ID
production omission control and RegistryUnique countermodel; the schema guard is
paired with an unindexed-state omission control. Assumes authenticated committed
state, exclusive namespace ownership, complete bootstrap and atomic transaction
commit/discard. These are conditional admission/locator refinements, not discharge
of Q-A3/Q-A5/Q-A9. See `evidence/m17q-r1-registry-identity-2026-09-06/`.

The registry bootstrap negative pairing now includes an actual backing-scan error
hidden by the former overlay iterator. The preserved failing regression and
QuvRegistryBootstrapHiddenError countermodel show why absence must be distinguished
from failed observation. The repaired guard remains conditional on accurate
backing storage and exclusive transaction custody. Q-A3/Q-A5/Q-A9 remain open.
Evidence: `evidence/m17q-r1-overlay-scan-2026-09-06/`.
