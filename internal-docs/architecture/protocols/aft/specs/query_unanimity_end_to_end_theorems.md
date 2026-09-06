# QUV ordering, recovery, and consequence lift

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is [the R1 fault/property matrix](query_unanimity_fault_property_matrix.md); no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

Status: M14Q local theorem candidate; not production admission or portable
finality. M17Q independent review remains required.

Date: 2026-09-03.

## 1. Additional assumptions

The M13Q assumptions remain visible. The lift adds:

| ID | Assumption | Purpose |
|---|---|---|
| Q-EA1 | Every ordered candidate binds its rooted configuration, independently provisioned policy root (including authority, timing, preparation budget and the typed initial bootstrap rule), domain, slot number, exact predecessor candidate hash, authority mode, and payload/manifest hash | prevents cross-history substitution and candidate-nominated authority |
| Q-EA2 | A correct runtime appends only the unique M13Q-accepted candidate for its next slot and durably commits the candidate, predecessor, and new head before exposing it | prefix and restart safety |
| Q-EA3 | Correct recovery begins from that durable head, never truncates or rewrites it, and replays no effect mutation from chain state alone | crash safety |
| Q-EA4 | Every irreversible executor performs its own QUV operation against the active rooted membership immediately before entering T10's durable `Claimed` state; after the online wait it re-derives authorization from currently committed admission, keeps that admission and execution height stable through claim/call, and validates the process-local continuation immediately before claim and any resumed call | consequence authorization |
| Q-EA5 | `EffectManifestV1` derives one stable idempotency key from the rooted conflict domain and slot, not from the candidate payload, and commits the exact atomic-resource profile | same-conflict deduplication |
| Q-EA6 | The external resource and executor satisfy T10's atomic idempotency-register and claim-before-call assumptions | at-most-once physical mutation |
| Q-EA7 | Reconfiguration is a typed handoff candidate under the old root that binds the exact old-root boundary block, state root, and authenticated ordering QC; before old-root expiry, every correct new member performs QUV against every old correct member within the old rooted bound, independently verifies that QC under the old root, and durably installs the accepted predecessor/state root before activating | live ordering and handoff continuity |
| Q-EA8 | A client joining after the old authority is no longer reachable receives the current root through an independently provisioned trust channel; historical bytes alone do not establish currentness | honest bootstrap boundary |

Q-EA7 is intentionally stronger than carrying a signed handoff transcript. A
transcript is bytes and cannot preserve QUV's online timing fact. If no correct
new member completes the live handoff before expiry, the new configuration does
not activate under this theorem.

The embedded boundary QC is replayable ordering evidence, not transition
authority. Every correct old member independently verifies the source QC under the old
root and matches it to its exact local executed boundary; a previously cached
aggregate QC is not required. A
successor uses the QC to seed parent continuity only after its own live QUV
operation succeeds; possession of the QC or handoff bytes alone never enables
the successor identity.

## 2. Theorems

### Q-E1: prefix-compatible accepted ordering

**Assumes:** Q-T1, Q-EA1 through Q-EA3, a fixed conflict domain, and correct
runtime admission.

Any two correct durable histories are prefix compatible. At each common slot,
both histories contain an M13Q-accepted candidate; Q-T1 makes those candidates
equal. Q-EA1/Q-EA2 prevent gaps and bind every append to the exact prior head.
Induction over the shorter history proves prefix compatibility. A restarted
runtime resumes from the same durable prefix by Q-EA3.

Mechanized as `QHistoryPrefixCompatibility` in
`QueryUnanimityCompositionProof.tla`, parameterized over arbitrary history and
candidate sets.

This conditional lift does not implement Q-EA2's accepted-head discovery or
advancement. In particular, fresh parent re-verification can abort after later
owner equivocation; Q-T4's singleton premise then does not apply. See
`query_unanimity_head_state_design.md` and its executable claim-boundary model.
The production expected-head/next-slot and transition-refinement gates remain
open; no assumption or liveness guarantee is added by this observation.

### Q-E2: accepted-consequence non-conflict

**Assumes:** Q-T1/Q-T2, Q-EA1, Q-EA4, and exact manifest validation.

Two mutation candidates admitted for the same rooted domain/slot are equal.
Every mutation candidate comes from an executor's own online QUV acceptance;
Q-T1 excludes two different accepted candidates. The executor may record
`Abort`, ambiguity, or attributable owner equivocation, but those records do
not authorize another mutation candidate.

Mechanized as `QConsequenceCandidateNonConflict` in the composition proof.

### Q-E3: at-most-once physical externalization

**Assumes:** Q-E2 and Q-EA4 through Q-EA6.

The rooted conflict-domain slot causes at most one modeled external-resource
mutation. Q-E2 gives one candidate class; Q-EA5 gives every duplicate delivery
the same stable resource key; T10's atomic put-if-absent/CAS register admits one
record and its claim-before-call recovery machine never blindly reinvokes after
ambiguity. The result composes QUV authorization with T10—it does not infer
endpoint semantics from consensus.

### Q-E4: live reconfiguration continuity

**Assumes:** Q-T1 through Q-T4, Q-EA1 through Q-EA3, Q-EA7, and at least one
correct member in both rooted configurations.

No two correct new members activate conflicting handoff roots. Each new
correct member is an honest relying verifier of the old configuration; Q-EA7
places every old-correct snapshot in each operation, so Q-T1 permits at most
one accepted handoff candidate. Q-EA2 durably installs that same predecessor
before activation. With one valid handoff and no conflict, Q-T4 completes each
new-correct operation within the old bound. A conflict may fail closed and
prevent reconfiguration; it cannot create a second lineage.

This is live-overlap handoff, not portable long-range verification. Q-EA8 is
mandatory for later bootstrap.

## 3. Composition boundaries

The admitted `EffectManifestV1` separates two predecessor meanings.
`predecessor_root` commits the external resource's authorized prior state;
`online_authorization_predecessor` commits the prior accepted QUV candidate
or independently rooted initial QUV predecessor. Neither substitutes for the
other. The manifest also explicitly commits
`online_authorization_authority_mode`. Both online fields are required for
QUV (with a nonzero predecessor) and forbidden for portable authorization.
Absent online fields remain omitted when portable manifests are serialized.

The live continuation and its non-authorizing audit bind this QUV predecessor
and authority mode, and both production effect entry points compare them to
the currently admitted manifest before the member interaction. Final claim
validation repeats the exact consumed-binding comparison. An admitted field
binding alone does not derive a durable expected head or prove next-slot
advancement: R1 finding 001 remains open on that separate enforcement and
refinement requirement. Old QUV manifests/audits missing the new binding fields
are not automatically promoted into authority.

- Q-E3's stable key is now also enforced below the QUV membership argument:
  the consequence store's claim index refuses a second effect for the same
  `(domain, slot)` key before its durable Claim even when the two manifests
  name distinct `resource_id` values, so distinct conflict-domain effects that
  the theorem says conflict cannot both mutate external state through one
  store. The index authorizes nothing and never replaces the executor's own
  live operation.
- Online acceptance is not convertible into a portable final receipt.
- An old configuration must remain reachable through every correct new
  member's handoff operation; expiry cannot be inferred from silence.
- QUV supplies accepted-value non-conflict, not global payload availability.
  Q-EA7 therefore requires the complete state/predecessor payload be installed
  durably by each correct new member before activation.
- Query-flood admission capacity, disk flush latency, clock error, and external
  endpoint latency must be measured against the rooted bounds in M16Q.
- The current executor retains the runtime-finality lock while revalidating
  committed admission and completing the synchronous claim/call path. Durable
  receipt writes and endpoint invocation therefore extend that critical
  section. Their effect on ordering and correct-member scheduling is an
  unqualified R2 cost, not an established timing guarantee.
- A later conflict can make re-verification reject even though an earlier
  candidate was validly accepted and executed. The durable executor record is
  audit evidence; it is not an offline finality certificate.

## 4. Mechanization and pairing

`QueryUnanimityCompositionProof.tla` lifts M13Q accepted uniqueness into
arbitrary-set history prefix compatibility and non-conflicting mutation
candidates. T10's existing `AtMostOnceExternalization.tla` supplies physical
deduplication and crash-to-lookup recovery. M12a remains the matching lower
bound for portable authorization; L-X remains the matching lower bound for
at-most-once mutation after ambiguous endpoint responses.

These are conditional lifting lemmas: they assume accepted histories and
mutation candidates satisfy the abstraction's premises. They do not mechanize
production admission, expected-head advancement, state authentication,
continuation consumption, or the implementation's lock and recovery
transitions. R1 finding `QUV-M17Q-005` reopens that transition-level refinement
obligation; earlier discharged set-theoretic obligations do not close it.

`QueryUnanimityCompositionProof.tla` is a conditional accepted-set lifting lemma: it assumes accepted-value uniqueness, accepted histories and accepted mutation candidates as premises and lifts them pointwise; it has no state or transition for admission, heads, recovery, continuation, handoff or the external register. `formal/maximal_visibility/QuvEndToEndRefinement.tla` is the transition-level composition witness that R1 finding QUV-M17Q-005 required: a finite explicit-state TLC model whose transitions include expected-predecessor admission with typed refusal, two-phase authenticated record/anchor durability with crash recovery, timed executor operations with the rooted cutoff, own-head advancement, process-local continuation expiry and height fence, T10 claim-before-call externalization on the stable key, and successor activation only through the successor's own live operation. Its positive instances (owned, unowned, sole correct member, handoff, two domains) preserve `NoConflictingAccepts`, `OneCanonicalConflictIdentity`, `NoClaimWithoutOwnLiveAccept`, `NoClaimAfterExpiryOrFence`, `AtMostOneExternalMutationPerStableKey`, `NoBlindReplayAfterCrash`, `RecoveryNeverAdvancesBeyondAuthenticatedRecords` and `NoSuccessorAuthorityFromBytes`, and `QuvEndToEndRefinementReachable.cfg` exhibits an accepted-and-executed two-slot trace with one correct member. Its registered mutations each break the named invariant: `PredecessorInKey` and `LateReplyAdmitted` break `NoConflictingAccepts`; `SkipExecutorQuv` breaks `NoClaimWithoutOwnLiveAccept`; `ClaimAfterExpiry` breaks `NoClaimAfterExpiryOrFence`; `CallBeforeClaim` breaks `NoBlindReplayAfterCrash` (the physical mutation count is protected by the T10 register, not by claim order); `ResourceIdSplitsKey` breaks `AtMostOneExternalMutationPerStableKey`; `UnauthenticatedRecovery` breaks `RecoveryNeverAdvancesBeyondAuthenticatedRecords`; `ActivateFromBytes` breaks `NoSuccessorAuthorityFromBytes`. This is bounded design evidence under the assumptions recorded in `evidence/m17q-r2-end-to-end-refinement-2026-09-06/README.md`; it is not a mechanized refinement of the implementation, and the implementation-refinement half of QUV-M17Q-005 remains open.

**Assumes (composed transition model):** This is a finite explicit-state transition model over an abstraction of the production state machine, not a mechanized refinement of the Rust implementation. It assumes atomic durable writes at record, anchor, head, claim and gate granularity; MAC unforgeability (an unauthenticated record is exactly the torn-write case, never a forged one); ideal model time (the rooted cutoff is a single shared clock, and Q-A3 is a constraint on that clock rather than a measured envelope); static faults with silent Byzantine members; direct executor reachability of every configured member; and a faithful T10 register (atomic put-if-absent on the idempotency key the call carries). Executors are identified with correct relying members; nonce freshness is abstracted as exact-context-plus-start binding; the admitted manifest chain is fixed; heads are root-independent across handoff; retention, retirement, capacity, scheduling and the runtime-finality lock are outside the model. It establishes that, under those assumptions and within the bounded instances listed here, the composed transitions preserve the named invariants and that each named mutation is sufficient to break the named invariant. It does not establish Q-A3, Q-A9, portable authority, liveness beyond the single reachability witness, or that `crates/consensus/src/aft/query_unanimity*` or `crates/validator/.../quv.rs` refine these transitions.

Local claim-boundary regressions and their limits are retained in
`../evidence/m17q-r1-local-remediation-2026-09-04/README.md`. Expired-height and
expired-continuation tests require typed refusal and zero resource mutation;
the store-level Claimed restart test includes a live positive case. The retry
now uses public admission and binding APIs: current committed authorization
must match the first trace entry, while `Claimed` still requires a fresh live
continuation before a resumed call. Changed admission is refused without
rewriting the receipt. Evidence is retained in
`../evidence/m17q-r1-claimed-readmission-2026-09-04/README.md`. Production
process qualification and exact-candidate independent review remain required.

M15Q may begin only after the composition proof, theorem-assumption discipline,
claim discipline, and architecture-document gates pass. Production must use a
new named profile and may not relabel the existing hash-async or terminal-seal
paths.

### Retry implementation evidence (R1 remediation; not refinement closure)

The production retry path distinguishes fresh effect authorization from reporting
an existing result. It rederives committed admission and candidate binding before
return/reconciliation. A terminal return includes a current resource lookup and
keeps the original nonportable audit. Unknown/InFlight reconciliation performs
lookup, never another mutation call. This preserves the requirement that every
new irreversible invocation has its executor's live QUV continuation; reporting
an earlier result grants no invocation authority. The additional lookup and
admission costs are part of retry latency. Expired-fence retrieval, fairness and
transition-level refinement remain unproved/unqualified. Conditional lifting
lemmas must not be cited as proof of these production transitions.

Reconciliation attempt accounting now has a finite component model under atomic
non-rollback reservation. Each lookup incurs an additional durable receipt write
before the resource read. This model does not extend the conditional composition
lemmas to production filesystem refinement or establish request fairness. Lost
reservations after a pre-lookup crash reduce availability and do not count as
successful reconciliation or effect liveness.

Result retrieval after upper-fence expiry is implemented separately from new
externalization: only an existing non-executable receipt, independently matched
to current committed admission, may use the result/lookup path. The strict
live-fence requirement remains on every new claim/call and resumable Claimed
operation. This separation grants no authority from stored audit bytes and is
not yet a transition-refinement or full process-qualification result.

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

Local accepted-history recovery now rejects a state whose accepted entry lacks
its exact retained candidate snapshot, before anchor reconciliation. This is an
additional implementation check for the existing retained-knowledge Assumes
condition. It does not close the transition-refinement gap or establish child
readiness, aggregate service bounds, effect liveness or end-to-end admission.


### Durable preparation-attempt reservation — 2026-09-05

Schema-6 local attempt reservation implements one prerequisite for bounded
preparation: rooted budgets survive restart and uncertain anchor writes under
the existing non-rollback storage Assumes condition. Accepted advancement retires
the old count atomically; it does not assert other members' readiness. Runtime
worker enforcement, per-domain fairness, bounded total service and restart-delay
refinement remain required. No end-to-end liveness claim follows from finite
retry exhaustion or from this local primitive's passing tests.


### Runtime preparation worker — 2026-09-05

Production now schedules independent preparation queries from local retained
snapshots through the existing own-query accepted-head path. This does not yet
establish CompleteCorrectProcessing for a child query: the relying executor still
needs the readiness condition from the timing model, and aggregate service and
restart bounds remain unproved/unqualified. No end-to-end progress disposition
changes on the strength of compilation or scheduling alone.


### Queued foreground/preparation admission — 2026-09-05

Foreground/preparation contention now queues locally with bounded waiting counts
and revalidation after waiting, rather than treating a busy process as a conflict
result. This repairs an observed admission behavior; it does not convert refusal
into progress or discharge service/readiness Assumes conditions. Effect admission,
height, expiry and immediate Claim checks remain independently required after any
queue delay. The new process result is pending.


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

The runtime cannot run its live decision or head transition while any configured
recipient lacks timely local dispatch completion. This closes a local cancellation
boundary between pending-operation insertion and completion of dispatch. It does
not discharge the Assumes condition that every correct member receives, durably
processes and replies within the complete rooted interval. Service deadlines,
readiness, restart and consequence composition remain separate obligations.


### Rooted active preparation service — 2026-09-05

Active preparation now has a rooted deadline and a non-extending process-local
grant cap. Dispatch cancellation cannot turn partial replies into acceptance;
completion at or after the active deadline cannot return a successful worker
result. An atomic head write already underway may complete late and is reported
as service failure, not rolled back or counted as timely progress.

The aggregate readiness Assumes condition still includes selection, queueing,
foreground service, retries, clock error and restart. This implementation does
not derive or qualify that bound, and adds no portable authority or end-to-end
liveness admission. Current-source process qualification is pending.


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


### Durable operation admission ownership on cancellation (2026-09-05)

The runtime now shares the operation's active admission permit with its blocking
preparation-reservation and accepted-head-commit closures. Cancelling or timing
out the async waiter cannot release admission while either already-started
closure still runs. The blocking share is released when that closure returns or
unwinds. The pending operation/finalizer retains its own share through normal
cleanup. This changes local scheduling ownership; it adds no new authorization
source and does not cancel, roll back or duplicate durable work.

All 15 QUV runtime tests passed. The new named regression blocks durable work,
cancels its async owner, requires the next foreground admission to remain pending,
then releases the work and requires admission to recover. Removing the closure's
permit retention makes that pending assertion fail; restored source passes.
Both production blocking boundaries use this checked helper. The M16Q runtime
phase now requires this exact test. Raw results and hashes are retained under
`evidence/m17q-r1-durable-admission-ownership-2026-09-05/`.

The store mutex already serialized writes, but that did not retain operation
admission after waiter cancellation. This repair closes that ownership gap, not
the elapsed-service bound: stalled blocking work correctly retains admission and
can still prevent progress. Rooted timing qualification must include actual
storage completion; a timeout/refusal cannot substitute for it. The repair does
not cover unrelated inbound member work or prove full storage/restart refinement.
Earlier process passes remain historical for their exact source hashes. Affected
process campaigns, full R2 and all whole R1 findings remain open.


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


### Post-commit node-state lock-order repair (2026-09-05)

Source inspection after the failed disjoint campaign found finalization holding
node_state from the Syncing-to-Synced update through its later engine/context
operations. Sync status handling owns the orchestration context and then locks
node_state. These paths permit opposite lock acquisition orders. The production
finalization helper now completes the short node-state update and releases that
mutex before polling the remaining continuation. The status update and existing
vote/configuration/admission checks remain in their original order.

The bounded two-task regression uses the production helper: a sync handler holds
context, finalization updates node state and waits for context, then the handler
must acquire node state and release context so finalization completes. It passes
for initially Syncing and Synced states. Retaining node state across the continuation
reproduces the blocked second acquisition; restored source passes. All 54 finalization
tests and the CLI aft_e2e compilation passed. M16Q now requires this exact regression
and hashes its implementation/test sources. Evidence is retained under
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/`.

This establishes and repairs a concrete component lock-order hazard. The retained
process logs do not conclusively identify it as the cause of validator-20400's
stall, and no claim of global deadlock freedom or full transition refinement is
made. The failed campaign remains failed. Current-source process requalification,
all aggregate timing/resource bounds, clean R2 and all whole R1 findings remain open.
The existing bounded-service assumption and nonportable authorization boundary
are unchanged; node synchronization status is not an authorization source.


### Post-commit lock repair disjoint campaign and formal gate (2026-09-05)

The repaired disjoint campaign passed (exit 0, unchanged recorded sources), and
both handoff and release-evidence checks passed. All four successors independently
accepted with exactly all four expected old-member replies; maximum valid-reply
observation was 922ms. All eight recorded completed operations had final release
records (nine releases total); maximum observed active release was 30,015,029
microseconds. These are finite observations under the recorded additional
consensus debug logging, not worst-case bounds.

The fixture observed post-handoff blocks from the installed successor set, recovered
a restarted successor from its durable local install gate, retrieved two further
blocks, and completed the subsequent live effect assertions. Block retrieval and
producer membership are the checked progress surfaces; they must not be amplified
into proof of fully admitted canonical history at every height. The prior failed
campaign remains retained, and the exact cause of its stall is not conclusively
attributed by this later pass.

The independent two-caller PostCommitLockOrder model is now in formal/concurrency.
Full formal and M16Q runners include its positive/fairness check and the required
retained-lock circular-wait witness. The focused --post-commit-lock-order-only
runner passed; the positive explores 17 states. This is component lock-order
reasoning, not full transition refinement or global deadlock freedom. Commands,
hashes and raw evidence remain in
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/`.

Overlapping-handoff qualification of the current repair remains outstanding, along
with aggregate readiness/resource bounds, complete mutation/refinement, clean R2
and closure of all whole R1 findings. No fixed assumption or authority boundary
changes.


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


### Schema-9 finite-profile disposition (2026-09-05)

The current production policy commits a finite slot horizon, first-two conflict
representation, candidate byte cap and encoded record/lifetime budgets.
Historical queries preserve retained conflict knowledge after the forward slot
horizon is exhausted. Enrollment rejects insufficient encoded lifetime headroom
before creating files. The abstract summary and lifetime proofs are mandatory
formal gates, including the event-reuse negative control.

This remains R1 remediation. Encoded accounting does not reserve physical disk
space or discharge transport/authentication, fair service, recovery duration,
cross-configuration retention or full transition refinement. The integrated
Q-A3/Q-A5/Q-A9 obligations are open. See the current journal specification and
single fault/property closure matrix. No whole finding, clean R2, independent
review or M18Q claim is admitted by these component results.


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

The AFTPQI04 implementation-to-primitive mapping is documented in the
verification specification's allocated queue-index section. It includes the
uncertain exchange-to-directory-sync interval; successful memory publication and
payload retirement follow directory durability. This is a conditional storage
sub-refinement, not the complete admission/head/recovery/continuation/handoff/T10
refinement. Assumes still require the full rooted transport, allocator, payload,
metadata, durable-write, recovery and consequence service profile. Reported
allocated blocks and syscall order alone do not establish those antecedents.

The payload sub-refinement maps protected old arena slots to the active index's
payload set and staged slots to uncommitted pending blobs. Arena fsync precedes
index exchange; retired bytes never supply recovery authority. The additional
PrecommitCapacityRefusal action preserves the index and removes only unreferenced
pending payloads. Assumes still require completed cleanup before continuing,
quarantine for other/uncertain failures, and the complete transport/storage/RAM/
service profile. Full admission/head/recovery/continuation/handoff/T10 refinement
and final-source process qualification remain open.

Production record persistence now maps an empty reserved inode to an authenticated
retained `.quv` record before anchor advancement and memory publication. Complete
semantic replay precedes resetting any unacknowledged pool file. The allocation/
retention kernel remains conditional on durable filesystem primitives; it does
not prove the full admission/head/recovery/continuation/handoff/T10 refinement.
Assumes still require a ready correct member for each live interval and explicit
qualification of startup/recovery wherever included in the service contract.
Fresh interaction after provisioning cannot be replaced by extending an expired
grant. Anchor/handoff/consequence allocation and the aggregate resource/service
profile remain open.


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

### Conditional endpoint reservation mapping (2026-09-06)

`QuvRecordReservationProof::ReservationSafety` also supplies the one-key storage
kernel for the named endpoint: Slots={key}; pool is the prepared staging inode;
Write is its bounded write and fsync; Publish is rename; AnchorAndReply is the
following directory sync and Inserted return. No independent anchor is added to
the endpoint contract. AuthenticatedRestart means accepting only the canonical,
key-matched ML-DSA record and resetting staging only when active is absent.
ForgetAcknowledged=FALSE depends on exclusive nonrollback endpoint custody;
TruncateLive=FALSE is checked in the live syscall window. A crash after rename
may leave a retained but unreported record, which is lookup evidence rather than
a new effect invocation. The T10 Claim-before-call theorem remains separately
required. This mapping is conditional on atomic filesystem publication, durable
synchronization, allocation semantics, custody, and sufficient pre-live capacity.
It does not prove full transition refinement, metadata/RAM bounds or synchrony.

### Conditional receipt replacement mapping (2026-09-06)

PqReservedIndexProof::ReservedIndexSafety is the two-file primitive used by
AFTCR001 receipt replacement: active/persistedActive are canonical names before
/after directory sync; valid means a complete, fsynced receipt envelope; BeginWrite
overwrites the spare; SyncImage completes fsync and envelope allocation checks;
Exchange is renameat2(EXCHANGE); SyncDirectory precedes every successful return.
EarlyExchange=FALSE and TruncateInactive=FALSE remain load-bearing. Initialization
of both files is before the executor's live operation. Recovery selects only the
canonical active name and validates its receipt; it never picks a newer spare.

Assumes: exclusive nonrollback store custody, atomic filesystem name exchange,
truthful durable synchronization/allocation accounting, sufficient pre-live
capacity, and filesystem behavior permitting overwrite of initialized blocks
without extra data allocation. The implementation checks each file's reported
allocation before/after writes. Filesystem inode/journal service and metadata
headroom are not discharged by this observation or conditional kernel. Full
admission/head/recovery/continuation/handoff/T10 transition refinement and the
global rooted resource/service proof remain mandatory.

### Policy v6 consequence storage charges (2026-09-06)

The policy-root domain is now ioi/aft/quv-policy/v6-consequence-storage. Its SCALE tuple appends the ordered twelve u64 fields of
QuvConsequenceStorageProfileV0: format version, audit ceiling/JSON expansion, PQ
evidence/record ceilings, base trace count/per-entry charge, fixed receipt charge,
header length, allocation unit, per-file physical factor and receipt file count.
Agentgres uses those same coefficients for audit, trace, endpoint, receipt and
physical-envelope checks. Old v5 roots do not match; no automatic custody or
configuration migration is introduced. The independent byte-construction fixture
in evidence/m17q-r1-consequence-profile-2026-09-06/policy_vector.py binds the new
root's wire encoding and the storage-field-removal negative.

The shared checked effect_allocated_bound is two reported receipt allocations
plus one endpoint record. It preserves every u32 observation budget and refuses
arithmetic overflow. It excludes inode/directory/journal costs and does not bound
the number of manifests/effects, predecode memory or time. No aggregate capacity
admission or fairness claim follows from rooting coefficients alone. These remain
Q-A3/Q-A5/Q-A9 and whole finding 006 obligations.

### Conditional committed-manifest locator refinement (2026-09-06)

QuvManifestLocatorProof::LocatorSafety proves the derived index fold and recovery
invariant (10 TLAPS obligations; 35-state positive model). Committed record IDs
map to independently verified manifest identities. A singleton maps to that exact
locator; duplicates map to ambiguity. Crash drops the transient index; recovery
folds durable records before the coordinator becomes observable. DropDuplicate
and TrustAfterCrash controls respectively violate IndexCorrect and ReadyComplete.

Production mapping: successful store.commit followed by remember_manifest_locator
is Admit under the existing coordinator mutex; open/rebuild is RecoverRecord and
FinishRecovery; dropping the process is Crash. Assumes include verified stable
committed source records, exclusive mutation/observer serialization and full
rebuild before use. Per-lookup selected-block/hash/root/identity rederivation is
a separate mandatory implementation check, tested with wrong-locator and corrupt
block controls. This is not complete admission/head/recovery/continuation/handoff/
T10 refinement and does not establish finite global history or memory/service.

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


### Queued preparation refinement (2026-09-06; scoped, not admission)

Executable effect requests now inspect committed receipt eligibility without
creating a receipt, release the consequence-store lock before bounded operation
admission, rederive committed admission after waiting, and prepare storage under
the acquired operation lease. Both executor entry points then dispatch a fresh
own live query under that same lease. Handoff capacity preparation likewise owns
the lease through its blocking worker. The in-process effect API consumes the
store so it can drop and reopen its exclusive lock across waits; repository
call-site inspection found no callers requiring migration.

**Assumes:** validated inspection predicates, committed-admission rederivation,
exclusive nonrollback store custody, the existing rooted admission implementation,
actual own live QUV before continuation delivery, and synchronous final
revalidation/Claim/call. QuvQueuedEffectPreparationProof establishes a conditional
phase/ownership safety kernel, with explicit phase-history strengthening; it
does not establish those predicates, OS worst-case service, or complete production
refinement. Inspection grants no authority. Preparation begins the existing
active-service interval; equality/late startup refuses without shortening QUV's
rooted decision interval. All timing and resource costs still require integrated
qualification.

The three countermodels remove no-write inspection, release-before-wait, or
queue-time revalidation. The production inspection-write control fails its
regression and restores the exact source. Reservation deadline before/equal/after
and permit lifetime pass. Evidence is collected under
`evidence/m17q-r1-queued-preparation-2026-09-06/`; initial noninductive proof failures
are retained. The scoped collector disposition is authoritative for its checks.
Terminal/reconciliation contention, aggregate admission/physical resources,
retention and full transition composition remain open. No whole R1 finding is
closed; M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED.


### Terminal readmission storage (2026-09-06; scoped)

After exact committed admission rederivation, Executed/Reconciled result
readmission skips receipt-pair allocation and reinitialization. It still performs
an exact current resource lookup. InFlight/Unknown retains preparation because
lookup reconciliation can durably change the receipt. No state is promoted to
executable and no terminal transcript authorizes an invocation.

**Assumes:** exact receipt-state/admission validation and the existing exclusive
nonrollback custody and resource contract. QuvEffectPreparation now distinguishes
validated preparation from storage preparation and proves TerminalReadOnly;
the removed rule produces its expected countermodel. The production regression
checks both file contents and active inode, expired retrieval and exact result;
restoring unconditional preparation fails that regression. Source is restored.
This does not bound lookup request rate, startup writes, global contention or
aggregate storage, and does not close terminal/reconciliation fairness.

Evidence: `evidence/m17q-r1-terminal-readonly-2026-09-06/`. All scoped checks pass
on the recorded selected dirty-worktree sources: 33 consequence, 15
runtime-finality, 23 QUV runtime, two executor tests, CLI compilation, format,
syntax, nine proof obligations, four countermodels and receipt syscall controls.
The M16Q reservation-test assertion was corrected to its actual quv::tests
namespace; the preceding campaign's assertion used admission::tests and would
have failed the full runner. Its scoped component passes never represented full
M16Q execution. R2 remains unqualified; all whole findings remain OPEN.


### Bounded consequence access and v7 roots (2026-09-06; remediation)

Both executor entries now acquire the same receipt-store FIFO before opening
storage. There is one active store owner, one waiting initial request per
enrolled committed domain, one shared historical-domain waiter, and one
protected waiter for the already-active QUV operation. Current admission and
domain identity are rederived after initial queueing. Store and receipt permits
are released before readiness/operation queueing or the live query. The same
active QUV lease survives both protected reopens and final Claim/call. Historical
readmission does not require a current candidate signature, head or live fence;
it still requires the exact committed manifest and stored result/reconciliation.

The policy-root separator is now `ioi/aft/quv-policy/v7-consequence-admission`.
The final SCALE tuple element is the pair of the existing thirteen storage u64
fields and `[1,1,1,1]` admission u64 fields (active, per-domain, historical,
active-operation). The live semaphores consume these exact constants. The
independent fixture root is
`5d93a2ea9a59eb1a306918647b4c8565e7a9656b15c32635666e48560b3ae58d`.
Schema-9 member data and AFTCR001 receipt envelopes are unchanged; old policy and
provisioning roots do not silently migrate. Earlier v6 evidence is historical.

**Assumes:** all production receipt-store access in these executor paths uses
this gate; independently opened stores remain subject to exclusive custody;
committed-domain rederivation is correct; synchronous holder work eventually
returns; semaphore FIFO and cancellation semantics hold. With N enrolled
domains, waiting capacity is N+2 plus one active holder. The receipt model maps
its worker to the protected active operation and its competing domains to the
N enrolled domains plus the shared historical slot. It checks two enrolled
domains plus history (630 states), cancellation, a finite predecessor count and
eventual admission under weak fairness. A non-FIFO countermodel violates the
predecessor bound. This finite model is not a general production timing proof.

A general service derivation still owes a bound S for non-owner inspection or
terminal/reconciliation holder work, including committed block reads, parsing,
authentication, receipt allocation, durable writes, resource lookup and lock
scheduling. Protected reopening can wait for up to N+2 non-owner completions;
both preparation and post-query reopen costs must fit the original rooted active
service and continuation intervals. Queue refusal and expiry do not prove
admitted-operation completion. Authentication/transport before this gate,
aggregate retained manifests, metadata/RAM and cross-configuration retention
remain outstanding. No hidden current-authority requirement is added to old
result retrieval, and no capacity refusal is claimed as inclusion or progress.

Evidence collection: `evidence/m17q-r1-receipt-admission-2026-09-06/`.
The source-bound collector disposition controls the scoped results. Development
compile failures and earlier unrooted queue controls are retained. Whole R1
findings remain OPEN; M16Q R2 unqualified; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


2026-09-06 v7 receipt pressure/restart outcome: the source-bound campaign in
`evidence/m17q-r1-receipt-admission-2026-09-06/pressure-process/` passes after
1068.80 seconds including release-node compilation and provisioning. Three
consecutive slots include exactly four expected correct members, with maximum
valid replies 394/646/495 ms against the unchanged 4000-ms envelope. An unrelated
same-executor effect completes while 120 exact parent-result replays run across
5773 ms; the child remains in its required readiness wait. Restart before slot
three preserves exact terminal recovery and the required positive child wait.
The strict checker passes with unchanged captured source hashes and complete
service-release evidence. A broader source archive, toolchain, command,
environment overrides and component hashes are retained. This is finite scoped
working-tree evidence, not clean R2 or a worst-case resource/service proof. All
whole R1 findings remain OPEN; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


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

Registry identity refinement extends QuvManifestLocator with
EnforceRegistryIdentity and RegistryUnique. With enforcement, Admit preserves at
most one committed record per effect ID (21-state model; 10 TLAPS obligations
including the existing index invariant). Disabling enforcement violates
RegistryUnique; existing duplicate-index and early-recovery controls remain.
**Assumes:** authenticated committed source state, exclusive registry namespace,
complete v2 bootstrap, atomic workload transaction commit/discard, and current
record revalidation. The mv_memory stale-write regression passes on retry after
a preserved ENOSPC compiler failure; it does not alone discharge transactional
crash refinement. Missing legacy indexes are refused, not silently reconstructed.
Evidence: `evidence/m17q-r1-registry-identity-2026-09-06/`. Global resource/service,
safe migration and full transition composition remain open.

QuvRegistryBootstrapProof discharges the scan-to-bootstrap guard: nine TLAPS
obligations, nine positive states and the hidden-error countermodel. Production
mapping is MergingIterator error propagation followed by require_registry_schema;
the service/overlay regression reproduces refusal without writes and successful
readable bootstrap. **Assumes:** truthful backing scans, exclusive namespace
custody and transactional commit/discard. This does not establish backing-store
crash consistency or full transition refinement. Evidence:
`evidence/m17q-r1-overlay-scan-2026-09-06/`.
