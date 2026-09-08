# AFT-CB P4.4 — Claim Adjudication

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is [the R1 fault/property matrix](query_unanimity_fault_property_matrix.md); no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

> **STATUS SUPERSESSION (2026-08-18, at `59294c96c`).** The yellow-paper
> v2 rewrite this document required is COMPLETE and merged (#333,
> `59294c96c`), including the owner-directed maximality presentation
> recorded below; R4c is merged (#318), so Q4 is killed at both layers.
> References below to the rewrite as "remaining editorial work" are
> historical — the merged manuscript IS the adjudicated final version,
> and this adjudication continues to bind it (the flagship rungs remain
> blocked and machine-gated).

This document adjudicates exactly which claim the program may print, and
enumerates the precise gates blocking each flagship rung. It is the
authority the machine gate enforces: `check_aft_claim_discipline.sh`
asserts that no flagship rung appears in the corpus as a bare assertion —
the "frontier-complete" strings may appear ONLY where they are marked
BLOCKED with their open gates named (as they are here).

The full `yellow_paper.tex` rewrite around the T1–T3/T4a–b/T5a–c′/T6/T7/T8
theorem surface is REMAINING EDITORIAL WORK; it may adopt the printable
claim below verbatim and MUST NOT print either flagship rung while this
adjudication records them blocked. The adjudication — not the LaTeX
prose — is what determines what can be claimed.

> **R10 CLOSURE (2026-09-03).** The normative hash-only fallback, its
> production admission path, adverse/mutation campaigns, exact `n=130`
> benchmark, cold restart, and native PQ re-entry are complete. T4a is paired
> with L-A. This closes only RES-R10; the other claim-ladder gates below keep
> their independent state.

## The printable claim (program doc §9, upgraded)

> **Deterministic all-but-one safety for certified boundaries. Live ordering
> is optimistically responsive after GST and has randomized asynchronous
> progress against a static Byzantine adversary below one-third under its
> separately declared reliable-private-channel profile.**

**PRINTABLE.** Every leg this claim depends on is closed:

- *Deterministic all-but-one safety for certified boundaries* is T1,
  paper-proved and MECHANIZED at P2.1 (`BoundaryRing.tla` + TLAPS
  inductive invariant; TLC at the MHA corner). It is unconditional under
  A2 and bond-independent — the economics memo (P4.2) prices how open
  selection SUPPLIES A2 but the safety statement does not rest on that
  supply.
- *Live ordering under separately declared profiles* is T4a. The optimistic
  arm consumes post-GST delivery; the hash-only fallback consumes static
  `f<n/3`, reliable private authenticated channels, eventual delivery and
  private randomness. The profiles do not inherit one another's timing or
  latency. L-A pairs the result with FLP and the optimal one-third
  asynchronous resilience boundary.

No rounded-percentage tolerance figure appears; the claim-discipline
gate (P0.2) enforces that.

## Intermediate flagship — BLOCKED

> "AFT is a frontier-complete consensus architecture…" (program doc §0b) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Its condition set (spec: the §9 claim's
conditions PLUS the four below) is not satisfied:

| Condition | State | Gate |
|---|---|---|
| R10 asynchronous fallback DEMONSTRATED (not residual) | CLOSED | D1–D4 and the hash-only adverse production/cold-restart gate pass; see `../evidence/m3-adversarial-release-gate-2026-09-03.md`. |
| T7 proven against the wire format | CLOSED | P2.6 (`ForensicAccountability.tla`, 146/146) proves T7 against the P2.6 seal-share wire format; R9 lands the attribution-preserving signer. |
| T8 published in probabilistic form | CLOSED | P4.2 publishes T8 in correlated-failure probabilistic form, with the no-deterministic-conversion rule. |
| Pairing table has ZERO `L-OPEN` rows | **OPEN** | One `L-OPEN` row stands: T8 (the supply analysis is not yet a proved cheapest-capture lower bound). T5d is paired with L-S; its responsive positive theorem is refuted rather than open. |

The remaining T8 `L-OPEN` row blocks this rung. It cannot print while that row
remains open.

## Final flagship — BLOCKED

> "frontier-complete, fully accountable… succession pre-consented at formation and clocked by verifiable elapsed time… verifier held to its proofs by continuous conformance" (program doc §0c) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Beyond the intermediate rung's open gates, its
additional conditions are not satisfied:

| Condition | State | Gate |
|---|---|---|
| Positive responsive T5d cadence theorem | **IMPOSSIBLE IN THE DECLARED ASYNC MODEL** | L-S and `SuccessionSchedule.tla` resolve the question: silence cannot prove inaction. Scheduled slot-disjoint safety is mechanized, but it is not responsive cadence. |
| R11 + scheduled R12 landed | **OPEN** | RES-R11 remains an owner-action VDF-vetting residual. R12 is buildable only as formation-time, clock-fenced scheduled succession after R11; it cannot restore the responsive wording. |
| T9/L9 paired in the table | CLOSED | The pairing table pairs T9 (maximal accountable safety) with L9 (attribution cap, ratio 1.0). |
| R13 trace-conformance lane green | CLOSED | R13 merged; the lane runs in `aft_formal_floor` on every build. |

The final rung's responsive reading is unreachable in the declared model even
if R11 and scheduled R12 land: a clock proves elapsed time, never death.
"Held to its proofs by continuous conformance" is R13-green, but that does not
repair the impossible cadence clause. The rung cannot print as written.

## Maximality presentation (owner-directed, 2026-08-18)

The owner directed the yellow paper's claims to their maximum defensible
strength. The adjudicated resolution: the defensible superlative is
PROVABLE MAXIMALITY, not comparison. Two presentation-level claims are
authorized because each is a CITED positive-theorem/lower-bound pair in
the pairing table — the ceiling and the achievement print together:

- **Safety at the terminal threshold** (T1 + L1): no protocol in any
  model exceeds all-but-one for safety, and AFT meets that ceiling,
  mechanized. "The safety axis ends here" is a theorem, not marketing.
- **Accountability at the attribution ceiling** (T9 + L9): ratio 1.0 is
  the cap and AFT meets it.

The carrier-replacement framing ("the classical bound is refused, not
refuted — its carrier is replaced, and in the replaced carrier the
threshold ascends to the information-theoretic maximum") is promoted to
the abstract. Conditions preserved: the model delta stays first-class,
the liveness price (L2's forced trade) and the residual list print
BESIDE the maximality claims, no rounded figure appears, and the blocked
flagship rungs remain unprinted — this presentation strengthens the
SAFETY-AXIS claims, which are closed, and touches no completeness-class
rung, which are not.

## Adjudication summary

The separate ADR 0050 interactive QUV track is **NOT ADMITTED**. M17Q R1
returned `REPAIR_REQUIRED`; M14Q refinement, M15Q implementation, and M16Q
qualification are reopened. Historical M16Q passes and current local repairs
do not authorize a QUV release headline. Its retained M12a lower bound,
known-synchronous live executor requirement, and
`portable_final_receipt=false` remain fixed. QUV is not classical Byzantine
consensus, asynchronous authorization, or offline finality. The R1 fault and
property obligations are tracked separately in
`query_unanimity_fault_property_matrix.md`.

- **Prints now:** the upgraded model-relative claim (deterministic all-but-one
  boundary safety, post-GST optimistic progress, and static-adversary
  randomized asynchronous fallback below one-third).
- **Blocked:** the intermediate rung by T8's one `L-OPEN` supply-bound row;
  the final responsive rung by L-S's impossibility result, plus the unbuilt
  R11/scheduled-R12 plane for the weaker scheduled construction.
- **Enforcement:** the flagship strings appear in this corpus only where
  marked BLOCKED; the claim-discipline gate fails on any bare flagship
  assertion.
- **Remaining editorial:** the `yellow_paper.tex` v2 prose rewrite may
  adopt the printable claim and the pairing/measured-cost surfaces, and
  is bound by this adjudication.

### QUV parent preparation boundary (R1 remediation)

The owned-mode accept/conflict/abort witness does not refute Q-T4, whose
introduced-candidate singleton premise is absent in that schedule. It does
refute unconditional persistence of fresh acceptance. Neither Q-E1's
conditional lift nor a prior transcript supplies production accepted-head
advancement. No stronger history-progress claim is admitted; R1 001/005 and
clean M16Q R2 remain open. The executable boundary model and raw witness are
linked from `query_unanimity_head_state_design.md`.

### Rooted bootstrap implementation boundary

The new policy encoding binds explicit initial coordinates or a typed handoff
rule and rejects mismatched initial requests. It does not satisfy Q-EA2's
durable next-slot/head advancement premise for later slots. R1 001/005 remain
open, and prior process/review evidence predates the policy-root change. No
M16Q R2 or M18Q admission follows.

Member schema 4 provisioning binding is a partial R1 001/002 repair: it
authenticates network/configuration/domain-policy scope and rejects changed
provisioning before pending anchor recovery writes. It does not establish
accepted-head advancement or successor effect-history continuity. The preceding
three-process regression pass remains bound to its earlier source hashes; no
R2/M18Q admission is inferred for the changed schema. Evidence:
`evidence/m17q-r1-member-provisioning-2026-09-05/`.

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

Accepted-history retention check: locally tested, not release admission.
Recovery rejects authenticated structurally inconsistent accepted histories
before recovery writes; 36 core tests passed and the removed-check regression
failed as required. No entire R1 finding is closed by this increment. Existing
R1 repair-required, R2 not-established and M18Q boundaries remain unchanged.


### Durable preparation-attempt reservation — 2026-09-05

Durable preparation-attempt reservation is implemented and locally tested in
member schema 6; handoff schema remains 3. It binds the policy limit, authenticates
spent counts, refuses exhausted budgets and retires counters atomically with own
accepted advancement. The worker does not yet use it. Finite retry exhaustion is
not effect or history liveness. R1 001/002/005/006/009 remain open as complete
findings, and neither R2 qualification nor M18Q admission is established.


### Runtime preparation worker — 2026-09-05

Preparation-worker integration is implemented and compiles. It is not admitted
as bounded service or child readiness. Process and mutation evidence are pending,
external operation-slot fairness is unproved, and the existing timing-model
Assumes obligations remain. No entire R1 finding, R2 qualification or M18Q gate
is closed by this integration.


### Queued foreground/preparation admission — 2026-09-05

The original preparation-worker process run failed a required conflict case with
a generic busy refusal and also lost early component diagnostics; it is retained
as failed development evidence. Queued admission is now implemented and its five
runtime tests pass, with two paired capacity mutations failing as required. The
new process campaign is pending. Local bounded queue order is not an admitted
service-time, child-readiness or effect-liveness guarantee. No whole R1 finding,
R2 or M18Q gate is closed.


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

Exact timely dispatch completion is now a tested runtime prerequisite to live
QUV finalization. Eight runtime tests, 38 core tests and CLI compilation passed;
two removed-rule controls failed as required. This does not qualify all correct
members' processing, worker service time, child readiness or effect liveness.
Earlier process results are historical for their exact source hashes. R1 remains
repair-required; no entire finding, clean R2 or M18Q gate is closed.


### Rooted active preparation service — 2026-09-05

Active preparation service enforcement is implemented and locally tested:
39 core tests, nine runtime tests, CLI compilation and three paired rule-removal
controls have their required dispositions. The current-source process campaign
is pending. Active cost starts after exclusive admission; aggregate readiness
must separately cover waiting/selection and other work. A reported timeout or
late atomic-write completion does not establish progress. No whole R1 finding,
clean R2 qualification or M18Q gate is closed.


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


### Scheduling/service failure evidence gates (2026-09-05)

Both the single-correct process checker and the handoff checker now reject
`push_admission_overflow`, `push_admission_worker_stopped` and
`preparation_service_expired` in any retained component record, including records
whose nonce is unrelated to the selected workload. Passing selected acceptance
assertions cannot erase a declared scheduling/service failure elsewhere in that
same qualification campaign. These diagnostics remain evidence, never authority.

The handoff checker self-test passes 1 positive and 21 negative cases. The main
checker passes 2 positive/26 negative process cases and 1 positive/26 negative
component-overlap cases. Replacing each checker's scheduling/service failure
condition with False causes its self-test to fail. Raw commands, outputs and
checker hashes are retained in `evidence/m17q-r1-scheduling-evidence-gates-2026-09-05/`.
The stronger handoff checker was applied to the completed disjoint campaign's
retained raw logs after that campaign terminated; its original and recheck
checker hashes remain distinct. No runtime-source change is attributed to that
recheck. Full R2 and all whole R1 findings remain open.


The scheduler/worker-ownership runtime passed disjoint and overlapping handoff
campaigns with four independent successor acceptances, exact four-old-member
participation, and maximum observed valid replies of 939ms and 911ms. The overlap
fixture also passed local-gate recovery diagnostics, retrieval of a block two
heights beyond the pre-restart tip, and retired-member role-refusal diagnostics. Stronger scheduling/service diagnostic gates
pass the retained logs; the disjoint recheck used a newer checker after runtime
termination, with both hashes retained. Evidence is in
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`. These scoped checks
are not full restart/refinement, worst-case timing, whole R1 closure or clean R2.


### Current scheduler foreground campaign (2026-09-05)

The foreground process campaign after the cancellation-ownership repair passed
(exit 0, unchanged selected sources). The strengthened checker confirms all four
sole-correct placements, all four concurrent saturation operations, one conflict
acceptance with one typed rejection and non-mutation, unrelated effect execution,
and unchanged terminal-result retrieval beyond the committed expiry fence
(observed height 66 > 65). Four-way workload overlap was 4674.706ms. Worker checks
matched 16 independent preparation starts and 12 accepted completions across all
four workers, with no scheduling/service-failure markers. Refusals are not progress.

Raw logs, exact source/command hashes and checker results are retained under
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/foreground-process/`.
This supersedes the earlier pending foreground status only. Previous failed runs
remain unexplained and retained. These selected assertions do not establish
worst-case timing, aggregate readiness, full transition/restart/storage refinement,
clean R2, or closure of any whole R1 finding. No theorem assumption changes.


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


### Durable-admission repair foreground qualification (2026-09-05)

The post-repair foreground campaign terminated with exit 0 and no recorded source
changes. The strict checker confirms all four sole-correct placements, four
concurrent saturation operations, one conflict acceptance and one typed rejection
with non-mutation, unrelated effect execution, and unchanged terminal-result
retrieval at committed height 67 beyond expiry height 65. Four-way workload
overlap was 4974.655ms. Worker diagnostics matched 17 starts and 13 accepted
completions across all four workers; no scheduling/service-failure markers were
found. All three retained evidence checks passed. The reply-stage analyzer found
21 remote replies with no missing stages; host timestamps are observations,
not a proof of worst-case latency or authority.

Evidence: `evidence/m17q-r1-durable-admission-ownership-2026-09-05/foreground-process/`;
`check_foreground.py` rechecks only a terminal retained run and never launches
another campaign. This qualifies the selected foreground assertions for the
recorded repair source. It does not qualify handoff/restart after this repair,
derive aggregate queue/readiness bounds, explain earlier failures, provide full
transition refinement, complete R2, or close any whole R1 finding.


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


### All-operation service local validation (2026-09-05)

For the v3-operation-service implementation, configuration validation passed,
40 core tests passed with the separately retained existing ignored test, and all
16 QUV runtime tests passed. The CLI aft_e2e test target compiled. Omitting the
operation-service field from canonical hashing makes the new binding regression
fail; bypassing the foreground budget makes the role-selection regression fail.
Restored source passes both. These are scoped binding/selection controls, not a
claim that the complete production timeout workflow has been mutated end to end.

The strengthened main checker passes 2 positive/26 negative process cases and
1 positive/31 negative overlap/component cases; the handoff checker passes
1 positive/26 negative cases. Removing each checker's completed-operation service
guard causes its self-test to fail. Affected Rust formatting, runner syntax and
diff checks pass. The CLI fixture was formatted after compilation; this formatting
change has no behavioral validation claim beyond rustfmt's successful parse.
Raw commands, outcomes and final hashes are retained in
`evidence/m17q-r1-all-operation-service-2026-09-05/`.

Process and restart qualification of this root/behavior change remains required,
as do a derived and qualified queue/readiness bound, full transition refinement,
clean R2 and closure of every whole R1 finding. No declaration of finite service
or successful local test turns refusal, timeout or a stalled durable write into
progress.


### v3-operation-service foreground campaign (2026-09-05)

The unchanged-source campaign passed its process test and all three retained
evidence checks. All four sole-correct placements and saturation operations
executed; four-way overlap was 4927.347ms. The concurrent conflict case had zero
acceptances, two typed refusals, zero durable records and non-mutation: safety
only, no conflict-case progress. The unrelated effect executed, and unchanged
terminal-result retrieval observed height 70 beyond expiry 65. Worker diagnostics
matched 17 starts and 9 accepted completions across the expected workers.

Evidence is under `evidence/m17q-r1-all-operation-service-2026-09-05/foreground-process/`.
The source audits in that directory still identify incomplete startup/dispatch
admission ownership and completion sampling before final permit release. This
process pass neither resolves those findings nor proves actual admission-release
or aggregate queue/readiness bounds. All whole R1 findings and clean R2 remain open.


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


### Final-release foreground process evidence (2026-09-05)

The unchanged-source foreground campaign passed the process test and all three
evidence gates. All four sole-correct placements, four saturation operations,
one conflict acceptance with one typed rejection/non-mutation, unrelated execution,
and unchanged terminal-result retrieval at height 70 beyond expiry 65 passed.
Four-way workload overlap was 3777.211ms. Worker diagnostics matched 18 starts
and 15 accepted completions. Every one of the 26 recorded completed operations
had a matching successful final admission release; 32 release records were retained
in total, including releases without a completed-operation record.

The largest observed active release duration was 7,142,340 microseconds
(preparation); the foreground maximum was 6,818,118 microseconds. These are runtime
monotonic observations sampled after final semaphore release, not a worst-case
service bound or aggregate queue/readiness proof. Raw component logs, release rows,
source/checker hashes and terminal dispositions are retained under
`evidence/m17q-r1-final-admission-release-2026-09-05/foreground-process/`.

This validates selected foreground assertions and release-record completeness on
the recorded repair source. Handoff/restart qualification of the current root and
lifetime changes, full refinement/resource bounds, clean R2 and closure of all
whole R1 findings remain open. Earlier failures remain retained and unexplained.


### Failed disjoint campaign after final-release repair (2026-09-05)

The current-source disjoint campaign failed (exit 101, no recorded source changes):
successor node 4 did not observe required post-QUV height 5. The mandatory handoff
evidence checker rejected the failed campaign. The separate release analyzer passed;
that component result is not a handoff/progress pass. Four successor live-acceptance
audit records match the expected old root/domain/member set, but post-install
progress remains required. Validator-20400's retained consensus progress records
end after beginning a height-3 proposal; other successor logs contain later admitted
height diagnostics. The exact stalled boundary is not yet isolated, and public
status values must not be conflated with those internal diagnostic heights.

Raw logs, failed terminal result, rejected checker result and partial source-bound
analysis remain under `evidence/m17q-r1-final-admission-release-2026-09-05/disjoint-process/`.
No assertion is relaxed, no retry is substituted for this failure, and no freeze or
refusal is counted as progress. Post-install production/finality boundaries require
investigation before requalification. Overlapping-handoff qualification of this
repair is still outstanding. All whole R1 findings and clean R2 remain open.


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


### Consecutive readiness restart failure retained (2026-09-05)

The first three-slot campaign is FAILED (exit 101, unchanged recorded sources).
Slot one, unchanged terminal parent replay, same-executor unrelated execution
while slot two waited, and slot-two execution passed their selected assertions.
Slot two required 39.175024726s and observed 39.176213856s of waiting. The fixture
then missed the slot-three wait event after restart. Its checker rejects the
campaign; the passing prefix is not restart qualification.

The test was awaiting diagnostics while leaving an early spawned RPC result
unobserved. It now selects between the wait event and an early RPC completion,
preserving the underlying typed error. The new regression passes; restoring the
masking behavior fails within the regression's one-second observation bound.
An initial failed source-edit attempt caused a zero-test command, explicitly
retained as non-qualification; the corrected test ran and passed. M16Q requires
that regression. A diagnostic rerun of the same unchanged scenario/profile is
running under `consecutive-process-rpc-observed/`; no production cause or repair
is inferred yet. Recovery logs naming height 1 and a listening RPC endpoint are
insufficient to attribute the failure.

Both campaigns retain copies of every source named by their recorded source
hashes. The first fixture/runner versions were reconstructed by reversing the
known diagnostic edit and verified against their original SHA-256 values. This
is scoped source retention, not a full immutable repository candidate. All whole
R1 findings, aggregate bounds, full refinement, clean R2 and fresh review remain
open. Evidence: `evidence/m17q-r1-readiness-process-2026-09-05/`.


### Restart connection race identified; bounded read-only readiness probe (2026-09-05)

The diagnostic rerun failed with the explicit slot-three connection error:
`Failed to connect to public gRPC: transport error`. Its recorded sources were
unchanged. The restart helper returns after spawn; the fixture had made one RPC
connection attempt without a startup barrier. Both failed runs remain retained.

The fixture now probes the exact already-executed parent result for at most 20s
before requesting the restarted child. Only a typed ConnectionRefused cause or
Unavailable/`Node is initializing` permits another probe. Other errors and any
changed result are failures. The testing RPC connector now preserves its typed
transport cause. A real loopback refusal and the exact-result/startup classifier
pass; erasing the transport type or accepting changed result bytes fails the
regression, and restored checks pass. This is read-only startup observation, not
authority for the child: the child must still perform and consume its own fresh
live operation under the unchanged rooted 40,000ms readiness profile.

The checker now requires the recovered-parent probe and the executor's second RPC
listener between slot-two completion and slot-three waiting. Its self-test passes
one positive and 24 negatives. The initial self-test extension failed on optional
event fields in listener records; that construction error and correction are
retained. M16Q requires the new recovery regression. The corrected campaign is
running under `consecutive-process-recovery-probed/`; no pass is claimed yet.
Raw evidence and exact recorded source copies remain in
`evidence/m17q-r1-readiness-process-2026-09-05/`. All whole R1 findings, aggregate
bounds, full refinement, clean R2 and fresh review remain open.


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

AFTPQI04's two allocated index inodes remove live index file creation/truncation
under the Linux exchange storage profile. This is scoped R1 resource remediation;
full physical allocation, service guarantees, clean R2 and independent review
remain open. The nine-obligation reserved-index kernel is conditional on storage
primitives and is not an end-to-end QUV proof or release admission. M18Q remains
NOT_ADMITTED and portable_final_receipt=false.

The arena now reserves QUV payload data slots and preserves the two old lanes
while staging replacements. Normal storage-capacity refusal can preserve the
existing queue only after durable cleanup before index commit. Neither result
establishes aggregate metadata/RAM/timing bounds or non-refusal liveness. All
whole R1 findings remain open, M18Q remains NOT_ADMITTED, and
portable_final_receipt=false remains unchanged.

Preallocated member record data is additional R1 remediation, not M18Q admission.
The root-derived pool preserves authenticated record bytes, retained conflict
knowledge and final continuation checks. Its allocation/retention proof and
syscall evidence remain scoped; startup cost, metadata/RAM and the remaining
custody stores require integrated qualification. No whole finding closes and
portable_final_receipt=false remains binding.


The member anchor and pre-live handoff reservation increments have scoped
source-bound evidence through `evidence/m17q-r1-handoff-reservation-2026-09-06/`.
They admit no new claim: all whole R1 findings remain open; M15Q reopened,
M16Q R2 unqualified, M17Q REPAIR_REQUIRED and M18Q NOT_ADMITTED. Full resource/
refinement, immutable qualification and fresh review gates remain mandatory.

R1 endpoint preallocation (2026-09-06) adds a scoped per-key allocated-data and
publication-order result. It admits no aggregate resource, timing, inclusion or
external-effect liveness claim. M18Q remains NOT_ADMITTED.

AFTCR001 adds a checked per-effect two-file allocation ceiling and conditional
replacement primitive. No aggregate capacity, fair service, worst-case latency,
inclusion or external-effect completion guarantee is thereby admitted. The full
M18Q disposition remains NOT_ADMITTED.

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

Continuation ownership repair retains local admission through the irreversible
call/install boundary. Its conditional proof and scoped regressions do not
establish worst-case service or full resource fairness. Evidence:
m17q-r1-continuation-admission-2026-09-06. M18Q remains NOT_ADMITTED.

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

Registry schema v2 identity preservation is a scoped admission repair, supported
by `evidence/m17q-r1-registry-identity-2026-09-06/`. Its conditional uniqueness
proof and defensive regressions do not establish aggregate capacity, migration,
full transition refinement or final-source qualification. M17Q remains
REPAIR_REQUIRED and M18Q NOT_ADMITTED; no portable authority or progress claim
is added.

Overlay scan propagation and M16Q formal coverage were repaired with scoped
evidence in `evidence/m17q-r1-overlay-scan-2026-09-06/`. Error-aware bootstrap is
not a global storage/timing theorem. Scheduling all automated formal checks is
not their final-source execution. No claim admission, finding closure or fresh
review follows; M18Q remains NOT_ADMITTED.
