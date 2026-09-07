# QUV R1 fault, property, and profile matrix

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is this document; no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

Status: **REPAIR_REQUIRED; no production/release admission**.
Current policy-root profile: v7-consequence-admission; earlier v6 evidence is historical.

This matrix records open R1 obligations. It is not a claim that tests establish
all assumptions. The immutable report and incomplete reproduction are retained
in `../evidence/m17q-r1-import-2026-09-04/`; local development results are in
`../evidence/m17q-r1-local-remediation-2026-09-04/`.

## Profile and task boundaries

| Profile/task | Property and assumptions | Current admissible scope |
|---|---|---|
| M12a portable byte-only authorization | Copyable participant state; unknown sole correct member | `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`; original M13-M18 blocked |
| M12b / `aft_quv_v0` | Every executor interacts live with configured members; every correct member replies within known end-to-end synchrony; atomic durable non-rollback retained conflict state | Construction result only; M15Q-M18Q remain unadmitted |
| QUV accepted-value non-conflict | Q-A1–Q-A10, canonical conflict identity, exact context binding | Conditional theorem; implementation/refinement and R2 qualification open |
| QUV decision termination | Complete rooted decision interval under the timing assumptions | Typed Abort/rejection is not inclusion, authorization, or effect liveness |
| QUV no-conflict progress | Exactly one independently valid candidate, no disclosed valid conflict, all required timely correct participation | No fairness claim for arbitrary valid competing submissions |
| QUV consequence externalization | Fresh process-local QUV plus current admission, stable execution fence, and T10 atomic resource contract | Conditional at-most-once model; no guarantee for arbitrary physical resources |
| QUV audit transcript | Historical executor observations, `portable_final_receipt=false` | Audit only; never authorizes another executor |
| PQ v1 / Hypervisor | Existing separately admitted profile and isolated dependency graph | No QUV guarantee amplification or fallback authority; fresh isolation/build measurements required |

## Controlling gates beyond the stable findings

These gates share this closure index with findings 001–013; none is satisfied
by component evidence alone. Fixed truth boundaries above remain binding.

| Requirement | Remaining implementation/artifact work | Proof and defensive checks | Mandatory evidence and exact closure condition |
| --- | --- | --- | --- |
| Retain attributable R1 | Preserve imported report, reproductions, twin and stable identifiers; label incomplete imported material | Never infer a clean disposition from missing review text | Retained import provenance plus explicit disposition of every stable finding in fresh review |
| M15Q production completion | Integrate all finding repairs, schemas, CLI and both executor entries | Complete transition refinement; meaningful positive and removed-rule checks | All production obligations above discharged, then accepted on the exact final candidate |
| Complete M16Q R2 | Finish the integrated resource/service profile and all process fixtures | All TLAPS, model, mutation, deadline, recovery and consequence obligations; no required skipped gate | Clean checkout; format, affected workspace/PQ/QUV, all correct-member placements, conflicts and unrelated domains, reconfiguration, sustained pressure/restarts, deadline edges, Hypervisor build/smoke and retained performance; every mandatory gate passes |
| Immutable evidence binding | Isolate intended changes while preserving unrelated dirt; include required tracked artifacts | Verify source/configuration/toolchain/command/artifact hashes and clean reproduction | One immutable candidate contains all intended source and evidence; a selected dirty-tree subset never satisfies this gate |
| Fresh M17Q | After clean R2 and freezing only, commission the authorized gpt-daybreak-blue-latest reviewer with candidate and packet only | Independent source inspection, full runner reproduction, process validation, spec-only twin/equivalent model and independence disclosure | Attributable automated review of that exact candidate with no unresolved critical/high finding; every security repair restarts qualification/freezing/review |
| M18Q claim consistency | Reconcile implementation, schemas, proofs, receipts, CLI, documentation, yellow paper and public wording | Preserve M12a/M12b, live per-executor interaction, non-portability and separate safety/decision/inclusion/effect/fairness claims | Exact reviewed candidate admits only proved claims; explicit storage, synchrony, reachability, PQ, reconfiguration, consequence, latency and audit costs; no guarantee amplification |
| Owner release handoff | Prepare release notes, immutable tag, manifest, checksums, reproduction, push/deploy/publication commands | Verify artifact/commit bindings and preserve owner-only action boundary | Concrete handoff for the admitted candidate; no public push, deployment, spend, disclosure or publication performed without contemporaneous authorization |

## R1 obligations and lower-bound pairings

All rows remain **OPEN**. A local regression is supporting evidence, not a
finding disposition. All rows require production negative/positive coverage,
clean R2 qualification, and fresh exact-candidate independent review.

| Finding / property | Remaining production obligation | Specification / proof | Positive and negative regression | Required qualification | Closure condition |
|---|---|---|---|---|---|
| QUV-M17Q-001: Canonical identity and expected head | Finish head/handoff composition; retain canonical domain/slot and durable bootstrap | Q-T1, Q-EA ordering; runtime head transitions | Wrong predecessor/root and conflicting head refuse without writes; own live grant advances | All placements, successive slots, conflict/unrelated and handoff/restart | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-002: Authenticated durable custody | Complete recovery/retirement compatibility; preserve journal/anchor ordering and quarantine | Q-A4/Q-A5; record/anchor/memory recovery refinement | Corruption and stale/pending anchors refuse or recover exact state; legacy formats never reset knowledge | Member/handoff crash boundaries, rollback and storage pressure | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-003: Complete rooted deadline | Reconcile every reply observation/dispatch deadline edge on final runtime | Q-A3; request through fully processed reply timing | Before/equal/after deadline with exact member participation and typed outcomes | Delayed-process and all rooted timing-component campaigns | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-004: Nonvacuous production evidence | Require exact correct members, typed conflicts and resource nonmutation everywhere | Q-T1/Q-T4; distinguish refusal from progress | Missing member or arbitrary error fails evidence checker; positive assertions require execution | Every sole-correct placement, saturation, conflicts and unrelated domains | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-005: Full transition refinement | Complete admission/head/recovery/continuation/handoff/T10 transition bridge | All Q-T/Q-E obligations; discharge conditional antecedents | Meaningful invalid-transition regressions paired with valid traces | All TLAPS and transition checks plus production conformance | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-006: Rooted resource and service profile | Finite rooted slot horizon, first-two state, encoded lifetime accounting, allocated indices/QUV payload arena, member record/anchor data, exact pre-live handoff data, pre-live named endpoint record data and normal-capacity failure isolation implemented; finish metadata/RAM/consequence allocation and aggregate handoff recovery, rate/fair service, cross-configuration retention and aggregate bounds | Q-A3/Q-A5/Q-A9; finite resources without premature forgetting | Root substitutions, exhausted quotas and recovery preserve state; admitted correct work completes | Sustained resource pressure, unrelated progress, restart and full timing/cost envelope | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-007: Authenticated PQ carriers | Complete provisional expiry/eviction/routing qualification | Q-A1/Q-A2/Q-A3; identity proof before carrier ownership | Unproven identities cannot replace carrier; proved enrollment evicts provisional entries | PQ carrier lifecycle and bounded-load process tests | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-008: Current execution height | Qualify immediate T10 height/authority fences in both executor entries | Q-EA4; current committed authority through Claim | Height/expiry changes refuse before mutation; applicable authority executes | Process height changes and consequence crash boundaries | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-009: Live continuation and retry | Qualify immediate Claim expiry and restart/retry rules | Q-A6/Q-EA4; process-local authorization consumed at Claim | Expired or substituted continuation refuses; live retry preserves durable idempotency | Continuation deadline edges and consequence recovery | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-010: Terminal results and reconciliation | Complete terminal lookup budgets and unrelated-domain fairness | Idempotency, reconciliation budget and Q-A9 composition | Terminal replay returns exact result; exhausted reconciliation cannot call again | Ambiguous-call lookup, restart, duplicate calls and unrelated progress | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-011: Durable outbox lifecycle | Complete silent-recipient retirement/retry and restart qualification | Q-A9; finite durable transport capacity | Persistence failure quarantines; bounded retirement preserves retry rules | Silent-recipient sustained load and outbox crash/recovery | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-012: Nonce lanes and ACKs | Complete nonce/context-before-lane and ACK process qualification | Q-A3/Q-A8/Q-A9; exact fresh operation binding | Stale/cross-operation replies do not consume current lane; duplicate ACK is safe | Overlapping operations, duplicate delivery and restart | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |
| QUV-M17Q-013: Committed effect authority | Qualify unconditional current admission and exact receipt/root checks end to end | Q-EA4; audit bytes never mint effect authority | Forged/stale/substituted/unadmitted receipt refuses; exact committed effect executes | Both executor entries, readmission and T10 process checks | OPEN: complete this row, pass clean final-source R2 and obtain fresh exact-candidate reviewer closure |

This is the single current closure index. The dated sections below retain scoped evidence and superseded observations; they do not override these closure conditions. Every row also requires exact root/profile binding, the objective's lower-bound pairings and no claim amplification. Cross-cutting completion requires Hypervisor isolation, immutable evidence, M15Q–M18Q dispositions, exact public/schema/code/proof wording and the owner release handoff. The journal-production campaign dated 2026-09-05 qualifies only its recorded schema-7 sources; subsequent source changes require fresh applicable qualification.

## R2 remediation wave — 2026-09-06

Integrated repair wave toward the R2 candidate, executed on the dirty tree at
HEAD `24a9888e3`. Every item below is scoped development evidence with its own
README under `../evidence/m17q-r2-*-2026-09-06/`; none is qualification, and
no row above changes from OPEN until the exact R2 candidate passes the clean
full M16Q run and fresh independent review.

| Finding | Landed in this wave | Evidence | Still required before R2 admission |
|---|---|---|---|
| 001 | Exact-trace handoff/predecessor regressions; removed-rule controls for the conflict key (`QuvConflictSlotV0`), the push-path `check_expected_slot` (extended to the saturated-slot reply path after the first control unexpectedly passed) and the head predecessor comparison; member-side handoff predecessor enforcement traced and pinned by test; process fixture with different predecessors for one numeric slot in owned/unowned domains and both orders; stable-key claim index below the QUV argument | `m17q-r2-consensus-identity-custody`, `m17q-r2-consequence-claim-guard`, `m17q-r2-process-fixtures` | Clean process campaign pass; exact-candidate review |
| 002 | Forged generation+1 handoff gate regression, every-byte and per-field handoff mutations, foreign-scope / mismatched-generation / valid-record-at-scratch-name journal negatives | `m17q-r2-consensus-identity-custody` | Clean R2; review |
| 003 | Runtime late-timer-wake regression through the production finalization closure (`finalize_operation_at_deadline`) | `m17q-r2-validator-deadline-fairness` | Clean R2; review |
| 004 | Measured (not literal) conflict-register evidence; predecessor-fork, concurrent-replay and flood checker rules with self-tests; component-log cross-checks that refused payloads start no member operation | `m17q-r2-process-fixtures` | Single-correct and flood campaigns pass with the strict checker on the integrated dirty tree (c26, c23 in `m17q-r2-process-fixtures`); clean R2 on the committed tree and review remain |
| 005 | `QuvEndToEndRefinement.tla`: composed finite transition model (admission, two-phase authenticated durability and recovery, timed operations, own head, continuation expiry/fence, T10 claim-before-call on the stable key, handoff activation) with 5 positive instances, one reachability witness and 8 named countermodels, registered in the formal runner; spec wording labels the composition proof a conditional lifting lemma | `m17q-r2-end-to-end-refinement` | Implementation-refinement half remains open by declaration; review |
| 006 | Policy-root v8: rooted per-identity/per-domain sliding-window push quota enforced before authentication and store access; claim-index storage charge and `WAITING_PER_PRINCIPAL` rooted; independent Python root reproduction; flood + high-water restart fixture with member-store byte inspection | `m17q-r2-push-admission`, `m17q-r2-process-fixtures` | Flood campaign passes (3 quota drops, unrelated singleton within three intervals, six-slot horizon, high-water restart); aggregate service envelope remains a measured cost, recorded in the verification specification |
| 007 | Squatter-disconnect, handoff-only squat, mid-handshake eviction and live swarm-level squat regressions; `PqEnrollmentLost` recovery with fresh status request instead of a blind handshake | `m17q-r2-pq-carrier-outbox` | Process case landed: a rooted node restarted with a test-only, fail-closed status override claiming the sole correct member's account is refused by every peer and all four genuine replies arrive (`m17q-r2-byzantine-status`); the first-contact variant (claimant lying from its very first status response, launched before the genuine carrier ever authenticated) passes as its own cold-start fixture: the claim is provisionally enrolled and evicted three times, the genuine carrier authenticates, every other process refuses the claimant, and the operation executes on exactly the three correct members with the claimant never bound under any account; review |
| 008 | Cached `Authorized` beyond fence refused on inspect, prepare and execute; fail-closed-in-place documented | `m17q-r2-consequence-claim-guard` | Clean R2; review |
| 009 | Injected store clock; inclusive deadline equality and expiry crossing between `Claimed` persist and `InFlight` check | `m17q-r2-consequence-claim-guard` | Clean R2; review |
| 010 | Per-principal waiting bound on foreground and historical receipt lanes (rooted); concurrent terminal replay against an unrelated singleton effect in the process fixture | `m17q-r2-validator-deadline-fairness`, `m17q-r2-process-fixtures` | Concurrent terminal replay against an unrelated singleton passes (8.5–11.0 s measured, three-interval fence); review |
| 011 | Silent-recipient 24-operation and reopen regressions; analysis that only a quarantined outbox can make enqueue fail | `m17q-r2-pq-carrier-outbox` | Review |
| 012 | Stale-reply-before-lane, stale-push lane, `PqChannelNack` retry path, in-flight drop branch now releases the lane; a deferred push ACK (held until `CompleteQuvPush`) was implemented, then reverted after process qualification showed it serialized replies behind pushes on the single in-flight lane and missed the rooted cutoff under saturation; ACK-before-durable-processing is a documented liveness-only boundary | `m17q-r2-pq-carrier-outbox`, `m17q-r2-validator-deadline-fairness` | Review |
| 013 | Substituted self-consistent receipt file (Authorized/Claimed/Executed) refused before QUV and invocation | `m17q-r2-consequence-claim-guard` | Clean R2; review |

Runner changes: portable `grep -E` instead of `rg`; formatting gate; every new
regression is a named required case; new `pq_swarm_quv_lanes`, flood process
and five fixture-parser phases; new sources and the composed model are hashed.
The complete formal corpus (92 modules) passed on this tree in 39 minutes
before the composed model was registered; the census now reports 79 executed
and 13 manual modules.

## Costs and residual gates

The runtime-finality critical section now spans post-QUV admission validation,
durable receipt writes, and synchronous resource invocation. Its lock ordering,
latency, and impact on correct-member scheduling are not yet qualified. A live
continuation check before persistence is not a measured upper bound on the
subsequent disk flush; that durable timing boundary remains an explicit R2
obligation. The store-level Claimed retry test does not establish the complete
production admission/retry workflow.

No deadline, freeze, veto, or attributable equivocation is counted as effect
liveness. No root, receipt, timeout, hidden relay, or coordinate-wise composition
may increase assurance beyond the exact verified constituents. Only the same
immutable fully qualified and independently reviewed candidate may reach M18Q.

### R1 001/005 parent re-verification boundary

The sequential owned-mode boundary model checks non-conflict and singleton
progress (22 reachable states) and refutes only the stronger claim that earlier
acceptance guarantees fresh acceptance despite later valid conflict. This is
abstract claim adjudication, not runtime refinement, head enforcement, a
production mutation, or an impossibility result for the interactive target.
R1 001/005 remain open. Raw evidence is retained in
`evidence/m17q-r1-parent-reverification-boundary-2026-09-05/`.

The subsequent `QuvHeadPreparation.tla` design model checks local grants,
atomic frontier advancement, durable conflict retention, and historical-query
admissibility in one/two-correct-member two-slot configurations. Its required
two-slot reachability trace is not a progress theorem. Complete live Query is
atomic and storage non-rollback is assumed; no production refinement or R1
001/005 closure follows. Evidence: `evidence/m17q-r1-head-transition-model-2026-09-05/`.

The interleaved head model further separates Begin/Capture/Observe/Decide and
checks accepted-grant compatibility before Advance. Combined two-slot/two-value
exploration covers 17,314 states. It assumes correct identity/routing, atomic
durability and complete correct-member observation; R1 001/002/005/012 and
production integration remain open. Its completion witness is not liveness.

R1 006 allocation follow-up: member preflight now borrows the existing slot,
avoiding its redundant full copy before capacity refusal. The regression checks
refusal without writes, exact-fit extension after reopen, ordered two-candidate
snapshots, and fresh-nonce duplicate replies without persistence. Whole-state
rewrite, rooted quotas, retention, fairness and flood qualification remain open.

The head transition model now checks both authority modes. Unowned acceptance
uses captured durable first-seen order, with retention and snapshot consistency
invariants; two-slot/two-value checks passed for one and two correct members.
The model still assumes the storage/routing/timing premises and does not close
R1 001/002/005/012. Evidence: `evidence/m17q-r1-head-unowned-model-2026-09-05/`.

Conditional head-preparation progress now has a finite temporal check for
singleton inputs, no crashes and per-action weak fairness. Preserving a live
accepted grant until advancement passes in both modes; discarding it on a new
query yields the required fair non-completion cycle. The production scheduler,
continuation expiry and rooted timing requirements remain open (R1 001/005/006/009).
Evidence: `evidence/m17q-r1-head-progress-model-2026-09-05/`.

R1 001 bootstrap implementation: required typed configuration now commits fixed
initial coordinates or the handoff-boundary rule in a new policy-root domain.
Initial mismatches are rejected before processing/admission; handoff requests
require the exact source/certified boundary regardless of old/staged requester
status. Durable next-slot/head state, stored-bootstrap comparison, preparation
and policy-transition qualification remain open. Old process evidence does
not qualify this changed root format. Evidence:
`evidence/m17q-r1-rooted-bootstrap-2026-09-05/`.

The bootstrap disjoint-handoff run failed its recovery-origin assertion and
exposed incomplete old-member participation: one old member refused all four
requests for lack of a cached QC. Repairs distinguish existing-gate activation
from a fresh live install and independently verify the source QC against local
executed state. A new post-validation audit checker requires every expected
old member for each expected successor. R1 002/004/005/007 and fresh process
qualification remain open. Original failure evidence:
`evidence/m17q-r1-rooted-bootstrap-2026-09-05/failed-process-analysis.json`;
repair evidence: `evidence/m17q-r1-handoff-origin-2026-09-05/`.

The repaired handoff/effect regression sequence passed both exact handoff
coverage checkers and the four-placement effect checker on its recorded sources
(`evidence/m17q-r1-handoff-origin-2026-09-05/process/`). This remains dirty-tree
local evidence, with prior failures retained.

R1 001/002 provisioning persistence slice: member schema 4 authenticates the
network/configuration/domain-policy-set commitment at creation and compares it
on reopen before pending-recovery writes. Positive unchanged-scope recovery
and negative changed-scope refusal cover both synchronized and pending anchors;
all-byte authentication tests now include this field. Canonical ordering, scope
changes and invalid/duplicate policy inputs have local tests. Durable expected
head, successor history transfer, complete storage refinement and fresh process
qualification remain open. Evidence:
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

Recovery row supplement: synthetic authenticated inconsistent state with a
missing or substituted snapshot at either of two accepted slots must produce
CorruptStore without changing state/anchor bytes. Coverage includes owned and
unowned domains and both synchronized and pending-anchor recovery. A complete
history reopens successfully. Removing the snapshot cross-check fails the named
regression. This row is local storage consistency evidence, not custody or
full restart/flood qualification.


### Durable preparation-attempt reservation — 2026-09-05

Preparation reservation row: both authority modes retain spent attempts across
reopen, refuse exhausted or substituted budgets without writes, and reset only
with durable own accepted-head advancement. An old grant replay preserves the
new slot's counter. One-byte-short capacity refuses before writes; exact capacity
succeeds. An uncertain anchor write quarantines the live instance, and recovery
retains the reservation. Changes to counter slot/count without authentication
are refused before recovery writes. Removed budget, root-binding and MAC-coverage
controls each fail their named regressions. This is local schema-6 evidence;
worker/fair-service/flood/restart timing qualification remains absent.


### Runtime preparation worker — 2026-09-05

Preparation-worker row is implementation present / qualification pending.
Startup scans retained pending work; member/completion events wake one rotating
worker. Rooted attempt reservation precedes opening a new transport epoch. The
same live query and durable own-head transition are required. Process-level
triggering, reservation ordering, restart and negative controls remain required;
compilation does not satisfy this row. External admission fairness and child
readiness remain open.


### Queued foreground/preparation admission — 2026-09-05

Queued-operation row: one active permit spans setup/live query/head commit;
one waiting foreground request per enrolled domain and one lifecycle preparation
worker may wait. Tests require exclusive activity, queue order in both directions,
unknown/occupied-domain refusal and capacity recovery on cancellation. Relaxing
active or waiting capacity fails the regressions. Candidate validation runs before
queuing and current rooted/head validation after waiting. Wall-clock fairness,
queue-byte cost, sustained flood and child-readiness qualification remain open.


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

Dispatch row: require a nonempty exact configured set and positive interval;
record only successful remote outbox admission/local write-before-reply. Each
omitted member prevents the decision callback. Duplicate/unconfigured completion
and late observations preserve outstanding membership. Cancellation after any
proper prefix leaves finalization refused. Completion before or at the deadline
permits the independently checked live decision; after the deadline does not.
Both complete-set and deadline guard removals fail the corresponding regressions.
This row covers local dispatch accounting, not remote delivery, all correct-member
processing or fresh process qualification.


### Rooted active preparation service — 2026-09-05

Active-service row: the clock starts immediately after exclusive admission;
startup/dispatch expiration aborts the matching pending operation without refunding
a spent attempt. Finalization requires both complete dispatch and the whole live
query interval. A consuming cap preserves the earlier of original grant expiry
and active deadline. Before-cutoff completion can succeed; equality/after-cutoff
cannot. An original expired grant cannot be revived by a later cap. Existing live
query failures remain failures. The three corresponding removed-rule controls
fail their regressions. Atomic-write overrun is reported, not undone or credited
as timely completion. Full process cancellation/restart and aggregate timing
qualification remain required.


The expired-result fixture requires the effect endpoint's own admitted height
strictly beyond the committed fence, while every preceding observation must also
preserve identical nonportable receipt bytes. Before/equal/after observations and
removed strictness/equality/portability guards are covered by
`quv_expired_result_requires_strict_admitted_height_and_unchanged_receipt`.
The active-service process run failed a formerly combined assertion; the failed
field is unknown. The new fixture does not retroactively admit that run or change
any protocol assumption. See `evidence/m17q-r1-expiry-observation-2026-09-05/`.


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


PQ durable-admission follow-up: the unchanged 16 MiB record plaintext limit is
now shared with outbox insertion and recovery validation, before hashing or
cloning unsendable entries. Exact-fit/oversized/non-mutation/reopen coverage and
20 channel plus 6 record-layer checks pass. Evidence:
`../evidence/m17q-r1-outbox-plaintext-2026-09-05/`. This preserves the sendable
payload domain; aggregate encoded/physical outbox capacity, bounded recovery
allocation and incremental persistence/service remain open. No whole finding
or release gate is closed by this boundary repair.


Outbox memory follow-up: immutable shared entries and fixed-buffer fallible
encoding preserve v2 bytes while removing whole-payload staging/serialization
copies. Positive old-format and negative writer-error coverage is retained in
`../evidence/m17q-r1-outbox-streaming-2026-09-05/`. Full-file recovery and snapshot
disk rewrites, aggregate physical capacity and service/refinement remain open.


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

The allocated-index sub-obligation for 006/011/012 is indexed by
`evidence/m17q-r1-index-reservation-2026-09-05/`. It includes retained failed
fixture evidence, final source hashes, production boundary tests, conditional
primitive proof, two lower-bound mutations and issued-syscall checks. It does
not close any whole finding; the row's physical payload/metadata/RAM, service,
refinement and immutable qualification/review conditions remain mandatory.

The 006/011/012 payload-data and normal-capacity-error sub-obligations now point
to `evidence/m17q-r1-payload-arena-2026-09-06/normal-capacity/`. This retains exact
current selected source, full-size replacement/recovery/corruption regressions,
capacity/I/O/cleanup controls and the capacity/index primitive proofs. Physical
metadata, RAM, member/consequence custody allocation, rate/service guarantees,
full refinement and clean final-source qualification/review conditions remain
OPEN. No whole finding is closed by this evidence.

Member record-data sub-obligations for 002/005/006 are indexed by
`evidence/m17q-r1-member-reservation-2026-09-06/allocation-charge/`. It binds the
current production source and oversized-allocation quarantine regression. The
parent benchmark has its own earlier source binding and is not a current M16Q
gate. The anchor-reservation draft is unlinked/untested. No whole finding closes;
metadata/anchor/handoff/consequence/RAM/service, full refinement and immutable
qualification/review conditions remain mandatory.


The member anchor-data follow-up for 002/005/006 is now integrated and indexed
by `evidence/m17q-r1-anchor-reservation-2026-09-06/`. The previous unlinked-draft
note is historical. Active-anchor authentication precedes preparation; live
record durability precedes reserved anchor exchange and directory sync; both
precede memory/reply. Its scoped source-bound test/proof/syscall results must be
read with their retained failures and limitations. No whole finding closes;
metadata/handoff/consequence/RAM/service, full refinement and immutable
qualification/review conditions remain mandatory.


Handoff final-continuation/recovery sub-obligations for 002/005/009 are indexed by
`evidence/m17q-r1-handoff-final-fence-2026-09-06/`: exact deadline outcomes,
nonmutation, authenticated unreachable-state refusal, restored production
negative controls and the conditional install/recovery kernel. This does not
close a whole finding. The subsequent handoff reservation work requires its own
source binding and qualification before being relied on.


Exact pre-live handoff-data sub-obligations for 002/005/006/009 are indexed by
`evidence/m17q-r1-handoff-reservation-2026-09-06/`: intact capacity before live
consumption, retained inode charge, preparation without authority, recovery and
issued state/anchor sync ordering. All whole findings remain OPEN. Physical
metadata, RAM, consequence allocation, aggregate service/recovery, cross-root
retention, complete refinement and immutable qualification/review still apply.


The handoff custody-ancestry sub-obligation now points to
`evidence/m17q-r1-handoff-reservation-2026-09-06/ancestry/deep-custody/`, which
passes the isolated intermediate-custody sync control and all its declared
source-stable scoped checks. This supersedes the parent collector error and
broader ancestry control, without superseding any whole-finding closure gate.


Consequence sub-obligations for 005/006/010 now reference
`evidence/m17q-r1-consequence-trace-bound-2026-09-06/`: rooted trace count,
fixed-adapter evidence/read bounds, canonical-byte-preserving hash memory
improvement and the derived named-profile receipt ceiling. Their separate
source revisions and conditional proofs do not close physical preallocation,
incremental persistence, predecode memory, full service/retention/refinement or
any whole finding. All clean R2, immutable review and admission conditions remain.

Endpoint sub-obligation index (005/006/010, all whole rows OPEN): production
`consequence/resource_reservation.rs` plus both executor preparation call sites;
specification and conditional ReservationSafety mapping above; regressions
`online_pq_endpoint_consumes_reserved_inode_and_retains_active_authority` and
`endpoint_reservation_refuses_lost_capacity_and_recovers_only_uncommitted_staging`;
mandatory `endpoint_reservation` syscall gate. Closure still requires all row
obligations, clean full R2 and fresh exact-candidate reviewer disposition.

Receipt sub-obligation index (005/006/010, whole rows OPEN):
consequence/receipt_reservation.rs, prepare_online_storage in both executor
paths, AFTCR001 specification and conditional ReservedIndexSafety mapping;
positive shrinking-payload/two-inode and own-online execution regressions,
negative lost-capacity/non-mutation/quarantine/corrupt-active regressions;
mandatory receipt_reservation syscall gate. Remaining production work includes
rooted aggregate manifest admission and capacity feasibility, predecode RAM,
metadata and service bounds. Closure requires every whole-row obligation and
clean R2/fresh exact-candidate independent disposition.

Policy v6 extends the same 006 row with shared rooted consequence format/charge
coefficients and checked per-effect arithmetic. Mandatory evidence includes the
independently encoded policy vector, missing-field mutation, full-budget/overflow
types regression, all current core/runtime checks and final-source R2. Aggregate
manifest/admission accounting remains a production change required for closure.

Locator sub-obligation index (005/006/013; whole rows OPEN):
runtime_finality.rs::committed_consequence_manifest, manifest_from_committed,
rebuild_manifest_index and remember_manifest_locator; QuvManifestLocatorProof
and default full-harness positive/negative gates; one-block-read, wrong locator,
selected corruption, duplicate admission and reopen regressions. Remaining
production changes include bounded admission/retention and startup/index memory
charges; closure still requires full rows, clean R2 and fresh exact-candidate review.

Preparation sub-obligation index (005/006/009/010/013; whole rows OPEN):
prepare_online_effect_checked plus both rooted executor preflights;
QuvEffectPreparationProof, three countermodels, positive/claimed/terminal
regressions, three production omission controls. Evidence:
evidence/m17q-r1-effect-preflight-2026-09-06. Per-placement process storage
non-mutation regression compiled only. Remaining changes: rooted aggregate
admission, physical/service bounds, safe retention and full transition
composition. Closure requires process reproduction, complete whole-row
obligations, clean R2 and fresh exact-candidate independent review.

Continuation ownership sub-obligation (005/006/009/010; whole rows OPEN):
QuvAdmittedContinuationV0 and completion delivery, both effect callbacks,
blocking handoff install; QuvContinuationAdmissionProof and two countermodels;
delivery/cancelled-worker regression and early-release production control.
Evidence: m17q-r1-continuation-admission-2026-09-06. Process reproduction pending.
Remaining production work includes admission before allocation and aggregate
resource/service/retention composition. Closure requires full rows, clean R2
and fresh review of the exact immutable candidate.

2026-09-06 continuation/preparation process outcome: the final scoped campaign
`evidence/m17q-r1-continuation-admission-2026-09-06/process-recovery/admission-diagnostic/`
passes four explicit initial admissions, four signature/storage negatives, all
sole-correct placements, exact recovery/replay, concurrent workload, typed
conflict/non-mutation, unrelated execution and expired-result retrieval. The
strict source-bound checker passes with retained component service/release
checks and 4053.866 ms observed four-way overlap. Sole replies are
288/298/300/297 ms; saturation maximum 2586 ms, all within 4000 ms. Ancestor
startup/unadmitted failures remain retained. Initial admission is now explicitly
proved by the probe before isolation; earlier unadmitted-state root cause is
not established by this later pass. Full R2 and every whole finding remain open.

Receipt leaf custody sub-obligation (002/005/013; whole rows OPEN): directory
entry presence, guarded staging/lock opens; QuvEffectPreparation's absent-state
mapping and reserved receipt private-file antecedent; active/staging/lock alias
refusals with unchanged fixture data, ordinary preparation/reopen/exclusion,
three restored omission controls and mandatory receipt syscall gate. Evidence:
m17q-r1-receipt-custody-2026-09-06/with-lock. Remaining namespace/aggregate
resource/full refinement obligations and final-source R2/review still required.


Queued preparation sub-obligation (005/006/009/010/013; whole rows OPEN):
read-only eligibility inspection, reserve/start split, both executor lock-release
and queue-time committed rederivation paths, admitted handoff worker;
QuvQueuedEffectPreparationProof + three negative models; inspection-write
production control and reservation deadline/ownership regression. Evidence:
m17q-r1-queued-preparation-2026-09-06. Mandatory runtime test-name assertion and
formal census include these checks. Remaining production change: terminal and
reconciliation admission, aggregate rooted physical/RAM/service/retention
profile; remaining proof: all conditional antecedents and complete transition
composition. Closure requires those changes with defensive regressions, full
final-source M16Q R2, and fresh exact-candidate independent review.


Terminal storage sub-obligation (005/006/010/013; whole rows OPEN): final
readmission preserves active/spare bytes and active inode; ambiguous-state
preparation retained. QuvEffectPreparation TerminalReadOnly proof/countermodel,
expired exact-result regression and restored unconditional-preparation control.
Evidence: m17q-r1-terminal-readonly-2026-09-06. Remaining production/proof work:
terminal/reconciliation fair admission, rooted lookup service and aggregate
retention/resource bounds. Closure still requires whole rows, clean R2 and fresh
exact-candidate review. The reservation regression assertion now matches its
actual test namespace; earlier scoped evidence did not exercise the full runner.


Receipt admission sub-obligation (005/006/009/010/013; whole rows OPEN): shared
bounded store FIFO, protected active-operation reopen, historical readmission
without current live authority, and queue-time committed-domain rederivation.
Policy-root v7 binds the exact queue constants. QuvReceiptAdmission model maps
onto QuvAdmissionOrder with history as a competing slot; non-FIFO negative,
production shared-capacity controls, cancellation/real-store reopen regression,
and independent root fixture/field-omission control are indexed in
m17q-r1-receipt-admission-2026-09-06. Remaining production and proof obligations:
pre-gate authentication/transport bounds, general service S and both reopen costs,
aggregate committed manifests/metadata/RAM/retention, and full refinement.
Mandatory full R2 must reproduce final-source pressure/restart/deadline campaigns
with these queues. Whole closure still requires the exact immutable review.


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

Registry identity sub-obligation (005/006/010/013; whole findings OPEN): v2
admission reserves the exact ID jointly with canonical manifest state; substituted
IDs and unindexed/unknown schemas refuse without writes. Positive coverage keeps
the original lookup valid and permits an unrelated manifest at the refused
height; two restored guard omissions fail. RegistryUnique and locator/recovery
invariants pass conditional on complete authenticated bootstrap and transactional
commit/discard. Four registry tests, 15 runtime-finality tests, one transaction
cleanup test (successful retry after preserved compiler ENOSPC), CLI, format,
syntax, 10 TLAPS obligations and three countermodels are source-bound in
`evidence/m17q-r1-registry-identity-2026-09-06/`. Remaining production/proof work:
aggregate lifetime/physical admission, safe legacy migration if needed, bounded
service and full transactional transition refinement. Mandatory clean R2 must
include both new named registry regressions and final-source process/recovery
checks. Whole closure requires those obligations and fresh exact-candidate review.

Overlay/registry read barrier (002/005/013; whole rows OPEN): backing-scan errors
propagate before merge selection; failed schema discovery creates no registry
writes. The original iterator fails the precise service regression; two iterator
regressions and readable-bootstrap positive pass. Conditional bootstrap proof:
nine obligations/nine states plus hidden-error negative. Scoped evidence includes
364 API tests (one unrelated legacy chat test ignored), five registry tests,
transaction cleanup, 15 runtime-finality tests, CLI/format/syntax and locator
formal checks. See `evidence/m17q-r1-overlay-scan-2026-09-06/`. Closure still needs
backing-store/transaction crash refinement and final-source R2/review.

Qualification coverage correction: M16Q now invokes the full scheduled formal
corpus instead of seven partial modes that omitted QUV repair obligations. This
includes scheduled proofs, models, negatives, trace replay and timed QUV checks.
Only syntax/census were run after this harness-only change; the expensive full
suite remains deferred until integration. Manual debt from other profiles is
neither counted as passing nor used to admit the online claim.

### Retired process and successor-root history (2026-09-07)

Q-EA7 activation boundary, orchestration side (no R1 row; whole findings
unchanged): a process rooted in the old configuration adopted successor-root
blocks through sync after restarting below the activation height, because the
canonical `ValidatorSetsV1` projection makes the staged successor effective by
height and no sync/gossip path consulted the process-local durable install
gate. The `quv_successor_root_gate` now defers successor-root blocks on a
staged successor until its own gate activates and refuses them on a process
with no successor identity (retirement diagnostic, sync dropped, node
quarantined); startup also consults the durable executed projection. Positive
regression, removed-rule control, standalone disjoint (569 s, max valid reply
888 ms) and overlapping (263 s, 824 ms) handoff campaigns and both evidence
checks passed on the fixed tree; the failed campaign on the unrepaired tree is
retained as the process-level control. The handoff evidence checker now
excuses a missing admission release only for a process whose component log
shows a later startup and no later nonce event (the fixture's armed crash
window). Evidence: `evidence/m17q-r2-retired-sync-2026-09-07/`. This
establishes the orchestration rule for these two campaigns only; it is not a
reconfiguration proof and grants no observer profile to retired members.

### PQ timeout drill bootstrap-window evidence (2026-09-07)

Fixture scope correction, no row change: the mandatory `pq_ordering_restart`
drill rejected a genuine scoped timeout certificate formed for a late-launched
round-robin leader before the drill baseline (launch stagger 33–36 s against
the 30 s view timeout). The drill now requires every embedded certificate to
name its own block height, records pre-baseline certificates, and applies the
scheduled-failure rule only inside the drill window. Evidence and the
rejected clean-run phase: `evidence/m17q-r2-pq-drill-bootstrap-timeout-2026-09-07/`.

### Flood active-service budget resized from measurement (2026-09-07)

Measured cost, no row change: over three retained clean-run flood campaigns
the executor's budgeted release maxima were 10.25 s, 10.20 s and 13.01 s; the
last (on a host under unrelated CPU load with an 11 s finality stall) exceeded
the 13 s budget by 9.5 ms and was correctly declared a service failure. The
flood fixture's continuation is now 11 s (16 s budget); interval, envelope
and failure semantics are unchanged. The executor's runtime-finality critical
section remains an unqualified timing cost, not a guarantee. Evidence:
`evidence/m17q-r2-flood-host-contention-2026-09-07/`.
