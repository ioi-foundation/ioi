# Durable domain head integration — unresolved R1 design boundary

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is [the R1 fault/property matrix](query_unanimity_fault_property_matrix.md); no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

Status: implementation design constraints established from current source. This
is not an implemented head protocol, production refinement proof, or R1 closure.

## Initial source observations (before bootstrap binding repair)

The initial source analysis found AftQuvDomainPolicyV0 provisioning domain identity, authority mode/owner and timing
qualification, but no initial accepted head or initial slot. provisioned_policy_root
commits the domain/authority/timing tuple through quv_policy_root. The native
RootedQuvCandidateValidatorV0 checks only a nonzero predecessor. QuvStoreStateV0
retains candidate snapshots by canonical conflict slot; its authenticated storage
head identifies a file generation, not an accepted candidate in domain history.
These two meanings of head must remain separate.

begin_online_authorization refuses another operation while one is starting or
live. The PQ transport likewise has one active_quv_operation nonce and retires
requests belonging to other operations. A recursive parent verification during
a child operation therefore cannot be added as a local validator callback: it
would be refused, or changing the nonce would disrupt the child operation.

## Required state semantics

Each domain needs an independently rooted bootstrap record containing its scope,
initial slot and initial predecessor, committed by the versioned policy. It must
be loaded before candidate insertion or executor authorization. An absent domain
must not be seeded from the first request. Reopening must compare the provisioned
bootstrap commitment with the authenticated stored scope; a changed bootstrap
must not silently reset an existing domain.

Separate state must record (a) the accepted frontier/next slot, (b) the expected
predecessor for retained historical slots, and (c) the existing complete conflict
snapshots. A storage generation or first-seen candidate is not evidence of live
acceptance. Advancing a frontier requires that this relying member itself has
completed the theorem-bearing live operation for the parent. A received audit,
candidate signature, or another executor's success notification cannot do this.
The durable advance must compare the expected old frontier and atomically retain
the new accepted candidate/next-slot mapping; an error requires authenticated
reopen. Candidate arrival alone never advances the frontier.

Old-slot queries must remain answerable from the retained predecessor mapping
and conflict snapshot. Rejecting every slot below next_slot would erase the live
visibility path needed by another relying executor. Compaction cannot discard
this information merely because the local frontier moved; safe retention depends
on the separately required rooted authority lifetime and retirement proof.

## Protocol integration boundary

Parent preparation must finish before the child executor occupies its live nonce,
or the transport/runtime must first be redesigned and qualified for multiple
independent live operations. The current single-operation lane is not compatible
with recursive child-to-parent verification. No such redesign is implicit here.

A preparation message can request work but cannot certify completion or transfer
parent authority. Each member must independently establish the parent, and the
child's timing/admission model must account for preparation and durable advance.
Rooted admission/fair scheduling is necessary to keep competing preparation and
execution requests within declared intervals. A naive all-members preparation
phase may require quadratic communication; its time and storage costs cannot be
hidden outside the claimed end-to-end authorization bound.

Re-verifying a previously accepted parent also needs an explicit progress proof.
In owned mode the present acceptance rule refuses any disclosed conflict. A later
conflicting owner submission can therefore prevent fresh parent acceptance even
when an earlier executor accepted the parent. This is a limitation of naive
re-verification, not a reproduced impossibility result for the interactive target.
The integration must adjudicate this schedule against the exact conditional
liveness claim; it must not silently count refusal as history progress or switch
acceptance rules without new proof and qualification.

The executable `OwnedParentReverification.tla` boundary model now isolates that
schedule. With one durable correct witness, silent Byzantine peers, two possible
valid owner values and two sequential atomic completed queries, TLC checks
accepted-value non-conflict and singleton progress over all 22 reachable states.
The deliberately stronger `PriorAcceptancePersists` property fails on
Query(A)/accept, Introduce(B), Query(A)/abort. The negative configuration checks
the two admitted invariants as well and requires this specific stronger-property
failure. This is not a production mutation, a concurrent-operation proof, or an
impossibility result for interactive head transfer.

Q-T4 quantifies over a singleton introduced candidate set for the operations
under consideration; the witness has two introduced candidates and therefore
does not contradict Q-T4. Q-E1 assumes the durable accepted append rule Q-EA2;
it does not supply a discovery or preparation protocol implementing that rule.
Consequently neither prior acceptance alone nor Q-E1 authorizes treating fresh
parent preparation as guaranteed successful. Production head integration and
its conditional progress proof remain required.

Reconfiguration must explicitly carry and validate domain frontier state through
each successor's own live handoff. The existing handoff-domain initial predecessor
is a commitment to the old boundary state, not automatically a bootstrap for all
effect-domain histories. No assumed equivalence between those objects is allowed.

## Required implementation evidence

The implementation must pair independently provisioned bootstrap, atomic live-
acceptance frontier advance, retained old-slot query handling, crash recovery,
and executor head matching in one transition model. Tests must cover absent and
changed bootstrap, skipped/repeated slots, predecessor mismatch, restart at each
advance boundary, retained conflicts, competing parent preparation, and successor
activation. The parent-preparation schedule and any changed protocol semantics
must be proved before their timing/inclusion claims enter qualification.

R1 001 remains open. Existing passing first-slot process campaigns do not satisfy
this integration. No extra trusted relay, portable parent receipt, majority
assumption, or authority from silence is authorized by this design note.

## Executable frontier transition design

`formal/maximal_visibility/QuvHeadPreparation.tla` now models independently
rooted genesis/slot 1, per-correct-member durable histories and retained slot
snapshots, process-local live grants, atomic frontier advance, and grant loss
on crash. Query checks every correct member's expected predecessor before
insertion. A local accepted query creates only that relying member's grant;
Advance compares its slot and predecessor to the current local frontier.
Old-slot queries remain admissible after advancement. Candidate arrival alone
does not advance history.

TLC checks one-correct and two-correct configurations through two slots (70
and 522 reachable states respectively): prefix compatibility, retained
knowledge, no future-slot insertion, and historical-query admissibility. A
required reachability probe retains a schedule in which both correct members
independently query and advance each slot. This rules out a vacuous frozen
model, but is an existential schedule, not a liveness or fairness theorem.

The Query transition abstracts a complete local live operation into one
atomic action, with silent Byzantine peers. Durable state writes are atomic
and non-rollback by assumption. It does not refine concurrent network
operations, error recovery, continuations, expiry, admission, or T10; it
does not prove the preparation scheduler fits the rooted time envelope.
Configuration and genesis are fixed, so reconfiguration and changed-bootstrap
rejection are not modeled here. These remain explicit production/refinement
requirements. The existing handoff path obtains its initial predecessor from
the locally verified boundary; a future bootstrap encoding must represent
that provisioned rule rather than infer an effect-domain head from it.

Evidence: `evidence/m17q-r1-head-transition-model-2026-09-05/`. The first model
run had a TLC mixed-type sentinel error, retained separately; the final model
uses a uniform grant record and passes. No production head enforcement has
been added by this model.

## Interleaved operation transition model

`QuvHeadInterleaving.tla` splits the atomic Query abstraction into Begin,
Capture, Observe and Decide, followed by the existing Advance. Capture writes
a correct member's candidate set before retaining its operation snapshot;
Observe can occur later, interleaved with another relying member's operation.
Decide requires observations from every correct member and applies the owned
singleton-snapshot rule. Each process has at most one live operation. Crash
clears that process's operation and grant while preserving all durable state.

The configurations check two correct members with two competing values at one
slot and at two slots. In addition to history prefix/retention properties, they
check that observed replies were captured, captured knowledge remains durable,
and live accepted grants agree with one another and with durable history. The
required completion probe reaches both members' two-slot histories through the
interleaved transitions; this remains an existential trace, not a fairness or
termination result.

| Model action or premise | Production connection and outstanding obligation |
|---|---|
| Begin | `begin_online_authorization` enforces one live local operation; rooted expected-head admission is still absent |
| Capture | `DurableQuvMemberV0::process_push` implements write-before-reply; durable expected-head validation is still absent and filesystem atomicity/refinement remains open |
| Observe | `QuvVerifierOperationV0::observe_reply` records replies; model assumes exact operation routing and authenticated correct identities, leaving the full nonce/PQ process qualification open |
| Decide | `finish_at` applies owned conflict-union validation; complete timely correct-member observation is a premise here, not a runtime count of known-correct members |
| Advance | Own accepted grant, expected predecessor and next-slot comparison are explicit model transitions; production durable frontier advancement is still absent |
| Crash | Durable histories/snapshots survive and local grants disappear; no filesystem recovery, rollback custody, deadline, expiry or T10 claim refinement is inferred |

This is a finite owned-mode design check with silent Byzantine peers and fixed
roots. It supplies neither unowned-mode refinement nor the scheduling protocol
that makes every required correct-member Capture timely. Evidence and exact
source hashes: `evidence/m17q-r1-head-interleaving-2026-09-05/`.

## Unowned first-seen extension

The interleaved model now selects the rooted AuthorityMode explicitly. Capture
atomically retains a per-member/per-slot firstSeen value if the slot was empty,
and records that value in each captured reply. Later insertions and crashes
preserve it. Owned Decide still requires singleton candidate snapshots; unowned
Decide requires every captured first value to equal the operation's candidate,
matching the distinct production branches in `finish_at`. Neither first-seen
arrival nor a reply by itself advances an accepted history.

Additional invariants check that a nonempty slot retains its first value and
that every captured first value remains equal to durable firstSeen and belongs
to its captured snapshot. With two values and two slots, unowned-mode TLC
checks 75,249 reachable states for two correct members and 171 for one correct
member. Owned mode was rerun with this extra state (27,217 two-slot states).
Both modes retain independent interleaved two-slot completion traces. These
are finite safety/reachability checks with silent Byzantine peers, fixed roots,
ideal operation routing, complete correct observation, and atomic non-rollback
storage. They do not establish production head enforcement, scheduler progress,
rooted time bounds, handoff, or full runtime refinement.

Evidence: `evidence/m17q-r1-head-unowned-model-2026-09-05/`. Earlier owned-only
model evidence remains tied to its original source hashes; its counts are not
reused as evidence for this extension.

## Conditional preparation progress and grant preservation

`QuvHeadProgress.tla` checks the temporal property that every correct history
eventually reaches the configured two-slot endpoint, for singleton inputs and
both authority modes. It inherits the interleaved Capture/Observe/Decide model
and its storage/routing premises, excludes crashes, and assumes weak fairness
separately for each process's Begin/Decide/Advance and each member's
Capture/Observe action. These are explicit model premises; production fair
admission and bounded service remain unimplemented/unqualified.

The positive model prevents Begin from replacing a still-present accepted
grant. This leaves Advance continuously enabled until serviced. TLC checks
AllHistoriesAdvance over 353 states in each mode. The negative configuration
removes only that protection. Its 407-state graph contains a weakly fair cycle
where one member repeatedly completes a query and starts another, discarding
the grant before advancement while the other member has finished. Because
Advance is only intermittently enabled, weak fairness alone does not exclude
this cycle. The runner requires the named temporal-property violation and
retains its full witness.

The future preparation scheduler must preserve a completed grant until its
frontier transition, or supply a separately proved alternative. This check
does not require changing Q-T4: it concerns the additional preparation
implementation needed for Q-EA2. It is not a production exploit, a general
interactive impossibility result, an arbitrary-size induction proof, or a
rooted deadline guarantee. Expiring process-local grants, crash/retry recovery,
and synchrony-qualified scheduling must still be integrated before production
progress can be claimed. Refusal/retry is never counted as advancement.

Evidence: `evidence/m17q-r1-head-progress-model-2026-09-05/`. The initial run
found the intended temporal violation but the harness expected a generic
message; the final harness matches the exact AllHistoriesAdvance diagnostic.
Both outputs are retained.

## Production bootstrap commitment implemented (partial R1 001)

The configuration now requires QuvDomainBootstrapV0, explicitly selecting Fixed
initial slot/predecessor or the owned HandoffBoundary activation rule. The
versioned policy hash commits it; runtime provisioned_policy rejects initial
coordinate mismatches before processing/admission. Typed handoff source and
local certified-boundary checks apply to both old-member and staged-successor
requesters. This replaces the initial source observation above that policies
had no bootstrap input.

The member store still lacks the durable accepted frontier, retained historical
expected-predecessor map, and stored-bootstrap comparison. Later Fixed slots
still need that mechanism. The model's Advance/preparation scheduler remains
unimplemented. No first-seen candidate or storage hash is promoted to an
accepted head. The policy-root break requires fresh qualification; no migration
or reconfiguration continuity is claimed by this change.

Evidence: `evidence/m17q-r1-rooted-bootstrap-2026-09-05/`.

### Stored-bootstrap integration points

Read-only audit after the bootstrap commitment repair identified both member
store constructors: lifecycle.rs for initial startup and quv.rs for successor
activation. They still receive only paths and a custody key. Configuration/
account-scoped storage paths stay the same when policy changes, and schema 3
contains no stored bootstrap registry. A future registry comparison must run
after authentication but before pending generation+1 recovery writes the
anchor; otherwise rejecting changed configuration can still mutate the store.
Successor registry enrollment must not reset an existing accepted effect-domain
history to its Fixed bootstrap. Evidence: storage-integration-audit.json in
`evidence/m17q-r1-rooted-bootstrap-2026-09-05/`. These are implementation
obligations established by inspection, not a completed repair or reproduction.

### Authenticated provisioning commitment (partial implementation)

Member schema 4 now authenticates a provisioning root committing network,
configuration and the canonical complete domain-to-policy-root map. Each
policy root includes its typed bootstrap. Both initial startup and successor
activation derive this commitment from provisioned configuration, never from
the request. Reopen authenticates state and anchor, compares the expected
provisioning root, and only then permits pending generation+1 anchor recovery.
A mismatch leaves both retained files unchanged. Empty/zero/duplicate policy
scopes are rejected; policy ordering does not change the commitment. Schema 3
member stores have no automatic conversion or fallback. Handoff store format
is unchanged.

This implements stored-bootstrap comparison through a cryptographic scope
commitment. It does not add accepted frontier state, retained historical
predecessors, the preparation scheduler or successor history transfer. A new
successor-scoped member store still must not be treated as proof of inherited
effect-domain history. Earlier process results bind earlier source revisions;
this schema/API change requires fresh qualification. Evidence:
`evidence/m17q-r1-member-provisioning-2026-09-05/`.

### Local completion and advancement reservation

Read-only inspection after schema 4 identifies an additional integration point:
`finish_operation` removes the pending operation under the context lock and
releases the transport nonce before constructing and sending the live result.
The oneshot receiver may disappear. `begin_online_authorization` currently
reserves only starting/live operations; it has no frontier-persistence phase.

Consequently a future Advance cannot be implemented solely by a downstream
receiver. The runtime must retain ownership of the accepted grant and reserve
its finishing transition until durable advancement completes or persistence
uncertainty requires authenticated reopen. The consensus-local transition must
check expiry and the exact expected old frontier immediately before writing;
it must expose the new head only after durability. A process can then forward
its remaining effect authorization under the existing immediate T10 checks.
This is a required implementation contract, not a claim that it exists today.
The grant-preservation temporal model already demonstrates why replacing an
unconsumed grant on a new Begin is insufficient under weak fairness.

Each other correct member must still complete its own parent preparation.
Neither the local Advance nor receipt delivery supplies that authority. The
current single-operation transport requires preparation to finish before child
admission, with its cost included in the qualified service envelope. Evidence:
`evidence/m17q-r1-member-provisioning-2026-09-05/frontier-integration-audit.json`.

### Candidate-triggered independent preparation model

`QuvHeadTriggeredPreparation.tla` restricts new singleton inputs to one
initiating member. Another member can begin only after that candidate appears
in its durable snapshot for its next slot. Reception schedules an independent
local query; it never creates a grant or advances history. Existing complete
Capture/Observe/Decide and own-grant Advance transitions remain unchanged.
A completed grant is preserved until advancement.

Both authority modes pass AllTriggeredHistoriesAdvance over 232 reachable
states for two correct members and two slots. Disabling only automatic
preparation yields the required temporal failure over 15 states: the initiator
advances once and waits on the next slot while the other member, although it
retains the first candidate, never performs its own query or advances. This
supports a candidate-triggered preparation design, not authority from received
bytes. No failure is counted as history progress.

The model assumes singleton inputs, fixed roots, no crashes, atomic non-rollback
durable writes, ideal authenticated routing, and per-action weak fairness.
An inadmissible future Capture can remain pending until the member catches up;
production requests currently refuse instead. Therefore bounded retry,
queue admission, timers, continuation expiry, competing domains, resource
budgets and handoff remain explicit unimplemented/unproved refinements. This
finite temporal check is not a production scheduler, arbitrary-size progress
proof, or qualified latency guarantee. Evidence:
`evidence/m17q-r1-triggered-preparation-2026-09-05/`. The full formal runner
includes both positives and the named negative, with a focused
`--quv-triggered-preparation-only` reproduction option.

### Accepted-history transition core (not yet persisted or runtime-enforced)

`QuvAcceptedHistoryV0` stores an independently provisioned initial coordinate
and an ordered vector of accepted candidate hashes. It derives the predecessor
for retained historical slots and the next slot, rejects earlier/skipped slots
and mismatched scope, and preserves old coordinates after advancement. Its
staged transition accepts only a process-local QuvOnlineAuthorizationV0 and
checks continuation expiry, scope/predecessor, exact historical idempotency and
capacity before changing the in-memory history. A terminal u64 slot is retained
without wrapping the next slot. Neither candidate arrival nor encoded history
or an audit can call the live-grant transition as authority.

This is an implemented transition primitive, not production history enforcement.
Member schema 4 does not yet persist this structure or check it on insertion;
runtime completion does not yet reserve or commit Advance. Independently
provisioned per-domain enrollment, authenticated encoding and recovery,
pre-write capacity, member/executor checks, candidate-triggered preparation and
successor frontier transfer are still required. The existing initial-slot
process passes do not discharge those obligations. R1 001/002/005/006/009 remain
open as complete findings.

Tests cover both authority modes, bootstrap and scope substitutions, historical
queries, two successive live grants, repeated/conflicting grants, expiry before/
equal/after the local cutoff, canonical encoding and the terminal slot. Removing
the predecessor/admissible-slot check causes the named regression to fail;
the exact source was restored. Evidence:
`evidence/m17q-r1-accepted-history-core-2026-09-05/`.

### Member schema 5 and local runtime advancement

Member schema 5 now authenticates an explicitly enrolled domain map alongside
candidate snapshots. Fixed domains contain QuvAcceptedHistoryV0; one-shot
handoff domains contain the provisioned activation scope and still require the
runtime's independently verified local executed boundary. The one-shot zero
predecessor is only an internal rule placeholder and is never accepted in a
request or promoted to history. Both production constructors derive enrollment
from configuration. Incoming candidates cannot enroll a domain. Startup rejects
non-initial enrollment and compares every stored bootstrap after authentication
but before pending anchor recovery; it does not import encoded accepted history
as a bootstrap. No schema 4 migration or fallback is provided.

Fixed-domain PUSHQUERY insertion and local executor start now check the exact
retained/next-slot predecessor and rooted scope. Accepted advancement requires
the member's process-local live grant and an already retained matching candidate
snapshot. It preflights exact encoded growth before cloning, stages the append,
serializes/authenticates the new state, rechecks expiry, and durably writes state
then anchor before exposing the new head. A persistence error quarantines the
instance until authenticated reopen. Exact historical advancement repeats are
idempotent; historical queries continue disclosing retained snapshots.

Runtime completion now reserves local admission while finishing and committing
the accepted Fixed-domain history. It holds the grant through that commit even
if the oneshot result receiver disappears, then releases the transport operation
and forwards the grant for the independent immediate T10 checks. The dedicated
handoff install gate remains responsible for one-shot handoff acceptance.

The core suite passed 32 tests (one separate component benchmark ignored in that
suite), including both modes, future-slot refusal without writes, two accepted
steps, historical queries, changed-enrollment refusal at synchronized/pending
anchors, exact byte headroom, persistence-error quarantine/reopen, and all-byte
corruption over an advanced history. Initial fixture failures are retained: an
unowned I/O fixture had been opened under an owned domain, and the old predecessor
substitution fixture expected insertion. They now enroll the intended fixture
scope and assert early refusal while retaining the canonical-slot and genuine
same-coordinate conflict checks. Runtime policy tests and CLI compilation passed.

This implements local history enforcement, not complete multi-member progress.
Candidate-triggered independent preparation, bounded retries, per-domain fair
admission, rooted service/storage quotas, incremental storage and successor
frontier transfer remain unimplemented/unqualified. A successor's newly scoped
Fixed bootstrap is not proof of inherited accepted history. The schema 4 process
results remain historical evidence for their exact source hashes. No schema 5
process qualification, full transition refinement, whole R1 closure or R2
admission is claimed. Evidence: `evidence/m17q-r1-durable-history-2026-09-05/`.

### Bounded preparation before child admission

`QuvHeadPreparationTiming.tla` isolates the timing obligation omitted by the
weak-fairness preparation models. At time zero the initiating member has its
own accepted parent grant, so the prior complete-processing premise supplies
durable parent-candidate knowledge at every correct member. Each other member
still needs its own query and durable parent commit. The model explicitly
assumes those local services complete within PreparationBound and that child
requests are delivered inside their decision interval. It does not prove a
production scheduler or derive that service bound.

Allowing child admission immediately produces the required
CompleteCorrectProcessing failure: a correct member receives the child before
its parent history is ready and refuses it. Waiting through the preparation
bound passes this finite check, and a separate required witness reaches a
completed child. This is a failure of the complete-processing premise in an
unprepared execution, not two conflicting accepts or an impossibility result
under Q-A3. Timely reachability alone does not imply timely admissible insertion.

The implementation therefore needs both independent preparation and a locally
rooted child-readiness rule. A delay alone is insufficient while preparation is
absent. Its service budget must be derived from bounded/fair admission, active
operation service, each own live query and durable frontier commit, including
clock error and restart behavior. A remote timestamp or transcript cannot set
that authority. Reopen must recover pending work from retained snapshots and
reestablish the local readiness delay; it cannot assume a volatile worker
survived. Every child executor still performs its fresh live QUV operation.

The finite model uses an ideal shared clock, fixed roots, two correct members,
one parent/child and no crashes or competing domains. Its bounded-service tick
constraint is an explicit assumption awaiting production refinement. It does
not establish latency, inclusion, queue fairness or handoff. The full formal
runner and M16Q head/preparation phase include the positive, no-wait negative
and completion witness. Evidence:
`evidence/m17q-r1-preparation-timing-2026-09-05/`.

### Recoverable preparation selection

The member store can now select one pending preparation candidate from its
authenticated retained snapshots, rotating after a supplied domain cursor.
It considers only the next unaccepted Fixed-domain slot. Already advanced
historical slots and one-shot handoffs are excluded. An owned snapshot with a
locally disclosed conflict is preserved but not selected for a futile fresh
owned query; an unowned snapshot retains first-seen order. A quarantined store
refuses selection until authenticated reopen.

Selection is read-only and does not create a grant, advance a head, mark a child
ready, or create a durable authorization from received bytes. A caller must
still independently validate and query the selected candidate. Restart tests
recover the same pending work without a volatile queue; rotation tests cover
two domains, historical duplicates, no state/anchor writes, both authority
modes and handoff exclusion. Replacing the next-slot filter with the initial
historical slot makes the advancement/selection regression fail; source is
restored afterward.

This is a scheduler input primitive, not the production worker or a fair-service
proof. A scan can visit every configured domain, so its cost belongs in the
pending admission/storage qualification. The worker, bounded attempt/service
policy, child readiness, restart timing and successor history transfer remain
open. Evidence: `evidence/m17q-r1-preparation-selection-2026-09-05/`.

### Explicit rooted preparation policy

AftQuvDomainPolicyV0 now requires QuvPreparationPolicyV0 with no serde default:
Independent for Fixed histories, or OneShot for handoff-boundary domains.
Independent commits max_attempts_per_slot, service_millis and readiness_millis.
Local syntax requires a nonzero attempt count, service longer than the live
query interval but no longer than query plus continuation, and readiness at
least the checked product of attempts and service. Incompatible kinds, missing
fields and arithmetic overflow refuse. These are necessary local consistency
checks, not a cross-domain queue-service proof.

The canonical policy-root domain is now `ioi/aft/quv-policy/v2-preparation` and
includes the entire preparation policy. Runtime derivation and all typed fixtures
use the new root. No old-root conversion, inferred policy or fallback is supplied;
changing these settings changes the authenticated member provisioning commitment.
At that policy-binding increment, member schema remained 5 and handoff schema 3;
the subsequent durable-attempt increment below uses member schema 6. Fixtures currently supply
explicit, generous preparation budgets for implementation tests; these are not
calibrated or qualified scheduling measurements.

Root tests vary each preparation limit independently and reject invalid budgets;
configuration tests cover required JSON/TOML fields and incompatible preparation.
Removing preparation from the root preimage makes the new binding regression
fail while syntax checks remain enabled; the source was restored afterward.
Evidence: `evidence/m17q-r1-rooted-preparation-policy-2026-09-05/`.

Durable attempt reservation, the worker, enforcement of service/readiness limits,
aggregate fair admission, restart timing and qualification are still missing.
Merely committing a budget does not make a member ready or authorize a child.
R1 001/005/006/009 remain open as complete findings. The earlier process results
remain bound to their old policy-root/source revisions and do not admit this
changed candidate.


### Accepted-history snapshot retention — 2026-09-05

Every accepted entry now has a recovery-time snapshot membership check.
Candidate-to-history validation alone misses a deleted historical snapshot or a
substituted final accepted candidate. The reverse check rejects these states
before anchor recovery. It scans retained accepted entries and hashes candidate
snapshots; this extra recovery cost remains unqualified at capacity. There is no
schema change, pruning mechanism, portable authorization or worker implementation
in this increment. Evidence: `../evidence/m17q-r1-history-retention-2026-09-05/`.


### Durable preparation-attempt reservation — 2026-09-05

The member store now uses schema 6 with a BTreeMap from domain to next-slot
coordinate and u16 spent-attempt count. reserve_preparation_attempt accepts a
retained candidate and full configured policy, recomputes the v2 policy root,
checks the enrolled next coordinate and rooted maximum, and durably increments
before returning. No bare caller-supplied limit is trusted. This API grants no
execution authority and does not start network work.

Accepted advancement removes the prior counter in the same authenticated state
transition; projected byte admission accounts for this removal before cloning.
Exact historical replay returns without clearing a next-slot counter. Reopen
checks counter structure and MAC before pending-anchor reconciliation. A failed
persistence attempt quarantines the instance; recovery never intentionally
refunds an attempt. No schema-5 migration is offered.

The worker must call this API before network work and rotate past exhausted
budgets without claiming completion. Its scheduling, aggregate fairness and
service/readiness enforcement remain unimplemented. Whole-store cloning and
encoding remain, and at-capacity costs are unqualified. Evidence is retained at
`../evidence/m17q-r1-durable-preparation-attempts-2026-09-05/`.


### Runtime preparation worker — 2026-09-05

The lifecycle now owns one event-driven preparation worker. It scans immediately
for crash-retained work, keeps a process-local rotation cursor, and wakes after
member durable work and executor completion. Selection and reservation use the
store serializer on blocking workers. The common begin path validates the rooted
candidate and reserves the sole local operation before durably spending an
independent attempt; only then does it open the transport reply epoch.

The worker awaits the same completion/head-persistence path as other executors.
It does not externally consume the returned grant. A refused candidate is skipped
within the current domain sweep; spent attempts survive restart. Waking is not
readiness. Aggregate fair admission, service deadline enforcement, restart
readiness delay and timely child acceptance remain to be implemented and proved.
A process campaign is pending; compilation alone supplies no process evidence.


### Queued foreground/preparation admission — 2026-09-05

The initial idle-flag worker failed the foreground conflict campaign with a
generic busy refusal. Runtime operation ownership now uses a queued semaphore
permit; an external domain can have one waiting foreground request, and the
single preparation worker shares that queue. Authority is checked before queuing,
then current roots/head are checked again after admission. Pending operations own
the active permit through durable completion. Queued cancellation releases its
waiting-domain permit. The worker joins the queue rather than polling an idle flag.

The queue regression tests check exclusivity, both ordering directions and
cancellation. Relaxing either active or waiting capacity to two fails them. The
new process campaign is pending. No service/readiness deadline is yet enforced;
logical queue order cannot by itself establish the timing model's bound.


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

Pending operations now own dispatch state alongside their operation permit and
live verifier. Dispatch state starts with the full configured set and records
successful local completion using the verifier's monotonic clock. Cancellation
cannot clear outstanding recipients. Finalization checks this state before calling
the live verifier; missing/late completion therefore cannot reach head advancement.

Remote completion means durable local outbox admission, not delivery. Local
completion means successful member write-before-reply. The complete rooted
end-to-end processing assumption remains necessary. This guard prepares the
runtime for cancellation during bounded service, but service enforcement and
child-readiness logic are still absent. Evidence is retained at
`../evidence/m17q-r1-dispatch-completion-2026-09-05/`.


### Rooted active preparation service — 2026-09-05

Active preparation service begins immediately after the worker obtains the
sole-operation permit. Its rooted duration is captured during prior policy
validation, and admitted work revalidates current roots/head under that deadline.
The startup/dispatch future can be canceled safely because incomplete dispatch
blocks finalization. The worker's grant is consumed into a cap that cannot extend
its original expiry. Store advancement checks the cap before its first write.
Finalization reports late completion as failure even when a validly started
atomic write finishes and advances durable history after the budget expires.

The active limit is not the aggregate readiness bound: selection, queued work,
foreground service, retries, restarts and full storage cost still need bounded
composition and qualification. Child readiness remains unimplemented. Evidence
is retained at `../evidence/m17q-r1-active-service-2026-09-05/`; its process campaign
is pending and earlier process evidence does not qualify this revised source.


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
