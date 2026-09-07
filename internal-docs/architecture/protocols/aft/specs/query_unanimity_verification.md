# Query-Unanimity Verification (`aft_quv_v0`)

Current profile (2026-09-06, R1 remediation toward the R2 candidate): policy root `ioi/aft/quv-policy/v8-push-admission`; member store schema 9 (journal records `AFTQJ001`, anchors `AFTQJA01`); handoff store schema 3; PQ outbox logical schema v2 inside `AFTPQI04` reserved envelopes with `AFTPQI05` indices and `AFTPQA01` payload arenas; consequence receipt envelope `AFTCR001`. This header is the single authoritative version statement for this document: dated sections below are retained history, and wherever one of them says a root, schema or format is "now" or "current", this header supersedes it. The single closure index is [the R1 fault/property matrix](query_unanimity_fault_property_matrix.md); no whole R1 finding is closed until the exact R2 candidate passes clean full M16Q and fresh independent review.

Status: M12b R4 received an independent automated `PASS_CONSTRUCTION`; M13Q and
M14Q are locally proved/mechanized and await M17Q independent review. M15Q is
in progress. This document creates no production or public consensus claim.

Date: 2026-09-03.

## 1. Result being attempted

QUV is a participant-interactive authorization primitive for a fixed rooted
configuration. It attempts this conditional result:

> With at least one correct member, known end-to-end verifier/member
> synchrony, and durable monotone member conflict state, no two honest executors
> accept conflicting candidates for one conflict-domain slot; when exactly one
> valid candidate exists, every honest executor that can reach every correct
> member within the bound completes the online check despite permanent silence
> from all Byzantine members.

This is not yet a consensus theorem. M13Q must define and prove how proposal,
validity, member decision, ordering, and termination compose with this online
authorization operation for arbitrary `n`.

## 2. Model and assumptions

Let `P` be the rooted configured membership, `n = |P| >= 2`, and let `H` be the
unknown set of correct members. The target tolerance is `|H| >= 1`, equivalently
`f <= n - 1`.

The result depends on all of the following:

| ID | Assumption | Class |
|---|---|---|
| Q-A1 | Rooted member and authority signatures are unforgeable and domain separated | cryptographic |
| Q-A2 | Every honest executor sends its complete request directly to every member in the rooted configuration | network |
| Q-A3 | For every honest executor operation and every `c in H`, request delivery, admission/queueing, validation, atomic durable processing, response delivery, and maximum clock error complete within rooted `delta_rt` | timing and availability |
| Q-A4 | Each correct member linearizes requests per `(configuration, domain, slot)` and durably writes before it signs the corresponding reply | storage |
| Q-A5 | Correct conflict knowledge is grow-only, survives restart, cannot roll back, and is retained and reachable for the authority lifetime | storage |
| Q-A6 | Every honest executor performs QUV itself immediately before irreversible externalization and never trusts a cached assertion that another verifier waited | execution |
| Q-A7 | Candidate validity and authority are fixed by the independently provisioned root; local arrival, timeout, and silence create no candidate authority | authorization |
| Q-A8 | During one live operation, the verifier admits at most the first authenticated response from each rooted member, then validates its exact binding and signature; a correct member emits exactly one valid response, while later Byzantine duplicates are irrelevant to Q-S1 | verifier |
| Q-A9 | Admission control reserves enough authenticated capacity for every correct member to satisfy Q-A3 despite Byzantine query traffic | resource/timing |
| Q-A10 | The fault assignment is static for the rooted configuration and authority lifetime; the result does not tolerate a mobile adversary that later corrupts the last correct state holder | adversary |

Q-A3 is a safety assumption. If the correct reply may arrive after the
deadline, two conflicting accepts are possible. The claim is therefore not
asynchronous safety and not eventual-synchronous safety before an independently
established bound is active.

Every production domain configuration also declares
`qualified_delta_rt_envelope_millis` and
`qualified_max_configured_members`. These are deployment-local operator
assertions backed by retained M16Q measurements, not portable proof that Q-A3
holds. Startup fails closed when the time envelope is zero or exceeds rooted
`delta_rt`, or when the membership envelope is zero or exceeds the v0 protocol
cap. The executor and member paths also refuse an active rooted configuration
larger than the qualified membership envelope.
Changing that assertion does not change the protocol policy root: the policy
root commits the actual decision interval, while the deployment envelope says
whether the current installation has measured enough room to use it.

The construction uses no relay, external selector, TEE, DKG, majority custody,
or trusted identity naming a correct member. It does assume direct executor
reachability to every correct configured member within the bound and does not
turn that timing fact into portable evidence. Requiring merely a possibly
different timely correct member for each operation is insufficient: opposite
serialization orders at two correct members permit conflicting accepts.

## 3. Rooted objects

Every candidate `s` binds:

```text
protocol = "aft_quv_v0"
configuration_root
policy_root = H("ioi/aft/quv-policy/v8-push-admission", domain_id, authority_mode, rooted_owner, delta_rt,
                continuation_bound, typed_bootstrap, preparation_policy, operation_service_bound,
                authority_slots, push_admission{max_requests_per_identity: u32, window_millis: u64},
                2_u64, 4096_u64, 8192_u64, 536870912_u64,
                (1024_u64, 16777216_u64, 2_u64, 16384_u64, 32768_u64),
                ([1_u64, 16777216_u64, 4_u64, 16384_u64, 81920_u64, 4_u64,
                 512_u64, 32768_u64, 32_u64, 4096_u64, 2_u64, 2_u64, 1_u64,
                 2_u64, 4096_u64],
                 [1_u64, 1_u64, 1_u64, 1_u64, 1_u64]))
network_id
domain_id
slot
predecessor
authority_mode
payload_hash
authority_signature
```

An owned slot admits only candidates authorized by the rooted owner policy. An
honest owner signs at most one candidate for a slot. An equivocating owner may
sign conflicts; those signatures are attributable evidence.

An unowned slot may admit independently authorized candidates. It uses the
first valid candidate linearized by each correct member as that member's
winner. Different correct members may initially choose different winners; this
can make all candidates reject, but cannot make conflicting candidates both
accept under the verifier rule below. Unowned liveness is promised only when
there is one valid candidate and no valid conflict is injected.

## 4. Correct-member state machine

Each correct member `p` stores, for every rooted conflict slot:

```text
K_p[configuration_root, policy_root, network_id, domain_id, slot,
    authority_mode] = ordered grow-only valid candidates
```

The conflict key deliberately excludes `predecessor`. The predecessor remains
part of candidate validity and the reply's exact request binding, but changing
it cannot create a second conflict store for the same numbered effect slot.
At the effect boundary, the executor separately requires the candidate
predecessor to equal the predecessor committed by the durable manifest.

The order records the linearization order; the set projection supplies conflict
knowledge. Processing one request is an atomic durable transaction:

```text
PUSHQUERY(request):
  1. verify protocol, root, network, domain, slot, predecessor,
     authority mode, candidate encoding, and authority signature;
  2. linearize the candidate in the slot's K_p if absent;
  3. durably commit K_p before exposing a reply;
  4. snapshot the complete canonical K_p for that slot;
  5. sign and return the nonce-bound snapshot.
```

The reply is:

```text
Sign_p(
  "AFT-QUV-REPLY-v0",
  verifier_nonce,
  configuration_root,
  network_id,
  domain_id,
  slot,
  predecessor,
  authority_mode,
  candidate_hash,
  snapshot_hash,
  complete_snapshot
)
```

Binding the configuration, independently provisioned policy root, domain,
slot, requested predecessor, authority mode, and candidate is load-bearing for
reply validity. Conflict storage intentionally normalizes away predecessor so
a predecessor substitution is disclosed as a conflict instead of partitioning
the slot. The policy root commits the owner and complete round-trip bound;
neither is inferred from candidate bytes. A fresh nonce is retained for
session integrity and replay hygiene even though the R3 same-slot monotonicity
check did not make it load-bearing for two-operation conflict safety.

The v4 policy commitment selects a bounded representation of logical K: retain
the first two distinct candidate hashes and their complete signed candidates.
A new distinct value is appended only while fewer than two are retained; after
saturation, processing another valid request preserves the durable summary and
returns a fresh nonce-bound signed reply. It does not refuse solely because a
third value is absent from the retained summary. The wire field keeps the name
`complete_snapshot`, but means the complete retained first-two summary.

A singleton reply must contain the requested candidate. A two-entry reply must
contain two distinct independently valid candidates in the exact conflict domain;
it may omit the requested value and remains a timely valid observation. The
owned decision then rejects because two distinct values cannot equal its wanted
singleton. The unowned decision still requires the immutable first entry to equal
the wanted value. Invalid signatures, duplicates, context substitutions and
wrong-singleton replies remain invalid. No summary or audit authorizes another
executor.

`QuvConflictSummaryProof.tla` proves the algebraic projection for arbitrary-length
distinct histories: the owned all-equal predicate is unchanged, nonemptiness is
preserved, and the unowned first index remains present. The full runtime
transition/refinement and resource timing bridge remain R1 obligations. Logical
K is a proof history; recovery restores only its decision-preserving summary,
not every omitted raw value. The absorbing owned conflict and unowned first
winner survive restart. Deleting either before authority retirement remains
forbidden; garbage collection is not established by this representation.

The current store has an absolute encoded-file ceiling of 512 MiB, enforced
on both read and write. A new member candidate must fit the exact projected
SCALE state size, including map/vector compact-length growth, before the next
state is cloned or authenticated. The resulting state is checked again, and
the atomic writer rejects an oversized buffer before touching its temporary
or destination file. Handoff state is checked before authentication and write.
Capacity refusal leaves the prior state and anchor unchanged and does not
count as progress. This implementation ceiling is not a rooted domain quota,
fair admission mechanism, incremental WAL, or measured Q-A3/Q-A9 envelope;
those remain R1 finding 006 obligations. Whole-store traversal, cloning,
authentication, and rewriting costs remain unqualified at large retained size.

The ordinary state file and its separately rooted rollback anchor are each
authenticated with HMAC-SHA-256 under the member's locally provisioned custody
key. Schema 3 binds the store-kind domain, magic, schema, generation, previous
head, and all member or installed-handoff contents; anchor tags bind the
store-kind domain, magic, schema, generation, and head. Verification uses the
provider's fixed-width tag comparison. Older storage schemas and custom keyed
hash tags are rejected; there is no automatic conversion from those bytes to
new authority. Key secrecy, MAC unforgeability, and separately protected
non-rollback anchor custody remain assumptions. Recovery may
complete the single crash window in which authenticated state is exactly one
generation ahead of its authenticated anchor and names that anchor's head;
unauthenticated ordinary bytes can never advance the anchor. The same rule
applies to the durable configuration-handoff gate.

## 5. Executor operation

For effect execution, the Agentgres-admitted manifest explicitly binds
`online_authorization_predecessor` and `online_authorization_authority_mode`
in addition to the policy/configuration/domain/slot and manifest roots.
The QUV predecessor is the prior accepted candidate or rooted initial QUV
head; the distinct resource-state `predecessor_root` cannot supply it.
The process-local continuation and non-authorizing audit retain both the
QUV predecessor and authority rule for exact matching at the effect boundary.

An honest executor holding candidate `s`:

1. samples a fresh nonce;
2. sends the same complete `PUSHQUERY` to every rooted member;
3. opens a fresh operation-scoped reply-admission epoch and only then starts
   the rooted `delta_rt` decision interval;
4. retains the first authenticated response from each rooted member received
   by the deadline, discards every response first observed after the deadline,
   and validates the retained responses' syntax, signature, and exact request
   binding;
5. rejects if no valid reply arrived;
6. for an owned slot, accepts only if the union of all valid candidates in all
   valid snapshots is exactly `{s}`;
7. for an unowned slot, accepts only if every disclosed first winner equals
   `s`; and
8. externalizes only as the continuation of this operation, never from a saved
   `QUV passed` assertion.

Stable-key claim index (2026-09-06). Immediately before the durable T10
`Claimed` transition, the consequence store writes a per-store claim-index
record keyed by SHA-256 of the manifest's `query_unanimity_idempotency_key()`
(`aft-quv-v0:{domain}:{slot}`), naming the claiming effect and manifest root.
The record's two files are reserved and initialized during effect preparation,
before the executor's own live operation, so no allocation occurs between QUV
and Claim. An existing record naming a different effect refuses the claim
(`ConflictSlotAlreadyClaimed`) with no consumption, audit installation or
resource invocation; the same effect may retry after a crash. Corrupt, aliased
or oversized records refuse as store corruption. The index therefore makes two
admitted manifests with the same conflict-domain slot but distinct
`resource_id` unable to both reach `Claimed` in one store, independently of the
QUV membership argument. It supplies no authority: an entry is never a
substitute for the executor's own live operation, current committed admission,
fence and continuation checks, which precede it on every path. Its storage
charge (two allocation units per claimed slot) is committed in policy-root v8.

Executor entry admission (2026-09-06). Both effect entry points bound queued
waiters per authorizing principal (`WAITING_PER_PRINCIPAL`, policy-root v8)
across all domains and across the historical receipt lane, in addition to the
per-domain waiting bound. The principal share is taken only when a request
joins the active-lane queue, after any child-slot readiness delay: a
reservation waiting out `readiness_millis` holds its domain permit but no
principal share, so a principal with a long readiness wait in one domain can
still run an unrelated effect in another (the clean R2 attempt on
`b4fb23106` refused exactly that and was repaired). Refusal is typed,
non-mutating and surfaces at the join; cancellation releases the share. This
is a queued-waiter bound, not wall-clock fairness or a worst-case service
proof.

Reply admission after a late timer wake (2026-09-06). The runtime finalization
closure is the same function for on-time and late timer wakes; a reply first
observed after the rooted decision interval is discarded at observation and
again at finalization, so a delayed wake yields `NoValidReplies`, no
continuation and no accepted audit. The exact-deadline observation followed by
a late finalization remains eligible.

The retained non-authorizing audit aligns every valid reply with the
executor's monotonic elapsed time at admission. This measurement permits M16Q
to reproduce the deployed reply-arrival envelope, but it is still an
executor-local claim and cannot make the transcript portable authority.

The admission cutoff is inclusive: an observation at exactly `delta_rt` is
eligible; an observation even one monotonic clock tick later is discarded
before retention. Finalization independently enforces the same cutoff.
A delayed finalization callback cannot extend reply eligibility. Audit timing
is encoded in milliseconds, while live admission compares the full monotonic
duration before that encoding; rounded audit bytes cannot authorize execution.

The verifier waits through the decision deadline; an early singleton reply is
not sufficient. Byzantine silence cannot block the operation under Q-A3.
The first response from a Byzantine member may disclose a separately valid
conflict and turn acceptance into rejection; invalid or forged material is
ignored. A later duplicate from that same Byzantine identity is not
theorem-bearing because Q-S1's unavoidable intersection is the first valid
response from each correct member, and a correct member emits exactly one.

## 6. Candidate theorems

### Q-S1: online conflicting-accept exclusion

**Assumes:** Q-A1 through Q-A10, fixed rooted configuration and slot, at least
one correct member, and correct execution of Sections 4 and 5.

No two honest executor operations accept different candidates for the same
rooted conflict-domain slot.

Proof sketch: choose any correct member `c`. Both executor operations send their
candidates to `c`. Correct processing at `c` is atomic and totally ordered for
the slot. Whichever conflicting request linearizes second receives a snapshot
containing both candidates. Q-A3 applies to the same `c` for both operations,
and the full-deadline rule places that signed
snapshot in the corresponding verifier's input before it decides. The owned
union predicate rejects that operation. In the unowned mode, the durable first
winner at `c` differs from at most one of the candidate values, so at most one
candidate can satisfy every received first-winner statement. Additional correct
members can add rejection evidence but cannot enable a conflict.

### Q-L1: no-conflict solo progress

**Assumes:** Q-A1 through Q-A10, a fixed rooted configuration and slot, exactly
one valid candidate `s`, and no environmental failure outside the bound.

Every honest executor operation on `s` accepts after at most its rooted
decision interval even when every Byzantine member is silent.

Proof sketch: the request reaches a correct member, which durably records `s`
and returns a snapshot containing only `s` within the bound. Silence supplies
no authority and no response requirement. Every other valid reply can contain
only `s` under the single-valid-candidate premise.

### Q-LB1: portability does not follow

**Assumes:** copyable Byzantine member state, unknown correct identity, and a
later verifier that sees only a finite transcript.

The online timing fact cannot be converted into a transferable offline final
receipt without an additional assumption. A transcript with fewer than `n`
member replies may omit the correct member under another admissible fault
assignment; requiring all `n` permits a permanent Byzantine withholder to block;
trusting the first executor or a delivery statement adds a notary or delivery
authority. This is the retained M12a boundary.

## 7. Failure boundaries

PQ status discovery supplies provisional metadata, not account authority.
The session manager caps unproven enrollments at four per claimed account and
4096 overall, with a 30-second monotonic lifetime from first enrollment.
Identical or changed provisional metadata does not extend that lifetime.
Expiration removes pending handshake/key state; the swarm's periodic
maintenance also removes obsolete ephemeral retry handles while retaining
the protected durable outbox. Successful application-ready proof removes the
provisional timestamp and atomically evicts other aliases for the account.
An authenticated enrollment survives ordinary expiry/disconnect semantics;
changing its identity metadata requires explicit configuration/manager
replacement. Account-addressed outbox routing waits for authenticated proof.

These are implementation limits, not a qualified discovery or Q-A9 fairness
guarantee. Exhausted provisional capacity can refuse fresh metadata, and
expiry/retry scheduling and the cost of repeated proof attempts require
production load qualification. No refusal or absence creates authority.

PQ carrier recovery and push acknowledgement (2026-09-06). When a handshake
or protected outbound request fails for a carrier whose enrollment is still
unproven, the swarm erases the provisional enrollment and reports
`PqEnrollmentLost`; peer management answers with a fresh status request, so
re-enrollment never depends on a redial or on the stale claim. Authenticated
enrollments survive that recovery. A member acknowledges an admitted QUV
PUSHQUERY on admission (after the authenticated record is forwarded to member
work) and holds the requester's timing lane until the validator's
`CompleteQuvPush` for that exact requester/nonce; an occupied or stale lane
returns `PqChannelNack`, and the sender retains its durable record and
retries. Withholding the acknowledgement until durable processing was tried
and reverted: on the single in-flight peer lane it serialized a member's reply
behind the verifier's own outstanding push and pushed replies past the rooted
cutoff under four-way saturation. A member that crashes between the
acknowledgement and processing simply misses that operation, which the
deadline turns into a typed abort; no authority is minted from the loss.
A reply whose verifier nonce is not
the live operation is acknowledged for retirement without occupying the
member's reply lane, and a duplicate live reply is acknowledged without a
second forward. One connected-but-silent recipient holds at most one live
push and one reply in its reserved lanes across any number of operations;
the only remaining enqueue error is a quarantined outbox.

Shared-lane reply latency (2026-09-07 clean-run observation). In the
consecutive-readiness campaign a child operation's members completed
write-before-reply and handed their replies to the swarm within 1.0 s of the
push, yet two replies reached the executor 2.9–3.2 s later
(`max_valid_reply_elapsed_millis=4210`, inside the rooted 5000 ms interval,
operation accepted) while three members' own preparation operations and an
ordering commit used the same single-in-flight PQ request lane per peer. The
retained logging has no per-record lane events, so the wait is not
attributed. Deployment obligation: the declared reply envelope for this host
is 4500 ms in both the flood and readiness profiles; operators must size
`delta_rt` against reply latency measured with concurrent preparation and
ordering traffic, not against an idle carrier. Q-A3 remains an assumption the
deployment must establish; these campaigns measure it, they do not prove it.

Cold first-operation latency (2026-09-06 requalification observation). The
first full-membership operation after process start delivered its pushes to
every remote member 4.7–4.9 s after dispatch, beyond the qualified 4000 ms
envelope, while every later operation in the same campaigns delivered in well
under a second (single-correct campaign: median 0.7 s, p90 2.2 s, max 3.0 s
over 123 remote pushes). The cause is not isolated in the retained logs. The
flood fixture therefore runs one recorded, unasserted warm-up operation on its
own domain before any measured phase. Deployment obligation: the first
operation after a process start is not covered by the qualified envelope; an
operator must either warm the lanes with a non-authorizing operation or treat
the first operation's typed abort as expected. No warm-up grants authority to
any later operation.

Measured end-to-end singleton cost (2026-09-06). An unrelated singleton
effect's RPC-level time is not the decision interval alone: it includes
executor admission behind the process's own member work, reserved-receipt
initialization (tens of MiB written and synced per effect under the named
storage profile), the full rooted interval, finalization under store
contention, and the durable claim and call. Retained campaigns measured
5.6–6.6 s unflooded (interval 5 s), 8.4 s under terminal-replay pressure and
7.3–9.9 s under a live Byzantine flood. The process fixtures bound these at
three intervals in both cases (under replay pressure 8.4 s and 11.0 s were measured; under flood the two-interval line proved to be the median, 7.3–10.1 s); those are fixture bounds
sized from measurement and recorded as costs, not theorem constants, and a
refusal, timeout or freeze never counts as progress under them.

Active service budget and reserved storage (2026-09-06). The rooted
`operation_service_millis` (at most delta plus continuation) is charged from
exclusive admission and, since queued preparation runs under operation
admission, includes reserved-receipt initialization. Requalification measured
that initialization at about 3 s under contention on the qualification host,
so a 5 s interval with a 5 s continuation (10 s service) released two
otherwise successful operations at 10.25 s; the evidence checker records such
a release as `operation_service_expired`, which invalidates the campaign. The
M16Q fixtures therefore root an 8 s continuation (13 s service) as this host's
deployment profile. An operator must size the rooted service budget from the
measured storage-initialization cost of the chosen profile; a late release is
a declared service failure, never progress.

Declared reply envelope for the qualification host (2026-09-06). The M16Q
fixtures declare `qualified_delta_rt_envelope_millis = 4500` against the
rooted 5000 ms interval. Retained flood-phase maxima for a correct member's
valid reply were 1249, 1368, 2921 and 4010 ms; the earlier 4000 ms declaration
was exceeded by 10 ms under live flood and is therefore not this host's
envelope. The declaration remains an operator assertion backed by retained
measurements with 500 ms of margin, never a theorem constant; replies first
observed after the rooted interval are still discarded.

Rooted push admission quota (policy root v8). Every domain policy commits
`push_admission = {max_requests_per_identity, window_millis}` with both values
nonzero, `max_requests_per_identity <= 4096` and `window_millis >= delta_rt`.
A member admits at most that many PUSHQUERY requests per authenticated
requester account per domain within a sliding monotonic window, measured
before candidate authentication and before any store access; a request beyond
the quota is dropped with no reply and no durable mutation, and the existing
one-in-flight-push-per-account rule still applies. Because the expected-slot
check and the first-two summary already make serial valid traffic non-mutating
after two candidates per slot, the quota bounds authentication, signing and
reply service consumed by a rooted Byzantine account rather than durable
growth. It is a rooted bound on admitted requests, not a wall-clock fairness
or worst-case service proof; the aggregate service envelope remains an M16Q
measurement obligation, and a dropped request is never progress.

- Missing the full round-trip deadline invalidates safety; the result does not
  degrade to a weaker certificate.
- Reply-before-durable, rollback, split snapshot/write, or premature garbage
  collection invalidates safety.
- Cross-configuration, cross-policy, cross-domain, cross-slot,
  cross-predecessor, or cross-authority-mode reply replay is rejected by exact
  request binding. A separately valid candidate with another predecessor is
  retained in the same conflict store and causes conflict rejection; it never
  creates a parallel authorization namespace.
- Query flooding invalidates Q-A3 unless Q-A9 is implemented and measured. The
  local M15Q runtime now has separate bounded command/event lanes, one admitted
  push per authenticated requester, one admitted reply per member per live
  operation, a single live executor operation, and priority/reserved durable
  outbox capacity. M16Q must still establish the end-to-end timing envelope
  under load before Q-A9 is qualified.
- Configured qualification envelopes are not self-proving. Operators must bind
  its request, queue, durable-processing, response, scheduling, PQ-session, and
  clock-error components to the deployed topology and retain the raw run. The
  parser and runtime enforce the fail-closed inequalities
  `0 < qualified_delta_rt_envelope_millis <= delta_rt_millis` and
  `0 < |P| <= qualified_max_configured_members <= 1024`.
- Owner equivocation may freeze future authorization. It yields attributable
  signatures but does not restore liveness or portable historical finality.
- A cached transcript is audit evidence only; it is not a portable final
  authorization.
- Reconfiguration, correct-member turnover, and long-range bootstrap are not
  solved. M14Q must define a state handoff whose assumptions do not smuggle in
  all-member availability or trusted publication.
- QUV does not by itself order multiple slots, make state globally available,
  or establish at-most-once external mutation.

### Claimed effect readmission

A durable `Claimed` effect may resume only after the executor re-derives current
committed admission and matches its exact manifest, guarantee, and initial
authorization evidence. The first consequence trace entry retains the initial
authorization commitment after the state becomes `Claimed`; accepting the phase
alone is insufficient. Readmission does not change the receipt or authorize a
resource call. The executor must perform a fresh live QUV operation and repeat
the current-admission, height, and continuation checks before resuming the call.
`InFlight` and later phases remain excluded from this admission path and require
the separately specified lookup/reconciliation handling. Local restart tests
cover the public store APIs; full process retry and timing qualification remain
open. This preserves Q-EA4 and does not extend QUV authority through audit bytes.

### Structured conflict diagnosis

The production completion channel preserves typed verifier failures. Only a
`ConflictDisclosed` result is exposed by the effect RPC as `Aborted` with
`ioi-quv-refusal: conflict-disclosed-v0`; unrelated errors cannot obtain this
classification merely by containing the same message. Qualification checks both
status code and marker. The marker reports an executor diagnosis, not a
transferable proof, inclusion guarantee, or authority to execute another effect.

## 8. Bounded executable evidence

The R4 Python model covers explicit time for `n=2`, one correct member, and two
verifier operations. It enumerates initial candidate placement, candidates, start ticks,
request/processing/response delays, clock skew, correct-member tie order,
Byzantine reply contents, crash ticks, and replay choices. It checks honest,
dishonest-owner, and unowned authority modes.

It also enumerates independent opposite serialization orders for two and three
correct members. Sound rows include every correct reply; the split-witness
mutation permits a different timely correct member per operation and must
recover conflicting accepts.

The positive rows must have zero conflicting accepts. The one-way deadline,
cross-slot/configuration replay, and reply-before-durable mutations must recover
conflicts. Same-slot stale snapshot replay is expected to remain harmless in
this bounded model because a correct snapshot is monotone and includes the
candidate pushed by its own operation.

Run:

```text
bash .github/scripts/run_aft_formal_checks.sh --quv-only
```

The liveness generator separately checks each authority mode with exactly one
submitted candidate, includes both empty and pre-populated correct state, and
permits only non-conflicting Byzantine replies.

These checks are bounded evidence. Q-S1 and Q-L1 require independent review and
mechanization for arbitrary `n`, multiple correct members, arbitrary operation
counts, restart, queueing, and reconfiguration before M13Q can pass.

### Production workload overlap evidence

The fixed four-member campaign prepares signed requests before releasing them
through a controller barrier. Its accepted workload receipts supply four
verifier nonces in the test log. Full M16Q qualification requires retained
component logs containing one matching start and accepted finish for each nonce,
with a common nonempty interval across all four operations. Each observed end
is capped at start plus the declared 5000 ms decision interval so delayed finish
logging cannot manufacture overlap after expiry. The checker rejects
missing, duplicate, malformed, failed, or nonoverlapping lifecycle evidence.
This is same-host wall-clock workload coverage, separate from the monotonic
rooted reply deadlines enforced by each executor. Neither the barrier nor these
logs establish sustained queue/storage saturation or authorize any effect.
Debug logging and capture costs must remain included in qualification accounting.

### Outbox persistence errors

A reported persistence error makes the live outbox instance unusable until
reopen. Enqueue, ACK, and retirement must fail, and front/recipient selection
must yield no work. This includes errors after replacement whose exact durable
outcome is uncertain. Reopen validates the disk snapshot before resuming.
Previously cached transport sends may still complete; their bytes confer no
authority independent of the live QUV operation. This conservative storage-fault
refusal does not count as inclusion, effect liveness, or a timing qualification.

### Non-executable consequence retries

The online consequence entry point must reject states other than Authorized or
Claimed before consuming a continuation or replacing the stored online audit.
InFlight and Unknown require recovery/reconciliation; Executed and Reconciled
must retain the audit of the original operation. This local rejection boundary
is separate from the still-required public idempotent result/reconciliation path.

### Returning an existing online result

An entry point may return an existing result without starting QUV only after
rederiving committed admission and matching the exact candidate binding.
Readmission compares the receipt's initial authorization trace evidence in every
phase. For Executed or Reconciled, current resource lookup must exactly match the
recorded outcome; returning it preserves the original receipt and nonportable
audit. InFlight or Unknown performs lookup-only reconciliation. Authorized or
Claimed continues through fresh live QUV and the immediate claim fence. No retry
path blindly invokes the resource, and Reconciled/Absent is not execution.
Current admission fences still apply; retrieval after expiry and global fairness
are not established by this change. `online_effect_binding` is inspection data,
never proof of an operation. `online_retry_result` is result/reconciliation only.

### Exhausted reconciliation observations

A recorded observation count at or above the manifest maximum must reject a
further reconciliation call before resource lookup. Clearing a transient resource
fault or reopening the store does not reset that count. This is currently a bound
on completed recorded observations; durable attempt reservation before lookup
and crash-between-lookup-and-record accounting remain required work. Terminal
result verification lookups have separate, still-unqualified request costs.

### Durable reconciliation attempt accounting

`ConsequenceReceiptV1.reconciliation_attempts` is persisted before each
reconciliation lookup. The admission count is the maximum of this field and
legacy ambiguous observations; reaching maximum_observations refuses another
lookup. A crash may consume a reservation without issuing the lookup, but cannot
recover spent budget under the atomic durable, non-rollback store assumption.
Executed remains Executed if a later reconciliation lookup is ambiguous.

The field is default-zero and omitted at zero, preserving prior canonical bytes.
Nonzero values participate in the receipt root; older deny-unknown-fields readers
reject them and must be upgraded together. The counter is separate from phase
trace/generation, just as audit persistence is: reserving lookup does not grant
mutation authority or constitute an effect phase transition. Terminal-result
verification lookups remain separately budgeted work, not covered by this limit.

### Expiry separates result retrieval from execution

`prepare_online_effect` may ignore only an expired upper fence for an existing
InFlight, Unknown, Executed or Reconciled online receipt. It validates the same
committed manifest, achieved profile, initial authorization evidence, authority
epoch/snapshot and protocol configuration binding. Protocol-height lower bounds
still apply. A missing, Authorized or Claimed receipt requires the live fence.
Both production entry points use this preparation before candidate matching and
lookup-only result handling. The `authorize` API used after live QUV remains
strict, as do continuation and immediate claim/call expiry checks. Retrieval
under a missing or substituted committed admission remains forbidden. This
supersedes the earlier implementation limitation that all result retries needed
an unexpired upper fence; process qualification of the new branch remains open.

### Expired-result process evidence

The result-only RPC branch emits `ioi-quv-result-height`, the committed height
used for readmission. This is diagnostic metadata, not receipt authority. The
process campaign must observe a height above the registered upper fence and
receive exactly the original nonportable receipt. Its result=recorded evidence
row must never be counted as a new execution or inclusion event. New execution
still uses the rooted live interval and strict claim/call fence.

Reservation budgeting is accompanied by an inductive component theorem for any
natural MaxAttempts, not only the finite three-attempt TLC fixture. Its Assumes
include atomic non-rollback reservation and single-use process-local readiness.
The paired abstract countermodel demonstrates failure when Crash forgets spent
reservations. Neither result establishes production filesystem refinement or
request fairness. The mandatory runner retains the proof and countermodel
outputs. The expired-result RPC fixture has passed locally; full clean R2 and
independent review remain separate gates.

### Member/handoff persistence errors

Once a member or handoff store begins persistence, it must not reply, reinstall,
or permit activation from that live instance if persistence reports an error.
Only authenticated reopen/recovery may restore service. A state file may already
contain generation+1 while the anchor remains at generation; retrying from the
old memory snapshot is therefore forbidden. The process-local quarantine flag
is cleared only after both writes complete and the in-memory state/head advance.
It adds no disk-format field or new custody authority. Quarantine is refusal,
not inclusion or effect liveness. This storage-head rule is distinct from the
still-required accepted-candidate head/next-slot validation for domain history.

### Parent preparation claim boundary

A fresh live query for a previously accepted parent can return Abort after a
later valid owner conflict. The sequential one-correct-witness model
`formal/maximal_visibility/OwnedParentReverification.tla` retains this schedule
while checking accepted-value non-conflict and singleton progress. It does not
implement head preparation or prove its timing. Production expected-head
enforcement remains required; prior acceptance is not a portable preparation
authority and an aborted preparation is not history progress.

### Member capacity preflight allocation

The duplicate/capacity preflight borrows the retained slot snapshot rather than
cloning it before admission. Refused growth therefore avoids that full-slot
copy. An admitted write still clones and serializes the complete store, and
constructing a reply still copies its complete snapshot. This is not an
incremental WAL, a byte/rate quota, or a measured flood/timing guarantee.

### Required bootstrap commitment and initial-coordinate admission

AftQuvDomainPolicyV0 now requires a typed QuvDomainBootstrapV0, with no serde
default. Fixed contains a nonzero initial_slot and predecessor; HandoffBoundary
contains an activation_height greater than one and requires owned mode. The
bootstrap repair originally used `ioi/aft/quv-policy/v1-bootstrap`. The current
`ioi/aft/quv-policy/v2-preparation` root also commits the explicit preparation
policy alongside bootstrap, domain, authority/owner and timing. Candidate policy roots
are still checked against independently provisioned configuration.

Before member processing or executor admission, a Fixed policy rejects slots
below its start and a different predecessor at the initial slot. A handoff
policy permits only its activation slot. Handoff source validation requires
the exact typed boundary policy; executor admission requires its exact source
candidate. Old-member processing requires the source-bound, independently
certified local boundary for handoff policies even when the requester is an
old rooted member, not only when it is a staged successor. No handoff rule
initializes an unrelated effect domain.

These checks establish bootstrap commitment and initial-coordinate admission.
They do NOT establish the still-absent durable expected head/next slot for
later Fixed slots, authenticated bootstrap comparison on store reopen, accepted
frontier advancement, parent preparation, or safe policy reconfiguration.
Those are R1 001/005 obligations and remain open.

Compatibility: this is an intentional policy-root break. Old configurations
without bootstrap fail decoding; old policy roots/candidates do not validate
under the new policy. No default, inferred first-request bootstrap, automatic
receipt conversion, or durable-history migration is supplied. Existing earlier
process evidence is historical and cannot qualify this changed candidate.

### Handoff member QC validation and install origin

A handoff PUSHQUERY now independently verifies the provisioned source QC under
the current rooted old set and matches its height/view/block hash to the
member's local executed boundary and state root. The local execution cursor
must have reached that boundary. An old member need not have assembled or
cached the aggregate QC itself. Invalid source QC, mismatched local boundary,
or unavailable local execution still causes refusal. All correct members must
finish these checks and durable processing within the declared bound; a
refusal does not satisfy that participation premise.

The install helper distinguishes an already authenticated durable gate from
a fresh live install. Activation keeps its existing authorization checks but
reports the actual origin, so a recovered gate is not logged as a fresh live
operation. The original failed disjoint campaign is retained: its interrupted
successor activated under the wrong origin label, and one old member refused
all four live queries because its QC cache was empty. Later phases did not run.

Post-validation operation audit diagnostics now report configured and valid
reply identities, candidate/root/domain bindings and observed reply times.
The handoff fixtures independently print expected old and successor sets;
the mandatory evidence checker requires exact agreement and one accepted live
audit per successor. These are host-retained diagnostics, not portable
authorization or an independent timing proof. Fresh production qualification
is required for the changed validation path.

### Member provisioning persistence

Member schema 4 authenticates an independently derived commitment to network,
configuration and the canonical complete map of domain IDs to versioned policy
roots (including bootstrap rules). Both production member constructors supply
this commitment. Reopen verifies state and anchor authentication before
comparing provisioning, and compares provisioning before any pending-recovery
anchor write. A changed scope refuses without modifying either retained file.
No schema 3 migration, fallback, candidate-derived enrollment or policy reset
is implemented. Handoff schema remains unchanged. This commitment is not an
accepted domain head and cannot authorize advancement or successor history
inheritance. Those refinement obligations remain open.

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

Successor-root adoption (2026-09-07): while a QUV successor is staged but not
yet activated in a process, blocks at or beyond the staged activation height
are not adopted from sync or gossip. A staged successor defers them until its
own durable install gate activates (the exact QC-certified boundary at
activation minus one is still admitted); a process with no successor identity
refuses them with the retirement diagnostic, drops sync progress, stops
re-initiating sync and quarantines itself. Startup additionally consults the
workload's durable executed projection, not only the admitted tip, so a
retired process whose projection already crossed activation refuses at
startup. This is an authority-boundary repair of the orchestration; it changes
no Q-A or Q-EA premise. It was found because the sync dedup repairs let a
retired member follow successor history through sync and then restart below
activation as an ordinary old member.

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

Member recovery additionally requires each accepted coordinate/hash to match
a candidate in its retained snapshot. Verify this after authenticated decoding
and before any recovery anchor write. A valid MAC alone does not establish this
structural invariant. Reject missing or substituted snapshots without modifying
state or anchor. This enforces retained knowledge locally; it does not make
stored history or audit bytes a portable authorization.


### Durable preparation-attempt reservation — 2026-09-05

Before an independent preparation query starts, its scheduler must reserve an
attempt durably under the exact enrolled policy. Member schema 6 provides the
reservation primitive: match next slot and retained candidate, recompute rooted
policy, enforce its maximum, preflight encoded size, then write authenticated
state and anchor. Never refund a spent attempt after failed or ambiguous work.
Successful durable head advancement alone retires the old counter. Historical
replay cannot retire the next slot's counter. Recovery validates positive counters
against enrolled next coordinates and retained snapshots before any anchor write.

This primitive does not itself start or authorize a query. The runtime worker is
not connected yet, and readiness/service bounds remain unenforced and unqualified.
Counters share the same non-rollback custody assumption as member state. No
schema-5 migration is supplied; handoff schema remains 3.


### Runtime preparation worker — 2026-09-05

The independent preparation worker now recovers pending candidates from local
durable snapshots and performs its own complete runtime QUV operation. It must
reserve a rooted attempt after rooted candidate validation but before transport
admission. A candidate snapshot only triggers work; it does not authorize head
advance. The existing own-query completion path persists accepted history before
returning a result. No preparation result is used as a portable receipt.

The implementation currently wakes on local durable work and operation release,
rotates pending domains, and skips refused/exhausted candidates in a bounded
sweep. It has not yet implemented a qualified aggregate fair-service schedule or
child-readiness gate. The preparation timing assumptions remain obligations,
not guarantees inferred from starting this worker.


### Queued foreground/preparation admission — 2026-09-05

Runtime admission uses one owned active permit and one waiting foreground permit
per enrolled domain, with one preparation worker sharing the active queue. Rooted
candidate authority is validated before queuing. Root, membership, policy and head
checks run again after waiting. The active permit is held from admission through
transport completion and durable own-head advancement; waiting cancellation frees
capacity and never spends a preparation attempt. Preparation reservation still
precedes transport admission once the worker owns the active permit.

These are bounded local queue semantics, not a qualified wall-clock service bound.
The readiness and complete-correct-processing assumptions remain unmet for child
queries until the separate readiness/service work is completed.


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

A runtime pending operation must retain every configured member until local
dispatch completion for that member. Record remote completion only after durable
outbox admission and local completion only after successful write-before-reply
processing. Reject duplicate/unconfigured records and records observed after the
operation's rooted decision interval. Keep the outstanding set unchanged on
refusal. Before the live decision, require that set to be empty; cancellation or
delayed dispatch must not turn partial replies into acceptance.

This local prerequisite does not prove delivery or timely processing by every
correct member. Q-A3 and the complete rooted end-to-end bound remain independently
required. Stored counters, dispatch diagnostics and transcripts authorize no
other executor. No schema or policy-root change is made by this runtime check.


### Rooted active preparation service — 2026-09-05

service_millis bounds one active preparation attempt from acquisition of the
exclusive operation permit through reservation, setup, the live query and head
commit. readiness_millis must additionally cover candidate selection, queue wait,
other active work, retries, clock error and restart behavior. The local product
check on attempts/service is necessary syntax, not a derivation of that aggregate
bound. The current runtime does not yet enforce or qualify child readiness.

The active deadline cancels startup/dispatch and aborts the matching operation.
A partial dispatch cannot run the live decision. A worker grant is consumed into
an expiry cap no later than either its original expiry or the active deadline;
an expired grant cannot be revived. Acceptance still requires the whole rooted
query interval. Head persistence checks that cap before its first write.

If an already-started atomic write completes after the deadline, retain its
actual durable outcome and report service failure without returning an expired
grant. Never turn this failure into a timely-preparation or effect-liveness claim.
Outbox admission remains distinct from delivery and correct-member processing.


### Expired-result qualification observation (2026-09-05)

The active-service process campaign failed its combined expired-result assertion;
its retained output does not establish which of height, portability or receipt
equality failed. Public block availability is insufficient to synchronize an
assertion about the effect endpoint's admitted-height metadata. The fixture now
polls that endpoint for at most 240 seconds, with each RPC bounded by 30 seconds.
It immediately rejects RPC errors, missing/malformed metadata, changed receipt
bytes or portable results, including observations before expiry. Only an exact
nonportable terminal result at admitted height strictly greater than the fence
satisfies the expiry case. Lower/equal heights remain pending, not success.

The named regression passes; removing strictness, byte equality or non-portability
individually fails it. Restored source passes. The full M16Q runner includes this
regression. Evidence: `evidence/m17q-r1-expiry-observation-2026-09-05/`. A fresh
local process campaign is running; no process pass or R1 closure is claimed.
This changes fixture synchronization and diagnostics, not authority semantics,
Q-A assumptions, or any theorem/lower-bound disposition. The earlier failed run
remains failed, and its root cause remains unproven.


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


### PQ outbox index storage (R1 remediation)

The active outbox backend separates immutable entry files from an atomically
replaced ordered index (`AFTPQI03`). The logical entry/scope schema remains v2;
this is a new index storage format, not a change to PQ wire bytes. New payloads
are synced and renamed before index replacement. Retired files are deleted only
after that index is durable. Memory changes follow successful persistence;
uncertain outcomes quarantine the manager until validated reopening. Unrelated
payload files are neither re-encoded nor rewritten by subsequent commits.

Recovery validates the rooted index and every referenced entry/commitment before
orphan cleanup. A corrupt referenced entry blocks cleanup and usable recovery.
After a crash before index replacement, the old queue remains; a crash after
replacement recovers the new queue and never derives membership from orphan files.
Valid legacy v2 snapshots are converted during startup, before live admission.
All required payload files become durable before replacing the legacy snapshot;
interrupted conversion is retryable from the remaining authoritative representation.
Malformed or out-of-scope legacy snapshots remain unchanged. This conversion is
specific to the transport queue and does not migrate member conflict journals.

Assumes: trustworthy configured path ancestry, exclusive ownership, atomic rename
and honored file/directory synchronization, plus the independently validated
rooted account declaration. Message commitments are hashes, not custody MACs;
the queue and index do not confer QUV authorization or nonrollback conflict custody.
The abstract commit-order proof includes partial payload staging, crash recovery
and orphan deletion; its two required mutations break recoverability. It does
not establish filesystem physics, full runtime refinement or the entire theorem.

Index work remains linear in pending entry count, and startup conversion/recovery
is linear in retained data. New-entry encoding remains bounded by one record;
retained state, index buffers, filesystem blocks/inodes/directory growth and
concurrent transport/consequence work still need aggregate physical reservations
and worst-case service accounting. Deleting files does not prove directory
allocation shrinks. No full R1 finding or M16Q–M18Q gate closes on these checks.


### Rooted outbox byte and lane profile

The v5 policy root additionally commits normal record count/bytes and QUV
record/frame/total-byte limits. Per rooted recipient, normal traffic has up to
1,024 entries and 16 MiB of encoded payloads. QUV has one request lane and one
reply lane, each at most 16 KiB, with a separate 32 KiB payload budget. Normal
backlog cannot consume that QUV budget. Reply replacement and nonce retirement
remain atomic; duplicate enqueue remains idempotent. A second distinct pending
request in the same recipient lane refuses before persistence until the old
operation is retired. This does not count refusal as progress.

Both sealing and opening OnlineAuthorization records enforce the 16 KiB limit
before sequence consumption (and before receive-side decryption). Ordinary
record types retain their existing 16 MiB wire limit. Complete two-candidate
QUV replies under the 4096-byte candidate cap and ML-DSA-44 signature width fit
in 10,915 encoded transport-payload bytes; requests fit in 4,131 bytes. The size
regression is a representation bound, not a valid signature or interaction.

Live preflight and streaming recovery enforce the same class budgets and lane
uniqueness. Recovery refuses an over-budget retained snapshot/index before
conversion or orphan cleanup; it never truncates evidence to fit. Old v4
policy roots are not equivalent to v5 roots. No member-custody migration or
mixed-policy deployment is qualified by this source change.

For N declared accounts, pending encoded payloads are bounded by
`N * (16 MiB + 32 KiB)`. Entry/index metadata, allocator overhead, temporary
files, migration copies, filesystem allocation and incoming/active work require
additional accounting. This is a logical byte reservation, not physical disk
or RAM preallocation. A formal reserve theorem ensures an empty QUV lane has
one full frame of capacity independently of normal usage; its shared-budget
mutation fails. The live lane invariant, physical guarantees and end-to-end
service/refinement obligations remain under the full production qualification
boundary. No full R1 finding, R2 or M18Q admission follows from these checks.

### Allocated queue-index exchange (R1 remediation, not admitted)

The Linux production outbox now requires two allocated index files before
returning a usable handle. Let N be the complete rooted account count and
C = 1026*N. The maximum encoded index is 64*C+128 bytes. Each reserved file has
R = 4096*ceil((64*C+176)/4096) bytes; startup uses posix_fallocate, verifies
reported allocated bytes >= R, syncs both images and their directory, and tests
RENAME_EXCHANGE support. Unsupported storage refuses startup. This is a storage
profile requirement, not an independently qualified platform assumption.

AFTPQI04 is a 48-byte envelope (magic, little-endian u64 used length, SHA-256 of
used bytes) around the existing AFTPQI03 index. Logical entries remain schema
v2; member custody remains schema 9 and the policy root remains v5-outbox-budget.
The rooted count/byte constants already determine R. Padding is never decoded.
The checksum detects damage and does not authenticate custody or authorize QUV.
Validated v2/AFTPQI03 queues convert before live admission. Invalid active data
is retained and refused; recovery never selects the inactive image as authority.

| Production transition | Reserved-index model transition / obligation |
|---|---|
| Write inactive image without truncation | BeginWrite; active and persisted-active images remain complete |
| fsync complete inactive image | SyncImage; inactive image becomes valid |
| RENAME_EXCHANGE | Exchange; visibility changes atomically, persisted directory outcome remains uncertain |
| fsync parent directory | SyncDirectory; only afterward retire old payload files and publish live state |
| Error or interrupted process | Quarantine; recovery validates the active name, repairs the spare at startup and syncs before admission |

`PqReservedIndexProof.tla` proves active recoverability and retention of both
allocated slots under its explicit atomic-exchange/durable-image primitives.
Crash recovery before directory sync permits either old or new name outcome;
both payload sets are retained until directory sync. The existing payload/index
ordering proof supplies the separate abstract payload-retention obligation.
Early exchange and inactive truncation each violate the corresponding invariant.
Rust tests cover inode identities, reported blocks, torn inactive bytes, sparse
capacity loss, active checksum damage, hard-link alias refusal and errors before
exchange and between exchange/directory sync. The syscall gate checks the actual
writer's sync/exchange order and absence of live index create/truncate/allocation.

This reserves 2R index data bytes on the declared filesystem interface. It does
not reserve payloads, filesystem journal/extent/directory metadata, member or
consequence storage, receiver buffers or allocator overhead. Full-index encode,
hash and writes still have a C-dependent worst-case cost. Filesystem power-loss
semantics and worst-case device/scheduler latency remain assumptions needing the
full production-profile qualification and transition refinement. Neither finite
samples nor this bounded storage model discharge Q-A3/Q-A5/Q-A9 or finding 006.

### Reserved QUV payload arena and normal capacity refusal

R1 working production now places QUV payloads in one preallocated arena, bound
by its header to the queue scope and complete sorted rooted account set. For N
accounts, the file is 4096 + N*4*20480 bytes. Each recipient owns four slots; each
slot has a 72-byte id/length/checksum header, the canonical 64-byte entry identity
plus at most 16384 encoded payload bytes, and unused padding. Before writing,
the writer validates both states' lane budgets and protects every slot selected
by the old index, including lanes being retired. It plans distinct free slots
for all new entries, writes only those slots and fsyncs the arena before index
publication. Two retained lanes plus two staged replacements fit four slots.

The allocated AFTPQI04 envelope now contains the AFTPQI05 index variant when
QUV entries are arena-backed. AFTPQA01 is the arena header version. Member schema
9, logical entry schema v2 and v5-outbox-budget policy roots remain unchanged;
the implementation's allocation formula follows the already rooted N and two-
lane/frame ceilings. Startup validates old v2/AFTPQI03 payload files, reserves
the arena, stages QUV bytes and commits AFTPQI05 before deleting obsolete copies.
An already active arena is never reset. Crash before the index commit keeps old
payload files/slots; after commit the index alone selects the live entries.
Retired arena bytes can remain physically present, but never re-enter the queue
by scanning storage. Corrupt selected arena data must not fall back to a retired
file. Checksums and queue custody are not live QUV authorization.

`QuvPayloadArenaCapacityProof.tla` supplies the arithmetic capacity/frame kernel;
`QuvPayloadArena.tla` checks all four-slot occupancy/staging states. Three slots
cannot stage both replacements while retaining both active lanes, and allowing
writes to retained slots violates the old-index invariant. Rust tests exercise
both full-size lanes, interrupted staging, post-exchange recovery, stable arena
inode/capacity and corruption despite an intact retired payload copy. These are
storage sub-obligations, not the complete production transition refinement.

A new normal payload's ENOSPC/EDQUOT failure is distinguished from an uncertain
queue commit only at its pre-index writer boundary. The new target must not
already exist. All uncommitted temporary/renamed files must be removed and the
payload directory synced before a typed capacity refusal leaves the existing
queue usable. Failure to clean/sync, any other I/O error, or any error during
index commit retains quarantine. The caller receives refusal, never inclusion
or effect progress. The regression injects capacity and I/O errors before/after
unreferenced payload rename, tests failed cleanup, and verifies existing QUV
retirement/new reply service after the successful capacity cleanup. The abstract
PrecommitCapacityRefusal transition preserves the active index and deletes only
unreferenced pending blobs.

Payload data reservation removes QUV's per-message payload file allocation, but
not filesystem metadata/journal capacity, memory allocation, normal queue
service guarantees, member/consequence storage or scheduling costs. The arena
currently revalidates retained QUV entries and builds staging metadata on each
commit; count those reads/hashes/allocations, global index encoding, fsync and
recovery in the still-open aggregate worst-case service profile. Actual sustained
storage-pressure/restart qualification, complete refinement, clean R2 and fresh
independent review remain mandatory.

### Member record-data reservation (R1 remediation)

The production member journal now allocates all G future 8192-byte record files
from the rooted lifetime count before admission. Authenticated canonical records
retain their schema-9 payload and AFTQJ001 encoding; the pool is a separate,
non-authorizing resource artifact. The journal specification records its exact
layout, allocation charge, continuation/prewrite order and recovery rules.

`QuvRecordReservationProof.tla` conditionally proves the pool/retained partition,
allocation retention and acknowledged-record retention for arbitrary Slot sets.
The two-slot model covers transitions; truncating a live reservation or forgetting
acknowledged records violates the corresponding invariant. The existing lifetime
proof supplies G = sum of the independently rooted per-domain capacities. The
production bridge derives that count before opening storage and reserves exactly
its future generations. Tests cover complete lifetime/inode transfer, refusal
before continuation, partial/missing allocation, authenticated restart, failed
anchor update, semantic replay refusal and pool-root corruption. A mandatory
syscall gate checks all seven fixture reservations and syncs before first live
write, absence of live record create/truncate/allocation, and both directory
syncs after each record rename.

The first broad run exposed obsolete temporary-file error injections and tests
that included member reopen in an already running decision interval or kept a
grant across lengthy provisioning. Failure evidence is retained. Injections now
target the actual reservation file; the correct member is ready before the live
clock starts, and advancement obtains its own fresh interaction after restart.
No deadline, continuation bound, capacity assertion or quarantine requirement
was relaxed. Startup allocation is batched before syncing every future inode;
this preserves durability without forcing an allocation/sync pair per file.
These unit-fixture changes do not qualify restart or reconfiguration service
latency. Full process recovery/cost qualification remains mandatory, including
any recovery that the production service contract places inside its envelope.

A subsequent physical-charge regression confirmed that an empty encoded file may
still exceed the permitted allocated-block charge. Current live preflight treats
that condition as StoreRequiresReopen and quarantines before continuation; it is
not classified as a healthy per-request byte-capacity refusal. The pre-fix failure
and passing current-source checks are retained in the member-reservation evidence.
The anchor-reservation module is still an unlinked, untested draft and supplies
no production or qualification claim.


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


### Exact handoff preparation before live authorization

Schema-3 handoff installation now prepares capacity from the already validated
exact envelope before the successor begins QUV. The state reservation charges
`ceil(encoded_install_bytes/4096)*4096`, bounded by the existing store cap; it
reserves exactly one pending install per handle identity. Two fixed raw HMAC
anchor images each reserve 4096 data bytes. Preparation itself never permits
activation and a different identity cannot reuse the handle's reservation.
Install preflights exact size/identity/allocation before the final live expiry
check, writes/syncs/renames the reserved state inode, then exchanges/syncs the
anchor before publishing memory. An uncertain result quarantines until full
authenticated recovery; recovered state never supplies a live grant.

The state budget includes the old uninstalled raw file plus its reserved install
until rename; afterward the installed inode is retained. Only uncommitted staging
may be reset after active-state authentication. This does not erase installed
handoff knowledge or authorize cross-configuration compaction. The existing
record/anchor primitive ordering lemmas and continuation kernel remain conditional
on exact live QUV, authenticated semantic recovery, exclusive nonrollback custody
and honored filesystem primitives. They do not close complete transition refinement.

`evidence/m17q-r1-handoff-reservation-2026-09-06/` retains 84 core/21 runtime checks,
CLI, focused formal and state/anchor syscall evidence, with exact source and
runner-follow-up bindings. No whole finding or M16Q R2/M17Q/M18Q gate closes.
Metadata, RAM, consequence resources, aggregate fair service, recovery and
cross-configuration retention remain mandatory integrated obligations.


### Consequence representation bounds — R1 resource work

The consequence trace now enforces the existing manifest's observation budget:
with M permitted reconciliation observations, its length is at most `4 + M`.
The four base entries are Authorized, Claimed, InFlight and one execution or
ambiguity outcome. A reserved lookup adds at most one entry; a crash loses
readiness without refunding its durable reservation. A receipt with an extra
legal-looking Unknown edge is refused even when its content hash is recomputed.
No observation allowance is shortened. The same bound is checked before a live
trace push and during receipt validation.

The named `ioi-durable-pq-register` v1 adapter now requires ML-DSA-44 keys and
canonical JCS evidence. Its fixed evidence envelope is bounded by 16 KiB;
its outer JSON resource record is bounded by 80 KiB. The record reader checks
size before reading, bounds the read across a metadata race, and refuses excess
without changing disk. These bounds cover two <=512-byte tokens, JSON escaping,
three fixed hash arrays, one u64, fixed syntax, and canonical base64 key/signature
lengths. They are format-derived charges, not finite performance measurements.
The resource's atomic invocation validates the manifest before locking/writing.
Other resource implementations do not inherit this adapter's bound.

For a QUV receipt using that exact named adapter, let B be the canonical byte
length of its exact committed manifest. Production enforces the conservative
encoded ceiling `B + 4*16 MiB + 512*(4+M) + 80 KiB + 32 KiB` before persistence.
The terms cover audit byte-array encoding, trace entries, one endpoint record,
and fixed receipt/audit/state syntax. This is **not** physical reservation,
a predecode heap limit or a complete aggregate service bound. Other profiles
retain their separate admission and representation contracts.

Receipt hashing uses a borrowed view with a zeroed self-hash field and writes
canonical output directly into SHA-256. Canonical bytes and zero-counter omission
remain unchanged. This removes the explicit audit/trace clone and additional
complete output Vec; the current JCS library still buffers object values to sort
keys. Receipt persistence itself still serializes and replaces a full JSON
snapshot. Physical state/endpoint reservations, incremental updates, complete
bounded recovery, metadata/RAM/fair-service and cross-configuration retention
remain required before R2.

`ConsequenceTraceLifetimeProof.tla` proves the trace counter invariant and
conditional JSON charge composition. The production assumptions still include
honored durable nonrollback reservations, one trace edge per reserved lookup,
the fixed serializer field bounds and the rooted resource contract. This is not
full admission/head/recovery/continuation/handoff/T10 refinement. Its positive
model has 44 states; reusing a lookup reservation violates TraceBound. Scoped
source and defensive controls are retained in
`evidence/m17q-r1-consequence-trace-bound-2026-09-06/`, with separate source
bindings for later hash-view and receipt-budget changes. Read each completed.json
before counting its declared checks. All whole R1 findings remain OPEN.

### Named endpoint reserved record data (R1 repair, 2026-09-06)

For the Linux durable PQ register deployment, both executor entry paths call
`ExternalResourceV1::prepare` after committed authorization verification and before
their own live operation. The adapter retains the exclusive endpoint lock while
validating an existing signed active record or allocating an absent key's staging
inode to 81,920 data bytes with KEEP_SIZE. The file and complete directory ancestry
are synchronized before preparation returns. Existing active values, including
conflicts, are retained. Preparation is capacity work and conveys no authority.

Online invocation opens existing lock/staging files, writes within the reserved
data charge, synchronizes, renames that same inode to the canonical record, and
synchronizes its directory before reporting insertion. It cannot create, truncate,
or allocate record data in that interval. Uncertain commit errors quarantine the
handle; reopening and authoritative active-record lookup are required. Active
records are bounded, canonical, key-matched and endpoint-signature verified before
use. A spare is never lookup authority. Portable invocation retains automatic
preparation before its call; other adapters retain their declared contract.

This per-key data reservation does not reserve filesystem metadata, all receipts,
aggregate admitted keys, memory or service time. Those remain QUV-M17Q-006
obligations. No resource bound or completion theorem is admitted by this change.

### Reserved receipt storage envelope (R1 repair, 2026-09-06)

The named online PQ resource profile now persists receipts inside AFTCR001: an
8-byte magic and little-endian u64 payload length, file capacity and reported
allocated bytes, followed by the canonical JSON receipt. Receipt object schema,
hashes, CLI JSON and portable_final_receipt=false are unchanged. For encoded
receipt bound B, C=4096*ceil((32+B)/4096). Each of the two initialized files has
logical size C and recorded physical allocation A with C<=A<=2C, checked against
the filesystem before/after each live write. The pair's reported allocation is
therefore <=4C; inode, directory and filesystem journal charges remain separate.

Preparation revalidates the active receipt first, builds a fully initialized
spare, fsyncs it, exchanges names, and durably syncs that name before resetting
the former active inode. It then prepares the second file and syncs all ancestry.
Both executor entry paths call prepare_online_storage before live QUV. The
post-Q admission recheck performs no such preparation. Initial authorization can
write legacy JSON before QUV; migration happens only during preparation. An
envelope's capacity must equal the bound derived from its validated manifest.
Invalid active bytes never select a spare.

Live audit/Claim/InFlight/result transitions overwrite existing initialized
capacity, sync, exchange, and sync the directory. They do not create, allocate,
truncate or initialize files. An uncertain persistence error quarantines the
store until reopening; active receipt recovery still determines the permitted
T10 continuation/reconciliation behavior. No lookup result grants new authority.

The first design incorrectly required reported blocks to equal payload capacity.
Reproduction found 4096 extra allocated bytes, including on replacement. The
failed sources/logs are retained; the envelope now explicitly charges reported
allocation and fully initializes blocks before live use. This is not proof of
filesystem metadata sufficiency or global admission feasibility. Predecode RAM,
all-key totals, fair service, initialization cost (at least two full C-byte writes
per preparation), recovery and declared timing still require integration.

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

Endpoint initialization follow-up: the v6 root now also binds a thirteenth
u64 field, ENDPOINT_INITIALIZED=1. Before QUV the 81920-byte endpoint staging
file is filled with ASCII spaces and fsynced, then exact reported allocation
and full ancestry are checked. Live commit requires the full-size, exact-charge,
all-space staging image, overwrites its prefix with canonical signed record JSON,
and publishes the same inode after file sync. Lookup accepts canonical raw JSON
or that exact full-size space-padded representation; other noncanonical bytes
remain invalid. No payload tail is authority and partial staging needs pre-live
reset. This removes unwritten-extent conversion from the live endpoint path.
Filesystem metadata/journal and aggregate/service bounds remain open.

### Committed manifest locator index (2026-09-06 R1 repair)

RuntimeFinalityCoordinator rebuilds a manifest-effect-ID to committed-record-ID
locator index from verified durable records on open. Successful admission updates
it under the existing coordinator mutex; duplicate manifest identities retain an
ambiguity marker. No manifest, receipt or authorization is cached in that index.
Each lookup re-reads exactly its selected staged block, verifies the filename/block
hash, rederives its workload manifest, matches the committed manifest root and
requested effect ID, then returns the current committed record. Wrong locators,
changed selected blocks and duplicate identities refuse. Lookup no longer sorts
and scans every committed effect; startup still scans history and the BTreeMap
still consumes memory proportional to distinct manifest IDs. Those costs remain
in the unqualified aggregate resource/recovery profile.

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

### Registry identity preservation (2026-09-06)

Registry schema v2 writes the exact effect-ID index, canonical manifest, block
height and completeness marker together in the workload transaction overlay.
An existing identity refuses before writes, including when substituted manifest
bytes have a different commitment. Refusal preserves the original admission and
does not consume the block's one-manifest slot. Only an empty registry namespace
may bootstrap v2; missing/unknown markers on existing state refuse unchanged.
Historical committed-manifest retrieval remains available. No automatic legacy
migration or aggregate lifetime bound is claimed. The completeness marker relies
on authenticated state, exclusive namespace ownership and atomic transaction
commit/discard. Evidence: `evidence/m17q-r1-registry-identity-2026-09-06/`.

The registry's empty-namespace check now preserves backing-scan errors through
StateOverlay: leading, repeated, middle and trailing errors remain observable,
including when local writes are pending. A failed scan cannot bootstrap the v2
index or emit overlay writes. A restored readable empty namespace can bootstrap
and commit normally. Evidence: `evidence/m17q-r1-overlay-scan-2026-09-06/`.
