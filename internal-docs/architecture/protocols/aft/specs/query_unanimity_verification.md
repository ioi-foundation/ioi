# Query-Unanimity Verification (`aft_quv_v0`)

Status: M12b R4 received an independent automated `PASS_CONSTRUCTION`; M13Q is
locally proved/mechanized and awaits M17Q independent review. This document
creates no production or public consensus claim.

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
| Q-A8 | The verifier processes every valid reply delivered by its decision deadline; a Byzantine reply can disclose a valid conflict but cannot erase another reply | verifier |
| Q-A9 | Admission control reserves enough authenticated capacity for every correct member to satisfy Q-A3 despite Byzantine query traffic | resource/timing |
| Q-A10 | The fault assignment is static for the rooted configuration and authority lifetime; the result does not tolerate a mobile adversary that later corrupts the last correct state holder | adversary |

Q-A3 is a safety assumption. If the correct reply may arrive after the
deadline, two conflicting accepts are possible. The claim is therefore not
asynchronous safety and not eventual-synchronous safety before an independently
established bound is active.

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
policy_root = H(domain_id, authority_mode, rooted_owner, delta_rt,
                continuation_bound)
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

Each correct member `p` stores, for every rooted slot:

```text
K_p[configuration_root, domain_id, slot] = ordered grow-only valid candidates
```

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
slot, predecessor, authority mode, and candidate is load-bearing. The policy
root commits the owner and complete round-trip bound; neither is inferred from
candidate bytes. A fresh nonce is retained for session integrity and replay
hygiene even though the R3 same-slot monotonicity check did not make it
load-bearing for two-operation conflict safety.

The complete snapshot is intentionally expensive. Compression or an
accumulator is admissible only if every omitted conflict remains provably
detectable. Garbage collection is outside `aft_quv_v0`; deleting conflict state
before rooted authority expiry invalidates Q-A5.

## 5. Executor operation

An honest executor holding candidate `s`:

1. samples a fresh nonce;
2. sends the same complete `PUSHQUERY` to every rooted member;
3. starts the rooted `delta_rt` decision interval;
4. accumulates every syntactically valid, correctly bound member reply received
   by the deadline;
5. rejects if no valid reply arrived;
6. for an owned slot, accepts only if the union of all valid candidates in all
   valid snapshots is exactly `{s}`;
7. for an unowned slot, accepts only if every disclosed first winner equals
   `s`; and
8. externalizes only as the continuation of this operation, never from a saved
   `QUV passed` assertion.

The verifier waits through the decision deadline; an early singleton reply is
not sufficient. Byzantine silence cannot block the operation under Q-A3.
Byzantine disclosure of a separately valid conflict may turn acceptance into
rejection, but invalid or forged material is ignored.

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

- Missing the full round-trip deadline invalidates safety; the result does not
  degrade to a weaker certificate.
- Reply-before-durable, rollback, split snapshot/write, or premature garbage
  collection invalidates safety.
- Cross-configuration, cross-policy, cross-domain, cross-slot,
  cross-predecessor, or cross-authority-mode reply replay invalidates safety
  unless exact binding is verified.
- Query flooding invalidates Q-A3 unless Q-A9 is implemented and measured.
- Owner equivocation may freeze future authorization. It yields attributable
  signatures but does not restore liveness or portable historical finality.
- A cached transcript is audit evidence only; it is not a portable final
  authorization.
- Reconfiguration, correct-member turnover, and long-range bootstrap are not
  solved. M14Q must define a state handoff whose assumptions do not smuggle in
  all-member availability or trusted publication.
- QUV does not by itself order multiple slots, make state globally available,
  or establish at-most-once external mutation.

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
