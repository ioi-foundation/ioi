# Maximal visibility viability and role-switching lower bound

Status: **M12 `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`**; R3 role-switch lower
bound upheld by the owner-accepted context-isolated automated review.

Date: 2026-09-03.

This document attacks the proposed canonical-public-state escape hatch before
any maximal production profile is built. The exact R3 candidate was upheld by
the context-isolated Daybreak review recorded in
`../evidence/m12-r3-daybreak-retest-2026-09-03.md`. Under ADR 0049 this closes
the owner-controlled M12 gate; it is explicitly automated, not human peer
review.

## 1. Candidate primitive contract

A proposed canonical public state (CPS) object for configuration `P`, instance
`s`, exposes:

```text
Publish(member, s, object, authentication) -> publication_receipt | error
Read(s)                                    -> finite public state
Close(s)                                   -> close_receipt | error
ProveInclusion(s, object)                   -> inclusion_proof | error
ProveFrontier(s)                            -> frontier_proof | error
Recover(root, s)                            -> state + proofs | error
```

For the maximal theorem it would need all of the following:

| Property | Required meaning | Classification |
|---|---|---|
| writer availability | the sole correct member can publish despite `n-1` silent members | liveness |
| reader availability | a reachable verifier can retrieve the accepted state | network/storage |
| consistency | no two accepted reads/closes select conflicting state | safety |
| inclusion | a correct publication is represented in the canonical state | validity |
| persistence | accepted state survives correct-process restart | storage |
| complete closure | close proves the final relevant frontier, including absence claims | safety + liveness |
| public verifiability | proof bytes suffice under external roots | cryptographic |
| non-circular construction | implemented by the named participants and ordinary network/storage operations | construction |

Hashes and signatures authenticate content and authorship. They do not choose
between two validly authenticated contents or prove that no later content can
exist. A receipt/frontier/challenge echo distributes what was emitted; it does
not force a Byzantine member to emit or reveal an artifact.

## 2. Generalized support-set model

For any finite accepted proof `pi`, partition its prerequisites as follows:

- `SupportP(pi)` is the set of configured members whose unforgeable acts are
  necessary to construct `pi`.
- `Common(pi)` is the replayable rooted/public material fixed across paired
  executions, including client bytes and explicit verifier freshness inputs.
- `ExternalSupport(pi)` is the set of required non-member acts whose
  consistency or liveness selects, closes, orders, or makes an authorization
  canonical.

Hashes, deterministic computation, wrapper signatures by already supported
members, and public copies of the same bytes do not add a new support identity.
L-MAX conditions on the same `Common` material and assumes
`ExternalSupport(pi) = {}`. An object emitted by an external service adds that
service to `ExternalSupport`; if its safety or liveness selects the decision,
the service must be included in the fault model. Calling it a bulletin does
not make it free.

## 3. L-MAX — role-switching proof/visibility dilemma

Assumes: the exact task in `maximal_consensus_task.md`; `n >= 2`; every
singleton correct set is admissible; proof verification is a deterministic
function of bytes, independently provisioned roots, and explicitly named
freshness inputs held common in the paired executions; after conditioning on
`Common`, every accepted proof has `ExternalSupport(pi) = {}`.

**Statement.** No protocol can simultaneously provide:

1. transferable non-conflict for accepted non-`Abort` decisions with
   `f = n - 1`; and
2. non-`Abort` authorization/effect liveness for a correctly submitted valid
   input while all `n - 1` Byzantine members remain permanently silent.

The result applies to arbitrary finite participant-generated proof formats,
not only threshold or `q`-of-`n` certificates.

**Proof.** Choose two members `a != b` and conflicting valid values `X` and
`Y` for the same rooted instance and fixed externally rooted context. Hold all
non-member public inputs and authorization prerequisites common between the
executions. If a proof instead needs a non-reproducible selecting output from a
non-member service, that service is an additional authority and falls outside
the premise.

In execution `E_a`, `a` is the sole correct member, `X` is the only valid
non-`Abort` effect correctly submitted for the instance, and every other
member is permanently silent. No conflict rule rejects `X`. By effect
liveness, at some finite prefix an offline verifier accepts a non-`Abort`
proof `pi_X`. Because no other member acted,
`SupportP(pi_X) subseteq {a}`.

In execution `E_b`, role-switch the correct member: `b` is sole correct, `Y`
is the only valid non-`Abort` effect correctly submitted for the instance,
and all others are silent. Liveness yields a finite accepted proof `pi_Y` with
`SupportP(pi_Y) subseteq {b}`.

Now construct `E_*` with `a` correct and every other member Byzantine. Keep
`b` silent until `a` follows its `E_a` prefix and emits `pi_X`. The adversary
possesses `b`'s legitimate keys and can then reproduce the finite local
computation, chosen random tape, publications, common public inputs, and proof
bytes from `E_b`, emitting byte-identical `pi_Y`. Byzantine members delay or
omit everything else. Known network bounds do not constrain when a Byzantine
sender begins an action. The verifier's roots and proof inputs are
byte-identical to the accepting inputs above, so it accepts both conflicting
non-`Abort` proofs. This violates transferable non-conflict in an admissible
execution.

Randomization does not repair safety. Almost-sure liveness supplies terminating
finite prefixes with nonzero probability; fix those random tapes for the
counterexecution. Synchrony does not repair the proof either: known delivery
bounds govern correct-to-correct messages, while the `n - 1` Byzantine members
may remain silent and `E_*` reproduces finite signed bytes.

To block the construction, any pair of potentially conflicting accepted
proofs must share an unforgeable act from the actual correct member. Because
each member may be the sole correct one, the intersection must depend on every
member. A permanently silent Byzantine member then prevents the proof, which
violates effect liveness. Alternatively, a non-member CPS close can select one
proof, but its consistency/availability becomes a new trusted authority.
Either outcome contradicts one of the premises. QED.

The theorem is about persistent, transferable authorization, not merely the
private decision register of the sole correct process. A verifier-local
first-seen cache does not repair the contradiction: two verifiers can receive
the proofs in opposite orders. A shared linearizable cache can repair that
ordering only by becoming the selecting service named in the second branch of
the dilemma.

The atomic idempotency-register resource modeled for consequence execution is
strictly downstream: its compare-and-set receipt is not an input to `Verify`.
Feeding that receipt back into proof acceptance moves the resource into
`ExternalSupport` and changes the theorem premises; it does not refute L-MAX.

## 4. Relation to existing AFT bounds

- L2 is the threshold-certificate specialization. At `f=n-1`, safety forces
  `q=n`, while silence-liveness forces `q<=1`.
- L-S is the temporal specialization. A timeout cannot distinguish delayed
  authority from dead authority; a formation-time fence gives scheduled safety
  but not gapless effect liveness.
- L-M prevents a wrapper or CPS receipt over unchanged constituent bytes from
  claiming the missing coordinate.
- L-H prevents accountability from being redescribed as data availability.

L-MAX unifies the identity-role switch that remains after moving beyond
threshold certificates.

## 5. The `n=2, f=1` paired executions

| Observable | `E_0`: `p0` honest | `E_1`: `p1` honest | `E_*`: `p0` honest, `p1` simulates `E_1` |
|---|---|---|---|
| root/instance | `R,s` | `R,s` | `R,s` |
| correct input | `X` to `p0` | `Y` to `p1` | `X` to `p0` |
| other member | silent | silent | Byzantine; emits `E_1` bytes |
| proof required by liveness | `pi_X` | `pi_Y` | both available |
| verifier result | accept `X` | accept `Y` | byte-determinism accepts both |

Requiring `{p0,p1}` support blocks the last column but also blocks both solo
columns. Accepting either singleton makes the last column unsafe.

## 6. Why named CPS variants do not yet escape

### Append-only replicated set

Concurrent authenticated objects can be merged, but the set supplies no
canonical winner. A deterministic choice over a closed complete set depends on
knowing closure; with a Byzantine writer, silence cannot prove that the set is
complete.

### First-publication wins

Different readers can observe different first objects under partition. A
globally linearizable first-publication receipt is already a selecting shared
object. Its implementers, quorum, timing, and failures must be modeled; with
the same `n` members and `n-1` Byzantine faults it inherits L-MAX.

### Receipt/frontier/challenge echo

Echo improves dissemination of an emitted object and can expose equivocation.
It cannot echo an object a Byzantine member withholds, establish a final
frontier without closure authority, or identify which of two self-consistent
singleton proofs came from the correct identity.

### Time, leases, or VDFs

A pre-consented fence can make old and new authority ranges disjoint. That is
scheduled succession, not responsive inclusion. Elapsed work/time does not
prove future inaction, and a Byzantine member can retain its signing state.

### Proof of work/stake/resource election

This changes the adversary model by bounding Byzantine resource weight. It may
be useful, but it is not the unweighted `f=n-1` target.

### External chain or storage service

This can implement canonical close only by importing its own consensus and
availability assumptions. It is a named external authority/relay, not a
relay-free construction from the target participants.

## 7. Separation from established results

The dated comparison in
`maximal_prior_art_comparison_2026-09-03.md` records the detailed task and
assumption deltas. The most important boundaries are:

- Dolev-Strong supplies authenticated synchronous internal Byzantine
  agreement with a `t+1`-round bound; it does not require a live persistent
  singleton authorization that remains non-conflicting to offline verifiers.
- FLP rules out deterministic asynchronous decision termination with one
  crash. L-MAX does not rely on asynchrony or determinism and instead couples
  transferable proof safety to non-`Abort` progress under Byzantine silence.
- DLS separates unconditional safety from post-GST termination and places
  authenticated Byzantine partial-synchrony consensus at `N >= 3t+1`; it does
  not establish the target at `t=N-1`.
- Reliable broadcast, ACS, and DAG availability certificates disseminate or
  certify participant data under quorum assumptions. They do not turn the
  absence of `N-1` Byzantine acts into a canonical selecting bit.
- A wait-free linearizable first-writer or sticky object can provide that bit,
  but it is consensus-powerful shared state. Treating it as an unmodeled
  bulletin would assume the disputed construction.

These comparisons are scope checks, not a novelty claim and not independent
validation of L-MAX.

## 8. M12 disposition

Result: **`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`**.

The R3 exact-candidate review returned `UPHELD`. A successful future
challenge must identify a concrete CPS operation whose output distinguishes
`E_a`, `E_b`, and `E_*`, then show:

1. who produces and stores that output;
2. why Byzantine instances cannot simulate or fork it;
3. why one correct instance can obtain it while all others are silent;
4. why it is not a trusted oracle, relay, sequencer, TEE, external consensus,
   hidden honest-majority/resource assumption, or authority minted from
   silence; and
5. how an offline verifier checks it from independently rooted bytes.

M12 therefore does not return `PASS_CONSTRUCTION`. M13-M18 remain blocked, and
no maximal implementation or headline is authorized. Resuming that path
requires an explicit owner decision changing at least one task property or
permitting and naming an additional authority/assumption.
