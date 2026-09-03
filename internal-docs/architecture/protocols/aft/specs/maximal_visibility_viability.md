# Maximal visibility viability and role-switching lower bound

Status: M12 local lower-bound candidate; **independent theorem review pending**.

Date: 2026-09-03.

This document attacks the proposed canonical-public-state escape hatch before
any maximal production profile is built. Its conclusion is local until an
independent theorem review disposes the argument.

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

For any finite accepted proof `pi`, let `Support(pi)` be the set of configured
members whose unforgeable acts are necessary to construct `pi`. Hashes,
deterministic computation, wrapper signatures by already supported members,
and public copies of the same bytes do not add a new support identity.

An object emitted by an external service adds that service as an authority. If
the service's safety or liveness is required to select the decision, it must be
included in the fault model; calling it a bulletin does not make it free.

## 3. L-MAX — role-switching proof/visibility dilemma

Assumes: the exact task in `maximal_consensus_task.md`; `n >= 2`; every
singleton correct set is admissible; proof verification is a deterministic
function of bytes and independently provisioned roots; there is no trusted
authority outside `P`.

**Statement.** No protocol can simultaneously provide:

1. transferable non-conflict for accepted non-`Abort` decisions with
   `f = n - 1`; and
2. non-`Abort` authorization/effect liveness for a correctly submitted valid
   input while all `n - 1` Byzantine members remain permanently silent.

The result applies to arbitrary finite participant-generated proof formats,
not only threshold or `q`-of-`n` certificates.

**Proof.** Choose two members `a != b` and conflicting valid values `X` and
`Y` for the same rooted instance.

In execution `E_a`, `a` is the sole correct member, `X` is correctly submitted
to `a`, and every other member is permanently silent. By effect liveness, at
some finite prefix an offline verifier accepts a non-`Abort` proof `pi_X`.
Because no other member acted, `Support(pi_X) subseteq {a}`.

In execution `E_b`, role-switch the correct member: `b` is sole correct, `Y`
is correctly submitted to `b`, and all others are silent. Liveness yields a
finite accepted proof `pi_Y` with `Support(pi_Y) subseteq {b}`.

Now construct `E_*` with `a` correct and every other member Byzantine. The
adversary possesses `b`'s legitimate keys and can reproduce the finite local
computation, chosen random tape, publications, and proof bytes from `E_b`.
It emits byte-identical `pi_Y`. Correct member `a` follows its `E_a` prefix and
emits `pi_X`; Byzantine members delay or omit everything else. The verifier's
roots and proof inputs are byte-identical to the accepting inputs above, so it
accepts both conflicting non-`Abort` proofs. This violates transferable
non-conflict in an admissible execution.

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

## 7. Current M12 disposition

Local result: **PROVED_IMPOSSIBLE candidate under the fixed task and excluded-
authority constraints**.

This is not yet the final `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS` gate outcome,
because the action plan requires independent theorem review. A successful
challenge must identify a concrete CPS operation whose output distinguishes
`E_a`, `E_b`, and `E_*`, then show:

1. who produces and stores that output;
2. why Byzantine instances cannot simulate or fork it;
3. why one correct instance can obtain it while all others are silent;
4. why it is not a trusted oracle, relay, sequencer, TEE, external consensus,
   hidden honest-majority/resource assumption, or authority minted from
   silence; and
5. how an offline verifier checks it from independently rooted bytes.

Until such a construction survives review, M12 does not return
`PASS_CONSTRUCTION`, M13-M18 remain locked, and no maximal implementation or
headline is authorized.
