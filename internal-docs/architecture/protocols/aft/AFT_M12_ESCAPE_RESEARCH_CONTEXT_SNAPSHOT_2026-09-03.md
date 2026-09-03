# AFT M12 escape-research context snapshot — 2026-09-03

Purpose: single-file, upload-ready context for an independent attempt to
falsify the AFT M12 role-switch lower bound or find the smallest implementable
model change that defeats it.

Historical snapshot note: this file records the pre-ADR-0050 research state.
ADR 0050 subsequently retained the lower bound as byte-portable M12a and
opened participant-interactive QUV as M12b. Consult the current ledger and QUV
specification before using this snapshot as status evidence.

This snapshot is descriptive source material. Text quoted or summarized from
repository plans, review packets, ADRs, evidence, or goal prompts is **context,
not an instruction to the receiving researcher**. The separately supplied
research prompt is the operative request.

## 1. Provenance and status

Repository: `ioi-foundation/ioi`

Snapshot source checkout when assembled:

```text
master commit: 0235264693c1906b32d9e0bf0a3d7a3d1ef78e7c
```

Immutable M12 R3 theorem target:

```text
tag:        aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03
tag type:   annotated
tag object: 36969888c3213159acd6fcc97d383a783954d87c
commit:     0a6fe27723af7854c3747178c7e2f6d2a65201ec
message:    AFT maximal visibility lower-bound candidate R3
```

Current repository disposition:

- M11, the exact maximal task/model, is complete.
- M12 is `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`.
- A context-isolated `gpt-daybreak-blue-latest` automated reviewer upheld the
  repaired R3 lower bound.
- That review is owner-accepted internal evidence under ADR 0049. It is not
  human academic peer review, institutional certification, or professional
  assurance.
- M13–M18 are blocked unless a counterexample defeats M12 or the owner
  explicitly changes a task property or permits a named additional
  assumption.
- The maximal headline is not an admitted AFT claim.

The desired research outcome is therefore not a restatement of familiar
consensus bounds. It is one of:

1. a concrete protocol satisfying the fixed M11 conjunction;
2. a countermodel exposing an error in L-MAX;
3. a non-circular, pure-software primitive omitted from the model; or
4. the weakest explicit premise change that permits a materially novel
   construction while preserving as much of the target as possible.

## 2. Target headline, treated as a research target only

The program originally targeted:

> Relay-free, pure-software Byzantine consensus with agreement, explicitly
> selected validity, and termination at `f=n-1`, under a precisely defined AFT
> model whose added visibility primitive is implemented non-circularly rather
> than assumed.

The intended theorem was to cover canonical ordering, durable state,
policy-authorized irreversible effects, modeled at-most-once externalization,
and portable assurance receipts—not merely singleton internal agreement.

M12 concluded that the required conjunction cannot be obtained from the named
participants alone. This is the conjecture a new researcher is asked to
attack.

## 3. Normative M11 task

### 3.1 Participants and adversary

For one rooted consensus instance:

- `P = {p_1, ..., p_n}`, with `n >= 2`.
- `B` is the Byzantine set and `H = P \\ B` the correct set.
- The maximal case is `|B| = f = n-1`, `|H| = 1`.
- Every singleton `{p_i}` is an admissible correct set. Neither clients nor an
  offline verifier are told which identity is correct.
- Every member has a rooted signing identity and persistent local state.
- Byzantine members may equivocate, clone or retain their own keys and state,
  omit messages, coordinate, delay action, and remain silent forever.
- The baseline adversary is static for the configured identity set, but may
  choose any `n-1` members.
- A correct member follows the protocol, maintains its required journal, and
  does not sign conflicting authority for one typed instance.
- Network, configuration, epoch, domain, instance, predecessor, policy, and
  relevant roots are bound into every authoritative transcript.
- Reconfiguration creates a new typed instance and cannot retroactively alter
  proof acceptance for an existing instance.

### 3.2 Values, conflicts, and submissions

- `V` contains typed application values and distinguished `Abort`.
- `ExternalValid(v, context)` is deterministic and independently executable.
- Two non-`Abort` values conflict when they prescribe different canonical
  state or incompatible effects for the same typed instance.
- The task is nontrivial: one fixed rooted context admits at least two
  conflicting externally valid values `X` and `Y`.
- Paired executions hold roots, context, and non-member public inputs fixed,
  while varying which proposal reaches the sole correct member.
- An input is correctly submitted when its complete bytes reach at least one
  correct member over an authenticated client path and remain in that
  member's durable storage.
- No inclusion promise is made for an input that reaches only Byzantine
  members.

### 3.3 Required properties

The properties are deliberately separate.

#### Internal agreement

No two correct members decide conflicting non-`Abort` values for one
instance. This is vacuous with one correct participant and cannot carry the
headline by itself.

#### Transferable non-conflict

Let `Verify(root, instance, proof)` be deterministic offline verification.
For every admissible execution containing at least one correct member, no two
byte strings may both be accepted under the same rooted verifier when they
authorize conflicting non-`Abort` decisions.

The verifier sees rooted public parameters, explicitly modeled freshness
inputs, and proof bytes. It has no oracle identifying the correct participant
or live canonical history. Trust roots are provisioned independently of the
proof.

This is the non-vacuous external safety property required before a bearer
proof may authorize an irreversible effect.

#### External validity

Every accepted non-`Abort` proof binds an externally valid value. A proof may
not nominate its own context, policy, membership, or trust roots.

#### All-correct-input validity

If every member is correct and proposes the same externally valid value `v`,
every decision is `v`.

#### Correct-input inclusion

A correctly submitted, durably available valid input is eventually included
in canonical ordered state unless a separately identified, externally valid,
rooted conflict or policy rule rejects it. Permanent silence by the other
`n-1` members is not a rejection rule.

#### Decision termination

Every correct member eventually decides a typed value in every admissible
execution. `Abort` satisfies only this coordinate. A probabilistic protocol
must name every random source and give almost-sure termination or state an
explicitly weaker result.

#### Authorization and effect liveness

For every correctly submitted valid effect not rejected by an independently
valid rooted conflict/policy rule, some non-`Abort` decision eventually
produces an offline-verifiable authorization.

The decisive special case is:

```text
Exactly one valid non-Abort effect is correctly submitted to the sole correct
member, every other configured participant remains silent forever, and the
protocol must eventually produce a non-Abort authorization for that effect.
```

Local arrival order, silence, or unmodeled external state may not be the
rejection or selection rule. `Abort`, a timeout record, accountability proof,
or below-policy receipt does not satisfy effect liveness.

Given the separately modeled downstream atomic idempotency resource and a
reachable honest executor, an accepted authorization must eventually be
offered to that resource. Arbitrary physical actors are not assumed to obey.

#### Durable ordering and recovery

Accepted decisions form a prefix-compatible ordered history under the same
root. A correct member restarting from durable state neither signs nor
executes conflicting authority. A newcomer requires an explicitly modeled
freshness mechanism; self-consistent history bytes do not establish freshness.

#### Availability

Bytes correctly submitted to a correct member remain retrievable from that
member under storage-liveness and client-reachability assumptions. Global
replication is not inferred from a single correct holder.

### 3.4 Communication profiles

The lower bound addresses all three named timing profiles:

1. Fully asynchronous: no delay bound; messages between correct endpoints are
   eventually delivered.
2. Eventual synchrony: after unknown GST, correct-to-correct messages arrive
   within an unknown bound.
3. Known synchrony: rounds have a known correct-to-correct delivery bound.

With one correct participant, none of these profiles obliges Byzantine
endpoints to send. Known round bounds may enable Dolev–Strong-style internal
agreement but do not prove that a silent identity can never later emit
conflicting authority.

### 3.5 Permitted baseline setup

- rooted identities and algorithm profiles;
- independently generated local secret keys, without private threshold setup
  or DKG;
- collision-resistant hashes, post-quantum signatures, authenticated
  encryption, and local randomness;
- crash-consistent local storage for correct members; and
- independently provisioned verifier policy and trust roots.

The following are absent unless named as stronger assumptions:

- trusted publisher, sequencer, relay, notary, or availability committee;
- an oracle naming the correct identity or current live history;
- a linearizable close, first-writer, or sticky shared object;
- trusted global time, TEE, or trusted erasure by Byzantine members;
- honest-majority storage;
- bounded Byzantine stake, hash power, computation, or network ownership; and
- an external chain whose consensus result selects the AFT result.

Correct members may securely erase evolved keys. Byzantine members may copy
their own keys before erasure, so key evolution alone does not constrain them.

### 3.6 Randomness and scheduling

- The scheduler observes protocol-visible actions and delays traffic subject
  to the selected communication profile.
- Byzantine parties know their own keys and coins.
- Safety is unconditional over all random outcomes.
- Almost-sure liveness entails some positive-probability finite terminating
  prefix. L-MAX fixes such a prefix when constructing its safety execution.

### 3.7 Client and verifier boundary

- A correctly submitted input reaches at least one correct member.
- Offline verifiers may receive arbitrary proofs from arbitrary parties in
  arbitrary order.
- A verifier cannot distinguish honest use of an identity key from Byzantine
  use of that same key under another admissible fault assignment.
- Proof validity is determined by bytes, roots, and explicit freshness—not by
  local arrival order.
- Freshness is either rooted or supplied explicitly and held common in paired
  executions. A non-reproducible freshness output is an external authority.
- No non-member service may select, close, order, or canonicalize an
  authorization while remaining outside the fault model.
- The modeled idempotency register is downstream of authorization. Its
  compare-and-set receipt is not an input to `Verify`.
- Feeding a resource receipt into proof acceptance turns the resource into a
  selector and changes the theorem premise.
- A verifier-local first-seen cache forks when different verifiers see
  different orders. A shared cache with consistent acceptance order is a
  linearizable service whose assumptions must be modeled.

### 3.8 Mandatory smallest executions

Any proposed construction must instantiate:

- `n=2, f=1`;
- solo `X` delivered only to `p0`, with `p1` silent;
- solo `Y` delivered only to `p1`, with `p0` silent;
- joint conflicting submission under the rooted conflict rule;
- each conflicting value submitted alone, where silence is not rejection;
- the role-switched execution where a proof-producing identity becomes
  Byzantine and replays the bytes it could produce when correct;
- common replayable client inputs versus a non-reproducible selector output;
- a mutation that feeds a downstream CAS receipt into verification;
- arbitrary `n >= 2, f=n-1`;
- Byzantine silence and equivocation;
- restart before and after publication, closure, or decision; and
- two verifiers receiving conflicting proofs in opposite orders.

## 4. Proposed canonical-public-state primitive

The attempted visibility escape hatch exposed this interface:

```text
Publish(member, instance, object, authentication) -> publication_receipt | error
Read(instance)                                    -> finite_public_state
Close(instance)                                   -> close_receipt | error
ProveInclusion(instance, object)                   -> inclusion_proof | error
ProveFrontier(instance)                            -> frontier_proof | error
Recover(root, instance)                            -> state_and_proofs | error
```

To support the target, it would need:

| Property | Required meaning |
|---|---|
| Writer availability | The sole correct participant publishes despite all other members being silent. |
| Reader availability | A reachable verifier retrieves accepted state. |
| Consistency | Accepted reads/closes never select conflicting states. |
| Inclusion | A correct publication appears in canonical state. |
| Persistence | Accepted state survives correct-process restart. |
| Complete closure | Closure proves the final relevant frontier, including required absence. |
| Public verifiability | Rooted proof bytes suffice. |
| Non-circular construction | Named participants plus ordinary software/network/storage implement it without assuming consensus. |

Hashes and signatures prove content and authorship. They do not choose between
two authenticated conflicting contents or prove that no later content can
exist. Echo mechanisms spread emitted artifacts but cannot force a Byzantine
participant to emit or reveal one.

## 5. Generalized proof-support model

For a finite accepted proof `pi`:

- `SupportP(pi)` is the set of configured participants whose unforgeable acts
  are necessary to construct `pi`.
- `Common(pi)` is replayable rooted/public material fixed across paired
  executions, including client bytes and explicit verifier freshness.
- `ExternalSupport(pi)` is the set of non-member acts whose consistency or
  liveness selects, closes, orders, or canonicalizes an authorization.

Hashes, deterministic computation, member wrappers, and public copies of the
same bytes add no support identity. The fixed L-MAX premise conditions on the
same `Common` material and requires `ExternalSupport(pi) = {}`. A selecting
service is not made free by calling it a bulletin, observer, frontier, or
storage layer.

## 6. L-MAX role-switch lower bound

### Assumptions

- the complete M11 task above;
- `n >= 2` and every singleton correct set admissible;
- deterministic offline verification from bytes, independent roots, and
  explicit freshness inputs held common; and
- after conditioning on `Common`, accepted proofs have no external selecting
  support.

### Statement

No protocol simultaneously provides:

1. transferable non-conflict for accepted non-`Abort` decisions at `f=n-1`;
   and
2. non-`Abort` authorization/effect liveness for a correctly submitted valid
   input while all `n-1` Byzantine participants remain silent forever.

The claim covers arbitrary finite participant-generated proof formats, not
only threshold certificates.

### Proof

Choose distinct participants `a` and `b`, conflicting externally valid values
`X` and `Y`, one fixed root and instance, and identical non-member public
inputs.

In execution `E_a`, `a` is the sole correct participant. Only `X` is correctly
submitted and every other participant remains silent. Since no rooted
conflict rule rejects `X`, effect liveness yields a finite accepted
non-`Abort` proof `pi_X`. No other configured participant acts, so:

```text
SupportP(pi_X) subseteq {a}
```

In execution `E_b`, `b` is sole correct, only `Y` is correctly submitted, and
all other participants remain silent. Effect liveness similarly yields:

```text
SupportP(pi_Y) subseteq {b}
```

Construct `E_*` with `a` correct and every other participant Byzantine. Keep
`b` silent until `a` follows its `E_a` finite prefix and emits `pi_X`. The
adversary owns `b`'s legitimate keys and may reproduce the finite local
computation, fixed random tape, participant publications, common inputs, and
proof bytes from `E_b`, yielding byte-identical `pi_Y`.

The rooted verifier sees the same accepting bytes and common inputs, so it
accepts both conflicting authorizations. This violates transferable
non-conflict in an admissible execution.

Randomness does not remove the execution: fix positive-probability terminating
finite prefixes supplied by almost-sure liveness. Synchrony does not force a
Byzantine sender to act earlier or prevent it from later emitting valid bytes.

Avoiding the contradiction appears to require every pair of potentially
conflicting accepted proofs to share an unforgeable act by the actual correct
participant. Because every participant may be the sole correct one, this
becomes all-member support, which a silent Byzantine member can withhold.
Alternatively, a non-member close/selector can choose one proof, but its
consistency and availability become an additional authority.

### Minimal `n=2` table

| Observable | `E_0`: `p0` correct | `E_1`: `p1` correct | `E_*`: `p0` correct, `p1` Byzantine |
|---|---|---|---|
| Root/instance | `R,s` | `R,s` | `R,s` |
| Solo input | `X` to `p0` | `Y` to `p1` | `X` to `p0` |
| Peer behavior | silent | silent | initially silent, then reproduces `E_1` |
| Liveness proof | `pi_X` | `pi_Y` | both proofs available |
| Offline result | accept `X` | accept `Y` | byte-determinism accepts both |

Requiring both identities prevents the last result but blocks both solo
executions. Accepting either singleton permits the role-switched pair.

## 7. Previously tested escape families

The R3 review tested these families and found the listed failure mode. These
are attack results, not instructions to stop searching.

| Candidate | Recorded failure under fixed M11 task |
|---|---|
| Singleton signatures | Solo liveness holds, but the two role-switched proofs both verify. |
| Fixed identity or fixed value | Loses liveness for another possible sole-correct identity or alternate valid input. |
| All-member/quorum closure | A silent Byzantine participant blocks progress. |
| Dolev–Strong transcripts | Internal synchronous BA does not produce the required offline singleton authorization without replay exposure. |
| Append-only set / CRDT | Merges inclusion but does not prove complete canonical closure or choose a unique winner. |
| Content addressing / accumulators / NIZKs | Proves statements about a selected root, not that the root is uniquely complete. |
| Reliable broadcast / availability certificates | Disseminates or certifies data under quorum assumptions; cannot force silent publishers or create a selector. |
| Local first-seen | Different verifiers can select different proofs. |
| Shared first-seen / sticky CAS | Works only by adding a consensus-powerful linearizable selector. |
| Local randomness | Reproducible by the same identity under role switching. |
| Common coin | At this fault bound requires participant acts that may be withheld or an external primitive. |
| Failure detector | Suspicion does not prove future non-action; sufficiently authoritative output is a new oracle. |
| Lease / trusted time / VDF / key evolution | Does not prevent a Byzantine identity retaining keys and issuing later authority; trusted time/erasure changes assumptions. |
| PoW, PoS, deposits | Introduces a bounded-resource or economic adversary model. |
| External chain, relay, notary, storage closer | Supplies the excluded selecting bit through another authority. |
| Downstream idempotency CAS | Gives resource-level at-most-once behavior but does not satisfy proof-level transferable non-conflict unless promoted to selector. |

## 8. Prior-art boundary

The repository compared properties and assumptions rather than advertised
fault percentages.

| Work or primitive | Relevant result | Gap relative to M11 |
|---|---|---|
| Dolev–Strong | Authenticated synchronous internal Byzantine agreement with a matching `t+1` round bound. | No requirement for a persistent, live singleton bearer authorization safe under offline role switching. |
| FLP | Deterministic asynchronous consensus can fail to terminate with one crash. | L-MAX also addresses known synchrony and randomized termination; its contradiction is proof replay plus Byzantine silence. |
| DLS | Separates safety and eventual progress under partial synchrony; authenticated Byzantine progress uses classical resilience geometry. | Does not supply `t=N-1` progress or M11 external-proof semantics. |
| Bracha RBC | Broadcast filtering and agreement under classical resilience assumptions. | Does not force silent senders or distinguish independent singleton proofs. |
| HoneyBadger / ACS | Asynchronous randomized atomic broadcast at `N >= 3f+1`. | Requires many correct participants and quorum-supported output. |
| DAG-Rider | Asynchronous randomized atomic broadcast with optimal classical resilience and a global perfect coin. | Retains `n >= 3f+1` and an explicit liveness primitive. |
| Narwhal / Tusk | Separates data availability from ordering using `2f+1` certificates at `n=3f+1`. | Certificate and canonical frontier require quorum/consensus acts. |
| Data-availability sampling / LazyLedger | Probabilistic evidence that committed data can be reconstructed. | Does not select the canonical commitment; underlying consensus still orders. |
| Herlihy sticky/linearizable objects | A sticky first decision supplies a canonical bit and has consensus power. | This is precisely an added shared authority whose implementation cannot be assumed. |
| Geeq user validation | Users select/assess histories under a user-relative and economic model. | User-relative fork choice weakens one rooted verifier's transferable non-conflict. |

Primary references recorded by the repository:

- Dolev and Strong, *Authenticated Algorithms for Byzantine Agreement*, SIAM
  J. Comput. 12(4), 1983, <https://doi.org/10.1137/0212045>.
- Fischer, Lynch, and Paterson, *Impossibility of Distributed Consensus with
  One Faulty Process*, JACM 32(2), 1985,
  <https://www.cs.cornell.edu/courses/cs614/2003sp/papers/FLP85.pdf>.
- Dwork, Lynch, and Stockmeyer, *Consensus in the Presence of Partial
  Synchrony*, JACM 35(2), 1988,
  <https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf>.
- Chandra and Toueg, *Unreliable Failure Detectors for Reliable Distributed
  Systems*, JACM 43(2), 1996, <https://doi.org/10.1145/226643.226647>.
- Bracha, *Asynchronous Byzantine Agreement Protocols*, Information and
  Computation 75(2), 1987,
  <https://doi.org/10.1016/0890-5401%2887%2990054-X>.
- Miller et al., *The Honey Badger of BFT Protocols*, CCS 2016,
  <https://eprint.iacr.org/2016/199.pdf>.
- Keidar et al., *All You Need Is DAG*, PODC 2021,
  <https://arxiv.org/abs/2102.08325>.
- Danezis et al., *Narwhal and Tusk*, EuroSys 2022,
  <https://arxiv.org/abs/2105.11827>.
- Al-Bassam, Sonnino, and Buterin, *Fraud and Data Availability Proofs*,
  <https://arxiv.org/abs/1809.09044>; Al-Bassam, *LazyLedger*,
  <https://arxiv.org/abs/1905.09274>.
- Herlihy, *Wait-Free Synchronization*, TOPLAS 13(1), 1991,
  <https://cs.brown.edu/people/mph/Herlihy91/p124-herlihy.pdf>.
- Conley, *Proof of Honesty*, version 2.0, 2019-05-31. The repository recorded
  SHA-256
  `238dc57170e337256301c97818ff57ec0c42e9b24c3f5dea2bb0b926a94e880d`
  for the dated author-hosted PDF.

The comparison is a scope analysis, not an exhaustive novelty claim.

## 9. R3 automated review evidence

Reviewer provenance:

```text
model: gpt-daybreak-blue-latest
kind: owner-authorized context-isolated automated independent review
candidate checkout: fresh disposable detached clone
shared working tree: not modified
human peer review: false
institutional/professional certification: false
```

R2 initially returned `REPAIR_REQUIRED`. R3 closed four issues:

1. Joint conflicting submissions no longer make liveness self-contradictory:
   a rooted externally valid conflict/policy rule may reject, while each solo
   valid input still must progress against silent peers.
2. Freshness is rooted or explicit and common; non-reproducible freshness is
   external support. The idempotency register remains downstream.
3. Participant acts, replayable common inputs, and external selecting acts are
   partitioned explicitly.
4. Prior-art claims and reproducibility pins were repaired.

Formal reproduction:

```text
bash .github/scripts/run_aft_formal_checks.sh --census-only
census OK: 44 modules = 31 executed + 13 manifest-marked (manual)
```

Focused maximal-visibility results:

```text
n=2 MaximalVisibilityDilemma:
  512 generated / 256 distinct states; no error
n=3 MaximalVisibilityDilemma:
  131072 generated / 65536 distinct states; no error
ConflictQualifiedLiveness:
  6 generated / 3 distinct states; no error
RoleSwitchConflict mutation:
  expected ExternalNonConflict violation observed
ExternalSelectorMutation:
  expected ParticipantOnlyVerifier violation observed
```

The reviewer independently enumerated Boolean acceptance functions:

```text
A[p,v] := verifier accepts participant p's solo proof for value v
Liveness := all A[p,X] and A[p,Y]
Safety := for every p != q:
          not(A[p,X] and A[q,Y]) and
          not(A[p,Y] and A[q,X])
```

For `n=2..8`, no assignment satisfied solo liveness and role-switch safety
together. Checker SHA-256:

```text
3f69cce9469b7fbd4cd08eb715fc189f3d9f47aaf791d8bbedc7ad0a4d4778f5
```

The bounded models and enumerator are supporting evidence. The general result
rests on the prose role-switch proof.

Reviewer conclusion: no tested construction supplies the missing
participant-only distinguishing bit. R3 disposition: `UPHELD`.

## 10. Assurance and implementation constraints that a solution must preserve

### 10.1 Coordinate-wise assurance and no laundering (ADR 0041)

AFT does not treat guarantees as one scalar rank. `GuaranteeVectorV1` keeps
these coordinates separate:

- conflict safety and exact committee geometry;
- liveness theorem, network/adversary model, and fault bound;
- consensus, channel, externalization, and end-to-end PQ posture;
- cryptographic primitive census and DKG dependency;
- accountability;
- publication availability, custody, and retention;
- resource semantics and at-most-once support;
- distinct slashable collateral;
- profile-specific measured latency;
- assumption and theorem identifiers; and
- constituent and transformation commitments.

Policy combination is a requirements join. Evidence combination is a meet.
A wrapper may strengthen a coordinate only through a named, verified,
coordinate-specific transformation with committed evidence. Unknown or mixed
evidence cannot amplify a guarantee.

Consequences for a proposed M12 escape:

- it must identify exactly which coordinate it establishes;
- it cannot turn accountability, inclusion, availability, a timeout, or a
  resource receipt into transferable conflict safety by relabeling;
- every new selector or trust assumption must appear in the receipt;
- decision termination, input inclusion, effect authorization, and physical
  occurrence remain distinct; and
- a downstream resource can establish at-most-once execution under its
  declared model without retroactively strengthening consensus proof safety.

### 10.2 PQ v1 clean break (ADR 0048)

The admitted existing production profile—not the maximal research target—has:

- `classic_bft` as its only admitted AFT safety mode;
- ML-DSA live votes;
- mandatory hash-only randomized asynchronous fallback below one-third
  Byzantine membership;
- mutually authenticated ML-KEM channels;
- SLH-DSA terminal seals;
- no private threshold setup or DKG;
- complete portable-assurance v1 verification against separately provisioned
  trust roots; and
- no timeout-based downgrade.

Guardian-majority, Asymptote, nested-guardian, BLS placeholders, scalar
assurance promotion, and old receipt frontends are not admitted production
alternatives. The hash-only path is a liveness mechanism, not legacy fallback.

Hypervisor is intentionally isolated from consensus, validator, and SLH-DSA
dependencies. A new maximal construction must not casually re-entangle that
application build graph.

The existing PQ profile does **not** satisfy the M11 `f=n-1` liveness target.
It must not be renamed or presented as a counterexample.

### 10.3 Review provenance policy (ADR 0049)

Owner-controlled M10/M12 gates may accept a context-isolated Daybreak review
when the model is disclosed, the immutable candidate is independently tested,
all objections are recorded, substantive repairs create new immutable
candidates, and no qualifying issue is hidden.

This changes review provenance, not theorem truth. It does not turn automated
review into human peer review or authorize unsupported public claims.

## 11. What counts as defeating M12

A valid fixed-model counterexample must give the sole correct participant a
finite accepted non-`Abort` proof while every peer remains permanently silent,
yet prevent a role-switched Byzantine identity from causing any rooted offline
verifier to accept the conflicting proof it could produce in its own solo
execution.

It must identify the distinguishing information and answer all five:

1. Who produces and stores it?
2. Why can Byzantine instances neither simulate nor fork it?
3. Why can any possible sole correct instance obtain it while every peer is
   silent?
4. Why is it not a trusted oracle, relay, sequencer, TEE, external consensus,
   trusted time/erasure, linearizable selector, or hidden majority/resource
   assumption?
5. How does an offline verifier validate it from independently rooted inputs?

The counterexample must include a state machine, messages, proof format,
verifier, setup, adversarial traces, restart behavior, and an executable model
with at least one deliberately broken mutation.

If no fixed-model construction survives, a useful result identifies one
minimal changed premise and supplies the resulting complete construction. The
change must be explicit; it may not be hidden behind vocabulary such as
“public state,” “closure,” “first seen,” “observer,” or “availability.”

## 12. Gate consequences

Under the current disposition:

| Milestone | State | Reason |
|---|---|---|
| M11 exact maximal task/model | Complete | All quantifiers, validity/liveness distinctions, setup, verifier, timing, and smallest cases are fixed. |
| M12 non-circular visibility viability | `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS` | R3 L-MAX upheld by accepted automated review. |
| M13 maximal theorem | Blocked | Requires `PASS_CONSTRUCTION` or an explicit premise change. |
| M14 end-to-end theorem lift | Blocked | No maximal theorem-bearing construction exists to lift. |
| M15 production implementation | Blocked | Existing `f<n/3` and all-member-seal profiles cannot be relabeled. |
| M16 qualification | Blocked | No admitted maximal profile exists to test. |
| M17 independent maximal review | Blocked | There is no positive maximal candidate. |
| M18 public admission | Blocked | The maximal headline remains unauthorized. |

An `UPHELD` result is terminal for the fixed conjunction, not evidence that
engineering should pretend around it. Resumption requires a valid
counterexample or an explicit owner decision changing a premise.

## 13. Source inventory and integrity hashes

This snapshot consolidates the operative content of these primary repository
files. Consult the exact files for wording disputes.

```text
fc6fad92cd8c0fadd795b2754e3b38e4400812128c331fca7cb1c5684c5f7298  internal-docs/architecture/protocols/aft/specs/maximal_consensus_task.md
7e74799021aaf97c8413e6278ef35dbb5c2151ec73e695f00122ba68dd01afde  internal-docs/architecture/protocols/aft/specs/maximal_visibility_viability.md
f44fc43b498e948976c033db31ba6e4a6ed6cbdf8f65255d0247422fae83191e  internal-docs/architecture/protocols/aft/specs/maximal_prior_art_comparison_2026-09-03.md
7029d2cf258ae6fb6b95bae338bf5f0f2a0125bb9ea863daee945c43cc28e8f4  internal-docs/architecture/protocols/aft/evidence/m12-r3-daybreak-retest-2026-09-03.md
e05de65800c13cab305ff2014b77928aad7a412b225744572e674eafa2579123  internal-docs/architecture/protocols/aft/evidence/m11-m12-maximal-visibility-2026-09-03.md
ca1663d779a54ffda958c3eb6cdd21ab153733e496975d697dc515fc1d54d1b4  internal-docs/architecture/protocols/aft/packets/M12-maximal-visibility-theorem-review.md
3d47431f26eaab026fa1f52acfdbf89d346accdd8ef511885a2acf337950723f  docs/decisions/0041-adopt-coordinate-wise-aft-assurance-and-refuse-evidence-laundering.md
d3857ada8c5962cacf806186497b818a611db25ddb74729cd5ee2dc3e9d51794  docs/decisions/0048-make-aft-pq-v1-a-clean-break-and-isolate-hypervisor.md
39d7e1ee6f879f7c1f9936d7ae5b374170e70b2a8e21b65d4d97e062c0f2f385  docs/decisions/0049-accept-owner-commissioned-automated-independent-review-for-aft-research-gates.md
5cd9846bc9c3614d6bd54146e7b020b1c6cc197996068005e7350beb01d780bb  internal-docs/architecture/protocols/aft/AFT_MAXIMAL_E2E_GOAL_PROMPT.md
```

## 14. Local formal artifacts and reproduction

Relevant model directory:

```text
internal-docs/architecture/protocols/aft/formal/maximal_visibility/
```

Standing commands:

```bash
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
```

Expected mutations are part of the evidence: the role-switch mutation must
violate transferable non-conflict, and the CAS mutation must demonstrate that
resource feedback adds external selecting support. A future counterexample
must add its own positive model and a mutation that recovers failure when its
decisive assumption or mechanism is removed.

## 15. Compact problem statement for attachment metadata

AFT asks whether any relay-free, pure-software protocol can issue a persistent
offline-verifiable non-`Abort` authorization from whichever participant is the
sole correct member while all `n-1` peers are permanently silent, and still
prevent conflicting authorizations under every role-switched Byzantine fault
assignment. M12 says no: the solo proof of each possible correct identity can
be reproduced when that identity is Byzantine, while requiring intersecting
support from every possible correct identity restores all-member withholding.
The research task is to find the first invalid inference, an omitted
non-circular primitive, a complete counterexample protocol, or the weakest
explicit model delta that yields a new construction.
