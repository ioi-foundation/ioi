# ADR 0039: Propose Finality Profiles Over The Agentgres Verifiable Batch Log

- Status: Proposed — design only; no runtime authority change
- Date: 2026-08-28 (revised 2026-08-28: profile labels reconciled to the
  canonical enum; the seven recognition **relationship** classes K1–K7 and
  their derivation added; successor-proof field binding and successor
  preconditions made explicit; signature/head claims narrowed to their declared
  verifier contract. Revised again 2026-08-28: implementation-evidence status
  recorded against the gates below, and the proof-audit blockers to any
  successor version stated. The status remains **Proposed**; no gate is closed
  by that revision and no runtime authority, default, or `v1` meaning changes.)
  Revised again 2026-08-28: the source-neutral recognition, availability,
  retention, verifier, certificate, and distinct v2 checkpoint/proof contracts
  are now registered, and a fail-closed offline verifier plus reference
  `single_authority_v1` emitter exists. This removes the proof-format blockers
  recorded below but does not accept the ADR: no production Agentgres path yet
  persists the admitted operation, state transition, individual receipt, v2
  checkpoint, certificate, availability commitment, and root at one durable
  linearization point before ACK, so atomic recovery and admitted cutover are
  not established.
- Owners: Agentgres / ordering and finality / wallet.network authority
- Refines if accepted: ADRs 0003 and 0038 and the ordering/finality profiles
- Bounded by, and does not amend: the source-neutral deterministic admission
  kernel contract C1–C12
  ([`web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md)),
  the canonical profile vocabulary
  ([`canonical-enums.md`](../architecture/foundations/canonical-enums.md)),
  and `INV-41`/`INV-42`
  ([`invariants.md`](../architecture/foundations/invariants.md))
- Confidence: supported for review by the M04.9 parity experiment; not accepted
  architecture and not implementation authority

## Context

The M04.9 experiment compared the current one-validator AFT authority path with
the existing immediate Solo path through the same wallet admission, execution,
IAVL state, Redb durability, receipt, restart, and authority abstractions. Six
release-mode runs independently configured ordering profile, scheduler ticker
plus genesis block floor, and polling interval with provenance. Every run
accepted the same 27-operation target-scope sequence, passed 15/15 fail-closed
semantic checks, and reproduced all nine room-child families after restart with
status/operations/latest sequence `200/21/20`.

The descriptive run-level client medians were Solo/AFT 907/1,481 ms at the
1,000 ms scheduler/block configuration with 25 ms polling, 106/1,324 ms at the
100 ms configuration with 25 ms polling, and an effectively null 1,003/1,004
ms at the 1,000 ms configuration with 500 ms polling. The first pair's
ordering/finalization medians were 48/60 ms. Independent fresh chains produced
different depth/version sample mixes, and depth-matched buckets do not preserve
all aggregate comparisons. Proposal wait and event-driven transaction
completion are not separately measured, realized proposal spacing was
unavailable, and the client phase is polling-quantized. These values are
descriptive rather than matched causal estimates. Semantic and restart parity,
not an uncontrolled latency delta, establishes sufficient grounds to review
single-authority ordering as a deployment profile rather than a second spine.

The fixture has one validator and exercises no cross-node ordering. It says
nothing about either engine with peers and does not qualify the replicated,
witnessed, AFT-with-peers, or external-finality profiles proposed below. Those
profiles require their own parity, fault, and transition evidence.

ADR 0038's AFT repair remains valid. The pre-repair quadratic canonical-collapse
rewalk was a usage defect, not an inherent BFT cost. AFT is still the control
and remains necessary wherever mutually distrusting authority owners require
shared finality. Latency alone does not authorize deleting or demoting it.

Agentgres already defines one operation-backed domain-truth spine. The design
question is therefore how that spine can express different ordering and
finality obligations without changing the state, receipt, replay, or authority
contracts underneath it.

Those underlying contracts are now stated source-neutrally as C1–C12 in
[`web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md)
§ The Deterministic Admission Kernel Contract, with Agentgres designated the
first-party conforming implementation and current runtime owner. This proposal
varies ordering and finality **over** that contract. It does not weaken a
clause, and a profile that would weaken one is out of scope for this ADR rather
than a cheaper profile.

## Proposed decision

If accepted after adversarial review and implementation evidence, Agentgres
will expose ordering/finality as a versioned deployment profile over one
cryptographically agile append-only batch log. This ADR is only a proposal. It
does not select a default, change any running path, or authorize a migration.

### One log and one authority spine

Agentgres remains the only durable operation-ordering spine. Each atomic batch
checkpoint must bind:

- the exact inclusive operation range and corresponding individual-receipt
  range;
- the preceding checkpoint identifier;
- the resulting state-map root and state version;
- the receipt root and receipt algorithm/version; and
- the ordering/finality profile and version that authorized the batch.

Batching may amortize append, root-construction, signing, and fsync work only
when every operation retains an individually verifiable authority receipt and
the recovery and ACK boundary remains atomic. No ACK may precede the required
append, state root, individual receipt, and durable linearization point for the
selected profile.

Content-addressed storage may hold immutable payload bytes referenced by the
log. CAS does not order operations, establish freshness or revocation, resolve
conflicts, or become authority. A missing or mismatched payload fails closed.

**Causal DAGs are permitted for proposals, not for accepted effects.**
Proposals, evidence, findings, observations, and messages may be organized as
an authenticated causal DAG under any profile; concurrency there is honest, and
the DAG usefully records what each participant actually saw. Accepted effects
compile against the **exact canonical heads** they name and carry the
recognition certificates their class requires. A causal edge records what was
seen; it never establishes what is true, who was authorized, or which of two
concurrent proposals wins.

**A shared physical log is not a semantic order.** Domains may share one file,
one flush, one batch, or one transport for I/O efficiency while each keeps an
independent head map, sequence, and commitment chain. Interleaving in a
multiplexed log creates no ordering, causal, or truth relation between the
domains that share it. No profile in this proposal introduces a global order
across domains, and none requires one.

### Versioned finality certificates

The batch-checkpoint envelope may carry a versioned finality certificate naming
the profile that authorized the batch. **The profile vocabulary is the existing
canonical one**, versioned as `ioi.ordering-admission-finality-profile.v1` and
owned by
[`canonical-enums.md`](../architecture/foundations/canonical-enums.md)
§ Autonomous-System Ordering And Finality Profiles:

```text
single_authority | replicated_single_authority | threshold_authority |
bft_consensus | external_chain_finality
```

An earlier revision of this ADR spelled five parallel labels — `single_authority`,
`replicated_cft`, `witnessed_threshold`, `aft`, `external_finality` — which
collided with that implemented enum and would have created a sixth-member
vocabulary by prose. They are labels, not members, and the exact compatibility
map now lives with the enum owner: `replicated_cft` → `replicated_single_authority`,
`aft` → `bft_consensus`, `external_finality` → `external_chain_finality`,
`single_authority` unchanged.

`witnessed_threshold` deliberately has **no** single mapping, and that is the
substantive correction rather than a spelling one. It conflated two separable
guarantees. When witnesses hold admission authority shares and their quorum
gates canonicality, the profile is `threshold_authority`. When witnesses only
attest to a head they observed and cannot block admission, that is not an
ordering/finality profile at all: it is a non-equivocation and freshness
obligation layered over whichever profile the system declares, carried by an
explicit witness contract — witness set, quorum, observation rule, failure
behavior. Writing it as a profile would claim admission strength the deployment
does not hold.

Every profile uses the same Agentgres operation log, state abstraction,
individual receipt semantics, restart/replay rules, and one-spine ownership,
and satisfies the same C1–C12 clauses. Changing profiles must be an admitted
log operation with an unambiguous cutover and no dual-authority interval
(`INV-41`). Because ordering, finality, durability, availability,
non-equivocation, freshness, and revocation guarantees each bound some
authority that rested on them, a profile change that relaxes any of them is an
authority-weakening change and takes the separately governed path with a
declared threshold, delay, checkpoint, and executable rollback or freeze
(`INV-42`) — it is not a redeployment. The current AFT path
(`bft_consensus`) remains the preserved control until a separate accepted
decision and implementation gate authorize any deployment default, and the
immediate Solo path (`single_authority`) remains a candidate **only within the
exact scope M04.9 qualified**: one validator, no cross-node ordering, that
27-operation target-scope sequence, on that fixture. Nothing in the evidence
qualifies it beyond that scope.

### Obligations remain separate

A checkpoint or finality certificate answers only its declared ordering and
finality claim. Protocols and verifiers must separately identify and prove:

- inclusion of an exact operation or receipt;
- consistency with the preceding admitted history;
- freshness relative to an accepted observation or witness policy;
- revocation status at the claimed state version;
- correctness of authority admission;
- payload availability and content integrity; and
- fail-closed cross-scope proof consumption and adjudication.

**A signature supports only the exact claim it was declared to verify, under a
named verifier contract.** By itself a signed head proves none of durability,
availability, non-equivocation, freshness, revocation status, authority
admission, economic recognition, or adjudication — and it does not prove
correct ordering either. A signature over a head establishes that some key
signed those bytes; that the bytes denote a position in a correctly ordered
history is a claim of the verifier contract, which must state what was checked,
against which history, by whom, and under what failure behavior. Without that
contract there is no ordering claim to inherit, only a signature. Witnessing
can contribute to a non-equivocation or freshness policy only when the witness
set, quorum, observation rules, and failure behavior are explicit and
verifiable.

### From proposed effect to admitted effect

Separating obligations is not enough by itself: something has to decide *which*
obligations a given effect owes, or the decision defaults to whatever the
implementer found convenient — which in practice means the weakest one that
passed. This ADR proposes that the decision be typed and derived, along one
fixed chain:

```text
proposed effect
  -> the invariant domains it touches and the conflict keys it writes
  -> its typed recognition class
  -> the weakest mechanism sufficient for that class
  -> admitted effect + receipt binding what was actually established
```

The class is **derived, never chosen**. An effect does not declare its own
recognition class any more than it declares its own authority; the class falls
out of which invariant domains it touches and which conflict keys it writes,
and the kernel computes it (`INV-37` — resolved, never asserted).

The classes are **relationship classes**, not severity labels. Each names the
relationship between the effect and the parties, objects, and worlds it touches,
because that relationship — not the effect's size, latency budget, or product
importance — is what determines how much recognition it owes. They are ordered
by increasing recognition requirement, and an effect is never admitted through a
mechanism belonging to a lower class.

Every class from K2 upward describes an **admitted operation** and therefore
owes the full C1–C12 base: deterministic transition, authenticated declared
inputs, exact expected head, operation-backed state, typed receipt, and boundary
revalidation of current authority and revocation. K1 is the deliberate
exception, because K1 is not an admitted operation at all — it owes C2
(authenticated declared inputs) and nothing that presumes a canonical head, and
it picks up the rest of the base at the moment it is compiled into an operation
at K2 or above.

**K1 — Private reasoning or monotone evidence.**

- *Trigger, invariants, conflict keys.* The effect writes no shared canonical
  head, consumes no scarce or conserved resource, and is externally relied on by
  nobody: private reasoning, drafts, observations, findings, traces, or an
  append to a structure whose **object class declares** monotone or commutative
  semantics. Conflict keys: none, or exactly one declared-monotone key.
  Invariants: `INV-17` (participant input is untrusted until admitted), `INV-9`.
- *Weakest sufficient mechanism.* Authenticated append with a reference to the
  causal parents actually observed. No linearization, no coordination, no
  ordering claim.
- *Additional binding.* The authoring principal, the causal parents observed,
  and the class declaration relied on for monotonicity. **No canonical head and
  no state-root claim.**

This class is the one most often over-read, so it is stated flatly: private
reasoning and monotone evidence remain **authenticated causal evidence**. They
are not canonical effect truth, and no accumulation of them becomes truth by
volume, agreement, or age. Such evidence becomes canonical only when it is
**compiled into an admitted operation** at K2 or above — an operation that names
its exact expected heads, revalidates current authority and revocation at the
boundary, and mints its own receipt. Compilation is where recognition happens;
until then the DAG faithfully records what someone saw and nothing more.

**K2 — Ownership-partitioned local mutations.**

- *Trigger, invariants, conflict keys.* The effect writes only conflict keys
  held exclusively by one writer inside one domain, with no external party yet
  relying on the result. Conflict keys: the exact owned object heads.
  Invariants: `INV-37`, C4.
- *Weakest sufficient mechanism.* Expected-head compare-and-swap on each owned
  head within that domain's deterministic writer. No cross-domain ordering and
  no agreement protocol; exclusive ownership needs no coordination.
- *Additional binding.* The exact predecessor head per touched object, the
  resulting head, and the domain sequence.

**K3 — Externally recognized use of a single-writer scarce object.**

- *Trigger, invariants, conflict keys.* The effect consumes, reserves, spends,
  or fences a scarce or conserved object that has exactly one writer — a
  capability, budget, lease, quota, nonce, seat, or reservation — and something
  outside the writing domain will rely on the result. Conflict keys: the scarce
  object's head **plus its consumption or nullifier key**. Invariants: `INV-1`,
  `INV-2`, `INV-35` (concurrently active children receive atomic disjoint
  reservations, never copies of one remaining allowance), `INV-14`.
- *Weakest sufficient mechanism.* Single-writer linearization of that object,
  the declared durability class reached before ACK, and revocation and expiry
  revalidated at the effect boundary. Consensus is not required here precisely
  because there is one writer — the recognition comes from scarcity and outside
  reliance, not from disagreement.
- *Additional binding.* The consumed capability or nullifier commitment, the
  remaining allowance, the revocation epoch checked, and the durability class
  **actually achieved** rather than the one requested.

**K4 — Multiwriter or cross-object atomic effects.**

- *Trigger, invariants, conflict keys.* The effect must hold all-or-nothing
  across two or more independently written objects, domains, or writers.
  Conflict keys: every touched object head **and the atomicity set itself as a
  joint key**. Invariants: `INV-23` (replication is not consensus), `INV-24`
  (fencing before promotion and effect), `INV-41`.
- *Weakest sufficient mechanism.* One admitted linearization point covering the
  whole set — either a single writer that owns every member, or agreement across
  their writers under the declared ordering/finality profile. Partial commit is
  not a cheaper option; it is a defect.
- *Additional binding.* The full set of touched object IDs with prior versions,
  the joint conflict-key commitment, and the ordering/finality profile and
  version that produced the linearization point.

**K5 — Public economic settlement.**

- *Trigger, invariants, conflict keys.* The effect moves value, discharges an
  obligation, or becomes economically final to a counterparty who does not trust
  the acting domain's writer. Conflict keys: the obligation head, the payer's
  conserved balance or budget key, and the accepted terms root. Invariants:
  `INV-11`, `INV-27`, `INV-30`, `INV-31` (attribution is not allocation).
- *Weakest sufficient mechanism.* The selected settlement mode's own finality
  rule, plus non-equivocation and freshness certificates over the exact
  checkpoint the counterparty relies on, each under its named verifier contract.
  A head signed by the paying domain is not sufficient, because the relying
  party's whole problem is that it does not trust that signer.
- *Additional binding.* The accepted terms root, the settlement mode and rail,
  the counterparty-verifiable finality certificate and its verifier identity,
  and the validity interval.

**K6 — Oracle, semantic, legal, or real-world adjudication.**

- *Trigger, invariants, conflict keys.* Correctness depends on a claim about the
  world, a semantic mapping across domains, a legal disposition, or a contested
  outcome that no head can settle — **or the effect cannot be classified at
  all**. Conflict keys: the contested assertion head, the oracle-evidence
  decision head, and the domain assertion-admission head. Invariants: `INV-25`
  (oracle input remains evidence), `INV-9`, `INV-17`, `INV-36`, `INV-39`.
- *Weakest sufficient mechanism.* The declared adjudication path executed
  **before** the effect, carrying both the current exact-head oracle-evidence
  decision and the current exact-head domain assertion-admission decision. No
  amount of signing, witnessing, or consensus substitutes: these are questions
  ordering cannot answer.
- *Additional binding.* The adjudication decision and its authority, what it
  resolved, the oracle receipt and assertion commitment, the fact class and
  consequence scope, and the validity interval.

**K7 — Authority-expanding constitutional upgrades.**

- *Trigger, invariants, conflict keys.* The effect would expand authority, or
  weaken a guarantee that bounds authority — ordering, admission, finality,
  durability, availability, non-equivocation, freshness, or revocation. Conflict
  keys: the constitution head, the authority-policy root, the ordering/finality
  profile head, and the amendment-gate head. Invariants: `INV-5`, `INV-21`,
  `INV-28`, `INV-42`.
- *Weakest sufficient mechanism.* **There is no weak sufficient mechanism, and
  ordinary admission cannot carry this class at any strength.** It takes the
  separately governed path with all four of a declared approval threshold, an
  enforced delay before effect, a checkpoint pinning the exact pre-change state
  and commitments, and a rollback or freeze executable *without* the changed
  authority (`INV-42`).
- *Additional binding.* The constitution, kernel, and policy roots before and
  after; the amendment authority and the threshold actually met; the delay
  observed; the checkpoint pinned; and evidence that the rollback or freeze path
  is executable without the new authority.

**Unknown routes to K6, never to a weaker default.** An effect whose invariant
domain is unknown, whose conflict keys cannot be enumerated, or whose class two
rules disagree about is **K6**. It is not K1 because nothing objected, it is not
K2 because no conflict was found, and it is not admitted provisionally pending
classification. The failure mode this closes is the ordinary one: an
unrecognized effect is indistinguishable from a trivial one right up until it
is not, and the cost of that mistake is paid at K5 or K7.

**Weakest sufficient, not weakest available.** "Weakest sufficient mechanism" is
a floor, not a budget. A deployment may always use a stronger mechanism than its
class requires; it may never use a weaker one because the stronger one was slow,
unavailable, or degraded. When the sufficient mechanism cannot be reached, the
effect is refused by a named reason (`INV-14`) — it does not fall through to a
lower class while keeping the higher class's label (`INV-38`).

**Relationship to `BranchMergePlan` merge classes.** This refines the existing
three-class merge vocabulary; it does not introduce a second one.
`declared_commutative` is the conflict-key test for K1's monotone case and
`exclusive_owner` is the test for K2, both unchanged. The merge class
`adjudicated` — the default when no other class applies — is what these classes
resolve: it lands at K3 through K7 according to scarcity, atomicity, economic
finality, world-dependence, and authority effect, and it lands at K6 whenever
the class cannot be determined.

This class set is now the registered source-neutral
`ioi.recognition-class.v1` member set. Registration makes the vocabulary
validatable; it does not accept this ADR's proposed mechanisms, grant runtime
authority, or let an effect choose its own class. Production derivation and
admission evidence remain separate gates.

### Receipt compatibility and portable proofs

`ReceiptCheckpoint` v1 remains the linear
`ioi.receipt-hash-chain-jcs-sha256.v1` contract, and `ReceiptProofBundle` v1
remains exactly as registered. **Neither v1 meaning changes under this
proposal, in any profile.** A successor is a new version alongside them, never
a redefinition of them: a Merkle or batch-inclusion structure introduced by
silently reinterpreting the v1 linear chain would invalidate every proof
already issued against it, which is the specific failure this paragraph exists
to prevent.

The distinctly versioned `ReceiptCheckpoint` v2 and `ReceiptProofBundle` v2 are
now registered alongside v1. Each v2 checkpoint/finality claim binds all of the
following. The list is deliberately long because each omission is a place a
verifier would have to guess, and a guessing verifier is a verifier that can be
walked:

- **institution/domain identity and authority epoch** — which bounded System's
  truth this is, under which authority and revocation epochs, so a claim cannot
  be replayed against a different institution or a superseded authority;
- the **exact inclusive operation range** and the corresponding **individual
  receipt range**, so no operation is provable only as part of an aggregate;
- the **previous and next canonical heads**, so both history consistency and
  the resulting position are checkable rather than assumed;
- the **resulting state root and receipt root**, each with its state version;
- the **touched object IDs with their prior versions, and the conflict-key
  commitment** over the set actually written, so an inclusion proof cannot hide
  what else moved;
- the **capability consumption or nullifier commitment** where the effect spent
  a scarce or conserved object, so double-spend is detectable offline;
- the **constitution, kernel, and policy roots** in force, so a verifier can
  tell which rules the admission was evaluated under;
- the **ordering/finality profile and version that authorized the batch**,
  spelled with the canonical member set above;
- the **availability manifest, retention class, and verifier contract** for
  every referenced payload, so availability is a stated obligation with a named
  checker rather than an assumption (`INV-12`);
- the **recognition/finality class** the effect was admitted at, so a reader can
  see which obligations were owed and check that the weakest sufficient
  mechanism for that class was actually used; and
- the **finality certificate and the identity of the verifier** that issued or
  is expected to check it.

The v2 verifier treats a claim missing any of these fields as incomplete, not compact. Each
field is a separate claim carrying its own verifier obligation; bundling them
in one envelope does not merge them into one proof, and a successor bundle
still proves only the claims it binds (`INV-9`).

The current portable verifier's `integrity` axis proves that the returned
signer identity signed the exact recomputed checkpoint; its bundle-carried
issuer expectation is not an independently rooted authority registry. It does
not prove that signer presently governs the named domain, that the authority is
current or unrevoked, or that the effect was admitted. Those are the separate
`authority_admission` and `currentness` axes, which this implementation refuses.
A relying party must pin or resolve the returned signer identity out of band.

The registered v2 contracts now satisfy these proof-format prerequisites: a
**distinct schema version** — never a redefinition of a `v1`; **registered
schemas and invariants** in the contract registry; **positive and negative
fixtures**, the negative half being the load-bearing one; **offline
verification** that needs no hosted IOI service; **downgrade resistance**, so a
verifier cannot be argued into accepting a weaker or older claim shape as
satisfying a stronger one; and **explicit compatibility behavior** stating what
a v1-only verifier does when handed a successor bundle and what a successor
verifier does when handed a v1 bundle. The `ioi-finality` verifier refuses v1,
unknown versions, unsupported profiles, unsupported certificate variants, and
unsupported verifier axes. This remains separate from the already-implemented
M03.5 portable v3 authority-grant verifier.

Cryptographic agility applies to hashes, signatures, receipt roots, and
certificate verification through the repository's existing crypto ownership
boundaries. No specific replacement state tree or proof system is selected.

## Evidence and gates before acceptance

The proposal may advance only after all of the following are mechanized:

- exact crash points around append, batch/root construction, state update,
  receipt creation, certificate signing, and fsync;
- deterministic recovery that either admits the whole checkpoint or none of
  it, with no ACK before durable recovery can reproduce the result;
- rejection of stale, missing, forged, reordered, replayed, and conflicting
  checkpoint, receipt, payload, state, and finality evidence;
- an event-driven transaction completion identity or an explicit decision to
  retain polling, with the two costs measured separately;
- repeated release-host baselines and a planted-delay mutation before any
  numeric latency tripwire;
- profile transition tests proving there is no dual-authority interval;
- portable verification fixtures for every claim a successor proof bundle
  makes;
- a derivation test for the recognition classes showing that an effect with an
  unknown invariant domain or unenumerable conflict keys resolves to **K6**,
  that no path admits it at a weaker class, and that K1 evidence never reaches
  a canonical head without being compiled into an admitted operation;
- a K7 test proving that no ordinary admission path, at any profile or
  mechanism strength, can carry an authority-expanding or guarantee-weakening
  change; and
- a downgrade-resistance and compatibility test proving a `v1` `ReceiptCheckpoint`
  or `ReceiptProofBundle` is neither reinterpreted under a successor verifier
  nor accepted as satisfying a successor claim, with the behavior of a v1-only
  verifier on a successor bundle, and of a successor verifier on a v1 bundle,
  both stated and exercised.

The M04.9 evidence is recorded in
[`m04-9-ordering-finality-parity-profile.v1.json`](../architecture/_meta/evidence/m04-9-ordering-finality-parity-profile.v1.json).
It supports proposing this direction, not accepting it. That artifact is the
historical parity record and is preserved unchanged: slots a later leg newly
measured were genuinely unmeasured when it was written, and a measurement
record that is edited to match what came after it is no longer a record.

### Implementation-evidence status

A first instrumentation leg landed at
`d0677b62c1ad4594e9d76d025b7f974c0a31fa05`. Its status is recorded in
[`m04-9-golden-boundary-implementation-status.v1.json`](../architecture/_meta/evidence/m04-9-golden-boundary-implementation-status.v1.json).
Summarized against the gates above: **no gate is closed, and exactly two moved
partway.** What exists now is:

- an **exact transaction-specific completion event**. On the canonical
  finalization path it is published only after the finalized header for that
  height was durably updated *and* `Committed` was published for that exact
  transaction, and it is driven by the hashes the status publisher returned, so
  on that path an event cannot exist for a transaction whose status was not
  published. That path holds its publishers as private nested helpers, which
  constrains the path — it does **not** make the event unconstructible
  elsewhere, since the enum variant is public. No global compile-time guarantee
  is claimed; the ordering is bound by focused tests, and any other
  construction site remains reviewable and is not canonical completion;
- **subscription before submit** in the profiled path, because a completion
  event can only be observed by a stream that already exists;
- **exact proposal first-seen and selection instrumentation**, correlated by
  transaction hash with height and view as dimensions rather than as the key,
  held in a structure no admission, ordering, nonce, or block decision reads;
- **separate proposal, order-durability, notification-transport, and
  client-observation slots**, splitting two previously bundled slots; and
- **fail-closed planted-delay seams** for proposal selection and durable-ACK
  publication, which refuse on an unarmed, malformed, unknown-phase, or
  out-of-range spec rather than silently doing nothing, since an armed no-op
  reads exactly like a planted delay that landed.

Gate four — an event-driven completion identity — now has its **identity**. It
does not have the separate measurement of the two costs the gate also requires.
Gate five has its **seam**. It has neither the planted-delay mutation run nor
the repeated release-host baselines, so **no numeric tripwire may be selected**,
and none is. The remaining gates are untouched.

The leg claims **no latency**. Its tests assert event identity, publication
ordering, observation isolation, parser line shape, and the refusal set — shape,
ordering, and refusal, never a measurement. It claims **no peer safety**: the
fixture is still one validator exercising no cross-node ordering. It alters
**no default**: the observation table and the client subscription are unarmed
without the existing test-only benchmark-trace gate, a planted delay
additionally requires its own spec, and the completion event is an additive
stream field whose timestamps are observations carried alongside a commit and
never inputs to admission, ordering, execution, or state. There is still no
exact crash injection at receipt creation, checkpoint construction, finality
signing, root publication, or ACK treated as one recognized-effect transaction;
no profile cutover, fencing, restart, downgrade, or dual-authority evidence; no
new batching evidence; and no production checkpoint or finality successor.

### Historical blockers to any successor version

These were prerequisites, not preferences, at the prior revision. They are
retained as the review record that forced a distinct successor instead of a v1
reinterpretation. The registered source-neutral contracts, v2 schemas and
invariants, offline verifier, and substitution suite now resolve items 1–7;
neither v1 schema was modified:

1. **Recognition vocabulary:** K1–K7 lacked a registered member set. Resolved
   by `ioi.recognition-class.v1`; unknown derivations resolve to K6/fail closed,
   K1 is non-canonical, and K7 is forbidden to ordinary admission.
2. **Certificate vocabulary:** `FinalityCertificate` and a verifier contract
   did not exist. Resolved by the source-neutral registered contracts; runtime
   verification still refuses every unimplemented certificate variant.
3. **Availability vocabulary:** retention classes and an availability manifest
   did not exist. Resolved by separate obligation and manifest contracts; a
   signature still does not imply availability.
4. **Verifier axes:** integrity, valid-as-of, and currentness were prose rather
   than a member set. Resolved by the registered seven-axis vocabulary, with no
   cross-axis promotion.
5. **v1 immutability:** the v1 proof bindings could not be silently tightened.
   Preserved: v2 is parallel and explicit, and both v1 meanings are unchanged.
6. **Substitution corpus:** the old v1 corpus lacked the necessary successor
   substitutions. Resolved in the v2 executable suite for root, predecessor,
   range, authority/revocation epoch, conflict keys, profile, availability,
   retention, verifier, certificate, and cross-version downgrade.
7. **Embedded checkpoint binding:** v1's bare checkpoint object could not be
   retroactively repaired. Resolved by v2's exact embedded checkpoint shape and
   offline recomputation, including immediate-predecessor body/signature and
   range/state/head continuity checks.

### Current acceptance blocker

The ADR remains **Proposed**. The smallest framework-level blocker is now the
missing production recognized-effect transaction: no Agentgres-owned runtime
path atomically persists the admitted operation append, resulting state,
individual receipt, v2 checkpoint/root, applicable certificate signature, and
availability commitment before one durable ACK/public completion. The
reference emitter operates on already assembled material and therefore does
not close that transaction boundary.

Until that seam exists, crash injection cannot prove complete-or-none recovery
for the whole recognized effect, and a profile-change operation cannot prove
prior-writer fencing or absence of a dual-authority interval. Consequently no
v2 profile is production-selectable or default-authorized. Peer-bearing AFT,
threshold/witness, external-chain, and batching work remain separate
per-profile qualifications, not prerequisites for registering or verifying the
framework.

The exact adjudication and per-profile matrix are recorded in
[`m04-9-finality-framework-adjudication.v1.json`](../architecture/_meta/evidence/m04-9-finality-framework-adjudication.v1.json).

## Options explicitly not reopened

JMT remains stopped until incremental commit, proof, persistence/restart,
pruning, and historical-anchor parity are proven through `StateManager`.
Fractal partitioning remains stopped until measured need and fail-closed
cross-partition proof consumption plus adjudication exist. Neither option is a
prerequisite for finality profiles, and this proposal grants neither option
implementation authority.

## Consequences if accepted later

- Deployments could match finality work to the trust relationship while
  retaining one Agentgres history and one receipt/state contract.
- AFT would remain available for mutually distrusting owners without imposing
  it as an unreviewed requirement on single-authority deployments.
- Checkpoint batching could amortize durability work without converting a
  batch root into the only user-visible receipt.
- Portable verification would gain explicit, separable claims instead of
  treating a signature as proof of current authority.
- The certificate and proof versioning surface would add protocol complexity
  and require migration, compatibility, and downgrade-resistance evidence.
- IOI L1 would remain optional throughout. `external_chain_finality` names
  whatever external system a deployment selected; it is not an IOI L1
  dependency, and no profile here creates network enrollment, a fee, or an
  ambient toll on local execution (`INV-27`).

## Rejection and reversal

Rejecting this proposal leaves ADR 0038 and the current AFT control unchanged.
If it is later accepted, any deployment-profile change remains reversible only
through an admitted transition operation whose recovery and finality rules are
defined by the then-accepted protocol. No implementation may cite this
Proposed ADR alone as authority to change the runtime spine.
