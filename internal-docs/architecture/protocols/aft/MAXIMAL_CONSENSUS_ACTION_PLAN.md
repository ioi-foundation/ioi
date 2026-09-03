# AFT maximal-consensus end-to-end action plan

Status: proposed execution plan; no new theorem or production claim is created
by this document.

Date: 2026-09-03.

Authority: accepted ADRs, canonical architecture documentation, executable
code, and reviewed proofs remain authoritative. This plan coordinates work and
records admission gates. When it conflicts with an accepted ADR or a proved
lower bound, the ADR or proof wins until deliberately superseded.

## 1. Required outcome

The research and implementation target is:

> Relay-free, pure-software Byzantine consensus with agreement, validity, and
> termination at `f = n - 1`, under a precisely defined AFT model whose added
> visibility primitive is implemented non-circularly rather than assumed.

The result is not complete unless the same theorem-bearing construction is
carried through canonical ordering, durable state, policy-authorized
irreversible effects, portable evidence, production admission, implementation
conformance, independent security review, and honest publication of every
assumption and cost.

This is a target, not a current claim. The present corpus proves an obstruction:
for a `q`-of-`n` certificate family, all-but-one safety forces `q = n`, while
liveness with `n - 1` withholders requires `q <= 1`. A visibility mechanism
that only distributes already-published artifacts does not remove that
obstruction. The first research gate must therefore establish that the target
is coherent under a non-circular model before production implementation of a
new consensus profile begins.

## 2. Non-negotiable meanings

No milestone may change these meanings merely to make a gate pass.

### 2.1 Agreement

No two correct participants decide conflicting values for the same typed
instance. Because agreement among one correct participant is otherwise
vacuous at `f = n - 1`, the theorem must also state what a transferable
certificate lets an external verifier conclude when Byzantine participants
can emit arbitrary competing artifacts.

### 2.2 Validity

The task specification must select and justify a named validity property. At a
minimum it must distinguish:

- all-correct-input validity;
- honest-proposal or external-validity admission;
- authorization validity for irreversible effects; and
- whether a typed `Abort` or no-op is a decision.

An `Abort` may satisfy a separately named termination theorem, but it does not
count as transaction inclusion, seal cadence, effect authorization, or
irreversible-effect liveness.

### 2.3 Termination

Every correct participant must eventually decide under the theorem's exact
admissible executions. A probabilistic result must say almost-sure or expected
termination and identify its randomness and adversary. A synchronous or
partially synchronous result must name its timing assumption. Permanent
Byzantine silence is included when claiming termination with `f = n - 1`.

### 2.4 Relay-free

Correctness may not require third-party message relays, a hidden committee, a
guardian service, or an operator forwarding protocol messages. Direct access
to an implemented shared medium is not automatically relay-free: its writers,
readers, storage providers, consistency rule, and failure model must be part of
the theorem.

### 2.5 Pure software and non-circular visibility

The theorem may not rely on a TEE, trusted publisher, trusted sequencer,
unmodeled global clock, trusted availability oracle, or a service whose own
contract is consensus-equivalent unless that stronger primitive is named as an
assumption and the headline is revised through claim adjudication. The
visibility primitive must have an executable construction and a proof that
does not invoke the consensus result it is used to prove.

### 2.6 End-to-end consequence

Consensus authorization and physical execution are distinct. The strongest
admissible consequence theorem remains conditional on a modeled external
resource contract, such as an atomic idempotency register. Network consensus
must not be described as forcing an arbitrary external actor or physical
resource to act.

### 2.7 No authority from silence and no laundering

Silence, timeout, observation of absence, certificate wrapping, economic
weight, or migration may not manufacture authority. Any pre-consent,
delegation, succession, lease, or escrow mechanism must identify the earlier
authenticated act that supplies authority and the exact scope and expiry of
that act. Every composed guarantee remains bounded coordinate-wise by verified
constituents.

## 3. Program invariants

These rules apply throughout the program:

1. Every positive theorem has a machine-readable `Assumes` line, an executable
   or mechanized conformance target, and a matching lower bound or a named
   `L-OPEN` blocker.
2. A claim does not enter an ADR, production receipt, CLI output, abstract, or
   README headline before its admission gate passes.
3. Safety, validity, availability, termination, latency, accountability,
   post-quantum status, setup, and consequence semantics remain separate
   guarantee-vector coordinates.
4. No timeout or compatibility path silently selects a weaker certificate
   class.
5. Research code cannot authorize production effects.
6. The Hypervisor default profile remains isolated from validator, consensus,
   and terminal-seal dependencies unless a measured product requirement
   deliberately changes that boundary.
7. Generated evidence records the exact commit, toolchain, configuration,
   seeds, commands, and result. A later code change invalidates affected
   evidence until reproduced.
8. An independent review must be performed by an identified independent party
   against an immutable candidate. By explicit owner decision in ADR 0049, a
   context-isolated Daybreak reviewer may satisfy the owner-controlled M10/M12
   gates when its model and automated provenance are disclosed, every finding
   is retained, and repairs are exactly retested. That evidence is never
   represented as human peer review, institutional certification, or external
   professional assurance. Internal clean rooms, interoperability oracles, and
   proof assistants remain supporting evidence rather than reviewers.
9. A failed theorem attempt is retained as evidence. The program redesigns the
   mechanism or records a formal impossibility; it does not weaken definitions
   invisibly.

## 4. Starting baseline

| Surface | Current state | Immediate implication |
|---|---|---|
| M0-M8 AFT PQ v1 | Local implementation, integration, formal, receipt, and Hypervisor gates pass | Freeze and independently review the candidate before release |
| PQ v1 live ordering | Optimistic `n = 3f + 1` plus mandatory hash-only randomized asynchronous fallback at `f < n/3` | This is the production baseline, not the requested `f = n - 1` theorem |
| Terminal boundary | `n`-of-`n`, one-honest conflict safety and maximal attribution | One withholder can stop cadence |
| T5d succession | Responsive succession refuted; scheduled fenced succession narrowed; claim bookkeeping still needs reconciliation | It cannot be cited as all-but-one termination |
| T8 supply | Positive economic analysis exists; cheapest-capture supply lower bound remains `L-OPEN` | Frontier-completeness remains blocked |
| Release | M1/M8 blocked on independent provider, custody, and channel review | No full-PQ or release headline yet |
| Working tree | M0-M8 candidate is not an immutable reviewed commit | Audit cannot begin until the candidate is frozen |

## 5. Execution sequence

The phases are ordered gates. Work may be parallelized inside a phase only
when artifacts do not share mutable authority or conceal a dependency.

### Phase A — Freeze and independently review AFT PQ v1

#### A1. Candidate stabilization

- Inventory and preserve all pre-existing user changes.
- Reconcile generated artifacts, ignored evidence, and source changes.
- Resolve inconsistent T5d status text across the theorem surface, pairing
  table, claim adjudication, yellow paper, and implementation ledger without
  promoting the withdrawn claim.
- Record T8's residual consistently.
- Run formatting, diff, claim-discipline, theorem-assumption, production-
  authorization, affected-workspace, formal, and integrated M8 gates.
- Create an immutable candidate commit and an annotated tag or signed external
  candidate manifest that resolves to that exact commit. A commit cannot
  contain its own commit hash; therefore the frozen packet describes the
  binding format, while the tag/commissioning record supplies the full hash.
  Never edit the candidate merely to insert its own hash, because that would
  create a different, unreviewed candidate.

Exit evidence: clean candidate checkout; full command transcript; artifact
manifest; immutable candidate hash; zero unexplained worktree differences.

#### A2. Owner commissioning checkpoint

The owner must identify and engage an independent reviewer. The engagement
must cover the complete scope in `packets/P4.5a-external-audit.md` and permit
publication or durable retention of all findings. Under ADR 0049, the owner
selected a fresh context-isolated `gpt-daybreak-blue-latest` agent for M10 and
M12. This is an explicit policy exception for those gates, not authority to
describe the result as human review or to waive independent review for later
milestones.

Required owner-supplied evidence:

- reviewer identity/model and relevant qualifications/capabilities;
- independence and conflict disclosure;
- candidate commit hash;
- agreed scope and review dates; and
- signed or otherwise attributable final report, with automation disclosed.

If this evidence is unavailable, the program is `BLOCKED_EXTERNAL_REVIEW`, not
complete.

#### A3. Review execution and remediation

- The reviewer independently reproduces the required gates and chooses
  additional tests.
- Findings receive stable IDs, severity, affected assumptions, and an owner.
- Every critical or high finding is fixed or causes the affected claim to be
  withdrawn. Medium and lower findings receive explicit dispositions.
- Security-relevant fixes create a new candidate and invalidate the prior
  sign-off for the changed surface.
- The reviewer verifies remediations and issues a final report against the
  exact release commit.
- Exercise production validator-set rotation across restart and validate a
  non-shared-filesystem, rollback-resistant seal-state anchor as part of the
  custody review.

#### A4. PQ v1 release admission

M1 and M8 may become complete only when:

- the final review reports no unresolved critical or high finding;
- every affected local gate passes on the reviewed commit;
- the release claim remains inside its static-adversary and resource-contract
  boundaries;
- portable trust roots remain externally provisioned; and
- release evidence and ADR status point to the reviewed commit and report.

Legacy guardian source extraction/deletion may follow as a mechanical cleanup.
It does not delay A4 because production admission already rejects it.

### Phase B — Specify and attack the maximal theorem

No new maximal production profile begins before this phase passes.

#### B1. Exact task and adversary specification

Create a normative model document defining:

- participants, configurations, identities, keys, and external verifiers;
- inputs, admissible values, decision values, and `Abort` semantics;
- agreement, each validity notion, termination, inclusion, and effect liveness;
- static and adaptive corruption choices;
- crash, Byzantine, omission, equivocation, withholding, and recovery powers;
- channel authentication, privacy, delivery, synchrony, clocks, randomness,
  setup, storage, and client reachability;
- what `f = n - 1` means during reconfiguration; and
- what evidence a third party accepts when only one participant is correct.

The model must include `n = 2, f = 1` and arbitrary `n, f = n - 1`. It must
prevent the tolerance statement from becoming vacuous merely because only one
correct participant remains.

#### B2. Canonical-public-state candidate specification

Specify the proposed visibility primitive independently of any consensus
algorithm:

- `publish`, `read`, `close`, `prove-inclusion`, `prove-frontier`, and recovery
  operations;
- canonical encoding and identity binding;
- consistency, inclusion, availability, persistence, and closure properties;
- who stores bytes and metadata;
- behavior under equivocation, partition, eclipse, crash, and permanent
  withholding;
- resource bounds and garbage collection; and
- a construction from ordinary software/network/storage operations.

Every property must be labeled `constructed`, `cryptographic`, `network`,
`storage`, `timing`, or `trusted`. Renaming a property as "public" does not
construct it.

#### B3. Deepest-obligation lower-bound campaign

Before attempting the positive proof:

1. Construct paired executions in which a participant is merely delayed in
   one and permanently silent in the other.
2. Model-check the smallest cases, beginning with `n = 2, f = 1`, with no
   message or signature from the Byzantine participant.
3. Prove what information and authorization are available at the correct
   participant and external verifier at every proposed closure point.
4. Attempt forks against any rule that treats absence as authority.
5. Attempt nontermination against any rule that waits for an authenticated act
   controlled by a Byzantine participant.
6. Generalize the current `q`-of-`n` withholding result to the proposed
   certificate and bulletin construction.
7. Record whether pre-consent, leases, delegation, or escrow move the required
   act earlier rather than eliminate it.

#### B4. Viability gate

This gate has only three honest outcomes:

- `PASS_CONSTRUCTION`: an executable primitive and proof establish the exact
  model delta without circularity, and the target properties survive the
  withholding campaign;
- `REDESIGN_REQUIRED`: a counterexample defeats the candidate but not every
  allowed construction, so the mechanism is replaced and B2-B4 repeat; or
- `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`: a reviewed lower bound shows the
  required conjunction cannot be achieved without violating a non-negotiable
  constraint.

Only `PASS_CONSTRUCTION` unlocks Phase C. An impossibility result is valuable
research but does not authorize wording the target as achieved. It requires an
owner decision about which assumption or required property, if any, may
change.

### Phase C — Prove the theorem-bearing protocol

#### C1. Consensus core

Define and prove, under the exact model from Phase B:

- agreement;
- the selected validity properties;
- termination with permanent Byzantine withholding at `f = n - 1`;
- externally verifiable non-conflict or the exact limitation on external
  evidence;
- configuration and domain separation;
- crash/restart and long-range behavior; and
- communication, storage, computation, and latency costs.

The proof must distinguish deterministic, randomized, synchronous, partially
synchronous, and asynchronous statements. It must identify the source of every
bit of authority and progress.

#### C2. Lower-bound pairings and prior-art delta

Pair every result with a necessity bound. Produce a dated, reproducible
comparison against at least:

- Dolev-Strong authenticated Byzantine agreement;
- FLP and DLS model boundaries;
- authenticated and asynchronous reliable broadcast;
- Byzantine agreement and common-subset constructions;
- data-availability sampling/certification constructions; and
- Geeq's user-selected fork model.

Compare task, validity, adversary, synchrony, setup, communication, external
verification, data availability, termination, and effect semantics—not just a
fault percentage. A novelty or superlative claim requires independent review
of this comparison.

#### C3. Mechanization

- Add executable small-state models for every new state machine.
- Prove inductive invariants in TLAPS or an equivalently reviewable system.
- Include liveness/fairness assumptions explicitly.
- Model `n = 2, f = 1`, multi-slot ordering, restart, reconfiguration,
  conflicting external evidence, and permanent silence.
- Generate traces consumed by implementation conformance tests.
- Add mutation models that remove each load-bearing assumption and recover the
  expected counterexample.

Exit gate: proofs pass; the pairing table has no unexplained `L-OPEN` row for
the new claim; independent theorists have attempted the deepest countermodel;
the positive theorem states exactly the task actually modeled.

### Phase D — Lift the theorem end to end

#### D1. Ordering and durable state

- Define how decisions become a single canonical ordered log.
- Prove prefix/non-conflict, validity, termination, and recovery for that log.
- Bind every durable record to network, configuration, epoch, instance,
  predecessor, and decision evidence.
- Prove storage assumptions separately from agreement; one correct process is
  not automatically globally available.
- Test total restart, partial loss, rollback, replay, equivocation, and
  historical synchronization.

#### D2. Irreversible-effect authorization

- Define whether maximal consensus produces authorization directly or carries
  prior policy authority.
- Re-run the no-authority-from-silence and no-laundering proofs at this seam.
- Preserve fail-closed policy selection and prohibit timeout downgrade.
- Prove that conflicting Byzantine artifacts cannot cause conflicting
  irreversible effects at an honest verifier/resource under the named model.
- Keep inclusion/authorization liveness distinct from typed `Abort`
  termination.

#### D3. Consequence theorem

- Extend the existing intent-root, execute, outcome-root, and reconciliation
  model to the new consensus evidence.
- Retain the exact atomic idempotency-register requirement for at-most-once
  mutation.
- Prove crash recovery, ambiguous-response reconciliation, and transferable
  attribution.
- State precisely which failures can be attributed and which remain omissions
  or environmental failures.

#### D4. Portable assurance

- Extend `GuaranteeVectorV1` or introduce a cleanly versioned successor.
- Populate separate coordinates for maximal agreement, selected validity,
  decision termination, inclusion/effect liveness, availability, PQ coverage,
  setup, accountability, and consequence semantics.
- Make receipts offline-verifiable against externally selected trust roots.
- Reject omitted constituents, self-nominated roots, unknown transforms,
  legacy evidence, and evidence whose model differs from policy.

Exit gate: one exact receipt can be traced from theorem-bearing decision through
the sole external mutation owner and independently reproduced without an IOI
runtime import.

### Phase E — Production implementation and migration

#### E1. New production profile

- Add one explicitly named maximal profile rather than relabeling
  `classic_bft` or the `f < n/3` hash-async profile.
- Make configuration validation enforce its exact geometry and assumptions.
- Use PQ primitives throughout any path intended to set `end_to_end_pq=true`.
- Keep any non-PQ optimization explicit and unable to satisfy a PQ policy.
- Preserve canonical domain separation, durable journals, replay resistance,
  and rooted membership.

#### E2. Implement the visibility primitive

- Implement the exact Phase-B construction as a separately testable component.
- Expose metrics and evidence for publication, frontier, closure, retrieval,
  and recovery.
- Prohibit fallback to trusted publication or operator relay.
- Add fault injection for Byzantine writers/readers, network partitions,
  eclipses, process death, disk rollback, and permanent silence.

#### E3. Wire the production path

- Integrate proposal, decision, ordering, execution, state persistence,
  receipts, synchronization, and externalization.
- Ensure production authorization has one auditable owner and accepts only an
  opaque verified guarantee object.
- Remove or permanently reject research-only shortcuts once the new profile is
  admitted.
- Keep the current reviewed PQ v1 profile available as a separately named
  baseline until migration policy deliberately retires it.

#### E4. Hypervisor performance boundary

- Keep the default Hypervisor dependency graph free of validator, consensus,
  and terminal-seal code.
- Record clean and incremental build times and binary/dependency deltas.
- Reject a maximal-consensus change that slows Hypervisor by accidental feature
  leakage.

Exit gate: production process tests execute the theorem-bearing protocol; no
configuration or receipt can claim it while running `classic_bft`, legacy
guardian code, or a research simulator.

### Phase F — Adversarial and conformance evidence

The integrated campaign must include:

- `n = 2, f = 1` and larger `f = n - 1` process tests;
- every Byzantine participant permanently silent;
- equivocation by every Byzantine participant;
- delayed-versus-dead indistinguishability schedules;
- restart before and after every durable transition;
- partition, eclipse, loss, duplication, reordering, and replay;
- visibility-state fork and rollback attempts;
- configuration rotation and long-range bootstrap;
- two conflicting external-verifier inputs;
- stalled-domain versus unrelated-domain mixed workloads;
- at-most-once consequence crash/reconciliation tests; and
- validly re-enveloped receipt mutations.

Reference traces from Phase C must replay against the production transition
system. Divergence reopens the theorem-to-code gate.

Performance evidence must report worst-case and distributional communication,
storage, CPU, memory, decision latency, recovery time, receipt size, and
externalization overhead. Results are labeled by profile; PQ and non-PQ figures
are never blended.

### Phase G — Independent validation and public claim admission

#### G1. Second immutable-candidate security review

The maximal protocol requires a fresh independent review; the PQ v1 audit does
not cover later theory or code. Scope includes the model delta, lower bounds,
visibility construction, mechanization, production refinement, cryptography,
storage, receipts, and consequence boundary. All Phase-A independence and
finding rules apply.

#### G2. Independent theorem review and twin

- Commission at least two independent theorem reviewers to attack the
  non-circularity and `f = n - 1` termination proof.
- Commission a spec-only twin implementation of the verifier and visibility
  primitive.
- Treat disagreements as specification findings, not majority votes.

#### G3. Public adversarial exercise

Run a time-bounded testnet or reproducible challenge environment with published
rules, assumptions, evidence capture, and meaningful incentives. Include the
permanent-withholder and bulletin-fork challenges rather than limiting the
exercise to terminal safety.

#### G4. Peer review and claim admission

- Submit the model, construction, lower bounds, proofs, implementation
  refinement, costs, and comparison for external peer review.
- Resolve or publish all substantive objections.
- Update claim adjudication only after the pairing table is closed and the
  final implementation review passes.
- Print the target headline only if every clause is proved, implemented,
  independently reviewed, and reproduced on the same immutable release.

## 6. Milestones and gates

| Milestone | Deliverable | Gate to close |
|---|---|---|
| M9 | Immutable PQ v1 candidate | Clean checkout and all local M8 gates pass |
| M10 | Independent PQ v1 review and release | Final independent report; no unresolved high/critical findings |
| M11 | Exact maximal task/model | Non-vacuous definitions and complete adversary/assumption ledger |
| M12 | Visibility viability result | `PASS_CONSTRUCTION`; a formal impossibility is retained evidence but blocks M13-M18 |
| M13 | Maximal consensus theorem | Agreement, validity, termination, external evidence, lower bounds, mechanization |
| M14 | End-to-end theorem lift | Ordering, durable state, effect authorization, consequence, portable assurance |
| M15 | Production implementation | Real processes use the theorem-bearing profile and conformance traces pass |
| M16 | Adversarial and performance qualification | Full `f=n-1`, restart, fork, receipt, and consequence campaigns pass |
| M17 | Independent maximal review | Security review, theorem review, twin, and finding remediation complete |
| M18 | Public admission and release | Claim gate, public evidence, peer-review disposition, immutable release |

Only one milestone may be the critical path. Initially M9 is critical; after
its completion M10 becomes critical, then M11, and so on. M13-M18 do not exist
as production claims unless M12 closes with `PASS_CONSTRUCTION`.

## 7. Evidence and issue discipline

Each milestone maintains:

- a ledger row with `NOT STARTED`, `IN PROGRESS`, `BLOCKED`, `REFUTED`, or
  `COMPLETE`;
- an evidence directory containing command transcripts and machine-readable
  manifests;
- stable finding and counterexample IDs;
- exact code/model/document trace links;
- an assumptions delta and claim delta;
- an owner-action list; and
- a rollback or withdrawal instruction when a gate reopens.

Recommended finding prefixes:

- `MAX-MODEL-*` — task/model ambiguity or circularity;
- `MAX-LB-*` — lower-bound and impossibility findings;
- `MAX-VIS-*` — visibility construction findings;
- `MAX-PROOF-*` — theorem/mechanization findings;
- `MAX-IMPL-*` — production/refinement findings;
- `MAX-PQ-*` — cryptographic/channel/custody findings;
- `MAX-EFFECT-*` — authorization/externalization findings; and
- `MAX-CLAIM-*` — comparison or overclaim findings.

## 8. Stop, block, and completion rules

The program is complete only when M9-M18 are complete and the final immutable
release supports the admitted headline end to end.

The program must stop and report a blocker when:

- an owner-only external engagement, credential, spend, disclosure, or
  publication decision is required;
- an independent reviewer has not supplied attributable evidence;
- the viability gate proves the target impossible under the non-negotiable
  constraints;
- a high or critical finding is unresolved;
- a proof/model/code divergence remains; or
- the only available next step would silently weaken the theorem.

Being difficult, slow, computationally expensive, or under active review is
not itself a reason to declare completion or invent evidence. Conversely, an
owner-action blocker does not erase completed local work: preserve the exact
resume point and the minimum evidence the owner must supply.

## 9. Immediate next actions

1. Freeze the existing M0-M8 tree as the PQ v1 review candidate.
2. Reconcile T5d and T8 status across the theorem/claim ledgers.
3. Run the complete release harness from a clean candidate checkout.
4. Resolve P4.5a's candidate field out of band with the annotated candidate
   tag/commissioning record and hand both to the independent reviewer selected
   by the owner; do not mutate the frozen candidate to self-record its hash.
5. While external review proceeds, draft M11's exact task/model and the
   `n=2, f=1` paired-execution challenge without modifying reviewed candidate
   code.
6. Do not start maximal production implementation until M12 returns
   `PASS_CONSTRUCTION`.
