# AFT maximal-consensus end-to-end action plan

Status: active execution plan, amended by ADR 0050; no theorem or production
claim is created by this document.

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

M12a proved that the original portable byte-verifier version of this target is
impossible under M11. ADR 0050 therefore authorizes a separate target rather
than weakening that result invisibly:

> Relay-free, participant-only, pure-software online Byzantine authorization
> at `f = n - 1`, where every relying executor performs a known-synchronous
> write-through query to the configured members and no portable-finality claim
> is made.

M13Q must still establish whether that per-slot authorization primitive can be
lifted into the requested agreement, validity, and termination theorem. Until
then, QUV is a construction candidate rather than “groundbreaking consensus.”

The result is not complete unless the same theorem-bearing construction is
carried through canonical ordering, durable state, policy-authorized
irreversible effects, production admission, implementation conformance,
independent security review, and honest publication of every assumption and
cost. The original track additionally requires portable final evidence. The
QUV track instead requires every relying executor to re-run the online check;
its portable artifacts are audit records explicitly marked non-final.

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

For the original track, Phase C remains blocked by M12a. For the ADR 0050 track,
substitute M13Q only after M12b receives an independently reviewed
`PASS_CONSTRUCTION`. All Phase C obligations still apply, but external evidence
means the live `VerifyOnline` operation rather than a bearer proof.

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

For the QUV track, a portable object may attest what an executor observed for
audit, but it must carry `portable_final_receipt=false` and cannot authorize a
later relying party. The later party must execute QUV again. Therefore the QUV
version of this exit gate is an independently reproduced online decision plus
a non-authorizing audit record, not an offline final receipt.

Original-track exit gate: one exact receipt can be traced from theorem-bearing
decision through the sole external mutation owner and independently reproduced
without an IOI runtime import. QUV-track exit gate: the executor's online
decision and external mutation are reproduced, while its portable audit object
is verified to be non-authorizing.

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
| M12a | Byte-portable visibility result | `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`; immutable lower bound retained and original M13-M18 blocked |
| M12b | Interactive visibility result | Independently reviewed `PASS_CONSTRUCTION` for QUV's exact known-synchronous assumptions |
| M13 | Maximal consensus theorem | Agreement, validity, termination, external evidence, lower bounds, mechanization |
| M14 | End-to-end theorem lift | Ordering, durable state, effect authorization, consequence, portable assurance |
| M15 | Production implementation | Real processes use the theorem-bearing profile and conformance traces pass |
| M16 | Adversarial and performance qualification | Full `f=n-1`, restart, fork, receipt, and consequence campaigns pass |
| M17 | Independent maximal review | Security review, theorem review, twin, and finding remediation complete |
| M18 | Public admission and release | Claim gate, public evidence, peer-review disposition, immutable release |
| M13Q | QUV theorem | Arbitrary-`n` online non-conflict and no-conflict solo progress, exact validity/termination task, lower bounds, and mechanization |
| M14Q | Online end-to-end lift | Ordering, durable state, executor-side revalidation, effect authorization, consequence, and non-authorizing audit evidence |
| M15Q | QUV production implementation | Real processes use the theorem-bearing profile; no cached transcript authorizes an effect |
| M16Q | QUV qualification | Timing/load, rollback, restart, reconfiguration, conflict, mixed-domain, and consequence campaigns pass |
| M17Q | Independent QUV review | Fresh security/theorem review, twin, and all finding remediation complete |
| M18Q | QUV public admission | Exact known-synchronous online claim admitted on an immutable release; portable finality remains false |

Only one milestone may be the critical path. Exact R5 qualification closed M10
and `AFT-M10-003`; M15Q is now the critical path. Original M13-M18 remain
blocked by M12a. M13Q-M18Q are the separately named interactive path admitted
by M12b's independently reviewed `PASS_CONSTRUCTION`, and remain non-production
claims until their own gates close.

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

Under ADR 0050, the executable program is complete only when M9-M12a and
M12b-M18Q have their terminal honest dispositions and the final immutable QUV
release supports its admitted online headline end to end. Original M13-M18 are
retained as blocked by the proved portable-byte impossibility; they are not
laundered into QUV completion.

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

1. Preserve M10's closed R5 qualification and the exact M12b R4
   `PASS_CONSTRUCTION` report and immutable
   candidate identity; do not broaden it into a consensus or production claim.
2. Finish M15Q from commit `e8ec2dc44` or its descendant. The eight-process
   disjoint-root Q-EA7 release fixture now passes through successor progress,
   with an old-root-authenticated boundary QC bound into the owner-signed
   payload and independently replay-verified by each successor. Add
   process-restart recovery at every durable transition, finish operator source
   tooling, and prove the executor-to-members-to-T10 external-resource path.
   Retain complete non-authorizing audit evidence without relabeling an
   existing certificate class.
3. Execute M16Q against the bounded QUV scheduling architecture. Qualify Q-A3
   and Q-A9 with load, deadline-edge, restart, rollback, flood, replay,
   reconfiguration, mixed-domain, and externalization campaigns.
4. Keep original M13-M18 blocked and `portable_final_receipt=false`; do not
   admit a public QUV claim until M16Q/M17Q pass.
