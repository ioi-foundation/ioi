# Bounded Recursive Improvement

Status: canonical architecture authority.
Canonical owner: this file for bounded recursive-improvement doctrine,
`ImprovementCampaign` and `ImprovementAgenda` responsibility boundaries,
Search/Judgment/Authority separation, path-relative improvement-order semantics,
evaluation-epoch and exposure rules, order-cutoff synchronization, and the
improvement-claim ladder.
Structural owner: `common-objects-and-envelopes.md` for canonical envelope and
receipt shapes; the target-specific owner remains authoritative for candidate
construction, evaluation, governance, activation, and recovery.
Supersedes: prose that treats autonomous optimization, self-editing, one
benchmark improvement, or one successful self-targeted mutation as sufficient
evidence of recursive self-improvement.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical.
Implementation status: planned campaign protocol over partial existing GoalRun,
Improvement Proposal Plane, Foundry, evaluation, governance, release, receipt,
and learning-boundary primitives. Current master retains the older direct
proposal/simulation/approval/release precursor; same-target-family
decomposition, deployment-aware simulation/waivers, exact-base freshness,
versioned impact, application-chain receipts, and the Campaign lifecycle remain
planned. Do not claim campaign conformance, recursive
improvement, ignition, or inflection until the corresponding conformance and
evidence profiles pass.
Last implementation audit: 2026-07-16 (direct-proposal precursor only).

## Canonical Definition

**Bounded recursive improvement is proposal-mediated improvement in which a
bounded autonomous system may search for successors to declared mutable
capability, including successors to an improvement method, but may not control
the evidence, resource meter, authority, or recovery path by which a successor
becomes canonical.**

Every Campaign is admitted under one immutable owner-qualified
`ImprovementGovernanceProfile`. It defines mutable/protected target posture,
target-order and active-depth ceilings, inherited resource/statistical-risk/
evaluation-exposure reservations, evaluator separation, stopping,
promotion-authority, and irreversible-effect recovery policy. A System
constitution protects the selected System-scoped profile; a non-System owner
binds it through its declared governance path. The profile constrains admission
but grants no execution or promotion authority.

The reusable method, live pursuit, and durable research lifecycle remain
separate:

| Primitive | Sole responsibility |
| --- | --- |
| `GoalRunProfile` | Immutable reusable definition of how one goal class should converge. |
| `GoalRun` | Durable state and coordination of one daemon-admitted pursuit. |
| `ImprovementCampaign` | Optional multi-epoch domain lifecycle for candidates, evaluation exposure, order cutoffs, selection, promotion lineage, and recovery references. |
| `ImprovementAgenda` | Immutable-by-revision, non-executable portfolio of targets, hypotheses, falsifiers, evidence gaps, and investigation priorities. |

A Campaign can coordinate one or more GoalRuns. A GoalRun does not become the
campaign database, and a Campaign does not become an execution engine. The Goal
Kernel interprets an admitted GoalRunProfile; HarnessInvocations resolve scoped
steps; the daemon admits and executes effects; Foundry constructs and evaluates
candidates; target-owner governance decides changes; Agentgres records admitted
operations and projections.

## Lightweight And Campaign Paths

The Improvement Proposal Plane retains two valid paths:

```text
ordinary bounded change
  evidence -> typed successor patch -> evaluation -> UpgradeProposal
           -> target-owner decision and activation

adaptive or multi-epoch improvement
  ImprovementAgenda revision
    -> admitted ImprovementCampaign
    -> GoalRuns / candidate attempts / frozen EvaluationEpochs
    -> archive, cutoff, reproduction, and claim evidence
    -> UpgradeProposal
    -> target-owner decision, activation, monitoring, and recovery
```

An ImprovementCampaign is optional. A direct `UpgradeProposal` remains the
clean path for a bounded, one-shot change whose target, evaluation, evidence,
and release posture do not require adaptive multi-trial accounting. A Campaign
is appropriate when work spans evaluation epochs, performs adaptive candidate
search, spends sealed evaluation exposure over repeated trials, preserves a
candidate archive, coordinates multiple improvement orders, or supports a
qualified recursive-improvement claim.

The current daemon makes this distinction enforceable at one narrow seam:
after three non-rejected Improvement Proposals against the same normalized
target family within a 24-hour window, a fourth or later proposal must cite a
resolvable `ImprovementCampaign`. The guard prevents indefinite decomposition
into nominal one-shots; it does not prove Campaign admission, freeze an epoch,
reserve exposure, or satisfy any claim gate. Those campaign-grade obligations
remain planned and are evaluated separately from the direct proposal's
simulation, approval, release, and receipt chain.

The Campaign is not:

- a universal recursive-self-improvement engine;
- a new runtime, authority plane, truth store, settlement layer, or fifth
  scaling plane;
- a new mandatory application or a synonym for Hypervisor Improvement;
- a global meta-harness, self-rewriting agent, or generic recipe;
- permission for a candidate to modify live state, evaluation truth, authority,
  the constitution, protected safety loops, or its recovery ancestor.

## Owner Boundaries

| Concern | Canonical owner |
| --- | --- |
| pursuit method and one pursuit | GoalRunProfile, GoalRun, and Goal Kernel owners |
| campaign and agenda lifecycle | this doctrine plus their canonical object envelopes |
| candidate construction, experiment execution, and scorecards | Foundry and daemon runtime |
| evaluation suites, evaluator validity, challenges, holdouts, and epochs | Evaluations |
| source rights, learning eligibility, custody, and cross-boundary egress | Institutional Learning Boundary and applicable authority owners |
| mutable/protected target classification and campaign admission | the governing owner and, when System-scoped, the bounded System constitution and Governance |
| upgrade decision and target-specific activation | the target owner and its ordinary governance/release path |
| authority, resource reservations, and revocation | wallet.network or the declared local/domain authority provider |
| admitted state, lineage, receipts, and rebuildable projections | Agentgres and receipt owners |
| cockpit and evidence rendering | Hypervisor Improvement, Evaluations, Foundry, Governance, Provenance, Work, Systems, and Packages |

An owner may project another owner's state but cannot silently copy its truth or
authority. A campaign-selected candidate is only eligible to become an
`UpgradeProposal`; selection never performs activation.

## Search, Judgment, And Authority

Every Campaign separates three logical trust functions under its admitted
governance owner and, when System-scoped, that System's constitution:

| Function | May | Must not |
| --- | --- | --- |
| Search | propose candidates, run admitted attempts, preserve findings, and request evaluation | redefine the active epoch, alter sealed evidence, mint authority, change the resource meter, or activate a candidate |
| Judgment | execute frozen evaluation policy, account for exposure and statistical risk, issue challenges, reproduce evidence, and determine eligibility | mutate the candidate, select its own promotion authority, conceal invalidation, or make a release canonical |
| Authority | admit scope and budgets, approve or reject proposals, activate releases, stop work, and invoke rollback, recall, containment, or compensation | fabricate scientific evidence, rewrite frozen receipts, or treat authority as proof that a candidate is better |

These are logical trust functions, not three new runtime planes or necessarily
three products. A low-risk local profile may place functions under one
accountable principal while declaring a lower assurance class. Higher-risk,
multi-party, public-claim, constitutional, financial, security, or embodied
profiles require independent actors, policies, credentials, or failure domains
in proportion to the claimed assurance. Multiplicity of agents, model routes,
or nodes alone does not establish independence.

Canonical separation rule:

> The candidate, evaluator, resource meter, promotion authority, and recovery
> path must remain separately identifiable, versioned, challengeable, and
> unable to silently widen one another.

## Campaign Admission And Lifecycle

Campaign admission freezes or content-addresses at least:

- the owner scope, admission domain, improvement-governance profile, target
  graph, mutable-target allowlist, protected-target classification, and exact
  target base roots; a System-scoped Campaign additionally freezes its System
  and constitution, while a user/project/organization Campaign makes no claim
  of bounded-DAS integration until admitted into a System;
- one `ImprovementAgenda` revision and one coordinating `GoalRunProfile`
  revision plus the admitted component-resolution snapshot;
- evaluator, task-distribution, benchmark, model-route, tool, environment,
  dependency, rights, custody, and policy roots applicable to the first epoch;
- total resource, wall-clock, statistical-risk, evaluation-exposure, nesting,
  target-order, and authority ceilings, with disjoint reservations for
  concurrent descendants;
- stop, escalation, challenge, reproduction, release, monitoring, rollback,
  recall, containment, compensation, and irreversible-effect-accounting
  posture appropriate to the target.

The canonical lifecycle is:

```text
agenda revision and target declaration
  -> campaign admission and immutable root snapshot
  -> EvaluationEpoch freeze
  -> bounded Search attempts and immutable candidate versions
  -> Judgment, challenges, reproduction, archive, and selection eligibility
  -> optional improvement-order cutoff and typed higher-order patch
  -> UpgradeProposal
  -> target-owner Governance decision
  -> future-cohort shadow / canary / activation where supported
  -> monitoring and rollback / recall / containment / compensation
  -> next epoch, successor Campaign, closure, or quarantine
```

Every candidate has an exact parent or base, immutable diff or artifact root,
generation, resolved component set, attempt lineage, and budget/epoch binding.
Promotion against a stale target base fails optimistic-concurrency admission.
Rebasing or resolving a conflict creates new candidate lineage and requires
fresh evaluation; it is not a clerical edit to approved evidence.

Campaign pause, stop, expiration, or failure revokes future authority and
reservations according to policy. It does not erase attempts, spent exposure,
negative findings, incidents, or irreversible effects.

## Agendas, Search, And Candidate Memory

An ImprovementAgenda governs what deserves investigation. It may declare:

- target families and protected exclusions;
- hypotheses, expected mechanisms, falsifiers, evidence gaps, and dependencies;
- exploration, exploitation, replication, simplification, transfer, safety-
  debt, and assurance priorities;
- resource and exposure allocation policy;
- stopping, saturation, drift, plateau, incident, and opportunity triggers.

The Agenda is non-executable and grants no authority. A Campaign may propose an
`ImprovementAgendaPatch`, but a candidate-search policy cannot change the
objective, evaluator, Agenda, or selection rule that judges the same candidate
generation.

Candidate search preserves enough lineage to explain success and failure. A
campaign may use a Pareto, quality-diversity, or other policy-filtered archive,
but no search algorithm is universally mandatory. The canonical requirement is
to retain admitted candidates, ancestry, outcomes, costs, hard-constraint
failures, exploit findings, negative knowledge, and stepping stones according
to a declared retention profile. IOI does not introduce a universal scalar
`fitness` field.

## Improvement Orders And Finite Recursion

Higher-order improvement is ordinary retargeting:

```text
order 0 target: admitted mutable domain capability
order 1 target: the method or component that improved order 0
order 2 target: the method or component that improved order 1
...
```

`target_improvement_order` is a path-relative semantic rank assigned against a
frozen, version-unrolled target graph. It is not process nesting, a permanent
property of a component, a capability score, or proof of recursion. The same
component can occupy different orders on different target paths.

The following coordinates are orthogonal and must not be substituted for one
another:

- target improvement order;
- pursuit-method order;
- target generation;
- candidate generation;
- active nesting depth;
- transfer tier;
- improvement claim class.

Every admitted graph and active stack is finite and acyclic. Budgets, deadlines,
authority, statistical risk, exposure, and learning rights narrow or remain
equal down the ancestor chain; they never reset when order or candidate identity
changes. Concurrent siblings receive atomic, disjoint reservations and cannot
each inherit the same unspent ancestor balance.

The architecture may represent arbitrarily high sequential orders. It does not
claim infinite active recursion, guaranteed perpetual gain, monotonic
intelligence, or demonstrated recursive improvement at any order.

## Evaluation Epochs And Exposure

An `EvaluationEpoch` freezes one utility and evidence regime for a Campaign.
Its commitment includes the target/base roots, task distribution, visible,
sealed, transfer, out-of-distribution, adversarial, and operational suites,
evaluator/controller versions, statistical methodology, minimum effects,
normalization policy, complexity and operability constraints, holdout custody,
independence disclosures, and inherited resource, false-promotion, and exposure
budgets.

Within an active epoch:

1. Search cannot change the evaluator, scoring rule, holdout, objective, meter,
   or promotion threshold that selects its current candidates.
2. Sealed identifiers, cases, labels, internals, and outputs are not campaign
   learning material while they protect the epoch or a dependent claim.
3. Each access or result spends append-only `EvaluationExposureLedger` entries
   against its candidate family and ancestor posture. Changing candidate,
   branch, generation, or order does not restore spent exposure.
4. Repeated adaptive trials spend a declared false-promotion budget and use a
   versioned statistical policy. An ordinary uncorrected holdout score is not a
   reusable guarantee after adaptive selection.
5. Candidate, evaluator, and campaign-controller or Agenda changes are not
   co-promoted on the evidence that they jointly redefined.
6. A new evaluator or utility definition requires a new epoch and explicit
   impact handling for dependent candidates, releases, and claims.

Evaluator validity has a lifecycle. Leakage, compromise, correlation,
miscalibration, dependency failure, or methodological invalidation can trigger
re-verification, downgrade, quarantine, rollback, recall, or claim withdrawal.
A content-addressed access receipt proves that access occurred; it does not
prove that the protected evidence remained scientifically valid.

## Cross-Order Synchronization

Improvement orders synchronize through immutable evidence cutoffs, not live-
state merging. `ImprovementOrderCutoffReceipt` binds the source Campaign,
epoch, archive and generation roots; eligible and excluded evidence; effective
learning policy; exposure/risk/resource posture; destination base; intended
adjacent order; and terminal disposition.

The only information eligible to move upward is typed evidence that passes
`LearningEvidenceEligibility` under the applicable source rights, privacy,
retention, custody, and derivative-use policy. A `LearningEgressReceipt` is
required only when an institutional-boundary crossing is attempted or occurs;
eligibility and applicable access/custody evidence are required either way.

Synchronization rules:

- evidence moves one adjacent target-order edge per cutoff;
- one synchronization wave cannot use same-wave descendants to validate their
  own ancestor patch;
- a cutoff may support a typed owner-qualified patch but never activates it;
- old/new method x old/new target cross-play, causal ablation, fresh descendant
  portfolios, or a stricter declared substitute establish attribution before a
  generalized improver claim;
- successful patches apply only to future cohorts and immutable successor
  revisions; active runs and frozen evidence are never reinterpreted by a hot
  swap.

## Learning Eligibility And Institutional Boundaries

Observed work is not automatically improvement evidence. Each Finding or
derived artifact admitted for pursuit-, policy-, evaluator-, workflow-, skill-,
route-, tool-, memory-, model-, or worker-improvement use binds a
`LearningEvidenceEligibility` decision or an exact owner-qualified equivalent.
The decision states the allowed improvement purposes, target and tenant scope,
source-rights basis, privacy/retention treatment, contamination status,
derivative disposition, and required lineage.

`TrainingEvidenceEligibility` remains a valid model/worker-training profile of
this broader decision. Training permission does not imply permission to improve
an Agenda, policy, evaluator, or cross-tenant service, and operational inference
permission does not imply any improvement right.

Cross-tenant and ecosystem learning remain default-deny. Accepted OutcomeRoom,
AIIP, marketplace, or external reproducer contributions bind terms, provenance,
license, taint, attribution, independence, reward basis, and disposition.
Cooperation, participation volume, leaderboard rank, and payment never grant
promotion authority.

## Promotion And Effect Recovery

A Campaign emits evidence and candidates; it never owns canonical activation.
The selected candidate enters a typed `UpgradeProposal` and the target owner's
ordinary path applies:

- GoalRunProfile, WorkflowTemplate, HarnessProfile, SkillManifest,
  RuntimeToolContract, route, memory, ontology, data-recipe, model, Worker,
  package, or evaluator owners decide their successor revisions;
- constitutional, authority-ceiling, membership, shutdown, and protected-
  safety-loop targets use their protected amendment path only;
- physical planning, perception, allocation, or controller improvements require
  simulation, hardware-in-the-loop, shadow, transfer, independently enforceable
  local-safety, and operator gates appropriate to their effects, plus the
  deployment's protected assurance-amendment or recertification path where
  applicable. Remote improvement never sits in a servo, interlock, or
  emergency-stop path.

Deployment fitness includes capability, cost, latency, safety, security,
rights, authority, maintainability, complexity, portability, monitorability,
trace quality, dependency posture, whole-workgraph effects, and recovery.
Safety, authority, rights, or protected-invariant regression is a hard failure,
not a score tradeoff.

Targets with reversible state bind rollback. Distributed artifacts or installed
capabilities bind recall and affected-System accounting. Irreversible physical,
financial, publication, notification, or external effects bind containment,
compensation, and residual-effect accounting. Calling an operation “rollback”
does not make an irreversible effect disappear.

## Improvement Evidence Claims

`ImprovementEvidenceClaim` is an immutable evidence artifact, never authority.
It freezes the methodology, target chain, orders and generations, transfer tier,
fixed budgets and environments, epoch/evaluator roots, synchronization lineage,
statistics, reproductions, ablations, operability, release/recovery evidence,
limitations, and evidence root applicable when issued.

Claim classes form an evidence ladder:

| Claim class | Minimum meaning |
| --- | --- |
| `bounded_optimization` | A candidate improved a declared target under one bounded comparison. It is not an RSI claim. |
| `self_targeted_improvement` | A system produced a successor to a component participating in its own pursuit method. This does not establish net-positive recursive gain. |
| `net_positive_recursive_improvement` | Under fixed resource and methodology, the improved method produces a better distribution of fresh lower-order outcomes after transfer, cross-play, ablation, and reproduction gates. |
| `ignition_evidence` | A separately defined recursive-seat portfolio supports improved ability to improve an improver. It remains evidence under the frozen methodology, not proof of runaway or indefinite improvement. |
| `inflection_evidence` | A separately defined methodology supports a sustained change in improvement dynamics across the declared range. It is not a claim of unbounded growth. |

Support, dispute, evaluator invalidation, supersession, withdrawal, and downgrade
append successor or lifecycle records. They never mutate the issued claim. A
later, looser definition cannot upgrade old evidence. Product surfaces must not
render a stronger label than the claim artifact and its still-valid evidence
support.

## Product Placement

Bounded improvement composes the existing application topology:

| Surface | Primary projection |
| --- | --- |
| Improvement | Agenda, Campaign, target/order graph, candidate archive, cutoff timeline, and upgrade handoff |
| Evaluations | epoch, suites, custody, exposure, evaluator validity, challenges, and re-verification |
| Foundry | experiments, candidates, scorecards, archives, reproduction, and promotion-bundle construction |
| Governance | admission, protected-target decisions, budgets, release, stop, rollback, recall, and escalation |
| Provenance | ancestry, attempts, evidence eligibility, cutoffs, decisions, receipts, disputes, and claims |
| Work | coordinating and child GoalRuns, Sessions, WorkRuns, reviews, queues, and incidents |
| Systems | mutable/protected posture, current incumbent, active Campaigns, and desired/observed release state |
| Packages | candidate/release artifacts, dependencies, installations, recall, and affected Systems |

Hypervisor Improvement is the campaign cockpit, not the Campaign's truth owner.
Foundry is the builder and evaluator workbench, not the promoter. ioi.ai may
originate a goal and render a collaboration room when conditional cooperation
has positive expected surplus, but it receives no privileged evaluation or
release path. AIIP may transport accepted findings, challenges, terms, and
results; it does not define a global recursive-improvement state machine. IOI
L1 may anchor explicitly enrolled public commitments or settle disputes; it
does not execute Campaign iterations or hold private traces.

## Required Invariants

1. Improvement evidence never self-promotes.
2. A candidate cannot control its evaluator, resource meter, promotion
   authority, or recovery ancestor.
3. Reusable definitions and active work bind exact immutable revisions; a
   successor never silently rewrites an active run or frozen epoch.
4. Protected targets remain outside ordinary Campaign authority regardless of
   candidate score or claimed improvement order.
5. Search cannot redefine the utility regime that selects its current
   generation.
6. Evaluation exposure, statistical risk, resources, authority, and learning
   rights are inherited ceilings, not resettable per child or order.
7. Negative, failed, disputed, exploit, and irreversible-effect evidence is
   retained according to policy and never erased to improve a claim.
8. Higher-order evidence moves through typed, eligibility-gated cutoffs and
   fresh evaluation, not live-state sharing or same-wave circular validation.
9. Candidate selection creates proposal eligibility only. Target-owner
   governance exclusively controls activation and recovery.
10. Claim strength never exceeds the frozen methodology, transfer,
    reproduction, independence, and still-valid evaluator evidence.

## Non-Claims

This doctrine does not establish that IOI currently implements an end-to-end
ImprovementCampaign, that any IOI component has recursively improved itself,
or that higher-order improvement will be monotonic, economical, safe, or even
useful for a given target. It does not prove evaluator truth, eliminate
Goodharting, solve model-internal alignment, guarantee recovery from
irreversible effects, or turn receipts into proof of external-world facts.

It establishes the bounded protocol and evidence semantics under which those
questions can be tested without allowing the search process to redefine its
own authority or evidence.

## Implementation And Conformance Gate

The doctrine is canonical; complete Campaign implementation is planned.
Existing GoalRuns, UpgradeProposals, Foundry experiments, evaluator versioning,
simulation/shadow/canary controls, receipts, learning-boundary primitives, and
the older direct-proposal gate are partial substrate only. The proposal
fingerprint, exact live target-base hash, versioned multi-dimensional impact
assessment, managed-deployment simulation waiver, application-chain receipt,
and decomposition guard described here are target controls. None of those controls creates
an EvaluationEpoch, exposure ledger, candidate archive, order cutoff, or
Campaign promotion path.

No implementation may claim the canonical Campaign profile until a vertical
conformance slice proves:

- immutable Campaign, Agenda, target-base, component-resolution, and epoch
  commitments;
- Search/Judgment/Authority separation at the declared assurance class;
- fail-closed budgets, evaluation exposure, stale-base handling, learning
  eligibility, and protected-target admission;
- candidate/evaluator isolation, challenge and invalidation handling,
  reproduction, and deterministic evidence lineage;
- target-owner proposal, activation, monitoring, and effect-recovery paths;
- honest rendering of partial, disputed, downgraded, and absent claims.

The first useful proof should be a single-System, target-order-0 software or
pursuit-method Campaign. Higher orders, multi-node execution, multi-party
evaluation, public claims, and embodied targets are separate assurance
escalations, not implicit properties of the first slice.

## Canonical References

- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/foundations/verifiable-bounded-agency.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/foundations/institutional-learning-boundary.md`
- `docs/architecture/foundations/invariants.md`
- `docs/architecture/foundations/security-privacy-policy-invariants.md`
- `docs/architecture/components/daemon-runtime/improvement-governance-gates.md`
- `docs/architecture/components/hypervisor/improvement.md`
- `docs/architecture/components/hypervisor/evaluations.md`
- `docs/architecture/components/hypervisor/foundry.md`
- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`
- `docs/architecture/components/wallet-network/doctrine.md`
- `docs/architecture/foundations/mixture-of-workers.md`
- `docs/architecture/foundations/physical-action-safety.md`
- `docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md`
