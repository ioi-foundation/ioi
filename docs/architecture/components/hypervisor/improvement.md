# Hypervisor Improvement

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Improvement as the product cockpit
for governed improvement agendas, bounded improvement campaigns, improvement
targets, candidate lineage and comparison, cross-order synchronization,
candidate nomination, change-proposal handoff, and qualified improvement
claims over Hypervisor Core.
Supersedes: product prose that treats Improvement as a self-modifying runtime,
a generic issue tracker, a release authority, or a Foundry experiment view.
Superseded by: none.
Last alignment pass: 2026-07-15.
Doctrine status: canonical
Implementation status: planned campaign/agenda/epoch integration over a narrow
transitional improvement-proposal and simulation/rollout slice. The current
slice must not be described as a general recursive-improvement substrate until
campaign-grade Search/Judgment/Authority conformance exists.

## Canonical Definition

**Hypervisor Improvement is the safe-change cockpit for bounded autonomous
systems.**

Improvement helps an accountable owner decide what should improve, coordinate
the bounded work needed to investigate it, compare immutable candidates, and
hand a supported change to the target owner's ordinary governance and release
path. It does not execute work, decide evaluation truth, possess target
authority, or activate a candidate.

A Campaign may be admitted under a user, project, organization, or System
owner. Every Campaign freezes one owner-qualified
`ImprovementGovernanceProfile`. A System-scoped Campaign additionally freezes
the active constitution and its protected profile binding. A non-System Campaign
freezes an explicit owner policy and admission domain and may improve candidate
assets before deployment, but it does not become a bounded DAS or inherit System
authority by implication.

The product supports two proportionate paths:

```text
ordinary direct change
  evidence and typed target patch
    -> UpgradeProposal
    -> target-specific evaluation and simulation requirements
    -> UpgradeDecision
    -> target-owner activation and effect recovery

adaptive or multi-epoch improvement
  released ImprovementAgenda revision
    -> admitted ImprovementCampaign
    -> coordinating and child GoalRuns
    -> immutable candidate Attempts / Findings / WorkResults
    -> frozen EvaluationEpochs and exposure accounting
    -> attributable candidate nomination
    -> UpgradeProposal
    -> target-owner UpgradeDecision, activation, monitoring, and effect recovery
```

An `ImprovementCampaign` is optional. A known, one-shot change with sufficient
evidence should continue to use a direct `UpgradeProposal`. A campaign is
appropriate when work needs adaptive search, multiple epochs, a durable
candidate/negative-result archive, inherited resource or statistical budgets,
sealed-evaluation exposure accounting, independent reproduction, or
cross-order synchronization.

The owner boundary is:

```text
Improvement
  coordinates the agenda and campaign domain lifecycle and renders the cockpit

Goal Kernel / GoalRuns
  pursue admitted campaign work

Foundry
  builds candidate and evaluator assets and executes admitted experiments

Evaluations
  owns frozen judgment contracts, exposure, evaluator validity, and
  re-verification posture

Governance and the target owner
  admit protected work and decide release, activation, rollback, recall,
  containment, compensation, succession, or rejection

Daemon / RuntimeAssignments
  admit and execute consequential effects

Agentgres and Provenance
  admit operational records and render evidence, lineage, receipts, and replay
```

## Owns

Improvement owns the product-level authoring, inspection, and coordination
workflows for:

- immutable-by-revision `ImprovementAgenda` portfolios, including targets,
  hypotheses, falsifiers, evidence gaps, dependencies, value-of-information,
  hard constraints, and requested allocation;
- `ImprovementCampaign` admission drafts and campaign workspaces;
- the declared mutable target or exceptional atomic target bundle, protected
  boundaries, deployment incumbent, and target-owner handoff;
- target/order graphs and the distinct rendering of target improvement order,
  pursuit-method order, target generation, candidate generation, active nested
  depth, transfer tier, and claim class;
- coordinating and child GoalRun projections without duplicating their live
  state;
- immutable candidate ancestry, accepted/rejected/inconclusive/exploit
  outcomes, Pareto and behavior-cell projections, stepping stones, plateaus,
  archive coverage, cost, complexity, maintainability, and monitorability;
- campaign selection policy and an attributable candidate nomination bound to
  the applicable frozen evaluation epoch;
- inherited resource, statistical-risk, evaluation-exposure, learning-rights,
  authority, stop, and nesting ceilings as campaign posture;
- adjacent-order synchronization through
  `ImprovementOrderCutoffReceipt` lineage, eligible and excluded evidence,
  synchronized target patches, and fresh descendant-work requirements;
- recursive-seat and transfer-test portfolio coordination;
- creation of an `UpgradeProposal` that freezes the chosen campaign, epoch,
  candidate, evidence, target diff, activation requirements, and effect-
  recovery posture before target-owner review;
- qualified `ImprovementEvidenceClaim` authoring and its support, dispute,
  downgrade, supersession, withdrawal, limitation, and reproduction views; and
- background-work visibility: child work, leases, budget burn, blockers,
  challenges, evidence, cutoff checkpoints, cancellation, and quarantine.

The surface may offer a campaign-level recommendation or nomination. It must
show who or which admitted policy produced it and against which frozen epoch.
That nomination is not an `UpgradeDecision` and cannot mutate the target.

## Does Not Own

Improvement does not own:

- GoalRun execution, Goal Kernel loop state, Sessions, WorkRuns, or
  RuntimeAssignments;
- candidate code, models, workers, datasets, evaluator assets, eval worlds,
  build jobs, or experiment execution;
- evaluation-suite truth, epoch scoring, holdout bytes or labels, exposure
  accounting, evaluator validity, challenges, or re-verification decisions;
- wallet.network authority, approvals, spend grants, secrets, or capability
  leases;
- Governance admission, protected amendment, release, activation, rollback,
  recall, kill-switch, containment, compensation, or irreversible-effect
  decisions;
- Agentgres operational truth, receipt correctness, or storage bytes;
- the System deployment-incumbent projection or observed runtime state;
- Package release/install/recall truth;
- a universal optimizer, recursive harness, meta-harness, new runtime, new
  authority plane, or generic self-rewriting object; or
- proof of recursive improvement merely because a profile, optimizer, or
  campaign can target another improvement component.

## Campaign And GoalRun Boundary

An `ImprovementCampaign` is durable domain state around many bounded pursuits.
It is not a second goal and does not reinterpret the selected
`GoalRunProfile`.

```text
ImprovementCampaign
  freezes campaign contract, owner, agenda, target, incumbent, boundaries,
  budgets, policies, recovery posture, and coordinating GoalRun

GoalRunProfile
  declares the reusable pursuit method

GoalRun
  carries one admitted pursue-verify-course-correct lifecycle

Attempt / Finding / WorkResult / OutcomeDelta
  preserve candidate work, mechanisms, failures, and learning-eligible results
```

A campaign may admit child GoalRuns for candidate construction, replication,
evaluator repair, transfer tests, or recursive-seat tests. Child work receives
atomic reservations from inherited ceilings; spawning work never duplicates
the parent's remaining budget, authority, evaluation exposure, or learning
rights. Successor profiles and policies apply only to future admitted work.
They cannot hot-swap a live GoalRun or reinterpret evidence already frozen by
an evaluation epoch.

## Target And Order Semantics

Every campaign resolves to an owner-qualified mutable target such as a
`GoalRunProfile`, `WorkflowTemplate`, `HarnessProfile`, `SkillManifest`,
`RuntimeToolContract` binding, Foundry asset, evaluator portfolio, memory or
context policy, automation, package, system policy, or other typed domain
object. A target bundle is exceptional and must have one attributable
activation owner, one admitted order, declared conflicts, all-or-nothing
semantics, evaluation, and effect recovery.

The following coordinates must not be collapsed:

| Coordinate | Meaning |
| --- | --- |
| target improvement order | path-relative order of the target in a frozen improvement graph |
| pursuit-method order | order of the method coordinating the current pursuit |
| target generation | successor generation of the target under investigation |
| candidate generation | ancestry depth inside one candidate family |
| active nested depth | simultaneously live campaign nesting, always finitely bounded |
| transfer tier | distance between development evidence and the claimed domain |
| claim class | bounded optimization, self-targeting, net-positive recursion, ignition, or inflection evidence |

Requested order is not intrinsic metadata on an object. Admission freezes a
rooted, version-unrolled acyclic path and emits an attributable order-assignment
receipt. A representable higher order is an architectural horizon, not proof
of improvement, indefinite recursion, or guaranteed gain.

## Candidate Search And Nomination

Candidate history is an immutable DAG projection over admitted Attempts and
derivation refs. Campaign policy may use Pareto ranking, behavior descriptors,
quality-diversity search, sequential trials, human review, or another declared
method, but no research algorithm is mandatory architecture.

The product must preserve more than a winner:

- rejected, inconclusive, exploit, unsafe, over-budget, and non-reproducible
  attempts;
- mechanisms, parentage, base roots, conflicts, diffs, environment and route
  versions, cost, measurement, and causal-ablation evidence;
- stepping stones and candidates useful for future investigation even when
  they are not deployable; and
- hard constraints across safety, authority, rights, privacy, security,
  maintainability, monitorability, portability, and effect recovery.

The campaign may nominate a candidate only under the active frozen
`EvaluationEpoch`. It cannot change the objective, evaluator, holdout,
threshold, exposure accounting, or statistical rule that selects the same
candidate generation. Evaluator changes become a separately governed future
epoch and require affected evidence to be re-established.

## Cross-Order Synchronization

Synchronization is an immutable evidence and activation barrier, not a live
state merge and not a new runtime owner.

```text
lower-order campaign and epoch close at an exact cutoff
  -> learning-eligible Findings and Outcomes are selected
  -> denied, sealed, contaminated, or otherwise ineligible information stays out
  -> institutional-boundary egress is separately receipted when applicable
  -> ImprovementOrderCutoffReceipt freezes roots, budgets, exposure, and policy
  -> destination owner receives a typed patch proposal
  -> fresh cross-play, causal ablation, and descendant work evaluate the patch
  -> ordinary UpgradeDecision and future-cohort activation apply
```

Evidence moves one adjacent order per cutoff. Same-wave descendant evidence
cannot confirm the policy that admitted it. Old/new outer by old/new inner
cross-play is the minimum shape for attributing an outer-method effect; the
applicable epoch may require additional seeds, transfer tiers, reproduction,
or operational acceptance.

## Search, Judgment, And Authority Separation

Search, Judgment, and Authority are logical trust rings under one system
constitution, not new runtime planes:

```text
Search
  proposes candidates and investigations; cannot alter evaluation, meters,
  authority, or effect-recovery controls

Judgment
  freezes and applies evaluation contracts; cannot mutate the candidate or
  activate it

Authority
  admits campaigns and activation decisions; cannot fabricate or silently
  rewrite evidence
```

A candidate or coalition must not control the evaluator, resource meter,
promotion authority, and recovery path by which it becomes canonical. Higher-
assurance deployments should separate actors, credentials, custody, and
failure domains as required by policy.

## Product Surface Shape

Improvement is one existing baseline owner application. Canonicalizing the
campaign contract does not add another application or permanent rail item.
The dedicated route remains `/improvement` through the Applications catalog
and singular Open Application slot.

Recommended IA:

```text
Overview
Agendas
Campaigns
Targets / Order Graph
Candidate Map
Plateaus / Negative Knowledge
Evaluation Posture             link/projection from Evaluations
Cutoffs / Synchronization Waves
Changes / Proposal Handoff
Release And Effect Recovery    handoff/projection from Governance
Claims / Reproductions
History / Receipts             projection from Provenance
```

The default flow remains understandable without recursive-improvement jargon:

```text
Choose what should improve.
Choose what must never regress.
Choose a budget and review posture.
Run bounded work.
Inspect candidates and why other attempts failed.
Propose a target-specific change only when evidence is sufficient.
Optionally admit a later campaign to improve the pursuit method itself.
```

Do not ship a universal **Self-improve** button. Advanced views may expose
epochs, exposure, statistical policy, ancestry, order, cross-play, evaluator
dependencies, and qualified claims without presenting them as ambient power.

## Cross-Surface Placement

| Surface | Improvement relationship |
| --- | --- |
| Systems | renders System-scoped posture, incumbent, protected boundaries, and active campaign |
| Work | renders coordinating/child GoalRuns, Sessions, WorkRuns, reviews, incidents, and intervention controls |
| Evaluations | owns epoch freeze, judgment, exposure, challenges, and re-verification |
| Foundry | builds candidate/evaluator assets and runs admitted experimental jobs |
| Governance | admits protected work and owns target-specific decision, activation, and effect recovery |
| Provenance | renders candidate/target DAGs, cutoffs, evidence eligibility, attempts, receipts, decisions, and claims |
| Packages | owns immutable releases, dependency impact, install posture, and recall |
| Developer Workspace | provides code, diff, test, profiling, debugging, and maintainability workspaces |
| Automations | may trigger scheduled evaluation or campaign-start requests; never owns campaign truth |
| Data / Ontology | supply policy-bound evidence and semantic target definitions |
| Operations / Environments | supply experiment placement, capacity, cost, isolation, rollout, and recovery projections |
| ioi.ai Goal Space | may render plain-language purpose, status, choices, costs, and collaboration; never evaluation or release truth |

## Claims And Product Language

Improvement claims must be narrower than their evidence. The product may state
that a bounded campaign optimized a declared target when that is what the
evidence supports. `Self-targeted`, `net-positive recursive improvement`,
`ignition evidence`, and `inflection evidence` require progressively stronger
fresh-descendant, transfer, cross-play, causal, resource-normalized,
reproduction, maintainability, and effect-recovery evidence.

Every displayed claim must bind the baseline, target/order path, generations,
fixed budgets and environments, model/tool/profile versions, evaluation epoch,
exposure posture, accepted and rejected attempts, evaluator changes,
statistical method, transfer tier, reproduction posture, complexity,
monitorability, recovery posture, and limitations. Product copy must not
collapse the ladder into unqualified `RSI`, `infinite improvement`, or
`self-improving` capability language.

## Conformance Checks

- Every campaign must freeze an owner, released agenda revision, coordinating
  GoalRun, mutable target, incumbent root, target-order path, admitted profile
  resolution, protected boundaries, inherited ceilings, and effect-recovery
  policy before candidate work begins.
- Direct `UpgradeProposal` remains valid; the API and product must not force a
  campaign around an ordinary one-shot change.
- Campaign state must not duplicate GoalRun, daemon execution, evaluation,
  Governance authority, Agentgres truth, or Package release state.
- Candidate attempts and negative results must remain immutable and replayable;
  a best-candidate projection must never erase the archive.
- Candidate nomination must reference one frozen EvaluationEpoch and disclose
  the declared selection policy and accountable selector.
- Candidate/evaluator/controller or agenda revisions must not be co-promoted
  on evidence produced by the evaluator or policy they silently changed.
- Descendant campaigns inherit resource, statistical-risk, exposure,
  authority, and learning-rights ceilings through disjoint reservations.
- Cross-order evidence must use immutable adjacent-order cutoff receipts,
  eligible information only, fresh downstream work, and future-cohort
  activation.
- Search cannot grant authority, Judgment cannot mutate or activate, and
  Authority cannot create evaluation evidence.
- Every proposed activation must route to its target owner's ordinary
  `UpgradeDecision` and effect-recovery path.
- Physical improvement must not target protected independently enforceable
  local-safety or emergency-stop control loops through ordinary adaptive
  campaign machinery.
- Claims must remain qualified and must be downgraded, reverified, rolled back,
  or recalled when a depended-on evaluator or evidence root is invalidated.

## Anti-Patterns

Avoid:

```text
ImprovementCampaign = long-running GoalRun
ImprovementCampaign = mandatory wrapper for every patch
Improvement = runtime, evaluator, or release authority
candidate nomination = production activation
best benchmark score = deployable winner
optimizer edits the evaluator that selects the same generation
new order label = restored holdout or statistical budget
same-wave evidence = proof of the policy that admitted it
negative result = disposable failed log
receipt = proof that the scientific claim is true
rollback = sufficient recovery for an irreversible physical or economic effect
higher-order schema = demonstrated recursive improvement
```

Correct:

```text
ImprovementAgenda = governed non-executable investigation portfolio
ImprovementCampaign = optional multi-epoch improvement domain lifecycle
GoalRun = one admitted pursuit inside or outside a campaign
Evaluations = frozen judgment and validity owner
Foundry = candidate/evaluator asset builder and admitted experiment executor
Governance + target owner = admission, activation, and effect-recovery authority
Improvement = the cockpit joining these owners without replacing them
```

## Related Canon

- [`../../foundations/bounded-recursive-improvement.md`](../../foundations/bounded-recursive-improvement.md)
- [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`evaluations.md`](./evaluations.md)
- [`foundry.md`](./foundry.md)
- [`../daemon-runtime/improvement-governance-gates.md`](../daemon-runtime/improvement-governance-gates.md)
- [`../../../decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md`](../../../decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md)
