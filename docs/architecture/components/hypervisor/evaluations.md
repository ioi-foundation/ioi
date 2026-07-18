# Hypervisor Evaluations

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Evaluations as the product judgment
surface for evaluation-suite lifecycle, frozen evaluation epochs, holdout and
evaluator custody posture, adaptive-exposure accounting, score and validity
projections, evaluator challenges, dependency impact, and re-verification over
Hypervisor Core.
Supersedes: product prose that treats evaluation as a benchmark tab inside
Foundry, an optimizer-owned reward function, a receipt-presence check, or an
automatic release decision.
Superseded by: none.
Last alignment pass: 2026-07-15.
Doctrine status: canonical
Implementation status: planned owner-application contract. Existing eval,
feedback, Foundry scorecard, verifier, simulation, canary, and receipt slices
are inputs to this target surface; they do not yet constitute campaign-grade
epoch freeze, sealed-holdout exposure accounting, evaluator-validity lineage,
and re-verification as one complete path.

## Canonical Definition

**Hypervisor Evaluations is the independent judgment surface for governed
autonomous systems.**

Evaluations defines what evidence is admissible for a declared decision,
freezes that judgment contract for an evaluation epoch, accounts for what an
adaptive search process learned from protected tests, and keeps dependent
claims and releases honest when an evaluator later fails.

It does not build the capability under test, execute its effects, select the
campaign target, or authorize release.

```text
evaluation assets and evaluator candidates
  built in Foundry, Developer Workspace, Data, Ontology, or a domain owner
    -> validation, custody, affiliation, rights, and independence checks
    -> released evaluation-suite revisions
    -> frozen EvaluationEpoch
    -> daemon-admitted evaluation jobs in admitted environments
    -> immutable observations, scores, challenges, and exposure entries
    -> evaluation finding / scorecard / validity posture
    -> Improvement candidate nomination or direct UpgradeProposal evidence
    -> Governance and target-owner decision
```

An evaluation result is evidence under a frozen contract. It is not authority,
operational truth merely because it has a receipt, or permission to deploy.

## Owns

Evaluations owns product-level authoring, inspection, and lifecycle workflows
for:

- evaluation-suite definitions and immutable released revisions, including
  tasks, worlds, rubrics, metrics, estimands, thresholds, minimum effects,
  power/inconclusive policy, guardrails, cost normalization, and required
  external-reality anchors;
- evaluation portfolios across visible development suites, sealed holdouts,
  transfer/out-of-distribution suites, adversarial suites, cross-play and
  causal-ablation matrices, production acceptance evidence, and independent
  reproduction;
- `EvaluationEpoch` drafting, freeze, activation, challenge, closure,
  invalidation, and successor-epoch lifecycle;
- exact commitments to the campaign/target/base roots, incumbent, task
  distribution, profile and component versions, synchronization cutoff,
  evaluator versions, decision rules, hard constraints, and inherited budgets
  applicable to an epoch;
- holdout-custodian, evaluator-controller, judge/verifier, operational-
  acceptance owner, affiliation, independence, conflict, and collusion-risk
  posture;
- `EvaluationExposureLedger` lifecycle and append-only reservations, accesses,
  information returns, spend, contamination, rotation, release, and
  invalidation entries;
- evaluator dependency and validity graphs, including model, tool, dataset,
  world, rubric, scorer, calibration, environment, route, and external-anchor
  dependencies;
- `VerifierChallenge` intake, evidence, triage, disposition, remediation, and
  affected-result discovery;
- re-verification plans, fresh-case requirements, claim downgrade or
  withdrawal recommendations, and rollback/recall escalation when depended-on
  judgment becomes invalid;
- quality dashboards and scorecard comparisons that preserve uncertainty,
  failure modes, guardrails, exposure, and applicability rather than one
  flattened benchmark number; and
- operator or participant feedback intake with its evidence-use, retention,
  privacy, source-rights, and institutional-learning eligibility posture.

The application owns the judgment contract and its lifecycle. Agentgres admits
the records; storage systems keep bytes; the daemon executes admitted jobs;
Foundry and other builders supply versioned assets.

## Does Not Own

Evaluations does not own:

- the `ImprovementAgenda`, `ImprovementCampaign`, target graph, candidate DAG,
  campaign selection policy, or candidate nomination;
- models, workers, GoalRunProfiles, HarnessProfiles, SkillManifests,
  RuntimeToolContracts, datasets, eval worlds, simulators, scorers, verifier
  models, or other build artifacts before their evaluation registration;
- Foundry experiment, training, tuning, conversion, reproduction-job, or
  candidate-construction execution;
- GoalRun, Session, WorkRun, RuntimeAssignment, environment, or daemon
  execution truth;
- wallet.network authority, approvals, secrets, access grants, or budget
  issuance;
- Governance admission, `UpgradeDecision`, release, cohort, traffic split,
  rollback, recall, kill-switch, containment, or compensation authority;
- Agentgres operational truth, receipt correctness, or storage payload bytes;
- System health, deployment-incumbent, package-release, or marketplace truth;
- a universal objective, one mandatory statistical method, one optimizer, or a
  claim that all important properties can be reduced to one score; or
- proof of safety, correctness, or scientific validity from a receipt alone.

## Evaluation Asset And Epoch Boundary

An evaluation asset says how a capability can be tested. An
`EvaluationEpoch` says exactly which immutable judgment contract governs a
particular bounded comparison.

```text
evaluation-suite revision
  reusable tasks, worlds, fixtures, scorers, rubrics, and policies

EvaluationEpoch
  immutable commitment to the exact target, incumbent, profile/component
  roots, task distribution, suite versions, evaluators, thresholds,
  statistical policy, exposure posture, budget, and applicability

evaluation run
  one admitted execution against that epoch

evaluation result / Finding / scorecard
  immutable observation and interpretation under the epoch
```

An epoch must not float with a mutable `latest` suite, route, dataset, world,
rubric, judge, profile, or campaign contract. Lifecycle state such as draft,
active, challenged, closed, or invalidated is appended around the frozen root;
it never rewrites the epoch body.

Candidate, evaluator, and controller/agenda changes must not be co-admitted on
evidence generated under their unrecorded new combination. A changed utility
function, threshold, scorer, holdout, information-return rule, or dependency
creates a successor epoch. Old evidence remains evidence about the old epoch
and may be re-evaluated only through an explicit, receipted path.

## Evaluation Portfolio

The judgment portfolio should reflect the actual claim and effect boundary:

| Lane | Purpose |
| --- | --- |
| visible | fast development feedback; presumed known to Search |
| sealed | confirmatory evidence with protected cases, labels, or evaluator internals |
| transfer / OOD | tests declared distance from the development distribution |
| adversarial | probes reward hacking, policy evasion, collusion, leakage, and unsafe edge cases |
| cross-play / ablation | attributes effects across old/new components and isolates causal mechanisms |
| external reality | binds simulator or proxy results to independent operational facts |
| production acceptance | target-owner evidence under the real operational envelope |
| independent reproduction | reruns under declared separation, resources, and environment |

Not every evaluation requires every lane. The epoch must declare which are
required for the claim and target risk. Missing required evidence produces
`inconclusive`, `blocked`, or `invalid`, not an optimistic pass.

Evaluation policy may use fixed tests, sequential tests, anytime-valid methods,
Bayesian or frequentist analysis, ranking, human judgment, simulation, formal
verification, or domain-specific acceptance. Canon requires declared,
versioned, reproducible policy and cumulative risk accounting where adaptive
trials occur; it does not mandate one research algorithm.

## Sealed Holdout And Exposure Contract

Sealed evaluation is a custody and information-flow boundary, not a hidden file
path. Before access, an epoch freezes:

- commitments to protected suites, worlds, cases, labels, scorers, and
  evaluator versions;
- custodians, execution principals, access policy, allowed information-return
  classes, rotation policy, and declassification policy;
- the exposure-spend function and inherited ancestor exposure posture;
- candidate commitment and family rules that prevent testing a result after
  looking at the answer; and
- which returned observations are ineligible learning material while the epoch
  or a dependent claim remains protected.

Every protected query or execution appends an exposure entry binding the
candidate commitment and family, case commitment, information returned,
evaluator versions, access/execution receipts, contamination flags, exposure
spent, and prior ledger root. Remaining exposure and contamination posture are
derived from the admitted ledger head. Renaming a candidate, starting a child
campaign, changing target order, or opening a new UI must not restore spent
exposure.

Sealed cases, labels, evaluator internals, and protected outputs are denied to
the Search ring unless a separately governed rotation/declassification path
makes them eligible. A content-addressed receipt may prove that access occurred
without revealing protected material; it does not by itself prove correct
custody or a valid score.

## Evaluator Validity And Challenges

Evaluators are fallible, versioned dependencies with a lifecycle. At minimum,
the product must preserve:

```text
draft -> validated -> released -> active
                       |            |
                       v            v
                   challenged -> degraded -> invalidated
                       |                         |
                       v                         v
                   reverified              superseded / retired
```

A challenge may concern leakage, contamination, calibration, scorer defects,
judge bias, affiliation or collusion, environment drift, fixture errors,
rights, reproducibility, external-anchor failure, reward hacking, or mismatch
between the tested and claimed effect boundary.

Challenge disposition must identify the affected evaluator revisions, epochs,
results, candidates, claims, certification posture, package releases, and live
deployments. It may require:

- score correction without changing the frozen source evidence;
- fresh evaluation under a successor epoch;
- independent reproduction or a different evaluator coalition;
- claim limitation, downgrade, withdrawal, or supersession;
- candidate rejection or a new nomination; or
- Governance review for rollout pause, rollback, recall, containment,
  compensation, or incident handling.

Evaluations emits the validity and impact evidence. It cannot itself rewrite a
campaign selection, revoke authority, or change production state.

## Improvement-Campaign Relationship

An Improvement campaign references exactly one active frozen epoch for a
candidate-generation decision. Search may see visible feedback according to
policy, but it cannot alter the epoch or receive sealed information beyond the
declared return class.

```text
ImprovementCampaign
  proposes immutable candidates and commits candidate families
    -> Evaluations applies the frozen epoch and exposure policy
    -> results and challenges return as immutable evidence
    -> Improvement records an attributable candidate nomination
    -> Governance and the target owner decide whether and how to activate
```

An evaluator-improvement campaign is allowed, but the evaluator under
construction cannot judge or select its own successor in the same epoch. It
uses an independent outer evaluator, separate custody, and a future epoch for
activation. Later evaluator invalidation must discover and re-assess dependent
campaign evidence and claims.

## Foundry Boundary

Foundry is the builder and admitted experimental executor. Evaluations is the
judgment owner.

| Foundry | Evaluations |
| --- | --- |
| builds eval suites, worlds, fixtures, scorers, verifier candidates, and reproduction jobs | releases judgment contracts and freezes exact revisions into epochs |
| packages and executes admitted experimental jobs | defines admissibility, comparison, applicability, and validity posture |
| records raw trajectories, observations, costs, and build-specific scorecards | owns protected information-return and exposure accounting |
| proposes evaluator repairs and candidate assets | challenges, invalidates, and requires re-verification of depended-on judgment |
| constructs promotion bundles | supplies independent epoch evidence; never makes the release decision |

Foundry may render Evaluation links and execution status. Evaluations may render
Foundry job and asset refs. Neither duplicates the other's lifecycle state.

## Product Surface Shape

Evaluations remains one of the twelve baseline owner applications. This
contract adds no application or permanent rail item. The route is
`/evaluations` through the Applications catalog and singular Open Application
slot.

Recommended IA:

```text
Overview
Suites / Revisions
Epochs
Runs / Scorecards
Sealed Holdouts
Exposure / Contamination
Evaluators / Dependencies
Challenges
Re-verification
Feedback / Evidence Eligibility
Quality / Drift
Claims And Release Impact
```

Default product views should answer:

```text
What was tested?
Against which exact incumbent, task distribution, and versions?
Which evidence was visible, sealed, transfer, adversarial, or operational?
What did Search learn from protected evaluation and how much exposure remains?
Who built, controlled, and validated the evaluator?
What is uncertain, inapplicable, challenged, or invalid?
Which claims and releases depend on this result?
What must be reverified if it changes?
```

## Feedback And Institutional Learning

Human corrections, acceptance/rejection reasons, outcome judgments, incident
labels, and evaluator critiques may be valuable evaluation evidence. Capture
does not imply permission to retain, train, distill, export, or share them.

Evaluations must render the applicable
`InstitutionalLearningBoundaryProfile`, source-specific rights and consent,
retention, privacy, destination scope, and evidence-eligibility decision.
Feedback may be eligible for a private evaluation but ineligible for model
training, cross-System reuse, publication, or sealed-test construction. The
most restrictive applicable boundary wins.

Protected holdout feedback remains ineligible for campaign learning while it
supports a live epoch or dependent claim. Rotation or declassification must
record the impact on every dependent comparison and claim before changing that
posture.

## Embodied And Irreversible Effects

Physical-action evaluation must preserve simulation, hardware-in-the-loop,
limited live transfer, calibration, time synchronization, embodiment, local
safety, supervision, and external-reality evidence as distinct stages.

An offline or simulated pass cannot grant actuator authority. Protected,
independently enforceable local-safety and emergency-stop loops remain outside
ordinary adaptive improvement. Where certification applies, changes follow the
deployment-specific assurance-amendment or recertification path. When effects
cannot be reversed, the epoch must evaluate recall, containment, compensation,
harm accounting, and monitorability rather than claiming that a software
rollback restores the world.

## Conformance Checks

- Every decision-bearing result must reference a frozen EvaluationEpoch and
  exact target, incumbent, task-distribution, component, evaluator, threshold,
  statistical, guardrail, cost, and applicability roots.
- Mutable `latest` datasets, suites, judges, routes, worlds, rubrics, or
  thresholds cannot supply promotion evidence.
- Search cannot mutate the epoch, exposure ledger, resource meter, or
  evaluator and cannot receive information outside the declared return class.
- Protected accesses must append chained exposure entries; remaining budget or
  contamination state cannot be maintained as an unreceipted mutable counter.
- Child campaigns inherit ancestor exposure and statistical-risk posture;
  identity or order changes do not reset them.
- Candidate, evaluator, and controller/agenda revisions cannot be silently
  co-selected using evidence from the changed judgment contract.
- A scorecard must preserve uncertainty, guardrails, applicability, cost,
  failures, and evaluator versions; one aggregate score cannot erase them.
- A challenge must discover affected epochs, results, claims, releases, and
  deployments and produce a re-verification or impact disposition.
- Evaluator invalidation appends lineage; it never mutates old evidence into a
  pass or silently deletes the dependency.
- Foundry execution records and receipts are inputs to evaluation judgment, not
  substitutes for epoch validity.
- Evaluations cannot nominate a campaign winner, issue an UpgradeDecision, or
  activate, roll back, or recall production state.
- Feedback and protected evaluation material must obey the effective learning,
  rights, consent, retention, custody, and destination boundary.
- Evaluation of embodied or irreversible effects must include the applicable
  transfer, local-safety, monitorability, containment, compensation, and harm-
  accounting requirements.

## Anti-Patterns

Avoid:

```text
eval suite = mutable collection at latest
Foundry experiment score = independent evaluation truth
optimizer-owned reward = separable judgment
sealed holdout = obscure file path
receipt exists = evaluator is correct
benchmark average = production fitness
new campaign or target order = fresh exposure budget
evaluator repaired = old dependent claims automatically repaired
simulation pass = physical deployment authority
feedback capture = learning permission
challenge = deletion of inconvenient evidence
```

Correct:

```text
Foundry builds and executes admitted experimental assets
Evaluations freezes and maintains independent judgment contracts
EvaluationEpoch binds one exact comparison boundary
EvaluationExposureLedger accounts for adaptive protected-test use
VerifierChallenge can invalidate depended-on judgment
re-verification and impact lineage keep claims and releases honest
Governance and the target owner make activation and recovery decisions
```

## Related Canon

- [`../../foundations/bounded-recursive-improvement.md`](../../foundations/bounded-recursive-improvement.md)
- [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`improvement.md`](./improvement.md)
- [`foundry.md`](./foundry.md)
- [`../daemon-runtime/improvement-governance-gates.md`](../daemon-runtime/improvement-governance-gates.md)
- [`../../../decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md`](../../../decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md)
