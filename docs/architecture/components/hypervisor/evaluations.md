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
Last alignment pass: 2026-08-29.
Doctrine status: canonical
Implementation status: partial (2026-09-15, M10.4). The four registered
shapes below — released suite revisions, evaluator revisions with the validity
lifecycle and a derived impact projection, runs admitted against a frozen and
active epoch, and immutable results with a derived verdict floor — are served
by the daemon on the shared owner-scoped mutation chain, with sealed-lane
exposure through the epoch's ledger and the model-swap continuity report
derived over ordinary results; the candidate archive, collective and
persistent-controller qualification, embodied evaluation and evaluation of
Foundry receipts as execution evidence stay planned with their owners. Existing
eval, feedback, Foundry scorecard, verifier, simulation, canary, and receipt
slices remain inputs to this surface.
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/evaluation_routes.rs`
  - `apps/hypervisor/scripts/verify-hypervisor-governed-evaluation-plane.mjs`
Last implementation audit: 2026-09-15

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

## Verification Cost Is A Declared Class

Verification cost is the binding constraint on the Internet of Intelligence,
not authority plumbing — the category owner
([`../../foundations/internet-of-intelligence.md`](../../foundations/internet-of-intelligence.md)
§ The Binding Constraint) states why. This section makes it a contract surface
instead of prose: a judgment contract that cannot say what it costs to check its
own subject cannot be routed over, priced against, or honestly compared.

**Every `VerifierPath` and acceptance profile declares a verification-cost
class.** The class is an order-of-magnitude statement of cost-to-verify relative
to cost-to-produce, drawn from a closed set:

```text
verification_cost_class:
  negligible          verification is a rounding error against production
                      (a deterministic check, a signature, a hash)
  sublinear           materially cheaper than producing the result
                      (a test suite over generated code, a spot check with
                      declared coverage)
  comparable          within the same order of magnitude as producing it
                      (independent replication, adversarial review, a judge
                      model of similar capability)
  superlinear         more expensive to verify than to produce
                      (long-horizon outcomes, causal claims, real-world
                      effects observable only over time)
  unverifiable_at_price  no admissible verifier establishes the claim within
                      the work's declared budget and horizon
```

The class describes the *verifier*, not the confidence of the result. A
`negligible` class does not mean the check is weak, and `superlinear` does not
mean the claim is doubtful — it means checking costs more than doing, which is
an economic fact with routing and pricing consequences, not a quality judgement.

`unverifiable_at_price` is a real, admissible class and not a failure state.
Much valuable intelligent work lands there. Naming it is the point: a contract
that had to choose between overstating its verifier and refusing the work would
be pressured into the first.

**What may reason over the class.** Routing and acceptance policy may select,
escalate, or refuse on the declared class — cheapest-adequate verifier
selection, escalation when a cheap verifier is inconclusive, refusal when the
declared class exceeds what a budget or horizon can carry. The class is an
input to those decisions, never itself an authority, an admission, or a verdict.
`RoutingDecisionEnvelope` changes only by carrying the declared class ref; its
shape is untouched.

**What the class must not do.** A declared class is not evidence that the
verifier ran, that it passed, or that its rule was appropriate — those remain
what they were before this section existed. Reclassifying a verifier downward to
make work look cheaper to check is a judgment-contract mutation and requires a
successor epoch, exactly as any other change to admissible evidence does. A
class declared once and never revisited as the subject distribution shifts is
stale evidence, and stale evidence is the failure mode this owner already exists
to catch.

The pricing consequence — that work whose assurance ceiling is
`unverifiable_at_price` must carry that ceiling visibly rather than price as
verified — is owned by
[`../../foundations/economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md).
`VerifierPath`'s own definition remains owned by
[`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md);
this owner supplies the class it declares, not the object.

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

## Registered Shapes

The plane's four objects beyond the epoch and its exposure ledger (owned by
[`bounded-improvement.md`](../../foundations/objects/bounded-improvement.md))
are registered contracts under `schema://ioi/components/hypervisor/…`
(2026-09-15, M10.4). Every one commits its immutable body with a `content_hash`
a relying party recomputes from the record alone; a lifecycle transition is a
successor admission on the shared owner-scoped mutation chain, never a rewrite.
Refs are hyphenated: `evaluation-suite://…/revision/{n}`,
`evaluator://…/revision/{n}`, `evaluation-run://…`, `evaluation-result://…`.

A suite REVISION freezes the declaration-only library suite (`eval-suite://`)
into something an epoch can commit to. Every task is bound to its exact source
commitment, so a mutable `latest` task cannot enter; only a RELEASED revision is
epoch- or run-eligible.

```yaml
EvaluationSuiteRevision:
  schema_version: ioi.evaluation-suite-revision.v1
  evaluation_suite_id: evaluation-suite://...
  revision_ref: evaluation-suite://.../revision/...
  revision: integer
  predecessor_revision_ref: evaluation-suite://.../revision/... | null
  content_hash: hash                      # the immutable body; excludes release_decision_ref, registry_status
  owner_ref: org://... | user://... | project://... | system://...
  library_suite_ref: eval-suite://...     # the declaration-only library object this revision freezes
  tasks:
    - task_ref: dataset://... | artifact://...
      source_commitment: hash             # the exact source; a task without one is refused
  scorer_revision_refs: [evaluator://.../revision/...]
  rubric_refs: [rubric://...]
  world_refs: [artifact://... | environment-class://...]
  required_lanes:
    - visible | sealed | transfer_ood | adversarial | cross_play_ablation |
      external_reality | production_acceptance | independent_reproduction
  nondeterminism_class: deterministic | seeded | declared_nondeterministic
  declared_seed_policy_ref: policy://... | null
  verification_cost_class: negligible | sublinear | comparable | superlinear | unverifiable_at_price
  release_decision_ref: decision://... | null
  registry_status: draft | released | superseded | retired
  admitted_at: timestamp
```

An evaluator revision freezes WHAT JUDGES under `evaluator_root` and carries its
validity lifecycle (§ *Evaluator Validity And Challenges*) as a projection
appended around that root; a challenged, degraded or invalidated revision names
the evidence that challenged it.

```yaml
EvaluatorRevision:
  schema_version: ioi.evaluator-revision.v1
  evaluator_id: evaluator://...
  revision_ref: evaluator://.../revision/...
  revision: integer
  predecessor_revision_ref: evaluator://.../revision/... | null
  evaluator_root: hash                    # over kind, implementation, affiliation, custodian and the revision identity
  content_hash: hash
  owner_ref: org://... | user://... | project://... | system://...
  evaluator_kind: scorer | judge | rubric_scorer | simulator | formal_verifier | human_panel | reproduction_harness
  implementation_ref: artifact://... | model-route:...
  affiliation_ref: org://... | null
  custodian_ref: org://... | null
  validity_status:
    draft | validated | released | active | challenged | degraded |
    invalidated | reverified | superseded | retired
  validity_decision_ref: decision://... | null
  challenge_refs: [receipt://... | decision://...]
  impact_disposition_ref: decision://... | null
  admitted_at: timestamp
```

A run is one ADMITTED execution against a frozen epoch. The daemon copies and
re-derives the epoch's frozen roots (a caller-supplied root is refused), resolves
the released suite revision, the active evaluator revision, the current
policy-bound data-view revision and every execution evidence ref through its
owner, and refuses Search as a submitter.

```yaml
EvaluationRun:
  schema_version: ioi.evaluation-run.v1
  evaluation_run_id: evaluation-run://...
  content_hash: hash
  owner_ref: org://... | user://... | project://... | system://...
  evaluation_epoch_ref: evaluation-epoch://...
  epoch_frozen_root: hash                 # copied from the epoch, re-derived
  suite_revision_ref: evaluation-suite://.../revision/...   # released
  evaluator_revision_ref: evaluator://.../revision/...      # active
  lane: visible | sealed | transfer_ood | adversarial | cross_play_ablation | external_reality | production_acceptance | independent_reproduction
  incumbent_ref: string
  incumbent_root: hash
  target_base_root: hash
  execution_evidence_refs: [model-invocation://... | receipt://... | session://... | foundry-recipe-run://...]
  policy_bound_data_view_revision_ref: view://.../revision/...
  nondeterminism_class: deterministic | seeded | declared_nondeterministic
  seed: integer | null
  submitter_role: evaluator | target_owner | independent_reproducer
  cost_units: integer
  cost_unit: tokens | usd_micros | seconds | units
  admitted_at: timestamp
```

A result is the immutable observation and its interpretation — the result and
the scorecard as one record. The verdict is drawn from the closed set and the
daemon DERIVES its floor: a missing required lane is at most `inconclusive`; a
mutable input, an inactive evaluator or undeclared nondeterminism is `invalid`;
unavailable protected input or exhausted exposure is `blocked`. A sealed-lane
result names the exposure entry its protected access appended. The record has
no promotion, nomination or activation member: Evaluations emits evidence and
decides nothing.

```yaml
EvaluationResult:
  schema_version: ioi.evaluation-result.v1
  evaluation_result_id: evaluation-result://...
  content_hash: hash
  owner_ref: org://... | user://... | project://... | system://...
  evaluation_run_ref: evaluation-run://...
  evaluation_epoch_ref: evaluation-epoch://...
  epoch_frozen_root: hash
  suite_revision_ref: evaluation-suite://.../revision/...
  evaluator_revision_ref: evaluator://.../revision/...
  lane: visible | sealed | transfer_ood | adversarial | cross_play_ablation | external_reality | production_acceptance | independent_reproduction
  observations:
    - observation_id: string
      case_commitment: hash
      outcome: pass | fail | error | skipped
      score_milli: integer                # 0..1000
      evidence_refs: [model-invocation://... | receipt://... | session://... | foundry-recipe-run://...]
  verdict: pass | fail | inconclusive | blocked | invalid
  verdict_basis:
    observed | required_lane_missing | mutable_input_refused | protected_input_unavailable |
    exposure_exhausted | evaluator_not_active | nondeterminism_undeclared
  uncertainty:
    method: fixed_test | sequential | anytime_valid | bayesian | frequentist | ranking | human_judgment | simulation | formal_verification | domain_acceptance
    interval_low_milli: integer
    interval_high_milli: integer
    sample_size: integer
  guardrail_findings: [string]
  applicability_scope: string
  cost_units: integer
  cost_unit: tokens | usd_micros | seconds | units
  failures: [string]
  evaluator_versions: [evaluator://.../revision/...]
  exposure_entry_ref: evaluation-exposure://.../entry/... | null   # sealed lane: the spend its protected access appended, or under exposure_exhausted the ledger head entry at which none remained
  admitted_at: timestamp
```

The model-swap continuity report these results feed is owned by
[`foundry.md`](./foundry.md) § *Model-Swap Continuity*
(`ModelSwapContinuityReport`).

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

## Collective And Persistent-Controller Qualification

A collective configuration is not qualified merely because many participants
completed a run. Its frozen epoch compares the exact collective composition
against the cheapest adequate simpler baseline—normally a direct path or one
GoalRun—under matched task distribution, authority, context, tools, environment,
budget, time and verifier posture. A Collective product claim requires evidence
that the additional machinery produces positive cooperation surplus for its
declared objective or a separately declared resilience/independence property.

The evaluation portfolio declares and exercises, as applicable:

- participant and role knockout;
- communication-edge restriction or removal, including environment/artifact-
  only coordination;
- artifact, controller, verifier and caretaker removal;
- stale or substituted artifact ancestry, fork or installation bindings;
- dependency unavailability and recovery;
- creator-Session and participant removal while a persistent runtime remains;
- authority, context, resource and budget expiry or revocation;
- stop, quarantine, repair, replacement and retirement;
- crash/restart with exact runtime, health and effect-receipt reconstruction;
- cost, latency, disclosure and verification overhead relative to the matched
  simpler baseline.

The epoch must distinguish robustness of the collective result from continuity
of a persistent controller. A result may remain valid after participant removal
while its runtime must stop; conversely, a healthy runtime says nothing about
the quality of its collective result. An artifact marked active is not evidence
that any runtime existed or that its authority remained current.

Knockout and ablation results are judgment evidence only. They do not rewrite
the live topology, revoke a participant, activate a controller, install an
artifact, or promote a profile. Those remain ordinary governed operations of
their target owners.

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
- A collective claim must bind a matched simpler baseline, declared cooperation-
  surplus or resilience estimand, and required participant, communication,
  artifact/controller, caretaker, authority and restart knockout matrix.
- Persistent-controller qualification must prove creator-Session independence
  through a durable accountable runtime subject and current leases; an active
  artifact ref or surviving process is insufficient.

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
