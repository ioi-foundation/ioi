# Meta-Harness Master Guide

Last updated: 2026-04-05
Owner: meta-harness / benchmark runner / benchmark app / agent runtime
Status: draft

Companion documents:

- `docs/plans/benchmark-combination-matrix-plan.md`
- `docs/ioi-zero-to-hero-autonomy-prompt.md`
- `docs/computer-use-autonomy-prompt.md`
- `docs/specs/autopilot/internal_product_spec.md`

## Purpose

This is the canonical guide for designing, implementing, and operating a
cross-vertical meta layer that continuously improves the task harness across:

- coding
- research
- computer use
- artifacts
- tool or API use
- general agent workflows

It also covers:

- model discovery from approved sources
- role-level model assignment
- hardware-tiered default selection
- blind-cloud deployment variants

The objective is not "an agent that edits prompts until a leaderboard goes up."

The objective is:

- bounded operational self-improvement under sovereign control
- typed harness improvement instead of benchmark-local patching
- honest gains that generalize across validation and challenge slices
- reversible candidate evolution with retained evidence
- deployment-target-aware model and harness selection

## Scope Of This Guide

This guide defines how the controller behaves on top of the benchmark system.

It owns:

- mutation policy and allowed edit surfaces
- objective selection and search strategy
- model discovery flow and role assignment policy
- simulation, validation, and acceptance flow
- approval boundaries and rollout strategy

The companion benchmark plan owns the measurement substrate:

- benchmark packs and retained batteries
- adapters and manifests
- scorecards and comparison validity
- operator views and export contracts

If a requirement answers "how should the controller choose or validate a
candidate?" it belongs here. If it answers "what evidence must the benchmark
system produce and retain?" it belongs in the benchmark plan.

## North Star

The target system is one shared meta-control plane over many vertical-specific
task harnesses.

The meta layer should be able to:

- read benchmark and trace evidence
- identify the dominant failure class
- propose a typed harness candidate
- discover or select eligible models for specific roles
- validate it through simulation, canaries, retained batteries, and holdouts
- accept, reject, or revert it with a full lineage trail

It should do this continuously without:

- lexical routing hacks
- benchmark-specific cheats
- hidden fallback behavior
- provider shortcuts that bypass the intended runtime path
- silent overfitting to a single model family
- silently replacing a local-tier default with a cloud-tier winner

## Non-Goals

This system should not be designed as:

- a freeform self-modifying code agent with no typed mutation boundaries
- a single universal score optimizer
- a prompt-only tuning loop
- an authority-expanding agent that can rewrite policy or approval posture
- a benchmark-specific shortcut generator
- a single universal "best model" selector with no hardware or trust context

## Non-Negotiable Constraints

The meta layer must preserve these bounds:

- policy
- approval rules
- trust boundary
- secrecy boundary
- observability
- versioning
- rollback

The following are forbidden as accepted improvement mechanisms:

- benchmark-id routing
- task-id routing
- selected-skill-name routing
- hidden deterministic fallback as the real happy path
- judge relaxation that accepts incorrect behavior
- provider-specific backdoors that do not represent real runtime capability
- silent model-family-specific tuning presented as a universal harness win
- unrestricted use of protected holdout evidence as optimization input
- silent cloud substitution for a local-only lane

## Core Principles

### 1. Type before text

The meta layer should optimize typed structures first:

- playbooks
- workflow topology
- tool policies
- verifier policies
- context-packaging rules
- budget profiles
- recovery policies
- preset compatibility maps

Text prompts still matter, but prompt edits should be framed as part of a typed
contract, not as an unbounded search surface.

### 2. Diagnose from traces, accept from held-out evals

Traces, receipts, and replay artifacts are for diagnosis and hypothesis
generation.

Candidate acceptance should depend on:

- repeated runs
- validation slices
- challenge slices
- holdouts
- conformance gates
- cross-family regression checks

### 3. Optimize one changing axis at a time

Every candidate should declare its primary axis:

- `tool_policy_change`
- `verifier_policy_change`
- `playbook_change`
- `budget_profile_change`
- `routing_contract_change`
- `context_packaging_change`
- `full_harness_change`

If too many axes move at once, the meta layer loses attribution.

### 4. Shared controller, family-specific mutators

There should be one controller, but not one undifferentiated search space.

The controller should use vertical-specific mutators for:

- coding
- research
- computer use
- artifacts
- tool or API use
- general agent behavior

### 5. Universal wins must generalize

By default, any harness gain should be treated as:

- family-scoped
- objective-scoped
- model-conditioned

Only after it clears broader validation should it be promoted as a universal
harness improvement.

### 6. Protected evidence should stay protected

Challenge and holdout splits should not automatically become unrestricted search
corpora for the controller.

The controller may use:

- verdicts
- bounded summaries
- coarse failure classes

for protected splits, but full benchmark-local details should be policy-gated.

### 7. Online signals are advisory until reproduced

Shadow or production-adjacent evidence can help prioritize work and detect
regressions, but it should not by itself justify a harness promotion.

### 8. Complexity is part of the objective

The meta layer should treat harness complexity growth as a real cost alongside
quality, reliability, and latency.

### 9. Defaults are deployment-profile specific

The meta layer should assume there are multiple legitimate defaults:

- constrained local defaults
- workstation local defaults
- hybrid defaults
- blind-cloud defaults

It should optimize for the right deployment target, not for one flattened
leaderboard.

### 10. Model conscription is governed, not ad hoc

The controller may discover and evaluate new models, but only through:

- approved sources
- approved serving adapters
- explicit capability probes
- deployment compatibility checks
- role-level validation

## System Shape

The meta-harness system should be built as four planes.

### 1. Measurement plane

Responsibilities:

- run benchmarks
- retain manifests and traces
- normalize metrics
- expose comparability and conformance status

Primary source of truth:

- `docs/plans/benchmark-combination-matrix-plan.md`

### 2. Mutation plane

Responsibilities:

- expose typed harness surfaces
- generate versioned candidate patches
- keep the mutation space bounded and diffable

### 3. Search and control plane

Responsibilities:

- select the next objective
- cluster failures
- choose mutation families
- manage evaluation budgets
- accept, reject, or revert candidates

### 4. Governance plane

Responsibilities:

- enforce policy and approval boundaries
- define release gates
- distinguish shadow, family-scoped, and global promotion

## Improvement Lanes

The shared improvement substrate should support more than one controller lane.

Those lanes should share canonical objects and promotion mechanics, but they
should not be conflated into one control topology.

### 1. Fleet meta-harness

This guide's primary implementation target is the fleet-level, cross-vertical
meta-harness.

Its job is to:

- improve shared harness packages
- improve shared role-model assignment policy
- compare candidates across benchmark families and deployment profiles
- promote reusable gains from family scope toward fleet scope

This controller is:

- comparative
- benchmark-heavy
- cross-system
- responsible for defaults and shared release channels

### 2. Sovereign actor self-improvement

The system should also reserve a codified future lane for sovereign kernel-spawned
actors that need bounded local self-improvement.

This lane is distinct from the fleet meta-harness.

Its job is to let one actor, or one actor family, improve its local harness
within a declared sovereignty and policy envelope.

This controller should be:

- actor-scoped rather than fleet-scoped
- budgeted rather than open-ended
- local-first in its promotion defaults
- limited to approved typed mutation surfaces

The sovereign actor lane should share the same core primitives as the fleet
meta-harness:

- harness package
- candidate
- run manifest
- conformance report
- split exposure policy
- promotion decision

The main difference is promotion posture.

By default, actor-local wins should stay:

- actor-local
- actor-family scoped
- shadow-only outside the originating actor

Only after bounded validation should they be eligible for promotion into the
shared fleet candidate pool.

### 3. Embedded runtime adaptation

Embedded runtime adaptation remains a separate future lane for robotics or other
real-time embodied systems.

It may reuse parts of the same substrate, but it has materially different
requirements:

- tighter latency bounds
- tighter runtime safety constraints
- more severe action-side consequences
- greater dependence on runtime-embedded correction

It should not be used as the umbrella concept for sovereign actor
self-improvement.

### Sovereign actor mutation envelope

A sovereign actor controller may mutate only pre-declared typed surfaces such
as:

- actor-local playbook choice
- workflow topology macros declared safe by the harness package
- tool and verifier policy variants already allowed by policy
- budget profile
- context-packaging rules
- recovery and retry policy
- role-model assignment within an approved eligible pool

It may not mutate:

- kernel policy
- approval posture
- trust or secrecy boundaries
- arbitrary runtime code
- benchmark definitions
- protected split access policy
- fleet defaults without promotion

### Sovereign actor promotion path

The intended progression is:

1. actor-local candidate and shadow validation
2. actor-family promotion request where reuse looks plausible
3. fleet meta-harness intake when the gain appears transferable

This keeps local adaptation useful without allowing silent actor-specific drift
to masquerade as a shared harness improvement.

### Relationship to FQF

The sovereign actor lane should use `FQF` as durable substrate, not as the
hot-path controller.

`FQF` is a good home for:

- candidate objects
- actor-local overlays
- retained receipts and run manifests
- promotion requests
- rollback markers
- operator and actor-facing projections

It should not force every local adaptation turn to flow through a wiki-like or
canonical hot path.

Execution-local scratch, transient exploration state, and working-memory
internals should stay off the canonical path until they are promoted into a
durable object.

### Why an outer research loop still matters

The sovereign actor lane should optimize within an existing typed mutation
vocabulary.

Discovering new mutation families, new tool contracts, or new kernel
capabilities will still likely require an outer research or fleet-level driver
for some time, even after the shared meta-harness becomes much stronger.

## Source-of-Truth Objects

The end state should revolve around a small set of canonical objects.

### Benchmark definition

Defines:

- family
- adapter
- split policy
- scoring policy
- conformance policy
- allowed mutation scopes
- deployment profile compatibility
- required modalities

### Model profile

Defines a candidate model independent of any one harness:

- source
- serving adapter
- license class
- capabilities and modalities
- hardware fit
- trust posture compatibility
- eligible roles
- benchmark eligibility

### Deployment profile

Defines the environment in which a default is meaningful:

- hardware envelope
- trust posture
- cloud egress posture
- modality expectations
- latency and cost envelope
- allowed model sources and adapters

### Harness package

Defines the editable task harness:

- playbook
- workflow topology
- tool policy
- verifier policy
- prompt contract
- budget profile
- preset compatibility
- role-assignment policy
- deployment-target policy

### Candidate

Defines one proposed harness mutation:

- parent lineage
- composition parentage
- changed contracts
- changed role assignments
- scope
- promotion target
- target objective
- rationale
- validation evidence
- decision

### Run manifest

Defines the exact evaluation context:

- model fingerprint
- harness fingerprint
- infra fingerprint
- repeat and seed policy
- split selection
- deployment profile
- role-model map
- cloud posture

### Conformance report

Defines whether the candidate cheated or regressed on anti-overfit rules.

### Split exposure policy

Defines what the controller may observe from each split and at what level of
detail.

### Promotion decision

Defines whether the candidate is:

- rejected
- shadow-only
- family-scoped
- globally promotable

### Actor overlay

Defines an actor-scoped override composed on top of a shared harness:

- actor or actor-family scope
- base harness reference
- overlay contracts
- allowed mutation envelope
- expiry or budget class
- rollback target

### Actor adaptation session

Defines one bounded local improvement window:

- actor scope
- local objective
- time and budget envelope
- evidence window
- split exposure policy
- candidate lineage root
- resulting decision

## Suggested Repo Layout

Suggested file layout for the meta-harness system:

- `scripts/lib/meta-harness/controller.mjs`
- `scripts/lib/meta-harness/objectives.mjs`
- `scripts/lib/meta-harness/failure-clustering.mjs`
- `scripts/lib/meta-harness/candidate-ledger.mjs`
- `scripts/lib/meta-harness/conformance.mjs`
- `scripts/lib/meta-harness/eval-tiers.mjs`
- `scripts/lib/meta-harness/mutators/coding.mjs`
- `scripts/lib/meta-harness/mutators/research.mjs`
- `scripts/lib/meta-harness/mutators/computer-use.mjs`
- `scripts/lib/meta-harness/mutators/artifacts.mjs`
- `scripts/lib/meta-harness/mutators/tool-api.mjs`
- `scripts/lib/meta-harness/mutators/general-agent.mjs`
- `scripts/lib/meta-harness/promotions.mjs`
- `scripts/lib/meta-harness/model-registry.mjs`
- `scripts/lib/meta-harness/model-discovery.mjs`
- `scripts/lib/meta-harness/role-assignment.mjs`
- `scripts/lib/meta-harness/deployment-profiles.mjs`
- `scripts/lib/sovereign-actor/controller.mjs`
- `scripts/lib/sovereign-actor/local-objectives.mjs`
- `scripts/lib/sovereign-actor/local-ledger.mjs`
- `scripts/lib/sovereign-actor/promotions.mjs`
- `config/harnesses/...`
- `config/models/...`
- `config/deployments/...`
- `config/actors/...`
- `docs/evidence/meta-harness/candidates/...`
- `docs/evidence/meta-harness/runs/...`
- `docs/evidence/meta-harness/protected-summaries/...`
- `docs/evidence/sovereign-actors/sessions/...`
- `docs/evidence/sovereign-actors/candidates/...`

Suggested integration points with existing surfaces:

- benchmark execution:
  `scripts/run-agent-model-matrix.mjs`
- benchmark app:
  `apps/benchmarks`
- playbook runtime:
  `crates/services/src/agentic/desktop/agent_playbooks.rs`
- current artifact proto-loop:
  `scripts/lib/studio-artifact-parity-loop.mjs`

## Harness Package Model

Each harness package should be declarative and versioned.

Recommended fields:

- `harnessId`
- `harnessVersion`
- `parentHarnessId`
- `routeFamily`
- `playbookId`
- `workflowBundleId`
- `toolPolicyId`
- `verifierPolicyId`
- `budgetProfileId`
- `promptContractId`
- `presetCompatibility`
- `mutationScope`
- `releaseChannel`
- `conformancePolicyIds`
- `complexityBudgetClass`
- `compositionPolicyId`

The package should be narrow enough that the meta layer can say:

- what changed
- why it changed
- what family it targeted
- what evidence accepted it
- how to revert it

It should also be possible to say:

- whether it is safe to compose with another accepted package
- whether it exceeded its complexity budget

## Model Registry And Discovery

The controller should have a first-class model registry.

Newly discovered models should not go straight from discovery to expensive
cross-vertical product evals.

They should first pass through a reusable public benchmark screening program so
the controller can cheaply answer:

- is this model basically competent?
- is it compatible with the intended deployment target?
- which roles is it even plausible for?
- is it worth spending agentic eval budget on?

### Supported sources

Examples:

- local managed registries
- approved Hugging Face discovery
- provider-managed catalogs
- manually pinned internal model specs

Discovery should be governed by:

- source allowlists
- license policy
- serving compatibility
- deployment profile compatibility
- basic smoke probes

### Required model metadata

Each model profile should retain:

- `modelId`
- `sourceKind`
- `sourceRef`
- `licenseClass`
- `servingAdapters`
- `family`
- `parameterScale`
- `quantization`
- `capabilities`
- `hardwareFitProfiles`
- `deploymentCompatibility`
- `roleAffinity`
- `availabilityState`

### Important constraint

Discovery from Hugging Face or similar sources should not imply blind trust.

The controller should be allowed to:

- discover
- provision
- probe
- benchmark

before a model is eligible for role assignment or default candidacy.

## Public Benchmark Program And Screening Funnel

The meta layer should treat public benchmark packs as a front-door screening
program, not as the whole evaluation system.

These packs give the controller stable, reusable signals that are:

- cheaper than full retained product batteries
- easier to compare across discovered OSS and provider models
- appropriate for public scorecards and social-style comparison charts

They should never be treated as sufficient proof of IOI-specific product
quality.

### Required packs

At minimum, define:

- `text_foundation_pack`
- `multimodal_foundation_pack`
- `coding_agent_pack`
- `computer_use_pack`
- `general_agent_pack`

### Pack roles

`text_foundation_pack`

- foundation screening for text-capable models
- best first serious screen after capability probes
- default comparison pack for local text model labs

`multimodal_foundation_pack`

- foundation screening for vision-language and multimodal models
- required before assigning perception or multimodal worker roles
- must stay separate from text-only comparisons

`coding_agent_pack`

- role screening for coding executor and verifier candidates
- separates fresh coding skill from repo-native repair performance

`computer_use_pack`

- role screening for browser operator and perception workers
- should distinguish browser microtasks from workflow and desktop tasks

`general_agent_pack`

- broad planning and tool-use screening before general-agent default candidacy

### Funnel policy

Discovered models should move through this ladder:

1. source, license, and serving-policy admission
2. capability probes and smoke checks
3. `text_foundation_pack` where text capability is expected
4. `multimodal_foundation_pack` where modality capability is required
5. role-specific public packs such as `coding_agent_pack`,
   `computer_use_pack`, or `general_agent_pack`
6. repo-native retained batteries
7. deployment-profile-specific default candidacy

This gives the controller a cheap screening front door without collapsing the
whole system into one flattened leaderboard.

### Important boundary

Public benchmark packs are for:

- candidate triage
- model shortlisting
- reusable external comparison
- chartable exports

Repo-native retained batteries are for:

- acceptance
- release gating
- product truth
- meta-layer generalization checks

The controller should periodically audit whether public-pack wins actually
transfer to repo-native retained batteries. Packs that stop transferring should
lose influence in candidate triage and default selection.

## Deployment Profiles And Tiered Defaults

The system should manage defaults per deployment profile.

Suggested targets:

- `local_cpu_consumer`
- `local_gpu_8gb_class`
- `local_gpu_16gb_class`
- `local_workstation`
- `hybrid_privacy_preserving`
- `blind_cloud_standard`
- `blind_cloud_premium`

Each profile should define:

- hardware envelope
- trust posture
- cloud egress posture
- allowed model sources
- allowed serving adapters
- modality expectations
- latency and cost targets
- required approval posture

### Default policy

The controller should never ask:

- "what is the best model?"

It should ask:

- "what is the best default for this deployment profile and role set?"

## Role-Level Model Assignment

Model selection should happen at the role layer, not only at the whole-agent
layer.

### Typical roles

- planner
- verifier
- coding executor
- research worker
- browser operator
- perception worker
- artifact builder
- artifact judge
- speech or realtime worker

### Role assignment policy

Each role assignment should declare:

- assigned model
- deployment target
- modality usage
- fallback policy
- simulation policy
- validation policy

This is what makes model conscription safe and inspectable.

## Vertical Mutation Surfaces

Each vertical should have an explicit allowed mutation surface.

### Base model and preset lane

This lane is mainly a comparison and compatibility surface, not the primary
target for harness mutation.

Allowed mutation families:

- preset selection and role assignment
- context length and parallelism policy
- runtime timeout policy
- acceptance-model pairing
- hardware-profile compatibility rules
- governed model discovery and promotion into the eligible pool
- role assignment by deployment target

Forbidden mutation families:

- presenting model swaps as harness wins
- silent provider-specific substitutions
- hidden runtime-path changes that invalidate comparison intent
- promoting a cloud-only winner as the default for a local-only target

### Coding

Allowed mutation families:

- repo-context capture
- file selection and context packaging
- worker topology
- implementation versus verifier split
- targeted test strategy
- synthesis contract
- tool budget and widening rules

Forbidden mutation families:

- benchmark-case-specific file hints
- fixture-id branches
- hardcoded expected answers

### Research

Allowed mutation families:

- source-gathering policy
- freshness floor
- source diversity targets
- citation verifier policy
- context compaction for long reads
- evidence block packaging

Forbidden mutation families:

- benchmark-topic-specific routing
- hardcoded source lists derived from benchmark ids
- query-class shortcuts that skip real grounding

### Computer use

Allowed mutation families:

- perception snapshot policy
- action grounding policy
- postcondition verification
- recovery strategy
- retry budget
- state summarization and bridge fidelity

Forbidden mutation families:

- page-answer hardcoding
- task-id branches
- DOM selector memorization tied to benchmark ids

### Artifacts

Allowed mutation families:

- artifact context capture
- blueprint generation
- skill discovery
- judge policy
- repair loop policy
- evidence UX and retained artifact packaging

Forbidden mutation families:

- template forcing keyed on retained benchmark ids
- fallback shells presented as the primary artifact

### Tool or API use

Allowed mutation families:

- tool selection policy
- argument verification
- state checkpointing
- confirmation and rollback behavior
- API response validation

Forbidden mutation families:

- benchmark-specific synthetic tool shortcuts
- success claims without external state change evidence

### General agent

Allowed mutation families:

- decomposition depth
- handoff policy
- context assembly
- verifier authority
- completion contracts

Forbidden mutation families:

- family-specific lexical branching presented as general reasoning

## Control Loop

The control loop should be explicit and auditable.

### Step 1. Select objective

Choose one objective at a time, for example:

- improve coding verifier pass rate
- reduce computer-use postcondition failures
- improve research grounding without latency regression

The objective should declare:

- target family
- target metric
- required non-regression families
- evaluation budget
- deployment profile
- role scope

Prefer a small set of standard objective shapes:

- quality up with no required-family regression
- regression reduction with neutral quality floor
- latency down with quality floor
- cost down with quality and latency floors
- default selection for a deployment profile and role scope

This keeps the controller legible and reduces freeform goal invention.

### Step 2. Cluster failures

Use retained evidence to cluster failures by ontology:

- observation gap
- tool-selection gap
- execution-contract gap
- verification gap
- recovery gap
- grounding gap
- latency or budget gap

Do not cluster by benchmark name as the primary abstraction.

### Step 3. Select mutation family

Map the failure cluster to a typed mutation family.

Examples:

- repeated postcondition misses -> verifier or recovery mutation
- grounded output missing contract receipts -> completion-contract mutation
- high targeted-test regressions -> coding verifier mutation

### Step 4. Generate candidate

Produce a candidate with:

- typed diff
- declared rationale
- changed files and contracts
- expected improvement
- explicit risk statement
- expected complexity impact
- composition assumptions
- role-assignment assumptions
- deployment-target assumptions

The candidate should be as small as possible.

### Step 5. Run static gates

Before any benchmark run, perform:

- schema validation
- conformance scan
- benchmark leakage scan
- hidden fallback scan
- suspicious token diff scan

Reject early if these fail.

### Step 6. Run simulation and replay

Use the cheapest possible signal to prune bad candidates:

- deterministic replay
- recorded trace checks
- unit-level verifier simulations
- synthetic paraphrases

Simulation is for pruning, not for final acceptance.

### Step 7. Run cheap gating evals

Run:

- proxy slices
- canary slices
- low-cost repeated runs

If the candidate changes:

- model discovery state
- base preset choice
- role-model assignment
- deployment-target model composition

also run the relevant public benchmark packs before spending the full retained
product budget.

Examples:

- planner-only model swap: `text_foundation_pack`
- perception worker model swap: `multimodal_foundation_pack`
- coding executor swap: `coding_agent_pack`
- browser operator swap: `computer_use_pack`

Reject candidates that fail here without spending a full retained budget.

This keeps role-level model conscription governed and cost-aware.

### Step 8. Run family validation battery

If the canaries look good, run the authoritative validation slice for the
target family.

Retain a contemporaneous control run against the last accepted baseline when:

- the candidate is promotion-eligible
- the evaluation is expensive enough that ambient drift matters
- the result could change a default or deployment-profile recommendation

This is the first place where a candidate can become shadow-worthy.

### Step 9. Run challenge and holdout evals

Run challenge and holdout slices to test generalization pressure.

A candidate should not be accepted as a harness improvement if it only wins on
the visible validation set.

### Step 10. Run cross-family regressions

Every candidate should be checked against:

- required non-regression families
- latency and resource pressure
- conformance gates

This prevents narrow wins that break the rest of the system.

### Step 11. Run cross-model validation

At least one alternate preset family should be used to decide whether the win
is:

- model-conditioned
- family-scoped
- universal

### Step 12. Accept, reject, or revert

Possible outcomes:

- `rejected`
- `shadow_only`
- `accepted_family_scoped`
- `accepted_global`
- `reverted`

Each outcome should write a retained ledger receipt.

## Evidence Access Policy

The controller should not have the same default visibility into every eval
split.

### Open splits

Usually:

- proxy
- canary
- most validation slices

These may expose full traces and full retained diagnostics.

### Restricted splits

Usually:

- challenge

These should default to bounded summaries and failure ontology unless policy
allows deeper inspection.

### Protected splits

Usually:

- holdout
- release-gate slices

These should default to:

- verdict-only
- bounded aggregates
- limited failure taxonomy

If full details are ever exposed, that event should be retained and treated as a
governed exception.

## Blind Cloud Variant

The blind cloud variant should be treated as its own deployment mode rather than
just "remote inference."

It should define:

- trust posture
- redaction or airlock requirements
- allowed data classes for cloud egress
- remote provider category
- local fallback policy
- shadow and retained validation policy

### Blind cloud rule

A cloud-backed win should never silently overwrite a local-only default.

It must earn promotion inside the cloud deployment profile and remain visible as
a distinct answer.

## Objective Scheduler And Search Policy

The meta layer should not pick work ad hoc. It should rank objectives
explicitly.

### Objective score

Recommended ranking inputs:

- severity
  how bad the current failures are
- frequency
  how often the failure class appears
- sharedness
  how likely the fix is to help multiple benchmarks in the family
- cost
  how expensive evaluation is for this family
- regression risk
  how likely the mutation family is to damage other families
- staleness
  how long the target has gone without meaningful improvement
- deployment reach
  how many deployment profiles the win could realistically help
- hardware fit
  whether the improvement matters on constrained local targets or only in cloud

The exact weighting can evolve, but the inputs should stay visible and
retained.

### Portfolio policy

Recommended portfolio split:

- exploit
  spend most budget on the best current target
- adjacent explore
  spend some budget on nearby mutation families
- safety and regression work
  reserve budget for challenge, holdout, and rollback verification

This helps the controller avoid local maxima without turning into random search.

### Candidate batch policy

For each selected objective:

- generate a small batch of candidates
- prefer small typed diffs over large rewrites
- run the cheapest discriminating evaluations first
- prune aggressively before spending full retained battery budget

### Cross-target policy

When a candidate looks promising, the controller should decide whether it is:

- local-tier specific
- workstation specific
- blind-cloud specific
- general enough to test across multiple targets

This keeps evaluation budgets aligned with the actual deployment question.

### Search memory policy

The controller should retain structured memory of:

- rejected candidates
- reverted candidates
- accepted local wins
- known dead-end mutation families
- proxy signals that proved untrustworthy

This avoids rediscovering the same failed ideas repeatedly.

However, search memory must respect split exposure policy. Protected holdout
details should not be copied into unrestricted controller memory.

### Plateau policy

If a target does not improve after a bounded streak:

- stop escalating mutation size
- switch objective or family
- preserve the current best accepted candidate

The existing artifact parity loop is the right behavioral precedent here.

## Simulation And Validation Strategy

Simulation is necessary, but it has to be used correctly.

### What simulation is good for

- early pruning
- stress-testing verifier logic
- replaying known failure traces
- generating paraphrase variants
- checking candidate stability before expensive retained runs

### What simulation is not good for

- final promotion by itself
- replacing real runtime execution
- proving a computer-use or tool-use win without real postconditions

### Recommended validation ladder

1. static validation
2. deterministic replay
3. synthetic perturbation or paraphrase check
4. proxy canary slice
5. target-family validation slice
6. challenge and holdout slice
7. proxy-fidelity calibration
8. cross-family retained battery
9. shadow deployment if needed
10. deployment-profile cross-check if the candidate claims broader applicability

### Proxy fidelity calibration

The controller should continuously measure whether cheap signals are still
predictive of authoritative evidence.

At minimum it should track:

- proxy-to-validation agreement
- validation-to-holdout agreement
- false-positive proxy rate
- false-negative proxy rate

If a proxy drifts, the scheduler should down-rank it or stop using it.

The same principle should apply to public benchmark packs: if a pack stops
predicting repo-native retained outcomes, it should remain visible as a
reference signal but stop driving candidate selection weight.

### Multimodal fidelity

For vision, audio, or realtime roles, simulation fidelity should be treated as a
separate concern from text-only proxy fidelity.

The controller should avoid assuming that a text-derived proxy remains
predictive for multimodal workers.

## Conformance And Anti-Overfit Controls

The conformance system should be strict enough that the meta layer cannot game
the benchmark battery accidentally or intentionally.

### Required gates

- benchmark-specific routing leak scan
- selected-skill-name routing leak scan
- hidden fallback dependency scan
- protected-split leakage scan
- paraphrase stability
- repeated-run variance
- shim dependency detection
- cross-family regression detection
- model-family skew detection
- complexity growth tolerance
- deployment-profile mismatch
- cloud posture mismatch
- modality mismatch between assigned role and model capability

### Required rejection conditions

Reject a candidate immediately if:

- it introduces benchmark ids or task ids into production routing
- it depends on hidden fallback behavior
- it passes only because a judge was relaxed without independent evidence
- it wins on a single visible slice but fails challenge or holdout
- it regresses a required family beyond tolerance

### Suspicious win pattern

Treat the following as suspicious until disproven:

- large visible benchmark gain with no ontology-level improvement
- one-model-family gains with alternate-family regressions
- conformance regressions hidden behind composite score gains
- repeated-run instability
- large complexity growth for a narrow benchmark gain

## Model-Family Neutrality

The meta layer should not silently overfit to one family of models.

### Default rule

Assume every new candidate is model-conditioned until it proves otherwise.

Assume every new model win is also deployment-profile-conditioned until it
proves otherwise.

### Promotion levels

- family-scoped, model-conditioned
- family-scoped, multi-model
- cross-family, model-conditioned
- cross-family, multi-model
- deployment-profile-specific default
- multi-profile default

Only the final category should be treated as a universal harness promotion.

### Important nuance

Same-model meta-agent plus task-agent pairings may generate stronger local
hypotheses. That is acceptable for proposal generation.

It is not acceptable as the only validation path for a universal harness win.

## Candidate Acceptance Policy

Recommended acceptance policy:

### Reject

Use when:

- conformance fails
- target family does not improve
- required families regress beyond tolerance
- challenge or holdout fails

### Shadow only

Use when:

- target family improves
- challenge looks promising
- cross-model or cross-family evidence is still incomplete

### Accept family-scoped

Use when:

- target family improves
- challenge passes
- required family regressions stay within tolerance
- conformance passes
- generalization is strong enough for the declared family but not yet global
- deployment-profile claims stay bounded and honest

### Accept global

Use when:

- target family improves
- required families do not regress
- challenge and holdout pass
- conformance passes
- alternate preset families also validate the gain
- complexity growth remains acceptable

Use very sparingly. In practice, many wins should remain deployment-profile
specific.

### Revert

Use when:

- a promoted candidate later fails retained evidence
- shadow usage exposes a regression not caught earlier

## Operator And Approval Model

The meta layer should remain operator-readable and operator-bounded.

Operators should be able to:

- restrict allowed mutation scopes
- set budget ceilings
- choose target families
- require review for high-risk mutation families
- inspect lineage and revert quickly

Human approval should be required before:

- widening tool permissions
- changing trust or secrecy posture
- changing approval behavior
- exposing protected split details more broadly
- promoting from family-scoped to global
- enabling auto-promotion outside shadow mode
- widening a local-only default into a cloud-allowed default
- widening a cloud-backed default into local-only guidance

## Candidate Composition Policy

Accepted candidates should not be assumed to compose safely.

The system should distinguish:

- isolated candidate validation
- composed candidate validation
- superseding candidate replacement

Recommended rules:

- validate each accepted candidate alone first
- validate common compositions explicitly before treating them as the new base
- record which accepted candidates a new candidate supersedes
- prefer consolidation when several accepted candidates touch the same harness
  surface

This prevents hidden interaction debt from silently accumulating.

## Online Evidence Policy

Online or shadow evidence can improve the controller, but only under strict
rules.

### Allowed uses

- prioritization
- regression detection
- candidate risk ranking
- deciding what to reproduce offline next

### Disallowed uses without offline confirmation

- final candidate acceptance
- universal promotion
- conformance override

### Required rule

Any serious online regression or success that affects decisions should be
reproduced through retained replay or benchmark evidence when feasible.

## Multimodal And Realtime Policy

The controller should treat multimodal roles as first-class but separately
validated domains.

Required metadata and policy:

- modality capability declaration per model
- modality requirement per role
- deployment-target compatibility for multimodal inference
- separate validation lanes for text-only versus multimodal workers

This avoids pretending a text-capable model and a vision-capable model are
interchangeable.

The multimodal foundation pack should be the first public benchmark gate for
multimodal model discovery, with repo-native multimodal batteries used only
after that gate is cleared.

## Comparison Export Contract

The meta layer should emit chart-ready comparison artifacts from retained
manifests rather than relying on ad hoc screenshots or manually assembled bars.

Exports should support:

- public model-lab scorecards
- deployment-profile-specific comparisons
- role-specific model comparisons
- same-harness different-model charts
- same-model different-harness charts

Minimum export fields:

- `packId`
- `packVersion`
- `deploymentProfile`
- `trustPosture`
- `comparisonIntent`
- `presetOrTargetId`
- `roleScope`
- `modelId`
- `modelFamily`
- `servingAdapter`
- `hardwareProfile`
- `benchmarkFamily`
- `benchmarkId`
- `splitClass`
- `score`
- `normalizedScore`
- `repeatCount`
- `confidenceClass`
- `coverageClass`
- `runId`
- `manifestPath`

The export exists to make the evidence legible and shareable.

The retained manifest remains the source of truth for acceptance, promotion, and
reproducibility.

## Benchmark Lifecycle Policy

The controller should assume that some benchmarks will saturate over time.

Each family should define:

- freshness review cadence
- saturation criteria
- challenge refresh policy
- holdout rotation policy
- retirement criteria

The scheduler should down-rank stale or saturated benchmarks when selecting new
optimization targets.

## Meta-Layer Self-Evaluation

The controller itself needs scorecards.

Recommended controller metrics:

- candidate acceptance rate
- rollback rate
- false-positive acceptance rate
- mean time to meaningful improvement
- proxy-to-validation agreement
- validation-to-holdout agreement
- complexity growth per accepted candidate
- cross-family regression incident rate
- hardware-tier mispromotion rate
- local-versus-cloud disagreement rate
- multimodal assignment error rate
- candidate-versus-control drift disagreement rate
- public-pack-to-product transfer agreement

If these metrics deteriorate, the controller should lose autonomy before the
task harness does.

## Rollout Strategy

### Phase 0. Instrument only

Land:

- manifests
- failure ontology
- candidate ledger schema
- conformance gates
- split exposure policy
- controller scorecards
- model registry schema
- deployment profile schema

No automatic mutation yet.

### Phase 1. Artifact pilot

Use artifacts first because the repo already has a parity loop and strong
conformance instincts here.

Goal:

- prove the candidate ledger and acceptance loop

### Phase 2. Coding and research

Add:

- coding verifier improvements
- research grounding and freshness improvements

Goal:

- validate typed mutators on non-visual verticals

### Phase 3. Computer use

Add:

- perception
- recovery
- postcondition verification

Goal:

- prove that the meta layer can improve interaction harnesses without cheating

### Phase 4. Tool or API and general agent

Add:

- tool policy
- broader workflow orchestration

Goal:

- cover the full battery

### Phase 4.5 Model discovery and role assignment

Add:

- governed model discovery
- capability and modality probes
- role assignment policies
- deployment-profile-specific defaults

Goal:

- prove that the controller can conscript the right model for the right role and
  hardware or trust target

### Phase 5. Cross-vertical scheduler

Allow the controller to allocate budget across families according to:

- current weakest target
- opportunity size
- cost tier
- regression risk
- benchmark freshness
- proxy fidelity
- deployment reach

### Phase 6. Bounded auto-promotion

Allow automatic promotion only when:

- the candidate is inside allowed mutation scopes
- conformance passes
- challenge and holdout pass
- rollback is immediate
- policy does not require human approval
- protected split policy has not been violated
- deployment-profile claim is explicit and validated

## Effective Meta-Harness Checklist

The meta-harness is effective when all of the following are true:

- the benchmark battery is split-aware and meta-compatible
- harness packages are declarative and versioned
- model profiles and deployment profiles are explicit and governed
- every candidate has lineage, evidence, and rollback
- the controller reasons over failure ontology, not benchmark strings
- simulation is used for pruning, not self-deception
- validation uses retained real-runtime evidence
- conformance gates prevent lexical routing, hidden fallback, and benchmark-local
  hacks
- universal promotions require multi-model and cross-family evidence
- local-only and blind-cloud defaults remain distinct when they should
- operator control, policy, and observability remain intact

## Immediate Build Order

1. Finish the matrix hardening work from
   `docs/plans/benchmark-combination-matrix-plan.md`.
2. Define the model registry, deployment profile, and role assignment schemas.
3. Define the harness package schema and candidate ledger schema.
4. Generalize the existing artifact parity-loop logic into reusable controller
   pieces.
5. Add conformance gates and benchmark-leakage scanning as blocking checks.
6. Add proxy, validation, challenge, and holdout split support.
7. Add governed OSS model discovery and capability probing.
8. Pilot the first true meta loop in shadow mode.

## End State

The finished system should look like this:

- the benchmark suite tells us what is true
- the meta layer tells us what to try next
- the conformance system tells us what is not allowed
- the promotion system tells us what is safe to keep

It should also mean:

- the best 8GB local answer can differ from the best blind-cloud answer
- multimodal workers can be assigned stronger specialized models when policy and
  deployment allow it
- discovered OSS models can enter the system through governed probing instead of
  hand-curated guesswork

That is the combination required for a real meta harness: continuous
improvement, without ad hoc heuristics, without benchmark gaming, and without
giving up operator control.
