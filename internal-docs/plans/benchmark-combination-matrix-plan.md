# Benchmark Combination Matrix Plan

Last updated: 2026-04-06
Owner: benchmark runner / benchmark app / local model strategy / meta-harness
Status: draft

Companion documents:

- `docs/plans/meta-harness-master-guide.md`
- `docs/specs/benchmarks-scorecard-ux.md`
- `apps/benchmarks/README.md`

## Purpose

Turn the current benchmark surface into a practical comparison matrix that is
honest enough for default selection today and structured enough to become the
measurement substrate for IOI's future meta layer.

The end state is:

- honest benchmark comparison
- scorecard-first operator readability
- hardware-tiered default selection
- a public benchmark screening program plus repo-native retained batteries
- public-pack parity with the benchmark families operators already expect to
  use for model comparison
- product-plus evidence that goes beyond public leaderboards by measuring
  IOI-specific runtime, verifier, policy, latency, and deployment-fit behavior
- explicit candidate lineage, rollback, conformance, and anti-overfit support
- future support for model discovery, role-model assignment, multimodal lanes,
  blind-cloud lanes, and sovereign-actor-compatible measurement

This plan should stay simple where possible. The goal is not a giant universal
benchmark system. The goal is one clean measurement stack that can answer the
real operational questions without hiding uncertainty.

## Scope And Boundaries

This document owns the benchmark substrate:

- benchmark families, packs, and retained batteries
- adapter-backed benchmark execution
- benchmark registry, run manifests, normalized result schema, and retained
  evidence
- comparison validity rules
- split discipline, holdout policy, and conformance policy
- candidate lineage and rollback objects
- deployment-profile-specific defaults
- benchmark app data requirements and public export requirements

The companion meta-harness guide owns controller behavior on top of this
substrate:

- objective selection
- mutation policy
- candidate generation
- search scheduling
- approval flow
- rollout flow
- actor-local versus fleet-shared control policy

The UX spec owns interaction and presentation details for `apps/benchmarks`.
This plan only defines what the app must be able to show.

Non-goals for this document:

- inventing one universal score that replaces family scorecards
- defining autonomous authority expansion policy
- deciding every future benchmark now
- turning benchmark evidence into benchmark-local routing logic

## Current State

The repo already has a credible phase-0 foundation:

- `scripts/run-agent-model-matrix.mjs` is a central matrix runner
- `docs/evidence/agent-model-matrix/benchmark-suite.catalog.json` is a retained
  benchmark catalog
- `apps/benchmarks` is already moving toward a scorecard-first benchmark app
- the app and runner already expose scorecard, candidate, and deployment
  concepts, even if the underlying contracts are still thin
- the current catalog has six retained benchmarks:
  three artifact cases, one MiniWoB-style computer-use case, one research case,
  and one repo-native coding case
- OSWorld and WorkArena bridge surfaces already exist in the repo and can be
  promoted into first-class matrix coverage
- the repo already retains rich playbook, trace, and artifact evidence that can
  feed future failure clustering and meta-harness diagnosis

That is the right starting shape. The current problem is not lack of ambition.
It is lack of normalized structure around comparison validity, split discipline,
family coverage, and candidate semantics.

## Main Gaps To Close

The current system is useful, but it still falls short of IOI's end state in a
small number of important ways:

1. Family coverage is too narrow for honest default decisions.
2. External benchmark families are mostly not yet first-class matrix adapters.
3. Run metadata is not yet rich enough to explain whether a delta is model,
   harness, dataset, judge, or infra drift.
4. Comparison intent is not yet explicit enough to separate model changes from
   harness changes or full-stack changes.
5. Split policy, holdouts, and protected evidence handling are not yet part of
   the core benchmark contract.
6. Candidate lineage, composition, rollback, and promotion semantics are still
   too implicit.
7. Conformance and anti-overfit rules are present as instincts, but not yet as
   blocking retained checks across the full matrix.
8. Deployment profiles, hardware-tiered defaults, blind-cloud posture, and
   role-level model assignment are not yet first-class.
9. Public benchmark screening and repo-native retained product batteries are
   not yet separated cleanly enough.
10. The benchmark app is directionally right, but the matrix still needs
    stronger data contracts behind its scorecard, candidate, and deployment
    surfaces.

## Design Rules

These rules keep the plan honest and keep it compatible with the future meta
layer.

### 1. Keep the battery, not a fake universal score

The system should preserve separate family scorecards. A weighted composite can
exist for operator convenience, but only as a summary view with visible
coverage, comparability, and confidence limits.

### 2. Compare one changing axis at a time

Every retained run must declare its comparison intent:

- `model_change`
- `harness_change`
- `role_assignment_change`
- `infra_change`
- `full_stack_change`

The app should only present strict deltas when the non-target axes are held
fixed or explicitly marked equivalent.

### 3. Public packs screen; repo-native batteries decide

Public benchmark packs are the front-door screening program for discovered
models and role candidates. Repo-native retained batteries remain the source of
truth for IOI-specific product readiness, default selection, and release gating.

The intended end state is parity plus:

- parity with the public benchmark families sophisticated operators already use
  to compare text, coding, tool or API, computer-use, multimodal, and
  general-agent model quality
- plus retained IOI-specific evidence about whether those candidates survive
  our real runtime path, verifier stack, policy boundary, latency envelope, and
  hardware-fit constraints

### 4. Diagnose from traces; accept from retained validation

Trace bundles, raw artifacts, and failure summaries help explain what happened.
They do not by themselves justify promotion. Promotion requires repeated,
retained, split-aware benchmark evidence.

### 5. Defaults are deployment-profile and role-scope specific

The system should never ask "what is the best model?" in the abstract. It
should ask "what is the best default for this deployment profile and role set?"

### 6. Hidden splits stay hidden

Holdout and protected challenge data are allowed to inform release confidence,
not become an unrestricted optimization corpus.

### 7. No benchmark-local hacks

The benchmark and meta systems must reject:

- benchmark-id or task-id routing
- retained skill-name routing
- hidden provider shortcuts that bypass the intended runtime path
- benchmark-specific fallback behavior
- judge relaxations that turn incorrect behavior into a pass

### 8. Control runs and repeat policy are mandatory

Authoritative decisions should retain both the candidate run and a
contemporaneous control run. Repeat count, seed policy, cache posture, and warm
state must be part of the comparison record.

### 9. Candidate composition requires re-evaluation

Two individually valid candidates do not become a safe combined candidate by
assumption. Composition creates a new candidate identity and a new validation
obligation.

### 10. One measurement substrate must serve both fleet and sovereign scopes

The same run, registry, lineage, and result objects should work for:

- fleet-shared candidates
- actor-family candidates
- actor-local candidates

Only approval policy changes between those scopes. The evidence model should
not fork.

## Target Measurement Contracts

The benchmark system only needs a few first-class objects, but they must be
clean and durable.

### Benchmark Registry

Keep `docs/evidence/agent-model-matrix/benchmark-suite.catalog.json` as the
source-of-truth registry path for now and evolve it in place.

Each benchmark entry should define at least:

- `benchmarkId`
- `family`
  `base_model | coding | computer_use | tool_api | general_agent | artifacts | research`
- `adapter`
- `packId`
- `datasetVersion`
- `harnessVersion`
- `splitClass`
  `proxy | canary | validation | challenge | holdout`
- `splitVisibility`
  `open | restricted | hidden`
- `labelExposurePolicy`
  `full_trace | bounded_summary | verdict_only`
- `seedPolicy`
- `repeatPolicy`
- `scoringPolicy`
- `requiredModalities`
- `deploymentProfiles`
- `conformancePolicyIds`
- `declaredMutationScopes`
- `lifecycleState`
  `active | shadow | saturating | retired`

What matters most is not exhaustiveness. It is that every retained benchmark
declares enough context to answer:

- what family it belongs to
- what it is allowed to prove
- which split it belongs to
- who is allowed to see what level of evidence
- which deployment profiles it is honest for

### Model Registry

Add a first-class model registry separate from preset definitions.

Each model profile should retain:

- `modelId`
- `sourceKind`
  `local_registry | huggingface | provider_catalog | manual`
- `sourceRef`
- `licenseClass`
- `servingAdapters`
- `family`
- `parameterScale`
- `quantization`
- `capabilities`
  `text | vision | audio | realtime | tool_calling | structured_output`
- `hardwareFitProfiles`
- `deploymentCompatibility`
  `local_only | hybrid | blind_cloud`
- `roleAffinity`
- `availabilityState`
  `discovered | provisioned | probed | benchmarked | retired`

Model discovery must be governed. Discovery from Hugging Face or other public
sources should mean "eligible for probing," not "trusted for default use."

### Deployment Profiles

Defaults and comparisons should be keyed by deployment profile, not by one
global leaderboard.

Suggested profiles:

- `local_cpu_consumer`
- `local_gpu_8gb_class`
- `local_gpu_16gb_class`
- `local_workstation`
- `hybrid_privacy_preserving`
- `blind_cloud_standard`
- `blind_cloud_premium`

Each profile should declare:

- hardware envelope
- trust posture
- cloud egress posture
- allowed model sources
- allowed serving adapters
- modality expectations
- latency and cost expectations
- approval posture for remote inference

### Role Assignment

Model selection must work at the role layer, not only at the whole-agent layer.

Representative roles:

- planner
- verifier
- coding executor
- research worker
- browser operator
- perception worker
- artifact builder
- artifact judge
- speech or realtime worker

Each role assignment should retain:

- `roleId`
- `modelId`
- `deploymentProfileId`
- `assignmentIntent`
- `modalityUse`
- `fallbackPolicy`
- `simulationPolicy`
- `validationPolicy`

This is how the benchmark substrate stays compatible with future role-model
conscription and multimodal specialization.

### Run Manifest

Every retained run should produce a normalized manifest that explains exactly
what was tested.

Required fields:

- repo commit SHA
- dirty worktree flag
- benchmark catalog hash
- runner version
- adapter version set
- benchmark and judge model fingerprints
- hardware profile
- runtime environment fingerprint
- seed set and repeat count
- cache and warmup posture
- comparison intent
- split selection
- conformance policy set
- deployment profile
- cloud egress posture
- role-model assignment map
- modality activation map
- execution scope
  `fleet_shared | actor_family | actor_local`
- actor scope id when applicable

If a serious benchmark decision cannot be reproduced from the manifest, the
manifest is incomplete.

### Normalized Result Schema

Each benchmark result should normalize into a compact, comparable object:

- `status`
  `completed | failed | timed_out | infra_blocked | dependency_blocked | not_run`
- `result`
  `pass | near_miss | red | unknown`
- `validForComparison`
- `invalidReason`
- `benchmarkFamily`
- `adapter`
- `normalizedMetrics`
- `rawMetrics`
- `artifactLinks`
- `traceSummary`
- `primaryFailureClass`
- `failureTags`
- `elapsedMs`
- `costEstimate`
- `conformanceReport`
- `deploymentProfile`
- `roleModelMap`
- `modalityCoverage`

Adapters can retain richer benchmark-local details, but the matrix and app
should depend on a stable normalized spine.

### Candidate Ledger

Add a retained lineage ledger that works for model candidates, harness
candidates, role-assignment candidates, and composed candidates.

Each candidate record should include:

- `candidateId`
- `candidateKind`
  `model | harness | role_assignment | full_stack | composed`
- `parentCandidateId`
- `parentHarnessId`
- `targetObjective`
- `targetFamily`
- `comparisonIntent`
- `changedFiles`
- `changedContracts`
- `roleAssignmentDelta`
- `generator`
  `human | meta_agent | hybrid`
- `proxyRunIds`
- `validationRunIds`
- `challengeRunIds`
- `holdoutRunIds`
- `crossFamilyRunIds`
- `controlRunIds`
- `deploymentProfileId`
- `executionScope`
  `fleet_shared | actor_family | actor_local`
- `actorScopeId`
- `complexityDelta`
- `decision`
  `accepted | rejected | shadow_only | reverted`
- `rollbackTarget`
- `summary`

The ledger is the minimum viable memory needed for rollback, shadow evaluation,
candidate composition, and future meta-harness search.

### Failure Ontology

All adapters should map into one shared failure ontology so the system can
learn from patterns instead of from benchmark strings.

Minimum cross-family classes:

- `infra`
- `dependency`
- `routing`
- `observation`
- `tool_selection`
- `execution_contract`
- `recovery`
- `verification`
- `grounding`
- `quality`
- `latency_or_budget`
- `policy`

## Benchmark Families And Scorecard Shape

The main scorecard should stay family-first.

Core performance families:

- Base model
- Coding
- Computer use
- Tool/API
- General agent
- Artifacts
- Research

Required supporting columns:

- Latency / resource pressure
- Conformance / operational discipline

Performance families answer "how good is it?" Supporting columns answer "is the
comparison trustworthy and is the result operationally usable?"

### Family Composition

| Family | What it measures | Public lane | Repo-native retained lane |
| --- | --- | --- | --- |
| Base model | text-first capability and reasoning floor | `text_foundation_pack` | only as supporting context, not the whole product answer |
| Coding | coding and repair ability | `coding_agent_pack` | repo-native coding tasks in the IOI runtime |
| Computer use | browser and desktop execution continuity | `computer_use_pack` | MiniWoB plus retained browser or workflow tasks |
| Tool/API | multi-step tool and policy use | `tool_api_pack` when stable | repo-native tool-policy and tool-state scenarios |
| General agent | broad planning and cross-tool competence | `general_agent_pack` | retained cross-tool product tasks where they exist |
| Artifacts | artifact-generation quality in IOI's product loop | none required | retained artifact parity and evaluation slices |
| Research | citation, verifier, and synthesis quality | none required | retained research slices |

`tool_api_pack` is desirable, but it does not need to block phase-1 progress.
If `tau-bench` or an equivalent local adapter is not yet stable, keep Tool/API
repo-native first and add the public lane later.

## Public Benchmark Program

The public benchmark program is the reusable front door for candidate models and
role assignments. It exists to prune the search space cheaply and produce
chart-ready comparisons that are legible outside the repo.

It does not replace retained IOI batteries.

The target is external legibility with internal product truth:

- if a public benchmark family is commonly used to compare model classes, the
  matrix should eventually expose an equivalent first-class screening lane
- if public benchmark evidence would usually make an operator rank model A above
  model B for a given family, the matrix should usually show the same
  directional ordering in that screening family unless serving-path,
  quantization, or modality constraints create a clearly explained deviation
- if a model looks strong on public packs but weak in retained IOI batteries,
  the matrix should make that mismatch explicit instead of flattening it into a
  single blended score

### Required Public Packs

#### `text_foundation_pack`

Purpose:

- screen text-first base models cheaply and repeatably

Recommended contents:

- `lm-evaluation-harness`
- an MMLU or MMLU-Pro style slice
- a GPQA-style reasoning slice
- a BBH-style slice
- a HellaSwag-style slice

#### `multimodal_foundation_pack`

Purpose:

- screen multimodal or perception-capable models before they are assigned to
  multimodal roles

Recommended contents:

- a stable multimodal foundation benchmark such as MMMU
- one retained vision-grounded smoke slice that uses IOI's real runtime path

#### `coding_agent_pack`

Purpose:

- separate coding ability from general language quality

Recommended contents:

- LiveCodeBench
- SWE-bench Verified
- optional HumanEval for cheap baseline screening

#### `computer_use_pack`

Purpose:

- screen serious browser and desktop operators

Recommended contents:

- MiniWoB
- OSWorld
- WorkArena

#### `general_agent_pack`

Purpose:

- screen broad planning and tool-use competence before general-agent default
  candidacy

Recommended contents:

- GAIA
- optional BrowseComp

#### `tool_api_pack`

Purpose:

- screen structured tool calling, stateful API use, and policy compliance

Recommended contents:

- `tau-bench` where feasible locally
- otherwise an adapter-compatible interim suite until a public lane is stable

This pack should exist, but it can arrive after the core text, coding, and
computer-use packs.

### Public-Pack Parity Standard

When this plan is complete, the matrix should be able to answer the same
high-level model-selection questions people currently ask of public benchmarks,
but with deployment-aware context.

Minimum parity expectations:

- base-model parity:
  text-foundation screening should support the same kind of directional model
  judgment operators infer today from MMLU-Pro, GPQA-style reasoning, and
  related text-foundation batteries
- coding parity:
  coding screening should support the same kind of directional judgment
  operators infer today from LiveCodeBench and SWE-bench Verified
- tool or API parity:
  tool screening should support the same kind of directional judgment
  operators infer today from tau-bench and BFCL-style tool-use batteries
- computer-use parity:
  computer-use screening should support the same kind of directional judgment
  operators infer today from OSWorld and WorkArena
- multimodal parity:
  multimodal screening should support the same kind of directional judgment
  operators infer today from MMMU-class evaluation
- general-agent parity:
  broad planning and cross-tool screening should support the same kind of
  directional judgment operators infer today from GAIA and similar agent suites

The "plus" layer is what public packs usually cannot provide by themselves:

- local hardware fit and residency
- latency and resource pressure in the real serving path
- verifier and acceptance behavior
- conformance and anti-cheat guarantees
- deployment-profile-specific default selection
- retained product tasks that exercise the IOI runtime directly

### Screening Funnel

Discovered or newly provisioned models should move through this funnel:

1. source, license, and serving-policy admission
2. capability probes and smoke checks
3. `text_foundation_pack` for text-capable models
4. `multimodal_foundation_pack` when modality is required
5. role-specific public packs such as `coding_agent_pack`,
   `computer_use_pack`, `tool_api_pack`, or `general_agent_pack`
6. repo-native retained batteries
7. deployment-profile-specific default candidacy

This is the right place to be selective. The public program should reduce
wasted product-eval spend without claiming to be product truth.

### Public-Pack Transfer Audit

The public program should earn its place by staying predictive.

Periodically measure:

- whether pack leaders survive repo-native retained batteries
- which packs are useful for pruning versus which are vanity signals
- whether a pack has saturated or stopped transferring to product outcomes

If a pack stops transferring, it should be:

- down-ranked in the funnel
- refreshed
- narrowed
- or retired as a decision input while remaining visible for reference

## Repo-Native Retained Batteries

Repo-native batteries remain the authoritative source of IOI-specific product
truth. They should stay narrower than the public program, but more trustworthy
for actual release and default decisions.

Near-term retained batteries should be:

- artifact generation and artifact parity slices
- repo-native coding tasks in the actual IOI runtime
- repo-native research tasks with citation and verifier pressure
- MiniWoB retained slices plus richer browser or workflow tasks
- repo-native Tool/API scenarios until the public lane is mature
- modality-specific retained slices where multimodal roles are in play

The benchmark matrix should explicitly represent both programs at once:

- public packs for candidate screening and external legibility
- repo-native retained batteries for product truth, default selection, and
  meta-layer validation

Public wins should never silently outweigh retained regressions in the scorecard
or promotion logic.

This is the "plus" in parity plus. Public packs tell us whether a model looks
credible in the broader ecosystem. Retained batteries tell us whether that
strength survives IOI's actual product loop.

## Deployment-Profile Default Batteries

Default selection should use different required batteries for different
deployment profiles. The system should compare like with like.

| Deployment profile | Default question | Minimum required battery |
| --- | --- | --- |
| `local_cpu_consumer` | best safe local default under tight resource limits | `text_foundation_pack`, retained coding or research smoke, retained artifact smoke, strict latency or resource gates |
| `local_gpu_8gb_class` | best constrained local GPU text-first default | `text_foundation_pack`, retained coding, retained research, retained artifacts, retained MiniWoB or browser smoke, latency or resource gates |
| `local_gpu_16gb_class` | best stronger local GPU default | same as `local_gpu_8gb_class` plus heavier coding and computer-use validation |
| `local_workstation` | best local high-capacity default | full retained local battery, heavier public coding and computer-use coverage, optional multimodal lanes where supported |
| `hybrid_privacy_preserving` | best mostly local default with bounded remote help | retained local battery plus explicit egress-posture validation and fallback checks |
| `blind_cloud_standard` | best cloud-backed default under blind-cloud standard posture | same family battery rerun under blind-cloud posture, redaction or airlock validation, no silent local or cloud substitution |
| `blind_cloud_premium` | best premium cloud-backed default under the strongest approved posture | blind-cloud standard battery plus heavier computer-use, general-agent, or multimodal coverage where relevant |

Important rules:

- a blind-cloud leader does not replace a local default
- a workstation winner does not answer the 8GB-class question
- multimodal-required roles should only compete on batteries that actually
  exercise their modality

When the plan is complete, every deployment-profile default should be explainable
in two layers:

- public parity layer:
  why the candidate is credible relative to the broader benchmark ecosystem
- product-plus layer:
  why it is or is not the right answer for this IOI deployment profile after
  runtime-fit, verifier, conformance, and retained-task evidence are included

## Split Discipline And Protected Evidence

The benchmark system should become split-aware before the meta layer is allowed
to rely on it.

### Split Classes

Every serious family should support:

- `proxy`
  cheapest local signals for pruning bad candidates
- `canary`
  small representative slice for iteration
- `validation`
  authoritative acceptance slice for the target family
- `challenge`
  harder adjacent slice for anti-overfit pressure
- `holdout`
  reserved slice for release or promotion only

### Evidence Exposure Policy

Recommended defaults:

- proxy and canary:
  full traces allowed
- validation:
  full traces allowed with retained evidence
- challenge:
  bounded summaries by default
- holdout:
  verdict-only or bounded summaries by default

Operators may inspect protected evidence under policy. The optimization loop
should not automatically inherit unrestricted access to it.

### Anti-Overfit Requirements

At minimum, the matrix should retain and surface:

- paraphrase-stability checks
- repeated-run variance
- cross-family regression checks
- control-run agreement
- proxy-to-validation agreement
- validation-to-challenge agreement
- validation-to-holdout agreement

The goal is not to eliminate all search bias. The goal is to make overfitting
visible and expensive enough that it cannot masquerade as improvement.

### Benchmark Lifecycle

Some visible tasks will saturate over time. The registry therefore needs
benchmark lifecycle support:

- freshness review cadence
- challenge refresh policy
- holdout rotation policy
- saturation detection
- retirement criteria

The matrix should tell operators not only which candidate is leading, but also
whether the battery itself is getting stale.

## Conformance And Honesty Rules

Conformance should become a blocking part of benchmark evaluation, not an
informal principle.

Required checks:

- benchmark-specific routing leak scan
- task-id or benchmark-id routing scan
- retained skill-name routing scan
- hidden fallback and shim dependence
- protected-split misuse
- paraphrase-stability failure
- repeated-run variance beyond tolerance
- model-family skew
- cross-family regression beyond tolerance
- deployment-profile mismatch
- cloud-posture mismatch
- judge or acceptance path changes that lower correctness standards

A candidate that fails conformance is not a benchmark win, even if a visible
score rises.

## Candidate Validation, Promotion, And Rollback

The benchmark system needs explicit candidate semantics before the meta layer is
allowed to depend on it.

### Candidate Kinds

The system should treat these as different kinds of change:

- model candidate
- harness candidate
- role-assignment candidate
- full-stack candidate
- composed candidate

Each kind needs a declared comparison intent and different comparability rules.

### Promotion Requirements

Any promotion or default change should require:

- minimum required family coverage for the relevant deployment profile
- axis-fixed comparison validity
- repeated wins against a contemporaneous control
- no blocking regression beyond declared tolerance in required families
- conformance success
- validation success
- challenge success
- holdout success where the decision is release-grade or default-grade
- acceptable latency, cost, and complexity growth

Accepted outcomes should be classified as:

- `pareto_improving`
- `targeted_tradeoff`
- `dominated`

Only the first two are promotable. `targeted_tradeoff` should remain visibly
marked in the scorecard and deployment views.

### Composition Rules

Composition should be explicit:

- accepted candidates do not silently merge
- any composed bundle gets its own `candidateId`
- the composed bundle must rerun the required retained battery
- rollback must be able to target either the bundle or one of its parents

### Rollback Rules

Rollback should be a first-class result, not an afterthought.

Required rollback state:

- rollback target
- reason for rollback
- restoring control run ids
- affected deployment profiles
- affected role assignments

The app should be able to answer "what was the last trusted state for this
profile and role set?" quickly.

## Scorecard And Operator Surface

The benchmark app should remain scorecard-first. The companion UX spec defines
the presentation details; this plan defines the required data and decision
semantics.

### Scorecard Home

The default landing surface should answer three questions immediately:

1. what is currently leading
2. whether the lead is honest and promotable
3. why the operator should trust or distrust that answer

The main board should stay family-first:

- rows:
  presets, candidates, or comparison targets
- columns:
  Base model, Coding, Computer use, Tool/API, General agent, Artifacts,
  Research, Latency or resource pressure, Conformance

Each cell should show:

- primary score
- delta versus baseline
- confidence or repeat badge
- coverage badge
- blocked, invalid, or not-comparable state when needed

### Candidate View

The candidate surface should be ledger-first.

It should show:

- parent and child lineage
- target family and mutation intent
- changed contracts and files
- proxy, validation, challenge, and holdout outcomes
- cross-family regressions
- conformance result
- role-assignment delta
- deployment profile
- rollback target and decision trail

### Deployments View

The deployment surface should answer:

- what is the current default for each hardware tier and trust posture
- what is the challenger for that profile
- whether the answer is profile-specific or shared
- how local-only, hybrid, and blind-cloud answers differ

### Triage View

Triage remains important, but it should be downstream of the scorecard.
Operators should arrive there from a scorecard question such as:

- why is this cell red
- which case is driving this regression
- what evidence blocks promotion here

### Public Export Contract

The benchmark engine should emit chart-ready exports for public packs and
deployment-profile comparisons.

Each export row should include:

- `packId`
- `packVersion`
- `deploymentProfile`
- `trustPosture`
- `comparisonIntent`
- `presetOrTargetId`
- `roleScope`
- `modelId`
- `servingAdapter`
- `quantization`
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

Exports are for charts and public comparison. The retained manifest remains the
source of truth.

## Implementation Phases

The implementation sequence should optimize for honesty first, then breadth,
then meta-layer readiness.

### Phase 1: Make The Current Matrix Honest

Scope:

- add the normalized run manifest
- make comparison intent explicit
- separate `infra_blocked` from real benchmark failure
- fill placeholder scorecard metrics where possible
- make the app show `comparable`, `caution`, and `not comparable`
- make deployment profile and conformance visible in the current scorecard

Definition of done:

- a model-only rerun and a harness-only rerun can be distinguished reliably
- a non-comparable run cannot quietly look like a clean score win

### Phase 2: Normalize The Execution Spine

Scope:

- evolve the benchmark catalog into a richer registry in place
- extract an adapter interface from `scripts/run-agent-model-matrix.mjs`
- route the current six retained benchmarks through the adapter interface
- define the normalized result schema and failure ontology

Definition of done:

- the current matrix runs through stable benchmark registry and adapter
  contracts with no behavior loss

### Phase 3: Make Defaults Deployment-Aware

Scope:

- define the model registry
- define deployment profiles
- define role-assignment objects
- add capability probes and smoke probes for newly discovered models
- make deployment-profile-specific default selection explicit in the app

Definition of done:

- the system can answer "best for 8GB local," "best for workstation local," and
  "best for blind cloud" as separate benchmark questions

### Phase 4: Expand The Battery

Scope:

- promote OSWorld and WorkArena into first-class matrix adapters
- add `lm-evaluation-harness`
- add LiveCodeBench
- add SWE-bench Verified
- keep MiniWoB, artifact, coding, and research repo-native slices in the
  retained battery
- add `tau-bench` and GAIA only when their lanes can be represented honestly

Definition of done:

- the matrix has serious base-model, coding, and computer-use coverage without
  flattening public and repo-native answers together
- the matrix can express parity-grade directional insight for the public
  benchmark families operators actually use to compare model classes
- public-pack results and retained IOI batteries can be read side by side so
  broader capability and product truth are both visible

### Phase 5: Add Split Discipline, Conformance, And Lineage

Scope:

- add split policy, split visibility, and label-exposure policy to the registry
- add challenge and holdout handling
- add contemporaneous control runs
- add repeated-run variance and paraphrase-stability checks
- add conformance scans as blocking checks
- add the candidate ledger and rollback metadata

Definition of done:

- candidates can be accepted, shadowed, rejected, or reverted with explicit
  lineage and without relying on one visible retained pass

### Phase 6: Turn The Public Program Into A Real Funnel

Scope:

- define named public packs and their versions
- add chart-ready public export outputs
- add public-pack transfer auditing
- define candidate admission from discovery through retained battery

Definition of done:

- newly discovered models and role candidates can be screened cheaply without
  confusing public-pack strength with product truth
- public-pack family coverage is broad enough that the matrix no longer feels
  obviously narrower than the benchmark sets sophisticated operators reference
  externally
- transfer audits make it clear when a public-pack winner should or should not
  survive into retained product-default candidacy

### Phase 7: Meta-Ready Shadow Integration

Scope:

- add benchmark lifecycle reporting
- add proxy-fidelity reporting
- add validation-to-holdout agreement reporting
- surface candidate, deployment, and rollback state cleanly in the app
- integrate the first shadow-only meta-controller on top of these retained
  contracts

Definition of done:

- the meta layer can propose typed candidates and validate them through the
  benchmark substrate without cheating, without hidden evidence leaks, and
  without silent authority expansion

## Immediate Next Moves

1. Evolve `docs/evidence/agent-model-matrix/benchmark-suite.catalog.json` in
   place so each benchmark declares family, adapter, pack, split, visibility,
   and deployment-profile compatibility.
2. Add a normalized run manifest and explicit comparison intent to
   `scripts/run-agent-model-matrix.mjs`.
3. Make `apps/benchmarks` show comparability, coverage, conformance, and
   deployment-profile context directly on the scorecard.
4. Extract the current retained benchmark paths behind a common adapter
   interface before adding more families.
5. Promote OSWorld and WorkArena into first-class matrix lanes next, because the
   bridge surfaces already exist in the repo.
6. Add `lm-evaluation-harness`, LiveCodeBench, and SWE-bench Verified once the
   adapter interface and result schema are stable.
7. Add `tau-bench`, GAIA, and MMMU-class screening once their adapters can be
   represented honestly enough to support parity-grade family comparisons.
8. Define the model registry, deployment profile, and role-assignment schemas
   before governed model discovery begins.
9. Add split visibility, protected-evidence handling, and conformance scans
   before any automated search loop is allowed to rely on benchmark results.
10. Add the candidate ledger and rollback metadata before any candidate
   composition or auto-promotion work begins.
11. Add public-pack transfer audits before public benchmark charts influence
    default selection strongly.

## Definition Of Success

The benchmark suite is successful when all of the following are true:

- one command can run a retained battery for a declared comparison intent
- the app shows family-level leaders, honest coverage gaps, and blocked or
  invalid comparisons at a glance
- model changes, harness changes, role-assignment changes, and full-stack
  changes are clearly distinguished
- public benchmark packs are useful for screening, and the matrix has enough
  family coverage to reproduce parity-grade directional insight with the public
  benchmark families operators commonly reference
- repo-native retained batteries remain the source of truth for defaults and
  release decisions
- defaults are selected per deployment profile and role scope, not by one global
  leaderboard
- blind-cloud, hybrid, and local-only answers remain distinguishable
- multimodal-required roles can be screened and validated without contaminating
  text-only scorecards
- candidate lineage, composition, rollback, and conformance are retained and
  operator-readable
- proxy, validation, challenge, and holdout behavior are all explicit
- protected splits cannot silently become leaked optimization corpora
- benchmark-local routing, hidden fallback behavior, and judge softening are
  blocked by conformance checks
- public-pack wins are periodically audited for transfer to retained product
  batteries
- when public-pack and retained results disagree, the matrix explains the gap in
  deployment-fit, runtime-path, verifier, policy, or hardware terms instead of
  hiding it
- the same measurement substrate works for fleet-shared, actor-family, and
  actor-local scopes
- the benchmark system is strong enough that a future meta layer can optimize
  against it without mistaking benchmark gaming for product improvement
- for local default selection, the matrix delivers parity with public benchmark
  directional insight plus extra decision power from IOI-specific runtime,
  verifier, conformance, and hardware-fit evidence
