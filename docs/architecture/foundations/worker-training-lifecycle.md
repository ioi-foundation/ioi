# Worker Training Lifecycle

Status: canonical architecture authority.
Canonical owner: this file for Worker Training lifecycle, training-vs-mutation doctrine, training receipts, training profile semantics, and training lineage semantics.
Supersedes: product, marketplace, or model docs when they reduce Worker Training to fine-tuning alone or crown one model architecture as the IOI default.
Superseded by: none.
Last alignment pass: 2026-05-15.

## Canonical Definition

**Worker Training is the supply-creation lifecycle for turning workflows,
examples, corrections, data, distilled ontology-bound datasets, tools,
policies, and evaluation gates into deployable, benchmarked workers.**

Worker Training is broader than model fine-tuning. A worker can be improved by:

- prompt or instruction optimization;
- workflow trace capture;
- retrieval and memory curation;
- context graph mutation and supersession;
- skill extraction;
- tool-policy hardening;
- verifier and quality-gate tuning;
- workflow graph refinement;
- route-policy training;
- adapter or worker-package promotion;
- model fine-tuning;
- distillation from larger systems;
- distillation of ontology-bound source truth into compact training and
  evaluation signal;
- evaluation and regression-suite expansion;
- benchmark and production feedback.

The output is not merely a checkpoint file. The output is a bounded worker with
manifest, policy envelope, training lineage, evaluation receipts, benchmark
receipts, deployment package, and contribution policy.

Serious Worker Training depends on
[`domain-ontologies-and-data-recipes.md`](./domain-ontologies-and-data-recipes.md).
Raw documents, traces, and connector payloads may seed training, but they do
not become durable domain truth until DataRecipes map them into
ontology-bound objects, evaluation datasets, policy-bound data views, and
receipted projections.

For high-efficiency specialist workers, the preferred substrate is often
**distilled ontology-bound data** rather than raw corpora: compact examples,
counterexamples, tool traces, canonical object transitions, verifier
assertions, rubric judgments, and failure regressions derived from
ontology-bound source truth. Distillation improves density; receipts preserve
provenance.

## Training Profile Flexibility

IOI does not canonize one model architecture. Hypervisor, daemon/runtime nodes,
and compatible training services should support any worker architecture that can
be trained or configured, bounded by policy, evaluated, published, routed
through MoW, rolled back, and made receipt-accountable.

Supported training profiles may include:

- dense transformer workers;
- Mixture-of-Experts-backed workers;
- nonquadratic or subquadratic workers;
- hybrid attention/state workers;
- retrieval-augmented or context-graph workers;
- mutable-context workers;
- adapter-trained workers;
- distillation-trained workers;
- perpetually post-trained workers;
- deterministic toolchain or verifier workers.

Subquadratic, hybrid, mutable-context, and perpetually post-trained workers are
high-value supported classes, especially for intake, routing, long-context
state, and operational memory. They are not IOI primitives and they do not
replace MoW. The rule is:

```text
support the class
do not crown the class
```

Claims about a worker profile's cost, context behavior, or improvement loop must
bind to evaluation, benchmark, promotion, and regression receipts before they
affect routing eligibility, reputation, payout, or trust.

## Product Home And Builder Substrate

The primary local product surface is **Hypervisor Foundry / Worker Training
Studio**.

Hypervisor exposes Worker Training as:

```text
Define Task
→ Select Base Model, Cognition Backend, or Training Profile
→ Bind Domain Ontology and Data Recipes
→ Plan Dataset Scope and Batch Strategy
→ Generate or Capture Raw Batches
→ Gate and Reject Weak Data
→ Human Review
→ Distill Ontology-Bound Data
→ Train or Configure
→ Evaluate
→ Package or Deploy as Worker
→ Monitor & Improve When Needed
```

The same lifecycle can be operated through CLI/headless clients, optional TUI
views, daemon APIs, hosted runtime-node jobs, or sas.xyz service engagements.
Hypervisor owns the local product experience, not the underlying state,
authority, or execution substrate.

Foundry is a product lens over the shared IOI builder substrate, not a
separate canvas environment. Training recipes, evaluation recipes, benchmark
recipes, deployment recipes, data recipes, and outcome workflows should share
the same graph model, typed node contracts, schemas, daemon execution, and
Agentgres receipt model. Different lenses may expose different palettes,
inspectors, run panels, templates, and validation rules.

The default product should be a guided Foundry experience. Advanced users may
open the same recipe in the Workflow Compositor for inspection,
customization, reuse, or composition.

## Foundry Versus Runtime Improvement

Foundry is not the meta-harness for Hypervisor. It is the training,
distillation, evaluation, benchmarking, packaging, and publishing surface for
workers, models, recipes, datasets, and gates.

The live runtime improvement path is the governed Improvement Proposal Plane:

```text
trace / failure / correction / eval / receipt
  -> SkillCandidate | MemoryCandidate | ToolCallRefinement |
     WorkflowPatch | HarnessProfilePatch | RoutingPolicyPatch |
     VerifierCandidate | ContextTopologyPatch | FoundryJobRequest
  -> simulation / eval / verifier checks
  -> policy and authority decision
  -> Agentgres admission and receipts
```

Only some proposals need Foundry. A small tool-call refinement, workspace skill,
Agent Wiki memory, route preference, verifier rule, or workflow patch may be
admitted directly through governance. Model training, distillation, dataset
curation, benchmark publication, or worker-package promotion should route
through Foundry.

This keeps scalable improvement practical: ordinary services can use one
workflow, one selected HarnessProfile, one model route, and persistent
workspace intelligence; specialized improvements escalate into Foundry only
when training or packaging is actually needed.

## Hypervisor Foundry Product Doctrine

Hypervisor Foundry is a worker creation and improvement studio.

The first product promise is not "upload data and fine-tune." It is:

```text
plan better examples
→ plan better batches
→ generate or capture better evidence
→ archive raw attempts
→ gate weak data faster
→ review with less friction
→ train or configure smaller/better workers
→ compare against baselines
→ deploy with bounded authority
→ learn from failures
→ repeat
```

Iteration is supported, not mandatory. A user may train once, package the
worker, and never revisit it. When a worker is used in production, Foundry
should make improvement loops available without forcing every training workflow
to become perpetual.

Receipts, lineage, and policy make this process accountable, but they should
mostly stay behind the glass. The user-facing product should help builders make
better workers faster.

Hypervisor Foundry should expose these product primitives:

- **Training Orchestrator**: owns the training goal, case specs, batch plans,
  prompt set, executor mix, gate policy, rejects, reports, and worklog. It may
  use planner, debugger, generator, verifier, and reviewer workers, but it is the
  accountable coordination role for the training run.
- **Training Copilot**: helps define task scope, output contracts, coverage
  gaps, examples, rubrics, deployment target, and likely failure modes.
- **Batch Planner**: turns the objective into bounded generation or capture
  batches with target scope or family, label boundaries, hard eval patterns,
  quota, split policy, provider/executor mix, and acceptance thresholds.
- **Dataset Workbench**: lets users inspect, edit, score, label, compare,
  reject, and promote examples, traces, distilled datasets, and evaluation
  cases.
- **Raw Batch Archive**: preserves generated or captured rows, prompts, caches,
  provider metadata, token/cost telemetry, and pre-gate artifacts before they are
  curated or rejected. A raw batch is evidence, not accepted training signal.
- **Gate Console**: shows the live quality funnel from generated/captured
  material through schema checks, rubric gates, dedupe, PII/secrets filters,
  human review, and accepted training signal.
- **Gate Library**: provides reusable deterministic, verifier, and human-review
  gates for schema validity, role/order checks, final user turn checks, allowed
  labels, canonical ordering, duplicate prompts, placeholder/meta text,
  target-scope signal, helper-scope policy, unsupported-primary policy, split
  intent, leakage risk, low-quality or synthetic-pattern detection, gold reason
  quality, and rubric fit.
- **Model Bake-Off**: runs the same eval set across the base model, trained
  worker, previous worker version, frontier model, competing worker, or
  deterministic baseline.
- **Model Capacity Advisor**: recommends a target worker/model size and serving
  profile from task difficulty, row structure, system-prompt budget, tool count,
  latency, privacy, cost, and eval risk. Smaller workers often need more
  structured rows, shorter system prompts, tighter label sets, and smaller tool
  batches.
- **Iteration Loop**: clusters failures and suggests the next data, recipe,
  gate, rubric, tool, model, or workflow change before the next training run.
- **Cost/Quality Simulator**: previews tradeoffs across base model, training
  profile, generator mix, data volume, gate strictness, adapter settings,
  latency, local vs remote compute, and expected cost.
- **Token and Cost Ledger**: tracks provider calls, tokens, runtime, spend,
  accepted/rejected row counts, cost per accepted row, dataset yield, and
  marginal quality lift.
- **Workflow Recipe Library**: provides reusable training workflows for common
  verticals such as support triage, construction estimating, code review,
  contract review, sales operations, research, and intake.
- **Deploy Preview**: lets users interact with the candidate worker before
  publication, inspect tool use, authority prompts, fallback behavior, and
  output contracts.
- **Worker Card Builder**: turns the result into an installable/publishable
  worker profile for Hypervisor, aiagent.xyz, or a sas.xyz service package.
- **Human Review Queue**: makes expert review fast: compare candidates,
  accept/reject/edit examples, mark gold cases, approve edge cases, and record
  rejection reasons.

The product loop should make training workflow recipes themselves improvable.
Foundry can learn which planners, generators, gates, evaluators, recipes,
training profiles, and deployment thresholds produce the best workers for a
given ontology, task class, privacy posture, and cost target.

Foundry should expose the role split without hardcoding provider names:

```text
orchestrator owns the goal, batch plan, gate policy, reject policy, and worklog
planner/debugger workers shape scope, cases, and failure analysis
executor/generator workers create or transform candidate rows
verifier workers and deterministic gates reject weak or unsafe material
human reviewers approve edge cases, gold reasons, and final promotion
```

This pattern lets a builder use any suitable mix of frontier APIs, local models,
small models, verifier workers, deterministic tools, or human reviewers while
preserving the same training semantics.

## Canonical Stages

1. **Capture**
   The user, provider, or runtime records a reference workflow, task
   description, example set, correction set, prior run trace, or legacy agent
   behavior.

2. **Specify**
   The builder defines the worker objective, input and output schemas, allowed
   tools, authority scopes, policy envelope, benchmark category, privacy class,
   domain ontology, canonical object models, data recipes, policy-bound data
   views, acceptance rubric, contribution policy, and optional training profile
   or cognition architecture metadata. For small or efficient workers, the
   builder should also bind a ModelCapacityProfile describing target model size,
   prompt budget, tool batch limits, row structure, latency, cost, and serving
   constraints.

3. **Generate**
   A Training Orchestrator creates TrainingBatchPlans and delegates to planner,
   generator, verifier, and reviewer workers. Generation and capture produce raw
   batches: examples, counterexamples, natural-language rows, gold reasons,
   quality notes, synthetic edge cases, verifier assertions, source-derived
   traces, and candidate workflow graphs. Raw batches should be archived before
   curation so cost, provenance, rejects, and gate decisions remain inspectable.

4. **Curate**
   Human reviewers, verifier workers, deterministic evaluators, PII filters,
   dedupers, and policy gates reject unsafe, duplicate, low-quality, or
   unauthorized material and bind the curated corpus to ontology-bound dataset
   commitments, EvaluationDatasets, and transformation receipts. Gate reports
   should classify rejection reasons such as schema failure, role/order failure,
   duplicate prompt, unsupported target scope, leakage risk, low-quality pattern,
   weak gold reason, rubric mismatch, or policy violation.

5. **Distill**
   Data recipes, teacher workers, verifier workers, deterministic gates, and
   human reviewers may compress ontology-bound source truth into
   DistilledOntologyDatasets. These datasets should preserve source
   commitments, recipe versions, policy-bound data view refs, transformation
   receipts, teacher/verifier refs when used, and rubric or benchmark bindings.

6. **Train or Configure**
   The worker is improved through one or more methods: prompt optimization,
   retrieval indexing, context graph revision, workflow graph refinement,
   verifier tuning, route-policy training, adapter training, tool policy
   changes, model fine-tuning, distillation, local model mounting, hosted
   cognition selection, evaluation generation, or package revision.

7. **Evaluate**
   The worker runs against the declared rubric, holdout set, golden tasks,
   ontology-bound EvaluationDatasets, benchmark profile, and regression suite.
   The system emits EvaluationReceipts and BenchmarkReceipts.

8. **Bind**
   The worker manifest, policy envelope, training lineage, benchmark results,
   receipt obligations, contribution policy, package refs, and runtime
   requirements are bound into a signed WorkerManifest.

9. **Publish or Deploy**
   The worker can be installed locally in Hypervisor, published to aiagent.xyz,
   submitted to a Sparse Worker Category, wrapped into a sas.xyz outcome, or
   deployed into enterprise/private runtimes.

10. **Monitor and Improve**
   Production failures, corrections, disputes, user approvals, cost/latency
   changes, routing mistakes, context supersessions, and quality deltas feed
   future training or promotion cycles under explicit authority.

## Training Does Not Grant Authority

Training improves capability. Policy grants power.

A trained worker remains inert until wallet.network or an equivalent authority
layer grants bounded execution authority. Training lineage can prove how a
worker was produced, but it cannot expand tool access, data access, spending
authority, publishing rights, or external effect permissions.

## Training vs Self-Mutation

IOI distinguishes **Worker Training** from post-deployment self-mutation.

Worker Training is a builder-authorized, customer-authorized, or
provider-authorized process that creates or improves a worker before deployment
or under an explicit retraining contract. It may expand the worker's logic,
tool strategy, retrieval corpus, verifier gates, workflow graph, or model
backend only when the resulting manifest and policy are explicitly signed by
the appropriate authority.

Self-mutation is a deployed worker proposing changes to itself after it already
has a policy envelope and operational identity. Self-mutation remains governed
by policy invariants and cannot relax policy, expand authority, or widen
capability without explicit human, guardian, or governance approval.

Both processes emit receipts. Only self-mutation requires recursive continuity
proofs across generations.

Governed post-training cycles sit between ordinary training and uncontrolled
self-mutation. A deployed worker may propose context updates, route-policy
updates, adapter candidates, evaluation additions, or package revisions, but
promotion requires declared authority, regression gates, receipts, and rollback.
Raw online weight mutation from user input is not canonical truth.

## Worker Training As Verifiable Work

Worker Training is itself a Service-as-Software outcome. A customer does not
buy a fine-tuned model; the customer buys a trained, benchmarked, policy-bound
worker capable of performing a scoped task under receipt obligations.

A Worker Training engagement may produce:

- workflow traces;
- examples and counterexamples;
- DomainOntology and CanonicalObjectModel refs;
- DataRecipe and ConnectorMapping refs;
- PolicyBoundDataView refs;
- curated ontology-bound training or configuration data;
- DistilledOntologyDataset refs;
- EvaluationDataset refs;
- TransformationReceipts;
- policy envelope;
- WorkerManifest;
- benchmark report;
- EvaluationReceipts and BenchmarkReceipts;
- deployment package;
- optional aiagent.xyz listing;
- optional sas.xyz outcome wrapper.

This is the first commercial leg of MoW because it creates supply before the
marketplace is fully liquid:

```text
train a worker
→ benchmark it against a sparse category
→ publish it to aiagent.xyz
→ compose it into workflows or services
→ sell outcomes through sas.xyz
→ route future work through MoW
```

## Full-Stack Boundary

Worker Training connects the IOI stack; it does not replace it:

- compute markets provide local, hosted, DePIN, TEE, VPC, GPU, or browser
  execution;
- data/provenance systems bind sources, traces, examples, corrections, and
  dataset commitments;
- Domain Ontologies and Data Recipes bind source material into ontology-bound
  objects, policy-bound data views, distilled ontology datasets, evaluation
  datasets, and Agentgres projections;
- model routing mounts cognition backends;
- evaluation markets provide benchmark profiles and verifier workers;
- MoW routes trained workers;
- workflow/service composition turns workers into outcomes;
- wallet.network grants authority;
- storage backends store large payloads and sealed archives;
- Agentgres records operational truth;
- IOI L1 anchors commitments, settlement, registry roots, and disputes.

## One-Line Doctrine

> **Worker Training turns work into workers; MoW routes those workers; authority and receipts make the result accountable.**
