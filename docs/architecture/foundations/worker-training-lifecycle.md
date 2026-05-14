# Worker Training Lifecycle

Status: canonical architecture authority.
Canonical owner: this file for Worker Training lifecycle, training-vs-mutation doctrine, training receipts, training profile semantics, and training lineage semantics.
Supersedes: product, marketplace, or model docs when they reduce Worker Training to fine-tuning alone or crown one model architecture as the IOI default.
Superseded by: none.
Last alignment pass: 2026-05-14.

## Canonical Definition

**Worker Training is the supply-creation lifecycle for turning workflows,
examples, corrections, data, tools, policies, and evaluation gates into
deployable, benchmarked workers.**

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

## Training Profile Flexibility

IOI does not canonize one model architecture. Autopilot, daemon/runtime nodes,
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

## Product Home

The primary local product surface is **Autopilot Foundry / Worker Training
Workbench**.

Autopilot exposes Worker Training as:

```text
Define Task
→ Select Base Model, Cognition Backend, or Training Profile
→ Bind Domain Ontology and Data Recipes
→ Plan Dataset Scope
→ Ingest / Generate Examples
→ Quality Gates
→ Human Review
→ Train or Configure
→ Evaluate
→ Deploy as Worker
→ Monitor & Improve
```

The same lifecycle can be operated through CLI/TUI, daemon APIs, hosted
runtime-node jobs, or sas.xyz service engagements. Autopilot owns the local
product experience, not the underlying state, authority, or execution substrate.

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
   or cognition architecture metadata.

3. **Generate**
   Planner, generator, and verifier workers produce examples, counterexamples,
   synthetic edge cases, verifier assertions, and candidate workflow graphs.

4. **Curate**
   Human reviewers, verifier workers, deterministic evaluators, PII filters,
   dedupers, and policy gates reject unsafe, duplicate, low-quality, or
   unauthorized material and bind the curated corpus to ontology-bound dataset
   commitments, EvaluationDatasets, and transformation receipts.

5. **Train or Configure**
   The worker is improved through one or more methods: prompt optimization,
   retrieval indexing, context graph revision, workflow graph refinement,
   verifier tuning, route-policy training, adapter training, tool policy
   changes, model fine-tuning, distillation, local model mounting, hosted
   cognition selection, evaluation generation, or package revision.

6. **Evaluate**
   The worker runs against the declared rubric, holdout set, golden tasks,
   ontology-bound EvaluationDatasets, benchmark profile, and regression suite.
   The system emits EvaluationReceipts and BenchmarkReceipts.

7. **Bind**
   The worker manifest, policy envelope, training lineage, benchmark results,
   receipt obligations, contribution policy, package refs, and runtime
   requirements are bound into a signed WorkerManifest.

8. **Publish or Deploy**
   The worker can be installed locally in Autopilot, published to aiagent.xyz,
   submitted to a Sparse Worker Category, wrapped into a sas.xyz outcome, or
   deployed into enterprise/private runtimes.

9. **Monitor and Improve**
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
  objects, policy-bound data views, evaluation datasets, and Agentgres
  projections;
- model routing mounts cognition backends;
- evaluation markets provide benchmark profiles and verifier workers;
- MoW routes trained workers;
- workflow/service composition turns workers into outcomes;
- wallet.network grants authority;
- Filecoin/CAS stores large payloads and sealed archives;
- Agentgres records operational truth;
- IOI L1 anchors commitments, settlement, registry roots, and disputes.

## One-Line Doctrine

> **Worker Training turns work into workers; MoW routes those workers; authority and receipts make the result accountable.**
