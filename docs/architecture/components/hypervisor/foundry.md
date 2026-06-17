# Hypervisor Foundry

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Foundry as the model, worker, eval,
training, registry, endpoint, experiment, pipeline, metadata, monitoring, and
ontology-aware build surface over Hypervisor Core.
Supersedes: product prose that treats Foundry as direct runtime mutation, a
generic dashboard, only a training UI, or the same concept as Outcome Rooms.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Canonical Definition

**Hypervisor Foundry is the build and improvement surface for models, workers,
evals, datasets, endpoints, experiments, pipelines, and ontology-aware
capability packages used by governed autonomous systems.**

Foundry is closer to an agent/model platform than a chat room. It gives builders
places to discover models, tune or train candidates, define evals, register
workers and models, publish endpoints, manage datasets, monitor runs, and turn
validated traces into reusable packages.

It is not:

```text
a runtime beside the daemon
an Outcome Room
a direct self-modification path
a wallet or authority layer
an Agentgres replacement
a generic notebook product
a model provider monopoly
```

## Owns

Foundry owns product-level projections and workflows for:

- model garden and model discovery;
- model registry and model cards;
- model route candidates and model-mount candidates;
- tuning, fine-tuning, distillation, post-training, and training plans;
- batch inference and evaluation runs;
- eval suites, benchmark gates, scorecards, and verifier candidates;
- datasets, feature views, distilled ontology datasets, and holdout sets;
- experiments, pipelines, metadata, and monitoring views;
- worker/package creation, improvement, and promotion proposals;
- endpoint and provisioned-throughput candidates where a model, worker, or
  service must be exposed as a governed capability;
- ontology-to-worker and ontology-to-eval planning.

## Does Not Own

Foundry does not own:

- daemon execution semantics;
- wallet.network authority, secrets, spend, approval, or declassification;
- Agentgres admitted truth, state roots, artifact refs, archive refs, or
  restore validity;
- storage backend payload meaning;
- live user intent coordination in chat.ioi.ai;
- Outcome Room coordination;
- Workbench code/systems operation;
- direct publication to aiagent.xyz, sas.xyz, or L1 without policy and receipt
  gates.

## Surface Shape

Foundry should expose a platform-style IA, not a single wizard:

```text
Overview
Model Garden
Model Registry
Model Routes / Mounts
Tuning / Training
Evaluation
Datasets
Feature Views
Experiments
Pipelines
Endpoints
Batch Inference
Metadata
Monitoring
Packages
Promotion Queue
```

The exact product labels may vary, but the conceptual split should stay stable:

```text
Discover
  model garden, worker/package catalog candidates

Build
  datasets, recipes, prompts, tool schemas, workers, packages, pipelines

Train / Tune
  fine-tuning, distillation, post-training, training batches, cost ledgers

Evaluate
  eval suites, benchmark gates, verifier candidates, scorecards, regressions

Deploy / Route
  model routes, model mounts, endpoints, provisioned capacity, batch inference

Govern
  metadata, monitoring, receipts, promotion queue, policy and authority checks
```

## Ontology-Aware Foundry

Foundry may use domain ontologies in the Palantir-like sense: objects, actions,
interfaces, properties, permissions, data recipes, and projections define how
real operational domains become teachable and governable agent substrates.

Canonical ontology inputs:

```text
DomainOntology
VerticalOntologyPack
ConnectorMapping
PolicyBoundDataView
DataRecipe
DistilledOntologyDataset
EvaluationDataset
OntologyProjection
OntologyToWorkerPlan
```

Foundry uses these to build:

```text
ontology-bound evals
ontology-bound worker packages
domain-specific tool/action schemas
permission-aware datasets
golden cases and adversarial tests
monitoring views by operational object
package promotion gates
```

Foundry does not make ontology truth by itself. Ontology state, projections,
datasets, and receipts are admitted through Agentgres and related domain
contracts.

## Relationship To Outcome Rooms

Outcome Rooms are ioi.ai/chat.ioi.ai's first-party coordination pattern for
multi-agent/multi-session search toward one outcome.

Foundry supports Outcome Rooms by providing:

- eval suites;
- benchmark gates;
- model and harness comparison views;
- scorecards;
- failure mining;
- skill/package improvement proposals;
- reusable datasets and worker candidates.

Outcome Rooms coordinate the race. Foundry builds the engines, tracks the
benchmarks, and turns proven lessons into reusable capability.

## Relationship To Workbench And Automations

```text
Workbench
  builds, edits, debugs, and operates systems and workspaces

Automations
  owns durable workflows, triggers, schedules, services, and missions

Foundry
  owns model/worker/eval/training/package build and improvement workflows
```

Canvas may appear inside Foundry for pipeline, eval, dataset, or package graphs.
Canvas is still only a visual editor/projection.

## Minimal Implementation Objects

```yaml
FoundryProject:
  foundry_project_id: foundry_project:...
  project_ref: project:...
  ontology_refs:
    - ontology://...
  dataset_refs:
    - dataset://...
  model_refs:
    - model://...
  worker_refs:
    - worker://...
  eval_suite_refs:
    - eval_suite://...
  package_refs:
    - package://...
  promotion_queue_ref: foundry_promotion_queue:...
  agentgres_refs:
    - agentgres://operation/...

FoundryJobRequest:
  job_id: foundry_job:...
  job_type:
    model_eval | model_tuning | worker_eval | dataset_distillation |
    ontology_projection | batch_inference | endpoint_candidate |
    package_promotion | verifier_candidate | failure_mining
  source_refs:
    - artifact://...
  ontology_refs:
    - ontology://...
  input_dataset_refs:
    - dataset://...
  model_route_refs:
    - model_route:...
  worker_refs:
    - worker:...
  eval_gate_refs:
    - eval_gate:...
  authority_refs:
    - grant://... | lease://...
  budget_policy_ref: policy://...
  output_contract_ref: schema://...
  receipt_policy_ref: policy://...

FoundryScorecard:
  scorecard_id: foundry_scorecard:...
  job_ref: foundry_job:...
  objective_scores:
    - metric:...
  quality_guardrails:
    - eval_gate:...
  regression_results:
    - regression:...
  cost_summary_ref: cost://...
  risk_labels:
    - risk:...
  promotion_verdict:
    promote | hold | reject | needs_review
```

## Conformance Checks

- Foundry jobs must route consequential execution through Hypervisor Core and
  the daemon.
- Foundry cannot directly mutate runtime, prompts, policies, workers, packages,
  model routes, or service definitions without proposal, eval, authority, and
  Agentgres gates.
- Dataset, ontology, and artifact payloads must use Agentgres artifact refs and
  storage backends only as byte stores.
- Training and tuning must produce receipts, cost ledgers, input/output refs,
  and quality-gate evidence.
- Endpoint, model-route, and package promotion must be reversible, replayable,
  and policy-bound.
- Outcome Room lessons may become Foundry proposals; they do not become runtime
  changes merely because a room leaderboard selected them.

## Anti-Patterns

Avoid:

```text
Foundry = Outcome Room
Foundry = chat interface
Foundry = direct self-modification
Foundry score = deployment permission
training dataset = Agentgres truth
model endpoint = unrestricted authority
ontology projection = storage blob
benchmark win = package publication
```

Correct:

```text
Foundry builds and evaluates capability
daemon executes consequential work
wallet.network authorizes power
Agentgres admits truth and refs
storage backends hold bytes
Outcome Rooms coordinate searches
Workbench operates systems
Automations owns durable workflow/service/mission specs
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`outcome-rooms.md`](./outcome-rooms.md)
- [`../../foundations/domain-ontologies-and-data-recipes.md`](../../foundations/domain-ontologies-and-data-recipes.md)
- [`../../foundations/worker-training-lifecycle.md`](../../foundations/worker-training-lifecycle.md)
- [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
- [`../model-router/api-byok-mounting.md`](../model-router/api-byok-mounting.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
