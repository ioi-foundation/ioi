# Hypervisor Foundry

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Foundry as the model, worker, eval,
training, registry, endpoint, experiment, pipeline, metadata, monitoring,
simulation-training, and ontology-aware build surface over Hypervisor Core.
Supersedes: product prose that treats Foundry as direct runtime mutation, a
generic dashboard, only a training UI, or the same concept as ioi.ai goal
coordination.
Superseded by: none.
Last alignment pass: 2026-06-20.

## Canonical Definition

**Hypervisor Foundry is the build and improvement surface for models, workers,
evals, datasets, endpoints, experiments, pipelines, simulations, and
ontology-aware capability packages used by governed autonomous systems.**

Foundry is closer to an agent/model platform than a chat room. It gives builders
places to discover models, tune or train candidates, define evals, register
workers and models, publish endpoints, manage datasets, monitor runs, and turn
validated traces into reusable packages.

It is not:

```text
a runtime beside the daemon
a chat.ioi.ai coordination surface
a direct self-modification path
a wallet or authority layer
an Agentgres replacement
a generic notebook product
a model provider monopoly
```

## Owns

Foundry owns product-level projections and workflows for:

- model catalog and model discovery;
- model registry and model cards;
- model route candidates and model-mount candidates;
- tuning, fine-tuning, distillation, post-training, and training plans;
- batch inference and evaluation runs;
- eval suites, benchmark gates, scorecards, and verifier candidates;
- datasets, feature views, distilled ontology datasets, and holdout sets;
- experiments, pipelines, metadata, and monitoring views;
- simulation worlds, digital twins, robotics training environments, and
  perception/action datasets;
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
- ioi.ai goal coordination;
- Workbench code/systems operation;
- direct publication to aiagent.xyz, sas.xyz, or L1 without policy and receipt
  gates.

## Surface Shape

Foundry should expose a platform-style IA, not a single wizard:

```text
Overview
Model Catalog
Model Registry
Models / Routes / Mounts
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
  model catalog, worker/package catalog candidates

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

## Capability Improvement Loop

Foundry is the product surface for turning observed autonomous work into better
capability. It should make the improvement loop explicit without giving Foundry
runtime authority:

```text
sessions, receipts, traces, corrections, and failures
  -> examples, holdouts, and failure clusters
  -> datasets, eval suites, scorecards, and simulations
  -> prompts, tools, model routes, workers, data recipes, or package changes
  -> offline, simulation, and online gates
  -> promotion, rollback, or continued review
```

This loop is the product path from work evidence to reusable capability.
Promotions still require the appropriate daemon, wallet.network, Agentgres,
policy, receipt, and marketplace gates.

## Pattern And Example Supply

Patterns, examples, role tracks, and solution diagrams are upstream demand and
capability-supply inputs for Foundry. They may propose datasets, eval packs,
worker manifests, model-route candidates, data recipes, ontology packs,
automation templates, package templates, or managed-service templates.

Foundry may turn a high-performing example into:

```text
eval suite
distilled ontology dataset
training or tuning plan
worker/package candidate
model-route benchmark
promotion gate
marketplace/package proposal
```

The example itself is not proof of production readiness. Production promotion
requires evaluation receipts, benchmark receipts, authority and privacy
posture, package metadata, rollback or recall posture, and Agentgres admission.

## Ontology-Aware Foundry

Foundry may use domain ontologies as operational contracts: objects, actions,
interfaces, properties, permissions, data recipes, and projections define how
real domains become teachable and governable agent substrates.

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

## Embodied Simulation And Robotics Training

Foundry is the home for embodied model-building and simulation-training
workflows. ioi.ai may request or summarize this work, and aiagent may package
the resulting worker, but Foundry owns the build/eval lane.

Foundry may manage:

```text
simulator worlds
digital twins
LiDAR maps and point-cloud datasets
camera / depth / IMU / telemetry datasets
Gaussian splats and neural scene representations
robotics task curricula
policy training runs
perception model training
navigation and manipulation eval worlds
safety-case eval suites
sim-to-real validation reports
```

These are build/eval artifacts, not live actuator authority. Live physical
execution requires:

```text
Hypervisor Daemon admission
PhysicalActionSafetyEnvelope
HumanSupervisionPolicy
EmergencyStopAuthority
SensorEvidenceReceipt
ActuatorCommandReceipt
wallet.network authority
Agentgres receipts
```

So:

```text
Train a carwash-prep humanoid in simulation
  -> Foundry

Run the humanoid against a real vehicle
  -> Hypervisor Daemon + Physical Action Safety + wallet.network + Agentgres
```

## Relationship To ioi.ai Collaborative Outcomes

ioi.ai is the user-facing intent-to-outcome surface. It may use multiple models
or strategies to answer a question, coordinate software repair, inspect
evidence, or draft a Foundry job.

Foundry supports ioi.ai collaborative outcomes by providing:

- eval suites;
- benchmark gates;
- model and harness comparison views;
- scorecards;
- failure mining;
- skill/package improvement proposals;
- reusable datasets and worker candidates.

ioi.ai coordinates the user-facing pursuit. Foundry builds the engines, tracks
the benchmarks, and turns proven lessons into reusable capability.

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
- ioi.ai collaborative outcome lessons may become Foundry proposals; they do
  not become runtime changes merely because a projected score or comparison
  selected them.

## Anti-Patterns

Avoid:

```text
Foundry = ioi.ai chat
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
ioi.ai coordinates user-facing goal pursuit
Workbench operates systems
Automations owns durable workflow/service/mission specs
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`../../foundations/domain-ontologies-and-data-recipes.md`](../../foundations/domain-ontologies-and-data-recipes.md)
- [`../../foundations/worker-training-lifecycle.md`](../../foundations/worker-training-lifecycle.md)
- [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
- [`../model-router/api-byok-mounting.md`](../model-router/api-byok-mounting.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
