# Hypervisor Foundry

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Foundry as the model, worker, eval,
training, registry, endpoint, experiment, pipeline, metadata, monitoring,
simulation-training, and ontology-aware build surface over Hypervisor Core.
Supersedes: product prose that treats Foundry as direct runtime mutation, a
generic dashboard, only a training UI, or the same concept as ioi.ai goal
coordination.
Superseded by: none.
Last alignment pass: 2026-06-23.

## Canonical Definition

**Hypervisor Foundry is the capability factory for governed autonomous
systems.**

Foundry is where observed work becomes reusable capability: models, workers,
evals, datasets, model routes, endpoints, experiments, persistent training
pipelines, simulations, conductor advisors, and ontology-aware capability
packages.

Foundry is closer to an agent/model platform than a chat room. It gives builders
places to discover models, tune or train candidates, define evals, register
workers and models, publish endpoints, manage datasets, monitor runs, and turn
validated traces, feedback, and work-analytics signals into reusable packages.
Its central product promise is not "train a model"; it is to industrialize
capability from data, traces, evals, feedback, policy, and governed work
evidence.

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
- dataset-factory runs that turn ideas, docs, traces, and policy-bound views
  into train-ready datasets;
- tuning, fine-tuning, distillation, post-training, and training plans;
- persistent autonomous training pipeline runs from dataset idea to registered
  model;
- experiment-optimization cycles that iteratively modify training code,
  recipes, hyperparameters, harnesses, or model-route policy under eval gates;
- conductor-advisor training, distillation, evals, and promotion proposals for
  ioi.ai or other Hypervisor-built coordinators;
- artifact conversion, quantization, adapter merge, and model registration
  candidates;
- batch inference and evaluation runs;
- eval suites, benchmark gates, scorecards, and verifier candidates;
- regression-record candidates from eval, shadow, canary, rollout, production,
  or recall evidence;
- feedback and annotation queues that turn corrections, acceptance/rejection
  reasons, reviewer judgments, and quality labels into evaluation or training
  candidates;
- datasets, feature views, distilled ontology datasets, and holdout sets;
- experiments, pipelines, metadata, work-analytics, tool-analytics, and
  monitoring views;
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
- conductor-training consent or training-data authority;
- Workbench code/systems operation;
- direct publication to aiagent.xyz, sas.xyz, or L1 without policy and receipt
  gates.
- rollout, rollback, recall, kill-switch, or remote-config truth after a
  candidate leaves Foundry for runtime promotion. Those transitions belong to
  Governance release/change controls, with Foundry evidence attached as gates.

## Surface Shape

Foundry should expose a platform-style IA, not a single wizard:

```text
Overview
Model Catalog
Model Registry
Models / Routes / Mounts
Tuning / Training
Dataset Factory
Evaluation
Datasets
Feature Views
Experiments
Pipelines
Experiment Optimizer
Artifact Conversion
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
  dataset factory, fine-tuning, distillation, post-training, training batches,
  notebooks/workspaces, cost ledgers

Evaluate
  eval suites, benchmark gates, verifier candidates, scorecards, regressions

Optimize
  autonomous experiment cycles, training recipe edits, hyperparameter search,
  model/harness comparisons, accepted-change logs

Deploy / Route
  artifact conversion, model registry, model routes, model mounts, endpoints,
  provisioned capacity, batch inference

Govern
  metadata, monitoring, receipts, promotion queue, policy and authority checks
```

## Capability Improvement Loop

Foundry is the product surface for turning observed autonomous work into better
capability. It should make the improvement loop explicit without giving Foundry
runtime authority:

```text
sessions, receipts, traces, work analytics, tool analytics, feedback,
  corrections, rollout outcomes, and failures
  -> examples, holdouts, and failure clusters
  -> datasets, eval suites, scorecards, and simulations
  -> prompts, tools, model routes, conductor advisors, workers, data recipes,
     or package changes
  -> offline, simulation, shadow, canary, and online gates
  -> CapabilityRegressionRecord when any accepted or candidate capability
     regresses safety, privacy, cost, authority, latency, reliability, or a
     holdout
  -> promotion, rollback, or continued review
```

This loop is the product path from work evidence to reusable capability.
Promotions still require the appropriate daemon, authority refs when delegated
power is involved, Agentgres, policy, receipt, Governance release/change
controls, and marketplace gates.

The compounding loop should remain visible in product and architecture:

```text
governed work happens
  -> receipts, artifacts, traces, work analytics, feedback, evals, and failures accumulate
  -> Foundry mines reusable improvement candidates
  -> Foundry builds, evaluates, trains, converts, packages, or promotes capability
  -> aiagent.xyz or private catalogs attribute external supply when applicable
  -> future work routes through better workers, models, tools, recipes, and evals
```

Foundry may train or distill a conductor advisor from eligible synthetic,
redacted, full-private opt-in, or org-policy evidence. The eligibility decision
is local product governance first: Hypervisor, Foundry, ODK, Domain Apps, and
Governance may propose it; Agentgres admits the
resulting record and receipts. wallet.network supplies authority refs when that
eligibility needs decryption, connector access, model-provider keys, GPU spend,
provider-trust acceptance, publication, export, cross-domain reuse, or another
delegated machine power.

Sensitive evidence must first receive a `TrainingEvidenceEligibility` record.
Evidence with `never_train`, expired consent, revoked authority, missing
policy-bound view, or blocked provider-trust posture is not eligible training
input. A promoted conductor advisor is a bounded planning/routing input
consumed by ioi.ai or another coordinator. It is not runtime authority, not
wallet authority, not marketplace truth, and not an automatic self-modification
path.

## Persistent Autonomous Training Pipeline

Foundry should make the model-building lane feel like persistent autonomous
pipeline orchestration, not a scattered set of notebook, eval, and registry
screens. A run may take minutes, hours, days, or longer. The product primitive
is resumable, inspectable, policy-bound training work, not a time-of-day
promise.

Canonical flow:

```text
dataset idea, docs, traces, or policy-bound data view
  -> Hypervisor/project/org governance and purpose selection
  -> DataRecipe / Ontology / PolicyBoundDataView draft
  -> TrainingEvidenceEligibility classification or exclusion
  -> wallet.network authority refs when decryption, connector access,
     model-provider key, GPU spend, provider-trust, publication, export, or
     cross-domain reuse is required
  -> Dataset Factory run
     define -> research -> ground -> generate -> audit -> export -> runbook
  -> train-ready dataset, holdouts, adversarial/regression sets, receipts
  -> Training Pipeline run
     prepare notebook/workspace -> train -> eval -> validate
     -> convert/quantize/package -> register model -> endpoint/route candidate
  -> scorecard, cost ledger, lineage, model card, and promotion proposal
  -> optional conductor-advisor training or shadow run
```

The pipeline may be driven from a notebook, Code Workspace, managed GPU job,
container image, training service, or headless Hypervisor job. The product
surface should still present one coherent persistent run with stages, elapsed
time, runtime/GPU occupancy, spend forecast, current burn, budget exhaustion
risk, continuation value, dataset yield, quality gates, evals, validation,
conversion artifacts, registration state, stop/resume policy, and promotion
readiness.

This lane supports small/local model training, adapter training, supervised
tuning, distillation, verifier tuning, route-policy training, conductor-advisor
training, package revision, and artifact conversion formats such as adapter
merge, quantization, GGUF, MLX, ONNX, TensorRT, model-card export, and
endpoint package preparation.

## Autonomous Experiment Optimizer

Foundry may run an autonomous experiment optimizer for training and capability
improvement. The optimizer is a governed worker or coordinator that proposes
recipe/code/config changes, runs experiments, compares objective metrics, keeps
only accepted improvements, and emits replayable evidence.

Canonical loop:

```text
baseline training recipe and objective metric
  -> propose code/config/hyperparameter/harness/model-route candidate
  -> run bounded experiment under budget, seed, privacy, and compute policy
  -> evaluate objective metric and guardrails
  -> accept, reject, or queue for human review
  -> update best-known recipe candidate
  -> repeat until budget, time, improvement, or policy stop condition
```

The objective may be loss, bits-per-byte, benchmark score, validation accuracy,
agent success rate, cost-adjusted quality, latency, verifier pass rate, or a
domain-specific metric. The optimizer can orchestrate multiple models or
workers as planners, executors, judges, verifiers, and code editors, but it
does not become runtime truth. Accepted changes are candidate artifacts until
they pass Foundry scorecards, Agentgres admission, authority checks, and
promotion/rollback gates.

The optimizer may not accept a single objective improvement when declared
guardrails regress. Mixed results produce a regression record, shadow-more
decision, rejection, or human-review queue. If the regression is discovered
after canary or production exposure, Governance release/change controls own
pause, rollback, recall, constraint, or patched-retry posture; Foundry receives the admitted
regression evidence as future eval or training material only after training
evidence eligibility permits that reuse.

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
- conductor-advisor candidates;
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
    dataset_factory | training_pipeline | experiment_optimization |
    artifact_conversion | model_registration | ontology_projection |
    batch_inference | endpoint_candidate | package_promotion |
    verifier_candidate | failure_mining |
    conductor_advisor_training | conductor_advisor_eval |
    conductor_advisor_shadow
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

FoundryDatasetFactoryRun:
  dataset_factory_run_id: run://dataset_factory/...
  foundry_job_ref: foundry_job://...
  source_refs:
    - artifact://... | connector://... | view://...
  data_recipe_refs:
    - recipe://...
  ontology_refs:
    - ontology://...
  stages:
    - define | research | ground | generate | audit | export | runbook
  stage: define | research | ground | generate | audit | export | runbook
  output_dataset_refs:
    - dataset://...
  holdout_dataset_refs:
    - dataset://...
  quality_gate_refs:
    - gate://...
  cost_ledger_ref: ledger://...
  status:
    draft | running | gated | exported | failed | rejected

FoundryTrainingPipelineRun:
  training_pipeline_run_id: trainpipe://...
  foundry_job_ref: foundry_job://...
  objective: string
  stage:
    idea | data_binding | dataset_factory | notebook_prep | training |
    eval | validation | conversion | registration | endpoint_candidate |
    promotion_review | completed | failed
  workspace_ref:
    code_workspace://... | notebook://... | runtime://...
  compute_session_refs:
    - compute://...
  checkpoint_refs:
    - artifact://... | receipt://...
  resume_ref: artifact://... | receipt://...
  last_heartbeat_ref: receipt://...
  training_evidence_eligibility_refs:
    - eligibility://...
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  model_base_refs:
    - model://...
  input_dataset_refs:
    - dataset://...
  training_config_ref: artifact://...
  eval_suite_refs:
    - benchmark://... | gate://...
  conversion_refs:
    - conversion://...
  registered_model_candidate_ref:
    model://... | model_route://... | package://...
  scorecard_ref: foundry_scorecard:...
  spend_forecast_ref: ledger://...
  current_burn_ref: ledger://...
  continuation_policy_ref: policy://...
  stop_resume_policy_ref: policy://...
  cost_ledger_ref: ledger://...
  promotion_proposal_ref: proposal://...
  receipt_root: hash
  status:
    planned | running | suspended | resuming | gated | registered |
    promoted | rejected | failed

FoundryExperimentOptimizationCycle:
  optimization_cycle_id: optcycle://...
  foundry_job_ref: foundry_job://...
  target_training_pipeline_ref: trainpipe://...
  optimizer_ref:
    worker://... | conductor://... | runtime://...
  objective_metric:
    name: string
    direction: minimize | maximize
  baseline_recipe_ref: artifact://...
  best_candidate_ref: artifact://...
  trial_refs:
    - experiment_trial://...
  accepted_change_refs:
    - artifact://...
  rejected_change_refs:
    - artifact://...
  stop_policy_ref: policy://...
  budget_policy_ref: policy://...
  status:
    planned | running | stopped | promoted_to_review | failed | rejected

FoundryArtifactConversionRun:
  conversion_run_id: conversion://...
  foundry_job_ref: foundry_job://...
  source_model_artifact_ref: artifact://...
  conversion_targets:
    - adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
      model_card | endpoint_package | custom
  output_artifact_refs:
    - artifact://...
  validation_refs:
    - benchmark://... | gate://... | receipt://...
  model_registry_candidate_ref:
    model://...
  status:
    planned | running | validated | registered | failed | rejected

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

FoundryConductorAdvisorCandidate:
  candidate_id: conductor://...
  foundry_job_ref: foundry_job://...
  intended_consumer:
    ioi_ai | hypervisor_operator_plane | custom_coordinator
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  training_consent_refs:
    - authority://training_consent/... | policy://...
  training_evidence_eligibility_refs:
    - eligibility://...
  input_refs:
    - artifact://... | receipt://... | dataset://...
  eval_suite_refs:
    - benchmark://... | gate://...
  scorecard_refs:
    - gate://... | artifact://...
  shadow_mode_refs:
    - run://...
  shadow_mode_receipt_refs:
    - receipt://...
  shadow_mode_summary:
    quality_delta: optional
    cost_delta: optional
    latency_delta: optional
    privacy_incidents: integer
    policy_denials: integer
    authority_escalations: integer
  promotion_status:
    draft | training | shadow | gated | promoted | rejected | paused |
    rolled_back | recalled
  rollback_ref: optional
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
- Persistent training pipelines must expose stage state from dataset idea
  through registration, including dataset yield, GPU/runtime occupancy, spend
  forecast/current burn, continuation value, stop/resume policy, eval,
  validation, conversion, and promotion readiness.
- Autonomous experiment optimizers must bind objective metrics, seed/budget
  policy, accepted/rejected changes, replay evidence, and stop conditions.
- Artifact conversion must produce validation receipts before converted models
  can be registered, routed, or published.
- Conductor-advisor training must bind training-data posture, authority refs
  when delegated power is involved, training evidence eligibility refs,
  policy-bound data views, eval suites, scorecards, privacy/incident counters
  from shadow mode, and promotion gates before any ioi.ai use.
- Endpoint, model-route, worker, package, and conductor-advisor promotion must
  be reversible, replayable, policy-bound, and handed to Governance
  release/change controls for rollout, rollback, recall, kill-switch, and
  runtime placement.
- Regression evidence from offline eval, shadow mode, canary, rollout,
  production, or recall review must be recorded as `CapabilityRegressionRecord`
  when it changes promotion, routing, eligibility, rollback, recall, or future
  eval/training posture.
- ioi.ai collaborative outcome lessons may become Foundry proposals; they do
  not become runtime changes merely because a projected score or comparison
  selected them.

## Anti-Patterns

Avoid:

```text
Foundry = ioi.ai chat
Foundry = chat interface
Foundry = direct self-modification
Foundry conductor = hidden ioi.ai authority
conductor-training consent = ioi.ai record
Foundry score = deployment permission
training dataset = Agentgres truth
model endpoint = unrestricted authority
persistent training run = opaque notebook side effect
experiment optimizer = self-modifying runtime
converted artifact = deployable model without validation receipt
ontology projection = storage blob
benchmark win = package publication
```

Correct:

```text
Foundry builds and evaluates capability
Foundry conductor candidates are bounded planning/routing advisors
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
- [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md)
- [`../wallet-network/api-authority-scopes.md`](../wallet-network/api-authority-scopes.md)
- [`../model-router/api-byok-mounting.md`](../model-router/api-byok-mounting.md)
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
