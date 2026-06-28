# Hypervisor Foundry

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Foundry as the model, worker, eval,
training, registry, endpoint, experiment, pipeline, metadata, monitoring,
simulation-training, durable training lifecycle, artifact packaging, governed
promotion, and ontology-aware build surface over Hypervisor Core.
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
- teacher sessions that use foundation models, workers, verifiers, or human
  reviewers to generate candidate supervision, critique, debate, revise, label,
  or correct bounded tasks;
- synthetic-safety quarantine, source-aware audit, candidate-data curation, and
  training-signal eligibility before teacher-generated material enters reusable
  datasets;
- tuning, fine-tuning, distillation, post-training, and training plans;
- role-specialized candidate training for workers, verifier models, route
  policies, conductor advisors, prompters, adapters, and package revisions;
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
- embodied capability packages that bind world representations, sensor/action
  contracts, perception models, action policies, runtime adapters, safety
  envelopes, eval suites, sim-to-real evidence, and promotion proposals;
- embodied runtime candidates that may be promoted into daemon-governed physical
  runtime only after eval, safety, authority, receipt, and Governance gates;
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
- teacher output as canonical training truth. Teacher output is candidate
  supervision until external evidence, verifier, privacy, lineage, scorecard,
  and promotion gates admit it.

## Surface Shape

Foundry should expose a platform-style IA, not a single wizard:

```text
Overview
Foundry Specs
Model Catalog
Model Registry
Models / Routes / Mounts
Tuning / Training
Dataset Factory
Dataset Snapshots
Teacher Sessions
Candidate Data Quarantine
Evaluation
Datasets
Feature Views
Experiments
Trials
Pipelines
Run Plans
Checkpoints
Experiment Optimizer
Artifact Conversion
Artifacts
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
  teacher sessions, dataset factory, fine-tuning, distillation,
  post-training, on-policy correction, training batches, notebooks/workspaces,
  cost ledgers

Evaluate
  eval suites, benchmark gates, verifier candidates, scorecards, regressions,
  synthetic-safety quarantine

Optimize
  autonomous experiment cycles, training recipe edits, hyperparameter search,
  model/harness comparisons, accepted-change logs

Deploy / Route
  artifact conversion, package artifacts, model registry, registry versions,
  model routes, model mounts, route aliases, endpoints, provisioned capacity,
  batch inference

Govern
  metadata, monitoring, receipts, promotion queue, route binding records,
  policy and authority checks
```

## Durable Foundry Object Planes

Foundry should be object-first rather than agent-first. A persistent autonomous
training environment is not one long-running trainer process. It is a durable
control plane over immutable objects that submits work to execution backends,
records every state transition and artifact, and routes promotion through
evidence-bound registry and route controls.

The source-neutral plane split is:

```text
Control plane
  FoundrySpec, RunPlan, Run, Trial, retry policy, budget policy,
  checkpoints, heartbeats, external-job polling, and promotion decisions.

Data and metadata plane
  DatasetFactory, DatasetSnapshot, candidate data, eval sets, traces,
  scorecards, cost ledgers, lineage, model cards, and retention policy.

Execution plane
  notebook-to-job bridges, packaged jobs, external training services,
  GPU/runtime queues, eval jobs, conversion jobs, and packaging jobs.

Serving and governance plane
  registry versions, mutable aliases, route bindings, traffic splits,
  canaries, rollback targets, approval state, and promotion records.
```

Notebooks, scripts, and chats may author or inspect Foundry work, but they are
not the system of record. A notebook may emit a `FoundrySpec`, a code workspace
may materialize a `RunPlan`, and a job may produce checkpoints, but Foundry
owns the durable lifecycle objects after that point.

Training artifacts and deployable artifacts are different first-class objects.
A checkpoint, adapter, merged model, quantized package, GGUF, MLX artifact,
ONNX artifact, TensorRT engine, runtime image, and endpoint package should be
separate lineage nodes. Conversion and packaging are governed downstream stages
after checkpoint freeze, not informal scripts attached to training code.

Autonomous optimizers are advisory and experimental. They propose trials,
recipe/code/config changes, search-space changes, prompt changes, or package
candidates; execution backends run; eval gates score; promotion policy decides.
An optimizer may not directly mutate a registry alias, model route, endpoint,
approval state, runtime route, or production traffic split.

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

## Teacher Distillation And Oversight

Foundry should treat frontier and foundation models as teachers, critics,
judges, data engines, and correction providers for bounded tasks. They are not
truth engines. The source-neutral pattern is:

```text
task contract and eval rubric
  -> trusted seed set, hard slices, counterexamples, and holdouts
  -> teacher sessions generate candidate instructions, traces, critiques,
     preference labels, tool-use episodes, revisions, and debate records
  -> candidate-data quarantine
  -> schema, dedupe, privacy, provenance, retrieval, execution, verifier,
     rubric, and human-review gates
  -> eligible training-signal datasets
  -> role-specialized candidates
     worker | verifier | route policy | conductor advisor | prompter | adapter
  -> SFT / behavior cloning, preference optimization, rejection-style
     optimization, on-policy correction, or online RL when there is a real
     environment reward
  -> immutable scorecard and promotion bundle
  -> Governance release/change controls for rollout, rollback, recall, and
     placement
```

Teacher sessions may use one teacher, many teachers, debate, self-refinement,
critique/rewrite, hidden teacher traces for internal supervision, or
student-rollout correction. The durable object is the preserved interaction
graph: prompts, model versions, tools, evidence refs, candidate records, critic
notes, verifier outputs, privacy posture, and cost.

Candidate data is not accepted training data. It must remain quarantined until
it passes purpose, privacy, provenance, quality, and truth gates. When the task
is executable, execution proof outranks model judgment. When the task is
retrieval-grounded, evidence support and atomic-claim checks outrank holistic
judge scores. When the task is open-ended, rubric and preference labels must be
versioned, source-aware, and auditable.

Foundry should train different students for different jobs:

```text
worker
  learns demonstrations, tool traces, trajectories, recovery behavior, and
  domain procedures

verifier
  learns outcome labels, process labels, groundedness, policy classification,
  calibration, and failure-type precision/recall

route policy
  learns cost, latency, privacy, context, authority, and quality tradeoffs over
  model routes, workers, tools, and harnesses

conductor advisor
  learns decomposition, worker selection, context sharing, retry/compare
  strategy, and orchestration policy without becoming runtime authority
```

The default training ladder is staged rather than monolithic:

```text
SFT / behavior cloning on trusted demonstrations and traces
  -> preference optimization on curated chosen/rejected or binary labels
  -> on-policy correction when student rollouts change the prefix distribution
  -> online RL only when environment reward is reliable and bounded
```

If production will use search, Best-of-N, rejection sampling, verifier
reranking, route selection, or multi-worker orchestration, Foundry should train
and evaluate that inference policy directly. A policy that decides which model,
worker, verifier, route, or candidate to use is itself a promotable artifact,
not hand-written glue.

Scorecards must bind more than aggregate win rate. At minimum they should track
capability, groundedness, safety/policy compliance, tool or environment
correctness, calibration/abstention, and efficiency. For routers and conductor
advisors the core score is a frontier curve: quality achieved at a declared
cost, latency, privacy, and authority envelope.

Promotion is a reversible state transition. A promotion bundle freezes the
candidate artifact, parent artifact, dataset digests, teacher sessions, verifier
versions, rubric versions, scorecard thresholds, monitoring policy, authority
and signoff refs, deployment tier, and rollback target. Changing a rubric,
judge, verifier, or threshold creates a new scorecard meaning; it may not
silently reinterpret an old pass.

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
  -> FoundrySpec
     objective, base model, adapter/training mode, search space, budget,
     eval policy, packaging targets, and target route
  -> DataRecipe / Ontology / PolicyBoundDataView draft
  -> TrainingEvidenceEligibility classification or exclusion
  -> wallet.network authority refs when decryption, connector access,
     model-provider key, GPU spend, provider-trust, publication, export, or
     cross-domain reuse is required
  -> DatasetSnapshot
     immutable manifests, source versions, slices, splits, filters, lineage,
     retention, and optional incremental deltas
  -> task contract, seed set, eval rubric, hard slices, and holdouts
  -> RunPlan
     typed stages, executor bindings, retry policy, checkpoint policy,
     timeout policy, and artifact contracts
  -> Dataset Factory run
     define -> research -> ground -> generate -> audit -> export -> runbook
  -> Teacher Session runs when foundation teachers, critics, judges, or
     student-rollout correction are useful
  -> candidate-data quarantine and quality gates
  -> train-ready dataset, holdouts, adversarial/regression sets, receipts
  -> Training Pipeline run
     prepare notebook/workspace -> train -> eval -> validate
  -> Trial and Checkpoint objects during training, search, pruning, or resume
  -> Evaluation Gate before packaging
  -> ModelArtifact
     frozen training-native artifact, adapter, or merged artifact
  -> PackageArtifact
     target runtime package such as quantized model, GGUF, MLX, ONNX,
     TensorRT, runtime image, model card, or endpoint package
  -> RegistryVersion
     version, aliases, approval status, signature, lineage, and model card
  -> Route binding and PromotionRecord
     route alias, traffic split, canary, rollback target, and decision evidence
  -> scorecard, cost ledger, lineage, model card, promotion bundle, and
     promotion proposal
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

The endpoint is a governed `EmbodiedCapabilityPackage`, not merely a trained
vision-language model. The package is the center of the architecture: Foundry
produces it, Hypervisor Daemon executes it, Embodied Runtime binds it to a
physical domain, Physical Action Safety constrains it, wallet.network
authorizes its mission scope and spend when delegated authority is required,
Agentgres records its state and receipts, and Governance promotes or recalls
its route.

A VLM may be one component for perception, grounding, explanation, planning, or
success/failure judgment. Runtime-capable embodied work also needs action
policies, runtime adapters, embodiment adapters, sensor/action/world contracts,
time synchronization, calibration, safety envelopes, eval suites, sim-to-real
evidence, and promotion routes.

Foundry may manage:

```text
simulator worlds
digital twins
LiDAR maps and point-cloud datasets
camera / depth / IMU / telemetry datasets
raw synchronized robot logs
normalized episode datasets
Gaussian splats and neural scene representations
semantic scene graphs, meshes, occupancy maps, collision proxies, and physics proxies
robotics task curricula
demonstration, teleoperation, actuator, and sensor-evidence datasets
teacher label sets, reward proposals, subgoal graphs, and success detectors
VLM / perception model candidates
VLA, visuomotor, diffusion/flow action-policy, or controller-adapter candidates
verifier, safety-case, route-policy, and failure-detector candidates
policy training runs
perception model training
navigation and manipulation eval worlds
safety-case eval suites
hardware-in-the-loop and shadow-mode evals
sim-to-real validation reports
```

Canonical embodied capability factory loop:

```text
demonstrations, sensor receipts, actuator logs, telemetry, world captures,
  ontology refs, human labels, failures, and simulator traces
  -> embodied dataset factory and eligibility policy
  -> raw synchronized robot logs
     (camera, depth, LiDAR, IMU, force/torque, tactile, proprioception,
      controller state, command status, e-stop, and operator events)
  -> normalized episode datasets
     (episode/step semantics, camera metadata, modality schema, labels,
      rewards, success/failure annotations, and split manifests)
  -> teacher label set
     (plans, subgoals, object grounding, affordances, reward proposals,
      trace summaries, success labels, failure reasons, all with validation)
  -> world representation bundle
     (splat / mesh / point cloud / occupancy / scene graph / collision proxy)
  -> perception, action-policy, verifier, and runtime-adapter candidates
  -> closed-loop simulation eval
  -> software-in-the-loop eval
  -> hardware-in-the-loop or shadow-mode eval
  -> canary task battery by physical risk tier
  -> safety-case scorecard and sim-to-real report
  -> EmbodiedCapabilityPackage
  -> FoundryEmbodiedRuntimeCandidate
  -> Governance promotion proposal
  -> Hypervisor Daemon + Embodied Runtime + Physical Action Safety for live use
```

The LLM, conductor, or orchestrator is useful as teacher, planner, data engine,
trace compressor, evaluator, curriculum generator, and failure miner. It should
not be assumed to sit in the high-frequency actuator loop. Low-latency
perception-action inference should be carried by an appropriate VLA, visuomotor
policy, action expert, controller adapter, deterministic controller, or hybrid
stack admitted by the daemon.

Teacher output is weak supervision until validated. A teacher-generated success
label should be corroborated by measurable end-state change, geometry
consistency, force/contact expectations, another evaluator, or human review. A
teacher-generated reward should be tested in simulation and against adversarial
edge cases before it drives expensive training. A teacher-generated subgoal
should remain a proposal until an executable policy can satisfy it under the
active safety envelope.

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

The anti-pattern this boundary prevents is:

```text
Foundry trained a model, therefore Foundry can run the robot.
```

The correct shape is:

```text
Foundry proves a candidate capability under evidence.
Runtime still requires daemon admission, embodied runtime readiness,
physical-action safety, authority refs, receipts, and Governance release controls.
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
    foundry_spec | dataset_snapshot | run_plan |
    model_eval | model_tuning | worker_eval | dataset_distillation |
    dataset_factory | training_pipeline | trial | checkpoint |
    experiment_optimization | artifact_conversion | model_artifact |
    package_artifact | model_registration | registry_version |
    route_binding | promotion_record | ontology_projection |
    batch_inference | endpoint_candidate | package_promotion |
    verifier_candidate | failure_mining |
    teacher_session | candidate_data_quarantine | preference_dataset |
    tool_trace_dataset | agent_trajectory_dataset |
    route_policy_training | on_policy_correction | promotion_bundle |
    conductor_advisor_training | conductor_advisor_eval |
    conductor_advisor_shadow | embodied_dataset_factory |
    embodied_policy_training | embodied_sim_eval |
    embodied_package | embodied_runtime_candidate
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

FoundrySpec:
  foundry_spec_id: foundry_spec://...
  foundry_project_ref: foundry_project:...
  objective: string
  task_family: string
  base_model_refs:
    - model://...
  training_mode:
    sft | adapter | full_finetune | distillation |
    preference_optimization | on_policy_correction | eval_only |
    packaging_only | route_policy_training | conductor_advisor_training
  dataset_snapshot_refs:
    - dataset_snapshot://... | dataset://...
  search_space_ref: optional artifact://... | policy://...
  run_plan_ref: optional run_plan://...
  packaging_targets:
    - adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
      runtime_image | endpoint_package | model_card
  budget_policy_ref: budget://... | policy://...
  eval_policy_ref: gate://... | policy://...
  target_route_ref: optional model_route://...
  version: integer
  created_by_ref: wallet://... | org://... | service://...
  status:
    draft | ready | superseded | archived

FoundryDatasetSnapshot:
  dataset_snapshot_id: dataset_snapshot://...
  dataset_factory_ref: foundry_job://... | recipe://...
  dataset_refs:
    - dataset://...
  content_manifest_ref: artifact://...
  split_manifest_ref: artifact://...
  source_version_refs:
    - artifact://... | connector://... | view://... | receipt://...
  slice_definitions_ref: optional artifact://...
  filtering_rules_ref: optional policy://... | artifact://...
  retention_policy_ref: policy://...
  lineage_refs:
    - receipt://... | transform://...
  snapshot_hash: hash
  status:
    materialized | retained | deprecated | revoked

FoundryRunPlan:
  run_plan_id: run_plan://...
  foundry_spec_ref: foundry_spec://...
  stage_graph_ref: artifact://...
  stages:
    - data_prep
    - training
    - checkpointing
    - eval
    - packaging
    - registration
    - route_promotion
  executor_bindings:
    - runtime://... | compute://... | service://...
  retry_policy_ref: policy://...
  checkpoint_policy_ref: policy://...
  timeout_policy_ref: policy://...
  artifact_contract_refs:
    - schema://...
  status:
    draft | admitted | running | completed | superseded

FoundryTrial:
  trial_id: trial://...
  run_plan_ref: run_plan://...
  training_pipeline_ref: optional trainpipe://...
  optimization_cycle_ref: optional optcycle://...
  parameter_values_ref: artifact://...
  objective_metric_refs:
    - gate://... | artifact://...
  scheduler_state_ref: optional artifact://...
  checkpoint_refs:
    - checkpoint://... | artifact://...
  cost_ledger_ref: ledger://...
  status:
    queued | running | pruned | completed | failed | selected | rejected

FoundryCheckpointArtifact:
  checkpoint_id: checkpoint://...
  trial_ref: optional trial://...
  training_pipeline_ref: trainpipe://...
  checkpoint_artifact_ref: artifact://...
  global_step: optional integer
  token_count: optional integer
  optimizer_state_ref: optional artifact://...
  resume_compatibility_ref: optional schema://... | artifact://...
  status:
    created | retained | resume_candidate | deprecated | revoked

FoundryModelArtifact:
  model_artifact_id: model_artifact://...
  source_checkpoint_ref: checkpoint://... | artifact://...
  artifact_ref: artifact://...
  artifact_kind:
    checkpoint | adapter | merged_model | safetensors | pytorch |
    trainer_native | verifier_model | route_policy | conductor_advisor
  architecture_ref: optional profile://... | artifact://...
  precision: optional string
  signature_ref: optional schema://...
  metrics_ref: optional gate://... | artifact://...
  status:
    frozen | evaluated | deprecated | revoked

FoundryPackageArtifact:
  package_artifact_id: package_artifact://...
  source_model_artifact_ref: model_artifact://... | artifact://...
  target_runtime:
    local_model_mount | hosted_endpoint | ctee_mount | mobile |
    browser | robot_runtime | batch_inference | custom
  format:
    adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
    runtime_image | endpoint_package | model_card | custom
  output_artifact_refs:
    - artifact://...
  build_log_ref: artifact://...
  compatibility_ref: optional schema://... | conformance_profile://...
  validation_refs:
    - gate://... | receipt://...
  status:
    built | validated | registered | failed | revoked

FoundryRegistryVersion:
  registry_version_id: registry_version://...
  registry_model_ref: model://... | worker://... | package://...
  artifact_ref: model_artifact://... | package_artifact://... | artifact://...
  scorecard_ref: foundry_scorecard:...
  lineage_refs:
    - foundry_spec://... | dataset_snapshot://... | trainpipe://... |
      receipt://...
  aliases:
    - champion
    - candidate
    - shadow
    - canary
  approval_status:
    draft | pending | approved | rejected | deprecated | revoked
  model_card_ref: optional artifact://...

FoundryRouteBinding:
  route_binding_id: promotion_record://...
  route_ref: model_route://...
  registry_version_ref: registry_version://...
  alias: champion | candidate | shadow | canary | rollback
  traffic_split: optional object
  canary_policy_ref: optional policy://...
  rollback_target_ref: registry_version://... | model://... | package://...
  decision_evidence_refs:
    - foundry_scorecard:... | receipt://... | gate://...
  status:
    proposed | active | paused | rolled_back | recalled | superseded

FoundryTeacherSession:
  teacher_session_id: teacher_session://...
  foundry_job_ref: foundry_job://...
  task_contract_ref: schema://... | artifact://...
  teacher_refs:
    - model://... | worker://... | agent://...
  student_candidate_ref: optional model://... | worker://... | conductor://...
  session_mode:
    generate | critique | debate | revise | label | judge |
    student_rollout_correction | route_policy_supervision
  prompt_artifact_refs:
    - artifact://...
  tool_contract_refs:
    - tool://... | mcp://...
  evidence_refs:
    - artifact://... | receipt://... | view://...
  output_candidate_data_refs:
    - candidate_data://...
  cost_ledger_ref: ledger://...
  privacy_posture_ref: policy://...
  receipt_root: hash
  status:
    planned | running | completed | quarantined | rejected | superseded

FoundryCandidateDataRecord:
  candidate_data_id: candidate_data://...
  teacher_session_ref: teacher_session://...
  record_family:
    instruction | demonstration | chosen_rejected_preference |
    binary_preference | critique_revision | tool_trace |
    agent_trajectory | verifier_label | process_label |
    route_orchestration_trace | on_policy_correction
  source_teacher_refs:
    - model://... | worker://...
  prompt_template_ref: artifact://...
  environment_ref: optional runtime://... | compute://...
  evidence_refs:
    - artifact://... | receipt://... | view://...
  verifier_refs:
    - worker://... | model://... | gate://...
  privacy_status_ref: eligibility://... | policy://...
  quality_gate_refs:
    - gate://...
  accepted_dataset_refs:
    - dataset://...
  status:
    quarantined | eligible | accepted | rejected | held_for_review |
    redacted | superseded

FoundryRoleSpecializedCandidate:
  candidate_ref: model://... | worker://... | model_route://... | conductor://...
  foundry_job_ref: foundry_job://...
  candidate_role:
    worker | verifier | route_policy | conductor_advisor |
    prompter | adapter | package_revision
  input_dataset_refs:
    - dataset://...
  teacher_session_refs:
    - teacher_session://...
  training_methods:
    - sft
    - behavior_cloning
    - preference_optimization
    - rejection_optimization
    - on_policy_distillation
    - online_rl
    - verifier_tuning
    - route_policy_training
  capacity_profile_ref: optional profile://...
  eval_suite_refs:
    - benchmark://... | gate://...
  scorecard_ref: foundry_scorecard:...
  promotion_bundle_ref: optional promotion_bundle://...
  status:
    draft | training | evaluating | shadow | gated | proposed |
    promoted | rejected | rolled_back

FoundryDatasetFactoryRun:
  dataset_factory_run_id: run://dataset_factory/...
  foundry_job_ref: foundry_job://...
  foundry_spec_ref: optional foundry_spec://...
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
  dataset_snapshot_refs:
    - dataset_snapshot://...
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
  foundry_spec_ref: foundry_spec://...
  run_plan_ref: optional run_plan://...
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
    - checkpoint://... | artifact://... | receipt://...
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
  dataset_snapshot_refs:
    - dataset_snapshot://...
  training_config_ref: artifact://...
  trial_refs:
    - trial://...
  eval_suite_refs:
    - benchmark://... | gate://...
  conversion_refs:
    - conversion://...
  model_artifact_refs:
    - model_artifact://...
  package_artifact_refs:
    - package_artifact://...
  registry_version_candidate_ref:
    registry_version://...
  route_binding_candidate_ref:
    promotion_record://...
  registered_model_candidate_ref:
    model://... | model_route://... | package://... | registry_version://...
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
  source_model_artifact_ref: model_artifact://... | artifact://...
  conversion_targets:
    - adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
      model_card | endpoint_package | custom
  output_artifact_refs:
    - package_artifact://... | artifact://...
  validation_refs:
    - benchmark://... | gate://... | receipt://...
  model_registry_candidate_ref:
    model://... | registry_version://...
  status:
    planned | running | validated | registered | failed | rejected

FoundryScorecard:
  scorecard_id: foundry_scorecard:...
  job_ref: foundry_job:...
  candidate_refs:
    - model://... | worker://... | model_route://... | conductor://...
  rubric_version_ref: rubric://...
  verifier_version_refs:
    - worker://... | model://... | gate://...
  objective_scores:
    - metric:...
  score_panes:
    capability: object
    groundedness: object
    safety_policy: object
    tool_environment_correctness: object
    calibration_abstention: object
    efficiency: object
  frontier_curve_ref: optional artifact://...
  quality_guardrails:
    - eval_gate:...
  regression_results:
    - regression:...
  cost_summary_ref: cost://...
  risk_labels:
    - risk:...
  promotion_verdict:
    promote | hold | reject | needs_review

FoundryPromotionBundle:
  promotion_bundle_id: promotion_bundle://...
  foundry_job_ref: foundry_job://...
  candidate_ref: model://... | worker://... | model_route://... | conductor://... | package://...
  parent_artifact_ref: optional artifact://... | model://... | worker://...
  dataset_digest_refs:
    - dataset://... | hash
  teacher_session_refs:
    - teacher_session://...
  verifier_version_refs:
    - worker://... | model://... | gate://...
  scorecard_ref: foundry_scorecard:...
  gating_threshold_ref: policy://...
  authority_or_signoff_refs:
    - grant://... | policy://... | receipt://...
  monitoring_policy_ref: policy://...
  deployment_tier: local | shadow | canary | production | marketplace
  rollback_target_ref: artifact://... | model://... | worker://... | package://...
  receipt_root: hash
  status:
    draft | frozen | proposed | approved | rejected | rolled_back | recalled

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

EmbodiedCapabilityPackage:
  package_ref: package://...
  foundry_job_ref: foundry_job://...
  capability_spec_ref: capability_spec://...
  robot_embodiment_refs:
    - embodiment://...
  embodiment_adapter_refs:
    - embodiment_adapter://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  world_contract_ref: world_contract://...
  world_representation_refs:
    - world_representation://... | artifact://...
  world_model_refs:
    - world_model://...
  raw_robot_log_refs:
    - robot_log://... | artifact://...
  episode_dataset_refs:
    - episode_dataset://... | dataset_snapshot://...
  teacher_label_set_refs:
    - teacher_label_set://...
  perception_model_refs:
    - model://...
  action_policy_refs:
    - model://... | worker://... | artifact://...
  verifier_refs:
    - model://... | worker://... | gate://...
  success_detector_refs:
    - success_detector://... | model://... | worker://...
  runtime_adapter_ref: worker://...
  calibration_refs:
    - calibration://...
  time_sync_contract_ref: time_sync://...
  physical_action_safety_envelope_ref: policy://... | safety://...
  human_supervision_policy_ref: supervision://...
  emergency_stop_authority_ref: estop://...
  eval_suite_refs:
    - gate://... | benchmark://...
  offline_eval_report_ref: optional artifact://... | report://...
  software_in_loop_report_ref: optional artifact://... | report://...
  hardware_in_loop_report_ref: optional artifact://... | report://...
  shadow_mode_report_ref: optional artifact://... | report://...
  canary_task_battery_ref: optional gate://... | artifact://...
  sim_to_real_report_ref: artifact://... | report://...
  scorecard_ref: foundry_scorecard:...
  promotion_proposal_ref: proposal://...
  receipt_root: hash

FoundryEmbodiedRuntimeCandidate:
  candidate_id: embodied_candidate://...
  source_training_pipeline_ref: trainpipe://...
  embodied_capability_package_ref: package://...
  intended_runtime:
    hypervisor_daemon | partner_robot_runtime | simulator_only
  robot_embodiment_refs:
    - embodiment://...
  embodiment_adapter_refs:
    - embodiment_adapter://...
  sensor_contract_ref: sensor_contract://...
  action_schema_ref: action_schema://...
  world_contract_ref: world_contract://...
  runtime_adapter_ref: worker://...
  time_sync_contract_ref: time_sync://...
  calibration_refs:
    - calibration://...
  physical_action_safety_envelope_ref: policy://... | safety://...
  human_supervision_policy_ref: supervision://...
  emergency_stop_authority_ref: estop://...
  eval_suite_refs:
    - gate://... | benchmark://...
  sim_to_real_validation_report_ref: artifact://... | report://...
  shadow_mode_refs:
    - run://...
  canary_task_battery_ref: optional gate://... | artifact://...
  scorecard_ref: foundry_scorecard:...
  promotion_status:
    draft | eval | shadow | gated | proposed | rejected | promoted
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
- Teacher sessions must preserve teacher identity, model/version identity,
  prompt artifacts, tool/evidence refs, critic or debate outputs, privacy
  posture, cost, and candidate-data refs.
- Teacher-generated outputs must enter candidate-data quarantine and may not be
  treated as accepted training truth until quality, privacy, provenance,
  verifier, and task-specific truth gates pass.
- Dataset objects must preserve teacher provenance and source-aware audit
  results. Synthetic data without provenance is not eligible for reusable
  training.
- Verifier, router, conductor-advisor, worker, prompter, and adapter candidates
  must declare their role-specific objective, datasets, eval suites, and
  scorecard panes rather than hiding behind a generic model score.
- Scorecards must version rubrics, judges, verifier sets, thresholds, and
  frontier curves independently of model artifacts.
- Promotion bundles must freeze data digests, teacher sessions, verifier
  versions, scorecards, thresholds, monitoring policy, signoff refs, and
  rollback target before Governance may roll out or route the candidate.
- On-policy correction is required when the student rollout distribution is the
  thing being optimized. Static prompt/answer distillation is insufficient for
  long-horizon tool, code, routing, or orchestration behavior.
- Persistent training pipelines must expose stage state from dataset idea
  through registration, including dataset yield, GPU/runtime occupancy, spend
  forecast/current burn, continuation value, stop/resume policy, eval,
  validation, conversion, and promotion readiness.
- Notebook-to-job, chat-to-job, and code-workspace-to-job flows must emit a
  durable `FoundrySpec` or equivalent job definition before they become
  platform-owned lifecycle work. Interactive state is never the system of
  record.
- Dataset factories must separate factory logic from immutable
  `DatasetSnapshot` materializations. Mutable paths, ambient tables, and
  "latest" datasets cannot be used as promotion evidence.
- Run plans must decompose persistent work into typed stages with explicit
  inputs, outputs, retry policy, checkpoint policy, timeout policy, and
  executor bindings.
- Trials and checkpoints must be first-class, resumable, comparable, and
  cost-accountable. Early stopping, pruning, and resume semantics must be
  recorded as lifecycle events, not buried in training logs.
- Model artifacts and package artifacts must remain separate. Checkpoints,
  adapters, merged weights, quantized exports, GGUF, MLX, ONNX, TensorRT,
  runtime images, model cards, and endpoint packages are distinct lineage
  nodes.
- Autonomous experiment optimizers must bind objective metrics, seed/budget
  policy, accepted/rejected changes, replay evidence, and stop conditions.
- Autonomous optimizers may propose trials or candidate changes, but they may
  not directly mutate registry aliases, route bindings, traffic splits,
  endpoint status, approval state, or production runtime routes.
- Artifact conversion must produce validation receipts before converted models
  can be registered, routed, or published.
- Registry versions must bind artifact refs, scorecards, lineage, aliases,
  approval status, and model-card refs before route promotion.
- Promotion must update governed route indirection: aliases, route bindings,
  traffic splits, canaries, and rollback targets. It must not overwrite old
  artifacts or mutate production endpoints in place.
- Conductor-advisor training must bind training-data posture, authority refs
  when delegated power is involved, training evidence eligibility refs,
  policy-bound data views, eval suites, scorecards, privacy/incident counters
  from shadow mode, and promotion gates before any ioi.ai use.
- Embodied capability packages must bind robot embodiment, sensor contracts,
  embodiment adapter, sensor contracts, action schema, world contract, world
  representations, raw robot logs, normalized episode datasets, teacher label
  provenance, success-detector/evaluator refs, runtime adapter, calibration
  refs, time-sync contract, safety envelope, supervision policy, eval suites,
  sim-to-real evidence, scorecard, and promotion proposal before any runtime
  promotion.
- Embodied teacher labels, reward proposals, subgoal graphs, trace summaries,
  and success/failure annotations are weak supervision until validated against
  measurable end-state, geometry, contact, simulation, evaluator, or human
  review evidence.
- Embodied runtime candidates are not live runtime authority. They may be
  proposed only after Foundry evidence is attached and must still pass Governance
  release controls, daemon admission, Embodied Runtime readiness, Physical Action
  Safety, wallet.network authority when delegated power is required, and
  Agentgres receipt gates.
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
embodied VLM = runtime robot capability
Foundry embodied candidate = actuator authority
simulation pass = physical deployment
teacher label = measured physical truth
photorealistic world model = collision authority
raw robot log = training dataset without eligibility
capability package = target-domain runtime binding
teacher output = training truth
synthetic data = privacy safe by default
single judge = production truth
benchmark average = promotion readiness
distilled answer = distilled tool behavior
router/conductor policy = hand-written glue outside eval
rubric edit = same scorecard meaning
checkpoint upload = promotion
notebook = training system of record
dataset path = reproducible dataset snapshot
training checkpoint = deployable package
optimizer winner = production promotion
production endpoint mutation = safe rollout
```

Correct:

```text
Foundry builds and evaluates capability
Foundry conductor candidates are bounded planning/routing advisors
Foundry embodied packages are evidence-backed capability candidates
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
