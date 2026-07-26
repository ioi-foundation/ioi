# Model, Foundry, and Worker-Training Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of model capacity/deployment/weight-custody profiles, the Foundry spec through registry-version and route-binding family, and the worker-training, dataset-factory, and post-training object families.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: planned (Foundry and worker-training object families are draft specs over real model substrate; no durable Foundry or training object plane is admitted)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/hypervisor/foundry.md`](../../components/hypervisor/foundry.md);
this module does not restate them.

## ModelCapacityProfileEnvelope

```yaml
ModelCapacityProfileEnvelope:
  model_capacity_profile_id: profile://...
  training_id: optional
  target_worker_id: optional
  target_class: small_local | balanced_local | specialist_local | hosted_frontier | hybrid_worker | deterministic_worker | custom
  parameter_range: optional
  context_budget_tokens: optional
  system_prompt_budget_tokens: optional
  tool_batch_limit: optional
  row_structure: freeform | structured | ontology_bound | tool_trace | mixed
  label_space_ref: optional
  latency_target: optional
  cost_target: optional
  privacy_posture: local | hosted | private_runtime | regulated
  recommendations:
    - structured_rows
    - shorter_system_prompt
    - tighter_label_set
    - smaller_tool_batches
    - stronger_gold_reasons
    - more_eval_coverage
  status: draft | active | superseded
```

## ModelDeploymentProfileEnvelope

Model deployment profiles describe how cognition backends are supplied to a
node or runtime. The router and invocation contract live in the node/runtime;
model weights and endpoints are profile resources.

```yaml
ModelDeploymentProfileEnvelope:
  model_deployment_profile_id: profile://...
  owner_id: wallet://... | org://... | project://...
  mount_mode: bundled_weights | local_file | local_server | external_api | hosted_pool | tee_session | depin_session | customer_vpc
  weight_custody_profile_id: model_weight_custody://...
  model_artifact_refs:
    - cid://... | artifact://... | file://...
  endpoint_refs:
    - endpoint://...
  provider_refs: []
  authority_scope_requirements:
    - scope:model.invoke.external
  execution_privacy_posture: local | external_api | tenant_private | tee_private | regulated
  run_to_idle_policy_ref: optional
  receipt_mode: hash_only | full_redacted | full_private
  status: draft | active | unavailable | revoked
```

Bundled local weights are valid for offline, demo, small sovereign, or
deployment-specific profiles. They are not the architecture default.

## ModelWeightCustodyProfileEnvelope

Model weight custody is tracked separately from workspace privacy. This avoids
the common mistake of treating cTEE/private-workspace custody as protection for
proprietary weights mounted on a root-owned rented GPU.

```yaml
ModelWeightCustodyProfileEnvelope:
  profile_id: model_weight_custody://...
  weight_class: public_open_weight | user_local_private_weight | remote_api_private_weight | provider_trust_remote_mount | tee_or_customer_cloud_mount | forbidden_plaintext_mount
  weight_owner: user | org | provider | public | marketplace_package
  mount_target: local_device | user_owned_node | rented_gpu | customer_cloud | provider_api | tee_session | none
  remote_provider_can_read_weights: true | false
  required_controls:
    - wallet_authorized_api_capability
    - local_only
    - customer_account_boundary
    - tee_attestation
    - no_remote_plaintext_mount
    - explicit_provider_trust_acceptance
  receipt_refs:
    - receipt://...
  status: proposed | accepted | blocked | revoked
```

## FoundrySpecEnvelope

The Foundry spec is the declarative source of truth for a durable training,
evaluation, packaging, or route-promotion lifecycle. Notebooks, chats, and code
workspaces may author it, but they are not the system of record.

```yaml
FoundrySpecEnvelope:
  foundry_spec_id: foundry_spec://...
  foundry_job_ref: optional foundry_job://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  objective: string
  task_family: string
  base_model_refs:
    - model://...
  training_mode:
    sft | adapter | full_finetune | distillation |
    preference_optimization | on_policy_correction | eval_only |
    packaging_only | route_policy_training | conductor_advisor_training
  training_stack_ref: optional training_stack://...
  trainer_backend_profile_refs:
    - trainer_backend://...
  reasoning_mode_policy_ref: optional reasoning_policy://...
  verifier_environment_set_refs:
    - verifier_set://... | interactive_world://... | gate://...
  dataset_snapshot_refs:
    - dataset_snapshot://... | dataset://...
  search_space_ref: optional artifact://... | policy://...
  packaging_targets:
    - adapter_merge | quantization | gguf | mlx | onnx | tensorrt |
      runtime_image | endpoint_package | model_card | custom
  budget_policy_ref: budget://... | policy://...
  eval_policy_ref: gate://... | policy://...
  target_route_ref: optional model_route://...
  version: integer
  created_by_ref: wallet://... | org://... | service://...
  status: draft | ready | superseded | archived
```

## DatasetSnapshotEnvelope

Dataset factories define how data is produced; dataset snapshots are immutable
materializations used for training, evaluation, regression, and promotion
replay.

```yaml
DatasetSnapshotEnvelope:
  dataset_snapshot_id: dataset_snapshot://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  dataset_factory_ref: foundry_job://... | data-recipe://.../revision/...
  dataset_refs:
    - dataset://...
  content_manifest_ref: artifact://...
  split_manifest_ref: artifact://...
  source_version_refs:
    - artifact://... | connector://... | view://... | receipt://...
  slice_definitions_ref: optional artifact://...
  filtering_rules_ref: optional policy://... | artifact://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  retention_policy_ref: policy://...
  lineage_refs:
    - receipt://... | transform://...
  snapshot_hash: hash
  status: materialized | retained | deprecated | revoked
```

## FoundryRunPlanEnvelope

Run plans turn a spec and snapshots into a typed stage graph with explicit
executor bindings, artifact contracts, retry policy, and checkpoint policy.

```yaml
FoundryRunPlanEnvelope:
  run_plan_id: run_plan://...
  foundry_spec_ref: foundry_spec://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  stage_graph_ref: artifact://...
  stages:
    - data_prep
    - dataset_factory
    - teacher_distillation
    - training
    - reasoning_mode_fusion
    - environment_feedback_rl
    - checkpointing
    - eval
    - packaging
    - artifact_conversion
    - registration
    - route_promotion
  executor_bindings:
    - runtime://... | compute://... | service://...
  retry_policy_ref: policy://...
  checkpoint_policy_ref: policy://...
  timeout_policy_ref: policy://...
  artifact_contract_refs:
    - schema://...
  status: draft | admitted | running | completed | superseded
```

## FoundryTrialEnvelope

Trials are the unit of search, pruning, early stopping, comparison, and
optimizer attribution.

```yaml
FoundryTrialEnvelope:
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
  status: queued | running | pruned | completed | failed | selected | rejected
```

## FoundryCheckpointArtifactEnvelope

Checkpoints are resumable state, not just files.

```yaml
FoundryCheckpointArtifactEnvelope:
  checkpoint_id: checkpoint://...
  trial_ref: optional trial://...
  training_pipeline_ref: trainpipe://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  checkpoint_artifact_ref: artifact://...
  global_step: optional integer
  token_count: optional integer
  optimizer_state_ref: optional artifact://...
  resume_compatibility_ref: optional schema://... | artifact://...
  status: created | retained | resume_candidate | deprecated | revoked
```

## FoundryModelAndPackageArtifactEnvelope

Training-native model artifacts and deployable package artifacts are distinct
lineage nodes. Packaging may merge adapters, quantize, export, build runtime
images, or create endpoint packages, but it must not overwrite the source
artifact.

```yaml
FoundryModelArtifactEnvelope:
  model_artifact_id: model_artifact://...
  source_checkpoint_ref: checkpoint://... | artifact://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  artifact_ref: artifact://...
  artifact_kind:
    checkpoint | adapter | merged_model | safetensors | pytorch |
    trainer_native | verifier_model | route_policy | conductor_advisor
  architecture_ref: optional profile://... | artifact://...
  precision: optional string
  signature_ref: optional schema://...
  metrics_ref: optional gate://... | artifact://...
  status: frozen | evaluated | deprecated | revoked

FoundryPackageArtifactEnvelope:
  package_artifact_id: package_artifact://...
  source_model_artifact_ref: model_artifact://... | artifact://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
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
  status: built | validated | registered | failed | revoked
```

## FoundryRegistryVersionAndRouteBindingEnvelope

Promotion updates route indirection. It does not mutate old artifacts in place.

```yaml
FoundryRegistryVersionEnvelope:
  registry_version_id: registry_version://...
  registry_model_ref: model://... | worker://... | package://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  artifact_ref: model_artifact://... | package_artifact://... | artifact://...
  scorecard_ref: gate://... | artifact://...
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

FoundryRouteBindingEnvelope:
  route_binding_id: promotion_record://...
  route_ref: model_route://...
  registry_version_ref: registry_version://...
  alias: champion | candidate | shadow | canary | rollback
  traffic_split: optional object
  canary_policy_ref: optional policy://...
  rollback_target_ref: registry_version://... | model://... | package://...
  decision_evidence_refs:
    - gate://... | artifact://... | receipt://...
  status: proposed | active | paused | rolled_back | recalled | superseded
```

## TrainingBatchPlanEnvelope

```yaml
TrainingBatchPlanEnvelope:
  batch_plan_id: batch://...
  training_id: training://...
  orchestrator_ref: worker://... | runtime://... | agent://...
  target_scope: string
  target_family: optional
  label_boundary_ref: optional
  hard_eval_pattern_ref: optional
  quota:
    target_rows: integer
    target_tokens: optional
    max_cost: optional
  split_policy:
    train: percentage
    holdout: percentage
    golden: percentage
    adversarial: percentage
    regression: percentage
  model_capacity_profile_ref: optional
  teacher_session_refs:
    - teacher_session://...
  candidate_data_quarantine_policy_ref: optional policy://...
  executor_worker_refs:
    - worker://...
  prompt_artifact_refs:
    - artifact://...
  acceptance_thresholds: object
  receipt_refs:
    - receipt://...
  status: draft | running | completed | rejected | superseded
```

## GenerationBatchEnvelope

```yaml
GenerationBatchEnvelope:
  generation_batch_id: batch://...
  batch_plan_ref: batch://...
  training_id: training://...
  executor_ref: worker://... | model://... | runtime://...
  provider_model_ref: optional
  input_prompt_ref: artifact://... | cid://...
  raw_batch_archive_ref: artifact://...
  row_count: integer
  token_count: optional
  provider_call_count: optional
  cost_estimate: optional
  started_at: timestamp
  completed_at: optional
  status: queued | running | archived | gated | rejected | failed
```

## TeacherSessionEnvelope

Teacher sessions record foundation-model, worker, verifier, or human-review
interactions used to generate candidate supervision. They produce candidate
training signal, not accepted truth.

```yaml
TeacherSessionEnvelope:
  teacher_session_id: teacher_session://...
  foundry_job_ref: foundry_job://...
  task_contract_ref: schema://... | artifact://...
  session_mode:
    generate | critique | debate | revise | label | judge |
    student_rollout_correction | route_policy_supervision
  teacher_refs:
    - model://... | worker://... | agent://...
  student_candidate_ref: optional model://... | worker://... | conductor://...
  prompt_artifact_refs:
    - artifact://...
  tool_contract_refs:
    - tool://... | mcp://...
  evidence_refs:
    - artifact://... | receipt://... | view://...
  output_candidate_data_refs:
    - candidate_data://...
  privacy_policy_ref: policy://...
  cost_ledger_ref: ledger://...
  receipt_refs:
    - receipt://...
  status:
    planned | running | completed | quarantined | rejected | superseded
```

## CandidateTrainingSignalEnvelope

Candidate training signal is quarantined by default. It may become an accepted
dataset row only after privacy, provenance, quality, and truth gates pass.

```yaml
CandidateTrainingSignalEnvelope:
  candidate_data_id: candidate_data://...
  teacher_session_ref: teacher_session://...
  training_id: optional training://...
  record_family:
    instruction | demonstration | chosen_rejected_preference |
    binary_preference | critique_revision | tool_trace |
    agent_trajectory | verifier_label | process_label |
    route_orchestration_trace | on_policy_correction
  source_teacher_refs:
    - model://... | worker://... | agent://...
  prompt_template_ref: optional artifact://...
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
```

## RawBatchArchiveEnvelope

```yaml
RawBatchArchiveEnvelope:
  raw_batch_archive_id: artifact://...
  training_id: training://...
  generation_batch_refs:
    - batch://...
  raw_artifact_refs:
    - artifact://...
  candidate_data_refs:
    - candidate_data://...
  cache_artifact_refs:
    - artifact://...
  provider_metadata_hash: optional
  prompt_hash: optional
  token_count: optional
  cost_estimate: optional
  policy_hash: hash
  status: archived | redacted | rejected | promoted_to_curation
```

## QualityGateReportEnvelope

```yaml
QualityGateReportEnvelope:
  gate_report_id: gate://...
  training_id: training://...
  batch_plan_ref: optional
  generation_batch_ref: optional
  gate_policy_hash: hash
  gate_results:
    schema_validity: pass | fail | skipped
    role_order: pass | fail | skipped
    final_user_turn: pass | fail | skipped
    allowed_labels: pass | fail | skipped
    canonical_order: pass | fail | skipped
    duplicate_prompt: pass | fail | skipped
    placeholder_or_meta_text: pass | fail | skipped
    target_scope_signal: pass | fail | skipped
    helper_scope_policy: pass | fail | skipped
    unsupported_primary_policy: pass | fail | skipped
    split_intent: pass | fail | skipped
    leakage_risk: pass | fail | skipped
    source_teacher_provenance: pass | fail | skipped
    candidate_data_quarantine: pass | fail | skipped
    execution_truth_gate: pass | fail | skipped
    retrieval_evidence_support: pass | fail | skipped
    verifier_agreement: pass | fail | skipped
    low_quality_or_synthetic_pattern: pass | fail | skipped
    gold_reason_quality: pass | fail | skipped
    rubric_fit: pass | fail | skipped
  accepted_count: integer
  rejected_count: integer
  rejection_reason_counts: object
  accepted_dataset_refs:
    - dataset://...
  receipt_refs:
    - receipt://...
  status: draft | completed | disputed | superseded
```

## TrainingCostLedgerEnvelope

```yaml
TrainingCostLedgerEnvelope:
  training_cost_ledger_id: ledger://...
  training_id: training://...
  batch_plan_refs:
    - batch://...
  provider_call_count: integer
  token_count: integer
  runtime_seconds: optional
  spend_estimate: optional
  accepted_row_count: integer
  rejected_row_count: integer
  cost_per_accepted_row: optional
  dataset_yield_summary_ref: optional
  quality_lift_summary_ref: optional
  status: open | closed | disputed
```

## WorkerTrainingEnvelope

```yaml
WorkerTrainingEnvelope:
  training_id: training://...
  target_worker_id: worker://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  requester_id: wallet://... | service://... | org://...
  provider_id: worker://... | service://... | ioi://publisher/...
  training_objective: string
  training_profile: dense_transformer | moe | subquadratic | hybrid_attention_state | retrieval_augmented | mutable_context | adapter_trained | distillation_trained | deterministic_verifier | custom
  training_methods:
    - prompt_optimization
    - workflow_trace
    - retrieval_curation
    - context_update
    - route_policy_training
    - adapter_training
    - verifier_tuning
    - eval_generation
    - model_finetune
    - distillation
    - policy_hardening
  dataset_commitment: hash
  domain_ontology_ref: optional
  canonical_object_model_refs: []
  data_recipe_refs: []
  policy_bound_data_view_refs: []
  distilled_dataset_refs: []
  evaluation_dataset_refs: []
  model_capacity_profile_ref: optional
  training_batch_plan_refs: []
  raw_batch_archive_refs: []
  quality_gate_report_refs: []
  training_cost_ledger_ref: optional
  ontology_to_worker_plan_ref: optional
  privacy_policy_ref: optional
  evaluation_rubric_ref: rubric://...
  post_training_policy_ref: optional
  context_graph_ref: optional
  promotion_gate_ref: optional
  output_manifest_ref: ai://...
  receipt_root: hash
  status: proposed | running | evaluated | accepted | rejected | disputed
```

## DatasetFactoryRunEnvelope

```yaml
DatasetFactoryRunEnvelope:
  dataset_factory_run_id: run://... | foundry_job://...
  foundry_job_ref: foundry_job://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  foundry_spec_ref: optional foundry_spec://...
  objective: string
  source_refs:
    - artifact://... | connector://... | view://... | receipt://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  ontology_refs:
    - ontology://...
  policy_bound_data_view_refs:
    - view://...
  stages:
    - define
    - research
    - ground
    - generate
    - audit
    - export
    - runbook
  stage: define | research | ground | generate | audit | export | runbook
  output_dataset_refs:
    - dataset://...
  dataset_snapshot_refs:
    - dataset_snapshot://...
  holdout_dataset_refs:
    - dataset://...
  adversarial_dataset_refs:
    - dataset://...
  quality_gate_refs:
    - gate://...
  cost_ledger_ref: ledger://...
  receipt_root: hash
  status: draft | running | gated | exported | failed | rejected
```

## TrainingPipelineRunEnvelope

```yaml
TrainingPipelineRunEnvelope:
  training_pipeline_run_id: trainpipe://...
  foundry_job_ref: foundry_job://...
  foundry_spec_ref: foundry_spec://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  run_plan_ref: optional run_plan://...
  objective: string
  stage:
    idea | data_binding | dataset_factory | notebook_prep | training |
    eval | validation | conversion | registration | endpoint_candidate |
    promotion_review | completed | failed
  workspace_ref: code_workspace://... | notebook://... | runtime://...
  compute_session_refs:
    - compute://...
  checkpoint_refs:
    - checkpoint://... | artifact://... | receipt://...
  resume_ref: optional artifact://... | receipt://...
  last_heartbeat_ref: optional receipt://...
  authority_grant_refs:
    - grant://...
  learning_evidence_eligibility_refs:
    - eligibility://...
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  model_base_refs:
    - model://... | model_mount://...
  input_dataset_refs:
    - dataset://...
  dataset_snapshot_refs:
    - dataset_snapshot://...
  training_config_ref: artifact://...
  training_batch_plan_refs:
    - batch://...
  trial_refs:
    - trial://...
  teacher_session_refs:
    - teacher_session://...
  candidate_data_refs:
    - candidate_data://...
  eval_suite_refs:
    - benchmark://... | gate://...
  validation_report_refs:
    - artifact://...
  optimization_cycle_refs:
    - optcycle://...
  artifact_conversion_refs:
    - conversion://...
  model_artifact_refs:
    - model_artifact://...
  package_artifact_refs:
    - package_artifact://...
  registered_model_candidate_ref: model://... | registry_version://...
  endpoint_candidate_ref: model_route://...
  route_binding_candidate_ref: optional promotion_record://...
  conductor_advisor_candidate_ref: optional conductor://...
  scorecard_ref: gate://... | artifact://...
  promotion_bundle_ref: optional promotion_bundle://...
  spend_forecast_ref: optional ledger://...
  current_burn_ref: optional ledger://...
  continuation_policy_ref: optional policy://...
  stop_resume_policy_ref: optional policy://...
  cost_ledger_ref: ledger://...
  promotion_proposal_ref: proposal://...
  receipt_root: hash
  status: planned | running | suspended | resuming | gated | registered | promoted | rejected | failed
```

## ExperimentOptimizationCycleEnvelope

```yaml
ExperimentOptimizationCycleEnvelope:
  optimization_cycle_id: optcycle://...
  foundry_job_ref: foundry_job://...
  improvement_campaign_ref: improvement-campaign://... | null
  evaluation_epoch_ref: evaluation-epoch://... | null
  coordinating_goal_run_ref: goal://... | null
  target_ref: string
  target_class:
    training_pipeline | foundry_spec | run_plan | model | worker |
    goal_run_profile | workflow_template | harness_profile | skill_manifest |
    runtime_tool_contract_binding | model_route | evaluator_asset |
    other_admitted_component
  target_owner_ref: string
  baseline_target_ref: string
  baseline_target_root: hash
  resolved_component_snapshot_ref: artifact://...
  optimizer_ref: worker://... | conductor://... | runtime://...
  search_policy_ref: policy://...
  objective_and_guardrail_policy_ref: policy://...
  randomness_and_repetition_policy_ref: policy://...
  resource_normalization_ref: policy://... | budget://...
  best_candidate_ref: artifact://... | null
  candidate_archive_projection_ref: artifact://... | null
  trial_refs:
    - trial://...
  accepted_change_refs:
    - artifact://...
  rejected_change_refs:
    - artifact://...
  inconclusive_change_refs:
    - artifact://...
  exploit_or_invalid_change_refs:
    - artifact://...
  evaluation_result_refs:
    - finding://... | gate://... | artifact://... | receipt://...
  typed_patch_candidate_ref: artifact://... | proposal://... | null
  promotion_bundle_candidate_ref: promotion_bundle://... | null
  budget_policy_ref: policy://...
  stop_policy_ref: policy://...
  receipt_root: hash
  status: planned | running | stopped | proposed_for_review | failed | rejected
```

This remains a Foundry-owned execution cycle, not the Campaign itself. A cycle
may run without an ImprovementCampaign for ordinary bounded optimization; when
campaign/epoch refs are present they must name the frozen contract that admitted
the cycle and its evaluation. The deprecated `target_training_pipeline_ref`
wire key may be accepted only by a versioned adapter that normalizes it to
`target_ref` with `target_class: training_pipeline`; canonical state does not
emit both. `best_candidate_ref` is an experiment-local selection under the
declared policies, not Campaign nomination, evaluation truth, or release
authority. No universal scalar `fitness` or mandatory Pareto/bandit algorithm
is canonical.
Foundry documentation may use the owner-qualified label
`FoundryExperimentOptimizationCycle`; the shared wire envelope and Agentgres
object class remain `ExperimentOptimizationCycle`.

## ArtifactConversionRunEnvelope

```yaml
ArtifactConversionRunEnvelope:
  conversion_run_id: conversion://...
  training_pipeline_ref: trainpipe://...
  source_model_artifact_ref: model_artifact://... | artifact://... | model://...
  conversion_targets:
    - adapter_merge
    - quantization
    - gguf
    - mlx
    - onnx
    - tensorrt
    - model_card
    - endpoint_package
    - custom
  output_artifact_refs:
    - package_artifact://... | artifact://...
  validation_refs:
    - gate://... | receipt://... | benchmark://...
  registered_model_candidate_ref: model://... | registry_version://...
  receipt_root: hash
  status: planned | running | validated | registered | failed | rejected
```

## ConductorAdvisorCandidateEnvelope

```yaml
ConductorAdvisorCandidateEnvelope:
  conductor_advisor_candidate_id: conductor://...
  foundry_job_ref: foundry_job://...
  intended_consumer: ioi_ai | hypervisor_operator_plane | custom_coordinator
  training_data_posture:
    synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  training_consent_refs:
    - grant://... | policy://...
  learning_evidence_eligibility_refs:
    - eligibility://...
  input_refs:
    - artifact://... | receipt://... | dataset://...
  teacher_session_refs:
    - teacher_session://...
  candidate_data_refs:
    - candidate_data://...
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
  promotion_bundle_ref: optional promotion_bundle://...
```

## PostTrainingCycleEnvelope

```yaml
PostTrainingCycleEnvelope:
  cycle_id: post-training-cycle://...
  worker_id: worker://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  trigger: user_correction | failed_eval | benchmark_submission | teacher_distillation | scheduled_retrain | service_delivery_feedback
  allowed_training_methods:
    - context_update
    - adapter_training
    - route_policy_training
    - distillation
    - eval_generation
    - package_revision
  source_trace_refs: []
  privacy_policy_ref: policy://...
  teacher_worker_refs: []
  candidate_artifact_ref: cid://... | artifact://...
  eval_profile_ref: benchmark://...
  promotion_gate_ref: gate://...
  rollback_required: true
  status: proposed | training | evaluating | promoted | rejected | rolled_back
```
