# Institutional Learning Boundary Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of learning source-rights claims, the institutional learning boundary profile, policy-bound data views, transformation runs, distilled ontology datasets, evaluation datasets, learning-evidence eligibility, and institutional intelligence export bundles.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: planned (the Institutional Learning Boundary family is not started)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../institutional-learning-boundary.md`](../institutional-learning-boundary.md);
this module does not restate them.

## LearningSourceRightsClaimEnvelope

A learning-source-rights claim records the evidence-backed rights posture that
policy uses to admit or reject inference, evaluation, improvement, derivative,
or export uses. It is an auditable assertion, not proof of legal title or an
automatic grant of authority.

```yaml
LearningSourceRightsClaimEnvelope:
  source_rights_claim_id: learning-source-rights://...
  subject_refs:
    - artifact://... | receipt://... | dataset://... | view://... |
      connector://... | memory://... | trace://... | model://... |
      worker://... | package://...
  source_class:
    employee | contractor | customer | patient | partner | vendor |
    licensed | purchased | public | synthetic | provider_output |
    machine_generated | mixed | unknown
  asserted_by_ref: user://... | org://... | system://... | project://...
  asserted_rights_holder_refs:
    - user://... | org://... | system://... | project://... | provider://...
  rights_basis_refs:
    - contract://... | terms://... | policy://... | grant://... |
      authority://... | license://... | evidence://...
  provider_or_model_route_contract_refs:
    - model-route-contract://...
  permitted_uses:
    - operational_inference
    - retain
    - replay
    - internal_evaluation
    - internal_analytics
    - memory_or_context_improvement
    - dataset_generation
    - fine_tune
    - distill
    - competing_model_training
    - worker_or_package_improvement
    - commercialize_derivative
    - export
    - publish
    - cross_tenant_aggregate_learning
  prohibited_uses: []
  derivative_disposition:
    inherit_intersection | internal_only | transferable_with_claims |
    noncommercial_only | no_derivatives | policy_defined
  beneficiary_scope_refs:
    - user://... | org://... | project://... | system://... | worker://...
  jurisdiction_and_region_refs: []
  retention_policy_ref: policy://...
  deletion_or_forget_policy_ref: policy://...
  validity:
    valid_from: timestamp
    valid_until: timestamp | null
  evidence_refs:
    - evidence://... | receipt://... | artifact://...
  claim_commitment: hash
  supersedes_ref: learning-source-rights://... | null
  status: asserted | admitted | disputed | expired | superseded | revoked | rejected
```

Unknown, expired, disputed, conflicting, or unsupported claims fail closed for
training, distillation, publication, cross-tenant learning, and export. A
separate policy may admit operational inference when its own access and use
rights are established.

## InstitutionalLearningBoundaryProfileEnvelope

The Institutional Learning Boundary is a composition profile over existing
authority, truth, runtime, custody, routing, data, and Foundry owners. Its
canonical doctrine and narrowing semantics are owned by
[`institutional-learning-boundary.md`](../institutional-learning-boundary.md).

```yaml
InstitutionalLearningBoundaryProfileEnvelope:
  schema_version: ioi.institutional-learning-boundary.v1
  boundary_profile_id: learning-boundary://...
  revision: semver_or_hash
  scope_level:
    organization | project | system | session | run |
    model_invocation | transformation | foundry_job
  scope_owner_ref:
    org://... | project://... | system://... | session://... | goal://... |
    run://... | invocation://... | transform://... | foundry_job://...
  applies_to_refs:
    - org://... | project://... | system://... | domain://... |
      session://... | goal://... | run://... | invocation://... |
      transform://... | foundry_job://... | worker://...
  governance_owner_ref: org://... | project://... | system://...
  parent_profile_refs:
    - learning-boundary://...
  system_binding:
    system_ref: system://... | null
    constitution_ref: constitution://... | null
    deployment_profile_ref: deployment-profile://... | null
    upgrade_required_for_widening: true
  protected_material_classes:
    - source_data
    - prompts_and_completions
    - connector_and_tool_io
    - work_graphs_traces_and_receipts
    - corrections_and_reviewer_judgments
    - evaluations_rubrics_holdouts_and_canaries
    - memory_context_procedures_workflows_and_skills
    - datasets_embeddings_and_indexes
    - adapters_checkpoints_weights_and_packages
    - router_verifier_authority_and_governance_policy
    - analytics_crash_support_and_security_telemetry
    - embodied_sensor_actuator_mission_and_operator_telemetry
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  enterprise_permitted_uses:
    - operational_inference
    - retain
    - replay
    - internal_evaluation
    - internal_analytics
    - memory_or_context_improvement
    - dataset_generation
    - fine_tune
    - distill
    - competing_model_training
    - worker_or_package_improvement
    - commercialize_derivative
    - export
    - publish
  enterprise_prohibited_uses: []
  external_recipient_permissions:
    transient_inference: allow | deny | policy_qualified
    service_logging: allow | deny | policy_qualified
    abuse_or_security_review: allow | deny | policy_qualified
    human_support_review: allow | deny | policy_qualified
    retention: allow | deny | policy_qualified
    service_improvement: allow | deny | policy_qualified
    provider_model_training: allow | deny | policy_qualified
    cross_customer_aggregation: allow | deny | policy_qualified
    publication: allow | deny | policy_qualified
  cross_tenant_learning:
    default: deny
    permitted_cohort_refs: []
    aggregation_policy_ref: policy://... | null
    contribution_and_benefit_terms_ref: terms://... | null
  route_and_custody:
    product_mode: standard | private
    runtime_operator: ioi_managed | customer_managed | local | hybrid
    permitted_provider_trust_postures: []
    permitted_custody_postures: []
    model_route_contract_refs:
      - model-route-contract://...
    private_claim_requires_current_proof: true
  data_and_improvement_policy_refs:
    - view://... | data-recipe://.../revision/... | eligibility://... | policy://... | gate://...
  retention_policy_ref: policy://...
  deletion_or_forget_policy_ref: policy://...
  legal_or_audit_hold_policy_ref: policy://... | null
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  export_policy_ref: policy://...
  revocation_policy_ref: policy://...
  declassification_policy_ref: policy://... | null
  receipt_obligations:
    - boundary_compilation
    - model_route_decision
    - learning_egress_decision
    - learning_evidence_eligibility
    - transformation
    - foundry_lineage
    - promotion_or_recall
    - export_or_denial
  compiled_policy_hash: hash
  effective_from: timestamp
  expires_at: timestamp | null
  supersedes_ref: learning-boundary://... | null
  status: draft | active | suspended | superseded | revoked
```

`enterprise_permitted_uses` never overrides a missing source right. Effective
policy is the most-restrictive deterministic intersection of applicable active
profiles, source-rights claims, data views, route contracts, custody rules,
retention rules, and authority decisions. Session, run, model-invocation,
transformation, and Foundry-job profiles are immutable snapshots. An active
system profile is pinned by system governance; a new organization or project
revision does not mutate it by implication.

## PolicyBoundDataViewEnvelope

```yaml
PolicyBoundDataViewEnvelope:
  view_id: view://...
  domain_id: agentgres://domain/...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  object_model_refs:
    - object-model://...
  source_refs: []
  allowed_uses:
    - read
    - transform
    - distill
    - train
    - evaluate
    - export
    - publish
    - route
  authority_grant_refs:
    - grant://...
  retention_policy_ref: optional
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  policy_hash: hash
  expires_at: optional
```

## TransformationRunEnvelope

```yaml
TransformationRunEnvelope:
  transformation_run_id: transform://...
  data_recipe_revision_ref: data-recipe://.../revision/...
  data_recipe_content_hash: hash
  resolved_semantic_component_set_snapshot_ref: artifact://...
  resolved_semantic_component_set_hash: hash
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  input_refs:
    - artifact://...
    - connector://...
    - agentgres://object/...
  output_object_refs:
    - agentgres://object/...
  output_dataset_refs:
    - dataset://...
  output_distilled_dataset_refs:
    - dataset://...
  output_artifact_refs:
    - artifact://...
  policy_bound_data_view_refs:
    - view://...
  authority_grant_refs:
    - grant://...
  derivative_policy_ref: policy://... | null
  impact_graph_ref: agentgres://projection/... | null
  receipt_refs:
    - receipt://...
  status: queued | running | completed | failed | rejected
```

The resolved semantic-component tuple must exactly equal the tuple committed by
the admitted DataRecipe revision. A run may not replace an ontology, mapping,
object model, schema, or policy-bound view with a current registry head. A
different semantic dependency set requires a successor recipe revision and a
new admission receipt.

## DistilledOntologyDatasetEnvelope

```yaml
DistilledOntologyDatasetEnvelope:
  distilled_dataset_id: dataset://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  source_commitments:
    - hash
  policy_bound_data_view_refs:
    - view://...
  transformation_receipt_refs:
    - receipt://...
  distillation_methods:
    - teacher_distillation
    - verifier_filtering
    - rubric_judgment
    - tool_trace_extraction
    - counterexample_generation
    - failure_regression
    - schema_canonicalization
  teacher_refs:
    - worker://...
  verifier_refs:
    - worker://...
  output_artifact_refs:
    - artifact://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  evaluation_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  receipt_root: hash
  status: draft | active | deprecated | revoked
```

## EvaluationDatasetEnvelope

```yaml
EvaluationDatasetEnvelope:
  evaluation_dataset_id: dataset://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  ontology_refs:
    - ontology://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  dataset_type: golden | holdout | adversarial | regression | benchmark | synthetic | distilled
  rubric_ref: rubric://...
  benchmark_profile_ref: optional
  source_commitment: hash
  privacy_policy_ref: optional
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  artifact_refs:
    - artifact://...
  receipt_root: hash
  status: draft | active | deprecated | revoked
```

## LearningEvidenceEligibilityEnvelope

Learning evidence eligibility is the local governance, admission, consent,
rights, and privacy classification record for reusing evidence to improve a
model, worker, pursuit method, workflow, policy, evaluator, agenda, memory, or
other governed component. It is where sensitive traces, Findings, connector
outputs, enterprise documents, feedback, receipts, or artifacts are explicitly
admitted or excluded before they cross from operational evidence into a
learning or improvement loop.

This is not a wallet.network object by default. Hypervisor, Foundry, Data /
Knowledge, Ontology, domain apps, or org governance surfaces may propose the
eligibility decision; Agentgres records the admitted decision and receipts;
wallet.network supplies authority refs only when the decision requires
delegated machine power such as decryption, connector access, model-provider
keys, GPU spend, provider-trust acceptance, publication, export, or
cross-domain reuse.

```yaml
LearningEvidenceEligibilityEnvelope:
  schema_version: ioi.learning-evidence-eligibility.v1
  eligibility_id: eligibility://...
  eligibility_profile: general_learning | training_compatibility
  governance_owner_ref: org://... | project://... | system://... | agentgres://domain/... | foundry_job://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  subject_refs:
    - artifact://... | receipt://... | dataset://... | view://... |
      connector://... | finding://... | outcome-delta://... |
      work-result://... | attempt://... | trace://... | memory://...
  requester_ref:
    wallet://... | org://... | system://... | foundry_job://... | goal://... |
    improvement-campaign://...
  intended_use:
    conductor_training | worker_training | eval_generation |
    dataset_distillation | benchmark | simulation | analytics_only |
    pursuit_method_improvement | workflow_or_policy_improvement |
    evaluator_improvement | improvement_agenda_revision |
    memory_or_context_improvement | package_or_tool_improvement
  learning_use_posture:
    operational_only | evaluation_only | synthetic_only | redacted_opt_in |
    full_private_opt_in | org_policy
  applicable_evaluation_epoch_refs:
    - evaluation-epoch://...
  allowed_improvement_target_refs: []
  owner_and_tenant_scope_refs: []
  contamination_posture:
    clean | evaluation_aware | exposed | quarantined | unknown
  policy_bound_data_view_refs:
    - view://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  local_policy_refs:
    - policy://...
  consent_refs:
    - grant://... | policy://... | authority://...
  wallet_authority_refs:
    - grant://... | lease://... | authority://...
  authority_requirement_kinds:
    - decryption | connector_access | model_provider_key | gpu_spend |
      provider_trust | sealed_evaluation_access | learning_egress |
      publication | export | cross_domain_reuse | none
  declassification_refs:
    - receipt://... | policy://...
  learning_egress_receipt_refs:
    - receipt://...
  provider_trust_posture:
    no_provider_plaintext | redacted_api | provider_trust_accepted |
    private_compute_required | blocked
  retention_policy_ref: policy://...
  derivative_policy_ref: policy://...
  lineage_root: hash
  exclusion_reason:
    optional operational_only_default | never_train_default |
    sealed_evaluation_material | revoked | expired | regulated_block |
    connector_scope_denied | no_provider_trust | data_subject_request |
    missing_policy_bound_view | incident_hold
  receipt_root: hash
  admitted_by_ref: optional agentgres://operation/... | policy://...
  status: proposed | eligible | excluded | revoked | expired | superseded
```

Live sealed holdout cases, labels, evaluator internals, and protected outputs
are ineligible learning evidence for the campaign they judge and for dependent
claims until their rotation/declassification policy explicitly releases them.
Recording an access receipt does not declassify its protected payload.

### TrainingEvidenceEligibilityEnvelope compatibility

`TrainingEvidenceEligibilityEnvelope` is the model/worker-training compatibility
profile of this same object, not a second eligibility decision. A compatibility
adapter accepts that envelope label and the legacy wire key
`training_evidence_eligibility_refs` only when `intended_use` is one of the
training, dataset, evaluation, or benchmark uses above; it normalizes them to
the same `eligibility_id` and emits `LearningEvidenceEligibilityEnvelope` with
`eligibility_profile: training_compatibility` and
`learning_evidence_eligibility_refs`.
The legacy `training_data_posture` field maps to `learning_use_posture`, with
`never_train` mapping to `operational_only`; conflicting old and new values fail
admission.
Training pipelines may still declare a separate `training_data_posture`; that
run configuration cannot widen the canonical learning-evidence decision.

## InstitutionalIntelligenceExportBundleEnvelope

The institutional-intelligence export bundle is a governed portability
manifest over rights-eligible state and artifacts. It records inclusions,
omissions, lineage, destination, residual obligations, and authority; it is not
a raw Agentgres dump, legal title certificate, or promise that every
provider-specific capability can move.

```yaml
InstitutionalIntelligenceExportBundleEnvelope:
  export_bundle_id: institutional-intelligence-export://...
  owner_scope_ref: user://... | org://... | project://... | system://...
  requested_by_ref: user://... | wallet://... | org://... | system://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  export_policy_ref: policy://...
  authority_refs:
    - grant://... | authority://... | policy://...
  recipient_ref: user://... | org://... | system://... | provider://... | endpoint://...
  destination_custody_posture_ref: policy://... | custody_proof://...
  included_manifest:
    ontology_and_object_model_refs: []
    data_recipe_mapping_and_view_refs: []
    wiki_memory_and_context_refs: []
    evaluation_rubric_canary_and_dataset_refs: []
    worker_workflow_skill_tool_and_package_refs: []
    adapter_checkpoint_weight_and_model_refs: []
    route_verifier_governance_and_retention_policy_refs: []
    lineage_receipt_and_state_root_refs: []
  excluded_entries:
    - subject_ref: artifact://... | dataset://... | memory://... | model://... | worker://...
      reason:
        missing_right | source_restricted | provider_restricted |
        privacy_block | retention_or_hold | revoked | incompatible |
        provider_native_unavailable | policy_defined
  payload_manifest_ref: artifact://... | cid://...
  payload_commitment: hash
  encryption_policy_ref: policy://...
  integrity_and_signature_refs:
    - receipt://... | evidence://... | artifact://...
  lineage_root: hash
  receipt_root: hash
  model_independence_report_ref: benchmark://... | gate://... | artifact://... | null
  retention_policy_ref: policy://...
  revocation_and_residual_obligation_ref: policy://... | artifact://...
  declassification_refs:
    - receipt://... | policy://...
  export_receipt_ref: receipt://... | null
  status:
    proposed | denied | assembling | ready | exported | partially_exported |
    expired | revoked
```

Export does not sever inherited restrictions. The receiver gets only the rights
and material that the bundle and its source claims admit. Revocation after an
irreversible export records future-use restrictions and residual exposure; it
must not rewrite history or claim remote deletion without evidence.
