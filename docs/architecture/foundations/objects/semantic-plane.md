# Ontology, Data-Recipe, and Ontology-Kit Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of domain ontologies, ontology assertions, ontology mappings, ontology action contracts, canonical object models, data recipes, connector mappings, ontology projections, ontology-to-worker plans, ontology development kit manifests, and ontology surface descriptors.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: planned (optional federated ontology and semantic-action families are not started)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../domain-ontologies-and-data-recipes.md`](../domain-ontologies-and-data-recipes.md);
this module does not restate them.

## DomainOntologyEnvelope

The ontology object family uses one wire/storage base with explicit profiles;
the first-class semantic names are not parallel schemas:

| Semantic object | Canonical envelope profile |
| --- | --- |
| `DomainOntology` | Aggregate lineage addressed by `ontology_family_ref`. |
| `OntologyVersion` | `DomainOntologyEnvelope` with `ontology_record_profile: ontology_version`; every version is immutable after admission. |
| `OntologyOverlay` | `DomainOntologyEnvelope` with `ontology_record_profile: ontology_overlay` and explicit base-version refs. |
| `ProvenanceAssertion` | `OntologyAssertionEnvelope` with `assertion_profile: provenance_assertion`. |
| `OntologyCrosswalk` | `OntologyMappingEnvelope` with `mapping_record_profile: ontology_crosswalk`. |
| `SemanticMappingDecision` | `OntologyMappingEnvelope` with `mapping_record_profile: semantic_mapping_decision`, an applied crosswalk/adapter target, and a decision receipt. |

Agentgres registers the semantic object/profile names while persisting the
corresponding base envelope. Implementations must not create separate,
incompatible `OntologyVersion`, `OntologyOverlay`, `OntologyCrosswalk`,
`SemanticMappingDecision`, or `ProvenanceAssertion` schemas.

```yaml
DomainOntologyEnvelope:
  ontology_id: ontology://...
  ontology_family_ref: ontology://...
  ontology_record_profile: ontology_version | ontology_overlay
  namespace: uri_or_domain_scoped_name
  name: string
  admission_domain_ref: agentgres://domain/... | domain://...
  version: semver_or_hash
  predecessor_version_ref: ontology://... | null
  base_ontology_version_refs:
    - ontology://...
  governing_scope_ref: system://... | domain://... | org://... | project://... | service://...
  extension_and_overlay_refs:
    - ontology://... | policy://...
  compatibility_profile_ref: compatibility://... | null
  deprecation_policy_ref: policy://... | null
  entity_types: []
  relationship_types: []
  event_types: []
  action_types: []
  state_machines: []
  invariant_refs: []
  owner_id: system://... | wallet://... | org://... | service://...
  policy_hash: hash
  status: draft | active | deprecated | revoked
```

No Domain Ontology is presumed globally canonical. A domain may make one
version locally canonical while other domains retain independent definitions,
extensions, overlays, and policy-bound views. Cross-domain work must negotiate
versioned profiles and explicit mappings rather than silently flattening them
into one enterprise or network graph.

## OntologyAssertionEnvelope

Operational truth and semantic belief are distinct. Agentgres may canonically
record that a domain admitted an assertion or decision; that admission does not
make the proposition universally true. Ontology-bound properties and
relationships therefore carry time, source, uncertainty, evidence,
applicability, supersession, and dispute state.

```yaml
OntologyAssertionEnvelope:
  assertion_id: ontology-assertion://...
  assertion_profile: provenance_assertion
  ontology_ref: ontology://...
  fact_class_ref: ontology://...#fact-class | null
  subject_ref: object://... | ontology-assertion://...
  predicate_ref: ontology://...#property_or_relationship
  object_or_value_ref: object://... | scalar | artifact://...
  valid_time: interval | null
  transaction_time: timestamp
  source_and_observation_context_refs:
    - source://... | observation://... | attempt://... | system://... | domain://...
  confidence_or_uncertainty: number | null
  supporting_evidence_refs:
    - evidence://... | receipt://... | artifact://...
  contradicting_assertion_refs:
    - ontology-assertion://... | finding://...
  oracle_evidence_profile_ref: oracle-evidence-profile://... | null
  oracle_evidence_admission_receipt_ref: receipt://... | null
  ontology_assertion_admission_receipt_ref: receipt://... | null
  applicability_scope_ref: policy://... | system://... | domain://... | null
  permitted_consequence_scope_refs:
    - policy://...
  causal_or_counterfactual_context_ref: artifact://... | finding://... | null
  supersedes_ref: ontology-assertion://... | null
  dispute_ref: dispute://... | null
  status:
    proposed | evidence_pending | held_unknown | admitted | contradicted |
    superseded | disputed | rejected
```

`oracle_evidence_admission_receipt_ref` identifies the evaluator's qualified
determination under the selected oracle/evidence profile.
`ontology_assertion_admission_receipt_ref` identifies the separate
`OntologyAssertionAdmissionReceipt` through which Agentgres/the domain admits
the assertion as operational truth. When an oracle/evidence profile governs an
assertion, `status: admitted` requires both receipts. Both bind the same
assertion commitment, fact class, profile revision, applicability scope, and
permitted consequence-scope set; the selected scopes must be permitted by the
active profile. Neither receipt can be substituted for the other.

## OntologyMappingEnvelope

```yaml
OntologyMappingEnvelope:
  ontology_mapping_id: ontology-mapping://...
  mapping_record_profile: ontology_crosswalk | semantic_mapping_decision
  source_ontology_ref: ontology://...
  target_ontology_ref: ontology://...
  source_and_target_version_refs:
    - ontology://...
  mapping_profile_ref: artifact://... | mapping://...
  applied_crosswalk_ref: ontology-mapping://... | null
  application_target_refs:
    - packet://... | handoff://... | object://... | query://... |
      ontology-action://... | artifact://...
  mapped_object_relationship_event_and_action_refs:
    - object-model://... | ontology-action://... | schema://...
  compatibility_result:
    exact | compatible | lossy | requires_adapter | incompatible
  policy_bound_view_refs:
    - view://... | restricted_view://...
  validation_and_challenge_refs:
    - test://... | verifier-challenge://... | evidence://...
  decided_by_ref: system://... | worker://... | org://... | domain://... | policy://... | null
  decision_timestamp: timestamp | null
  mapping_decision_receipt_ref: receipt://... | null
  deprecation_and_migration_policy_ref: policy://... | null
  status: proposed | validated | active | challenged | deprecated | revoked
```

## OntologyActionContractEnvelope

An ontology action becomes executable only through a contract that binds
semantic meaning to capability, runtime, authority, effects, compensation,
evidence, and verification. An action name or connector method alone is not an
execution contract.

```yaml
OntologyActionContractEnvelope:
  ontology_action_id: ontology-action://...
  ontology_ref: ontology://...
  action_type_ref: ontology://...#action
  target_object_model_refs:
    - object-model://...
  typed_input_schema_ref: schema://... | artifact://...
  typed_output_schema_ref: schema://... | artifact://...
  precondition_refs:
    - policy://... | invariant://... | state://...
  postcondition_and_invariant_refs:
    - policy://... | invariant://... | state://...
  expected_state_transition_ref: transition://... | state-delta://...
  capability_runtime_tool_and_automation_refs:
    - prim:... | runtime://... | tool://... | automation://...
  risk_class: read | draft | local_write | write_reversible |
    external_message | commerce | funds | credential_access |
    policy_widening | secret_export | identity_change |
    system_destructive | physical_action
  local_policy_and_authority_scope_refs:
    - policy://... | scope:... | grant://...
  approval_and_revocation_refs:
    - approval-policy://... | revocation://...
  preview_and_dry_run_profile_ref: policy://... | null
  idempotency_and_retry_profile_ref: policy://...
  ambiguous_effect_and_reconciliation_profile_ref: policy://...
  compensation_profile_ref: policy://... | null
  verifier_and_evidence_refs:
    - verifier_path://... | evidence://... | schema://...
  physical_safety_profile_ref: safety://... | null
  status: draft | validating | active | deprecated | revoked
```

## CanonicalObjectModelEnvelope

```yaml
CanonicalObjectModelEnvelope:
  object_model_id: object-model://...
  ontology_ref: ontology://...
  object_type: string
  id_strategy: deterministic | assigned | provider_mapped
  schema_ref: artifact://... | cid://... | inline
  lifecycle_states: []
  constraints:
    - constraint://...
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  authority_scopes_required: []
  projection_hints: []
  status: draft | active | deprecated
```

## DataRecipeEnvelope

```yaml
DataRecipeEnvelope:
  data_recipe_id: data-recipe://...
  revision_ref: data-recipe://.../revision/...
  predecessor_revision_ref: data-recipe://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | domain://... | ioi://publisher/...
  semantic_component_set_snapshot_ref: artifact://...
  semantic_component_set_hash: hash
  ontology_refs:
    - ontology://...
  input_source_types:
    - connector
    - document
    - trace
    - dataset
    - artifact
  connector_mapping_refs:
    - mapping://...
  output_object_model_refs:
    - object-model://...
  output_dataset_contract_refs:
    - schema://... | object-model://...
  transformation_steps:
    - extract
    - redact
    - normalize
    - dedupe
    - validate
    - map
    - link
    - export
  policy_bound_data_view_refs:
    - view://...
  receipt_obligations:
    - data_recipe_run
    - transformation
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | active | deprecated | revoked
```

Each released DataRecipe revision is immutable and content-addressed. It
declares transformations and output contracts but contains no concrete dataset,
distilled output, artifact, authority grant, run, or receipt. Those belong to
`TransformationRunEnvelope` and the resulting dataset/artifact objects.
`semantic_component_set_snapshot_ref` enumerates the exact revision ref and
content hash for every ontology version, ConnectorMapping, object model,
schema/contract, and policy-bound view named by the readable family-ref fields.
`content_hash` commits that snapshot ref and set hash, so a released recipe
cannot silently resolve a newer mapping or semantic head. Registry
lifecycle/status are excluded projections. `recipe://` is a typed legacy
DataRecipe alias only; it never identifies a generic recipe family.

## ConnectorMappingEnvelope

```yaml
ConnectorMappingEnvelope:
  connector_mapping_id: mapping://...
  revision_ref: mapping://.../revision/...
  predecessor_revision_ref: mapping://.../revision/... | null
  content_hash: hash
  semantic_component_set_snapshot_ref: artifact://...
  semantic_component_set_hash: hash
  connector_id: connector://...
  ontology_ref: ontology://...
  source_schema_ref: artifact://... | cid://... | provider_schema
  target_object_model_refs:
    - object-model://...
  field_mappings: []
  action_mappings: []
  authority_scopes_required: []
  redaction_policy_ref: optional
  evidence_required: []
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | active | deprecated | revoked
```

Each ConnectorMapping revision is immutable. Its semantic-component snapshot
commits the exact connector contract/schema, ontology version, target object
models, policy, and evidence-contract revisions/hashes represented by the
readable family refs. `content_hash` commits the snapshot ref and hash;
registry lifecycle/status remain excluded projections. Any field, action,
schema, ontology, object-model, or policy change creates a successor mapping
revision.

## OntologyProjectionEnvelope

```yaml
OntologyProjectionEnvelope:
  ontology_projection_id: projection://...
  agentgres_projection_id: projection://...
  ontology_refs:
    - ontology://...
  object_model_refs:
    - object-model://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  policy_bound_data_view_ref: optional
  freshness_watermark: domain_seq:...
  checkpoint_ref: optional
  status: building | active | stale | rebuilding | deprecated
```

## OntologyToWorkerPlanEnvelope

```yaml
OntologyToWorkerPlanEnvelope:
  plan_id: plan://...
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  workflow_schema_refs: []
  policy_bound_data_view_refs:
    - view://...
  evaluation_dataset_refs:
    - dataset://...
  distilled_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  proposed_worker_manifest_ref: optional
  worker_training_ref: optional
  status: draft | proposed | training | evaluated | bound | rejected
```

## OntologyDevelopmentKitManifestEnvelope

An Ontology Development Kit manifest packages the semantic contracts and builder
expectations needed to generate or validate object-aware surfaces, domain apps,
eval packs, worker packages, and marketplace-ready ontology packs. It is a
builder/conformance object, not semantic truth, runtime truth, permission truth,
or marketplace truth.

```yaml
OntologyDevelopmentKitManifestEnvelope:
  odk_manifest_id: odk://...
  name: string
  version: semver_or_hash
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  connector_mapping_refs:
    - mapping://...
  policy_bound_data_view_refs:
    - view://...
  ontology_projection_refs:
    - projection://...
  surface_descriptor_refs:
    - surface-descriptor://...
  workflow_schema_refs: []
  evaluation_dataset_refs:
    - dataset://...
  benchmark_profile_refs:
    - benchmark://...
  worker_plan_refs:
    - plan://...
  operator_contract_refs:
    - contract://...
  mcp_contract_refs:
    - mcp-profile://...
  conformance_profile_refs:
    - profile://...
  package_refs:
    - artifact://...
  receipt_obligations:
    - validation
    - artifact
    - data_recipe_run
    - transformation
    - evaluation_verdict
  status: draft | active | deprecated | revoked
```

## OntologySurfaceDescriptorEnvelope

An ontology surface descriptor declares how a UI, domain app, operator console,
or generated surface binds to ontology objects, projections, daemon contracts,
policy-bound views, and receipts. It can be authored by humans, generated by the
ODK, or emitted by an application builder, but it remains a descriptor over the
owning domains.

```yaml
OntologySurfaceDescriptorEnvelope:
  surface_descriptor_id: surface-descriptor://...
  surface_ref: surface://...
  display_name: string
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  connector_mapping_refs:
    - mapping://...
  policy_bound_data_view_refs:
    - view://...
  ontology_projection_refs:
    - projection://...
  composition_pattern:
    list_detail | object_view | object_editor | graph |
    wizard | review_inbox | monitoring_console | dashboard |
    data_recipe_builder | connector_mapping_editor | domain_app
  allowed_action_refs:
    - action://...
  daemon_api_refs:
    - api://...
  operator_contract_refs:
    - contract://...
  mcp_contract_refs:
    - mcp-profile://...
  authority_requirement_refs:
    - scope:* | policy://... | grant://...
  receipt_obligations:
    - receipt://...
  conformance_profile_refs:
    - profile://...
  generated_artifact_refs:
    - artifact://...
  status: draft | active | deprecated | revoked
```
