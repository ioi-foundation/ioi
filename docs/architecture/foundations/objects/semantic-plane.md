# Ontology, Data-Recipe, and Ontology-Kit Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of domain ontologies, ontology assertions, ontology mappings, ontology action contracts, canonical object models, data recipes, connector mappings, ontology projections, ontology-to-worker plans, ontology development kit manifests, ontology surface descriptors, domain apps, domain-app runtimes, and domain-app mount receipts.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-08-06.
Doctrine status: canonical
Implementation status: planned (optional federated ontology and semantic-action families are not started); the domain-app family has an implemented daemon ladder ahead of these shapes — see [`canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md)
Last implementation audit: 2026-08-06

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

**Registered contract.** `schema://ioi/foundations/objects/ontology-development-kit-manifest/v1` (`ioi.hypervisor.odk.manifest.v1`, deprecated and read-only) and `.../v2` (`ioi.ontology-development-kit-manifest.v2`) register this envelope. v2 is what the lane authors; v1 is the deprecated shape it minted before, and it diverges from the fields above in three folds it cannot undo by itself: `recipe_refs` for `data_recipe_refs`, one `eval_refs` list for `evaluation_dataset_refs` plus `benchmark_profile_refs`, and one `mcp_operator_contracts` list for `operator_contract_refs` plus `mcp_contract_refs`. v2 carries the members above under these names and commits itself under a registered domain separator. A stored v1 stays readable at its own contract and is never newly authored; converging one is an explicit create naming it in `migrated_from_manifest_ref`, which resolves that predecessor through its owner seam and commits its exact bytes — and the AUTHOR supplies the member split, because a v1 record does not say which member is which and a route that guessed would be inventing provenance. Each legacy member name is a typed refusal naming the successor member or members the author must choose between.

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

## DomainAppEnvelope

A **DomainApp** is a governed application candidate over exactly one
`OntologySurfaceDescriptor` whose `composition_pattern` is `domain_app`. The
descriptor declares what the app binds; the DomainApp declares who owns it, how
far it may be distributed, which authority and receipt obligations it carries,
and what its current runtime posture is.

A DomainApp is deliberately none of the following, and must not be treated as
any of them: it is not a runtime (`DomainAppRuntime` owns mounted/serving
state); it is not a catalog registration (`HypervisorApplicationSurfaceRegistration`
in [`core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md)
owns registration class, route, and placements); it is not an admission
(local Packages admission owns that); and it is not semantic truth (the bound
ontologies and object models are). A DomainApp with no admitted registration is
a candidate, not durable product inventory.

```yaml
DomainAppEnvelope:
  domain_app_id: domain-app://...
  name: string
  description: string
  surface_descriptor_ref: surface-descriptor://...
  odk_manifest_ref: odk://... | null
  owner_ref: org://... | user://... | system://... | project://... | null
  project_ref: project://... | null
  visibility: private | org | marketplace_candidate
  ontology_refs:
    - ontology://...
  canonical_object_model_refs:
    - object-model://...
  data_recipe_refs:
    - data-recipe://.../revision/...
  policy_bound_data_view_refs:
    - view://...
  operator_contract_refs:
    - contract://...
  mcp_contract_refs:
    - mcp-profile://...
  authority_requirement_refs:
    - scope:* | policy://... | grant://...
  receipt_obligations:
    - receipt://...
  generated_artifact_refs:
    - artifact://...
  surface_registration_ref: surface://... | null
  package_release_ref: package://.../release/... | null
  installation_ref: installation://... | null
  system_binding_refs:
    - system-binding://...
  runtime_posture:
    mounted: bool
    serving: bool
    route: string | null
    mount_ref: domain-app-runtime://... | null
  status: draft | admitted | installed | deprecated | revoked
```

`surface_descriptor_ref` is required and must resolve to a descriptor whose
`composition_pattern` is `domain_app`; a DomainApp without a resolving
app-shaped descriptor is a defect, not a draft. When `odk_manifest_ref` is
present it must itself name that descriptor, so packaging provenance cannot
disagree with the app-shape contract.

The `ontology_refs`, `canonical_object_model_refs`, `data_recipe_refs`, and
`policy_bound_data_view_refs` fields are a **derived snapshot** of the bound
descriptor and manifest, not independent authorship. A DomainApp cannot widen
the ontology, object-model, recipe, view, action, or authority set its
descriptor declares. Changing `surface_descriptor_ref` or `odk_manifest_ref`
re-validates the app-shape contract and re-derives the snapshot; it never
merges the old snapshot into the new one.

`surface_registration_ref`, `package_release_ref`, `installation_ref`, and
`system_binding_refs` are the stage bindings of the composable-application
journey owned by
[`domain-ontologies-and-data-recipes.md`](../domain-ontologies-and-data-recipes.md).
`system_binding_refs` must be non-empty before any effectful System launch;
their absence bounds the app to inspect-only use rather than silently
permitting effects.

**Registered contract.** `schema://ioi/foundations/objects/domain-app/v1` (`ioi.hypervisor.domain-app.v1`, deprecated and read-only) and `.../v2` (`ioi.domain-app.v2`). v2 adds four things this envelope implies but a wire contract has to carry: `surface_descriptor_schema_version` and `surface_descriptor_content_hash`, which bind the derived snapshot to the exact descriptor bytes it was projected from; `launch_posture`, which states canon's System-binding bound (`inspect_only` unless `system_binding_refs` is non-empty) as a checkable field rather than a rule a reader has to apply; and `content_hash`, a commitment over the whole record. Its `status` conditionals make each advance carry the stage binding that produced it, and its `runtime_posture` conditionals refuse a live posture that names no runtime.

## DomainAppRuntimeEnvelope

A **DomainAppRuntime** is the durable record of one governed mount of a
DomainApp. Mount is effectful and admission-gated; serving is a sub-step of the
same mount. The runtime — never the DomainApp — owns mounted/serving state, the
governance refs that permitted it, its route, and its receipt chain. The
DomainApp's `runtime_posture` is a backlink projection of the runtime, not a
second source of truth.

```yaml
DomainAppRuntimeEnvelope:
  domain_app_runtime_id: domain-app-runtime://...
  domain_app_ref: domain-app://...
  state: mounted | serving | unmounted | killed
  mounted: bool
  serving: bool
  internal_route_ref: string | null
  external_ingress_ref: ingress://... | null
  approval_request_ref: approval-request://...
  release_control_ref: release-control://...
  authority_refs:
    - grant://... | scope:* | policy://...
  receipt_refs:
    - mount-receipt://...
  rollback_posture:
    unmountable: bool
    note: string
  mounted_at: timestamp
  serve_started_at: timestamp | null
  serve_stopped_at: timestamp | null
  unmounted_at: timestamp | null
  unmount_reason: string | null
  killed_at: timestamp | null
```

At most one runtime per DomainApp may be mounted at a time; a mount attempt
against an already-mounted app refuses rather than creating a second runtime.

A serving runtime re-validates its `approval_request_ref` and
`release_control_ref` **live** at each serve transition. A withdrawn approval or
a closed release control refuses the transition; a mount's earlier permission is
never inherited forward as standing permission to serve.

`internal_route_ref` and `external_ingress_ref` are distinct admissions.
Assigning an internal route is part of the mount's governance; exposing external
ingress is a separate admission that this envelope records but does not grant.

Governance enforcement paths (KillSwitch and equivalent stops) drive the same
state transitions and emit the same receipt family as voluntary ones, so an
enforced stop is auditable in exactly the record a voluntary stop produces,
distinguished only by the receipt's `action` and the terminal `killed` state.

**Registered contract.** `schema://ioi/foundations/objects/domain-app-runtime/v1` (`ioi.hypervisor.domain-app-runtime.v1`, deprecated and read-only) and `.../v2` (`ioi.domain-app-runtime.v2`). v1 carried identity twice, named `rollback_posture` `rollback`, and had NO `external_ingress_ref` at all, so the distinct-admissions rule above had no wire form. v2 adds `owner_ref` and `revision` — the two facts that make the runtime identity a mount receipt binds owner-qualified and revision-exact — and `content_hash`, which is the value the receipt binds so a relying party can check offline that receipt and runtime describe the same state.

## DomainAppMountReceiptEnvelope

Every DomainApp transition across the governed ladder emits a receipt. A mount
receipt attests that a named transition was admitted for a named runtime under a
named approval and release control at a named time. It does not attest that the
app behaves correctly, that its semantic bindings are still valid, that an
external surface exists, or that any domain action ran.

```yaml
DomainAppMountReceiptEnvelope:
  mount_receipt_id: mount-receipt://...
  action:
    domain_app.mount | domain_app.serve_start | domain_app.serve_stop |
    domain_app.unmount | domain_app.kill_stop_serving | domain_app.kill_unmount
  domain_app_ref: domain-app://...
  domain_app_runtime_ref: domain-app-runtime://...
  approval_request_ref: approval-request://...
  release_control_ref: release-control://...
  state_root: hash
  at: timestamp
```

`domain_app_runtime_ref` is required: an app may accumulate several runtimes
over its life, and a receipt that names only the app cannot say which mount it
transitioned. `state_root` commits the transition's admitted facts; it is a
binding commitment over this receipt's own fields, not a proof about app
behavior.

**Registered contract.** `schema://ioi/foundations/objects/domain-app-mount-receipt/v1` (`ioi.hypervisor.domain-app-mount-receipt.v1`, deprecated and read-only) and `.../v2` (`ioi.domain-app-mount-receipt.v2`). v1 had no `domain_app_runtime_ref`, so the requirement above was unmet by every receipt this estate had written, and its `state_root` hashed five values joined with pipes — ambiguous under any component containing a pipe, and silent about the runtime. v2 requires the runtime ref and adds `domain_app_runtime_owner_ref`, `domain_app_runtime_revision`, `domain_app_runtime_content_hash` and `domain_app_admitted_head_before`, and its `state_root` is a canonical-JSON commitment over every field including those four. It also carries canon's four nonclaims as a `does_not_assert` array, so the receipt states its own limits in the bytes a relying party reads.
