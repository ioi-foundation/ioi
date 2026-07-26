# Event, Receipt, Artifact, and Delivery Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of runtime events, receipt envelopes, artifact envelopes, and delivery envelopes.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (`ReceiptEnvelope` v1, `ReceiptCheckpoint` v1, and `ReceiptProofBundle` v1 have registered schemas, invariants, adversarial fixtures, and generated projections; production receipt-proof cryptographic verifiers/CLIs, daemon/Agentgres checkpoint emission, network key discovery, and public transparency remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md);
this module does not restate them.

## RuntimeEventEnvelope

```yaml
RuntimeEventEnvelope:
  event_id: event://...
  parent_event_id: event://... | null
  run_id: run://...
  task_id: task://...
  turn_id: optional
  kind: session.started | model.requested | model.completed | tool.proposed | policy.decided | approval.requested | tool.started | tool.completed | artifact.created | ontology.bound | data_recipe.run_started | data_recipe.run_completed | transformation.receipt_emitted | distilled_dataset.bound | evaluation_dataset.bound | ontology_projection.updated | environment.failure_detected | environment.recovery_planned | environment.recovery_started | environment.recovery_completed | environment.recovery_failed | workrun.recovery_reconciled | resource.allocation_requested | resource.allocation_decided | resource.budget_warning | resource.budget_exhausted | resource.preemption_decided | resource.degradation_applied | scheduler.catchup_planned | scheduler.catchup_executed | assurance.policy_pack.applied | assurance.policy_pack.blocked | assurance.audit_export.requested | assurance.audit_export.generated | assurance.audit_export.delivered | assurance.audit_export.revoked | collaboration.context_created | collaboration.party_joined | collaboration.party_removed | collaboration.view_granted | collaboration.view_revoked | collaboration.proof_bundle_generated | orchestration.decision_recorded | training.foundry_spec_admitted | training.dataset_snapshot_materialized | training.run_plan_admitted | training.evidence_eligibility_recorded | training.dataset_factory_started | training.dataset_factory_completed | training.batch_planned | training.generation_batch_archived | training.teacher_session_started | training.teacher_session_completed | training.candidate_data_quarantined | training.on_policy_correction_recorded | training.quality_gates_reported | training.cost_ledger_updated | training.pipeline_started | training.pipeline_stage_advanced | training.pipeline_suspended | training.pipeline_resumed | training.pipeline_completed | training.pipeline_failed | training.trial_started | training.trial_pruned | training.trial_completed | training.checkpoint_created | training.experiment_trial_started | training.experiment_trial_completed | training.experiment_trial_accepted | training.experiment_trial_rejected | training.artifact_conversion_started | training.artifact_conversion_validated | training.model_artifact_frozen | training.package_artifact_validated | training.model_registered | training.registry_version_created | training.route_binding_proposed | training.route_binding_activated | training.promotion_bundle_frozen | training.conductor_advisor_candidate_created | training.conductor_advisor_shadow_started | training.conductor_advisor_promoted | capability.regression_detected | capability.regression_adjudicated | authority_client.* | mcp_gateway.* | revocation.* | embodied.* | sim_to_real.* | assurance.* | capability.* | job.* | receipt.emitted | run.completed | run.failed
  timestamp: timestamp
  actor_id: system://... | participant-lease://... | agent://... | worker://... | service://... | runtime://... | wallet://...
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  redaction_status: full | redacted | hash_only
  payload: object
  receipt_ref: optional
  cursor: integer
  terminal: boolean
```

The `kind` line above is a compatibility sample, not the exhaustive event
registry. `outcome_room.*` covers room lifecycle, participant, frontier,
claim, resource, attempt, finding, verifier-challenge, re-verification,
OutcomeDelta, and course-correction events. The exhaustive names and receipt
bindings are owned by
[`events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md).

## ReceiptEnvelope

The canonical v1 JSON wire shape, boundary-fact invariant, and golden fixtures
are registered by
[`architecture-contract-registry.v1.json`](../../_meta/schemas/architecture-contract-registry.v1.json).
That machine form owns field presence and ref validation for v1; this section
and the receipt registry retain semantic and profile ownership. The encoding
profile remains deliberately null and the optional signature remains opaque in
this pilot; portable signing is a separate successor contract, not an implied
property of v1.

```yaml
ReceiptEnvelope:
  receipt_id: receipt://...
  receipt_type: registered receipt type
  receipt_profile_ref: schema://...
  attested_boundary_fact_refs: []
  claim_scope_ref: schema://... | policy://... | null
  run_id: run://... | null
  task_id: task://... | null
  actor_id: ProtocolPrincipalRef | runtime://...
  input_hash: optional
  output_hash: optional
  policy_hash: optional
  authority_grant_id: grant://... | null
  primitive_capabilities: []
  authority_scopes: []
  artifact_refs: []
  evidence_bundle_refs: []
  verification_ref: verifier_path://... | null
  acceptance_ref: acceptance://... | null
  adjudication_ref: decision://... | dispute://... | null
  settlement_ref: settlement://... | null
  timestamp: timestamp
  signature: optional
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

The exhaustive `receipt_type` registry and cross-component field-level schemas
live in the events/receipts owner. This file owns only the portable base
envelope shared by every registered profile. A receipt proves only
its declared bound facts;
the evidence, verification, acceptance, adjudication, and settlement refs above
must not be inferred merely because a receipt exists.

For the registered target portable proof profile,
`ioi.receipt-envelope-jcs-sha256.v1` means SHA-256 over the RFC 8785 JCS bytes
of the exact closed v1
`ReceiptEnvelope`. Every present v1 field—including its legacy opaque
`signature`, when present—is inside that hash. The hash is then bound into a
domain-separated, indexed accumulator leaf. The signed checkpoint, inclusion
witness, consistency witness, and export-manifest rules are owned by
[`events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md#receipt-checkpoints-and-offline-proofs).

## ArtifactEnvelope

```yaml
ArtifactEnvelope:
  artifact_id: artifact://...
  cid: bafy...
  sha256: hash
  lineage_commitment: hash
  size_bytes: integer
  media_type: string
  artifact_role:
    immutable_source_snapshot | derived_export | evidence | deliverable |
    runtime_intermediate | package_payload | other
  source_lineage:
    editable_domain_object_ref:
      agentgres://object/... | project://... | ontology://... | workflow://... |
      goal://... | system://... | null
    editable_domain_object_revision_ref:
      agentgres://state-root/... | commitment://... | artifact://... | null
    source_snapshot_artifact_ref: artifact://... | null
    parent_artifact_refs: []
    derivation_kind:
      none | deterministic_export | receipted_transformation |
      compilation | rendering | conversion | aggregation | other
    derivation_run_ref: run://... | transform://... | conversion://... | null
    derivation_contract_ref: tool://... | workflow-template://.../revision/... | schema://... | null
    derivation_receipt_ref: receipt://... | null
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  encryption:
    mode: none | envelope | threshold | tee_sealed
    key_ref: optional
  provenance:
    run_id: optional
    worker_id: optional
    operation_id: optional
    receipt_id: optional
    ontology_ref: optional
    data_recipe_revision_ref: data-recipe://.../revision/... | null
    data_recipe_content_hash: hash | null
    transformation_run_id: optional
  access_policy_ref: optional
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://... | null
  impact_graph_ref: agentgres://projection/... | null
```

Editable canvas, document, design, ontology, source-tree, campaign, and other
domain state remains owned by its domain object. `ArtifactEnvelope` captures an
immutable snapshot or materialization of that state. A `derived_export` must
name the exact `source_snapshot_artifact_ref` and the tool, workflow revision,
or transformation contract plus its run and receipt; it may never point only
at a mutable editor object. Exporting therefore uses deterministic or
receipted tool/workflow machinery and explicit source -> snapshot -> derived
lineage. It does not create an `ExportHarness` or transfer artifact ownership
to a HarnessProfile.

`lineage_commitment` binds the payload `sha256`, `artifact_role`, and complete
`source_lineage` object so metadata cannot be rewritten while retaining the
same artifact commitment. For `immutable_source_snapshot`, the editable object
and exact editable revision are required, `source_snapshot_artifact_ref` is
null, and `derivation_kind` is `none`. For `derived_export`, the source snapshot
ref, derivation contract, run, and receipt are all required; the source ref must
resolve to an `immutable_source_snapshot`. The derivation receipt must bind the
output payload hash, output lineage commitment, source-snapshot ref and payload
hash, derivation contract, and derivation run. Any missing or inconsistent
conditional field fails admission.

## DeliveryEnvelope

```yaml
DeliveryEnvelope:
  delivery_id: delivery://...
  service_order_id: order://... | null
  buyer_domain_ref: optional system://... | domain://... | wallet://...
  provider_domain_ref: optional system://... | domain://... | service://...
  worker_invocation_id: invocation://... | null
  run_id: run://...
  delivery_update_refs: []
  output_artifacts: []
  evidence_bundle: []
  local_receipt_root: optional_hash
  remote_receipt_root: optional_hash
  dispute_refs: []
  settlement_intent_refs: []
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
  quality_summary: object
  policy_summary: object
  delivery_status: draft | partial | submitted | cancelled
  acceptance_status: pending | accepted | accepted_partial | rejected | revision_requested
  adjudication_status: none | disputed | adjudicating | resolved
  settlement_status: not_requested | intent_created | pending | settled | paid | refunded | slashed | failed
  acceptance_deadline: optional
```
