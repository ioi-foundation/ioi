# Memory, Context-Mutation, and Promotion Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of the Agent Wiki, portable agent memory, context mutations, promotion decisions, and capability regression records.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial (the portable memory vault serialization and memory-mutation path exist in the daemon; promotion-decision and capability-regression object planes remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/portable-memory-vault.md`](../../components/daemon-runtime/portable-memory-vault.md);
this module does not restate them.

## AgentWikiEnvelope

Agent Wiki is the user-facing and agent-facing semantic memory surface for
preferences, procedures, doctrine, route notes, failure lessons, source-backed
claims, and project knowledge. It is backed by the `ioi-memory` context plane
for product memory and retrieval. It is not itself Agentgres canonical truth.

Agent Wiki and `ioi-memory` form the portable agent-memory substrate. Harnesses
may keep local caches, summaries, embeddings, hidden scratchpads, or run-native
"brain" files, but those are adapters over admitted memory. They are not the
durable owner of user, org, project, worker, or managed-instance knowledge.

Agentgres admits authoritative wiki changes through operations such as
`ContextMutationEnvelope`, stores provenance and policy refs, and serves
rebuildable projections over accepted wiki state.

```yaml
AgentWikiEnvelope:
  wiki_id: wiki://...
  owner_ref: wallet://... | org://... | project://... | worker://...
  agentgres_domain_ref: agentgres://domain/...
  memory_plane_ref: memory://... | optional
  memory_profile_ref: memory_profile://... | optional
  scope: user | org | project | worker | service | domain
  visibility: private | shared | org | public
  policy_ref: policy://...
  default_retention_policy_ref: policy://...
  encryption_policy_ref: policy://... | optional
  restore_authority_ref: authority://... | policy://... | optional
  page_index_ref: projection://... | optional
  retrieval_projection_refs:
    - memory_projection://...
  latest_context_mutation_ref: context-mutation://... | optional
  archive_ref: memory_archive://... | cid://... | artifact://... | optional
  status: active | archived | restoring | deprecated
```

## Portable Agent Memory

Portable agent memory is user-, org-, project-, worker-, service-, or
domain-bound context that can survive harness swaps, model-route swaps,
runtime migration, node failure, payment lapse, or managed-instance restore when
policy allows. It is the durable layer beneath agent "personality," preferences,
procedures, route notes, game lessons, project conventions, tool affordances,
and failure memory.

The package declares what memory it can use. The instance owns the concrete
memory. Harnesses receive policy-filtered projections.

```text
WorkerPackage declares MemoryProfile compatibility
  -> install / managed instance binds an owner-scoped AgentWiki
  -> runs propose ContextMutationEnvelope changes
  -> Agentgres admits accepted memory refs and receipts
  -> storage backend holds encrypted payload/archive bytes
  -> authority provider releases restore/decryption when required
  -> harness/model receives a MemoryProjection, not raw private memory by default
```

The anti-pattern this prevents is:

```text
selected harness writes the agent's durable brain by itself
```

The correct shape is:

```text
adapter- and HarnessInvocation-local memory is cache;
Agent Wiki / ioi-memory is durable knowledge;
Agentgres admits memory truth;
encrypted archives preserve restorable bytes;
authority providers gate restore, export, decryption, and revocation
```

```yaml
MemoryProfileEnvelope:
  memory_profile_id: memory_profile://...
  owner_scope:
    user | org | project | worker | managed_instance | service | domain
  package_ref: optional package://...
  managed_instance_ref: optional agent://...
  allowed_memory_kinds:
    - preference
    - fact
    - procedure
    - doctrine
    - route
    - tool_affordance
    - failure
    - eval
    - game_lesson
    - project_convention
    - connector_observation
  portability:
    any_compatible_harness | package_family_only |
    instance_private | no_portability
  persistence:
    ephemeral | session | grace_archive | zero_to_idle | persistent | exportable
  default_retention_policy_ref: policy://...
  archive_policy_ref: policy://...
  projection_policy_ref: policy://...
  redaction_policy_ref: policy://...
  training_use_policy_ref: optional policy://...
  restore_authority_requirement:
    local_policy | authority_step_up | wallet_step_up | org_quorum |
    admin_policy | unavailable
  delete_or_forget_policy_ref: policy://...
  status:
    draft | active | suspended | archived | revoked

MemoryArchiveEnvelope:
  memory_archive_id: memory_archive://...
  wiki_ref: wiki://...
  memory_profile_ref: memory_profile://...
  managed_instance_ref: optional agent://...
  archive_payload_ref: cid://... | artifact://... | encrypted_ref
  payload_hash: hash
  encryption_policy_ref: policy://...
  retention_policy_ref: policy://...
  restore_policy_ref: policy://...
  authority_refs:
    - authority://... | grant://... | lease://...
  created_from_state_root_ref: state_root://...
  receipt_refs:
    - receipt://...
  status:
    retained | restoring | restored | expired | deleted | revoked

MemoryProjectionEnvelope:
  projection_id: memory_projection://...
  wiki_ref: wiki://...
  memory_profile_ref: memory_profile://...
  target_ref:
    harness-profile://... | agent-harness-adapter://... |
    model_route://... | worker://... | service://... |
    surface://... | agent://...
  projection_kind:
    prompt_context | retrieval_index | skill_bundle | route_notes |
    policy_filtered_summary | tool_affordance_map | eval_memory
  allowed_memory_kinds:
    - preference | fact | procedure | doctrine | route |
      tool_affordance | failure | eval | game_lesson |
      project_convention | connector_observation
  redaction_policy_ref: policy://...
  privacy_posture_ref: policy://...
  freshness:
    realtime | run_start_snapshot | scheduled_refresh | manual_refresh
  source_context_mutation_refs:
    - context-mutation://...
  receipt_ref: receipt://...
  status:
    active | stale | revoked | superseded
```

## ContextMutationEnvelope

```yaml
ContextMutationEnvelope:
  mutation_id: context-mutation://...
  wiki_ref: wiki://... | optional
  institutional_learning_boundary_profile_ref: learning-boundary://... | optional
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  worker_id: worker://...
  package_ref: optional package://...
  managed_instance_ref: optional agent://...
  memory_profile_ref: optional memory_profile://...
  project_ref: agentgres://project/... | optional
  mutation_type:
    fact | preference | doctrine | route | procedure | eval | failure |
    tool_affordance | game_lesson | project_convention | connector_observation
  operation: add | supersede | contradict | deprecate | activate | archive | forget
  scope: user | org | project | worker | service | domain | optional
  visibility: private | shared | org | public | optional
  validity_window: optional
  retention_policy_ref: optional policy://...
  projection_policy_ref: optional policy://...
  claim_ref: artifact://... | hash://... | optional
  prior_claim_refs: []
  evidence_refs: []
  source_authority: user | worker | verifier | benchmark | service_delivery | admin
  policy_hash: hash
  receipt_ref: receipt://...
```

## PromotionDecisionEnvelope

Foundry promotion bundles freeze the evidence package that Governance may use
for rollout, rollback, recall, or placement decisions. A bundle is not itself
deployment permission.

```yaml
FoundryPromotionBundleEnvelope:
  promotion_bundle_id: promotion_bundle://...
  foundry_job_ref: foundry_job://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  derivative_policy_ref: policy://...
  impact_graph_ref: agentgres://projection/... | null
  candidate_ref: model://... | worker://... | model_route://... | conductor://... | package://...
  parent_artifact_ref: optional artifact://... | model://... | worker://...
  dataset_digest_refs:
    - dataset://... | hash
  teacher_session_refs:
    - teacher_session://...
  verifier_version_refs:
    - worker://... | model://... | gate://...
  scorecard_ref: gate://... | artifact://...
  gating_threshold_ref: policy://...
  authority_or_signoff_refs:
    - grant://... | policy://... | receipt://...
  monitoring_policy_ref: policy://...
  deployment_tier: local | shadow | canary | production | marketplace
  rollback_target_ref: artifact://... | model://... | worker://... | package://...
  receipt_root: hash
  status:
    draft | frozen | proposed | approved | rejected | rolled_back | recalled
```

```yaml
PromotionDecisionEnvelope:
  promotion_id: promotion://...
  cycle_id: post-training-cycle://...
  candidate_ref: cid://... | artifact://...
  baseline_version: worker://...@semver
  candidate_version: worker://...@semver-candidate
  eval_profile_ref: benchmark://...
  baseline_score_commitment: hash
  candidate_score_commitment: hash
  regression_receipt_refs: []
  decision: promoted | rejected | rolled_back
  reason_ref: artifact://... | hash://...
  rollback_ref: optional
  receipt_ref: receipt://...
```

## CapabilityRegressionRecordEnvelope

```yaml
CapabilityRegressionRecordEnvelope:
  regression_id: regression://...
  capability_ref:
    worker://... | model_route://... | goal-run-profile://.../revision/... |
    workflow-template://.../revision/... | harness-profile://.../revision/... |
    skill://.../revision/... | tool://... | mcp://... | automation://... |
    service://... | package://... | policy://... | artifact://... | domain_app://...
  capability_kind:
    worker | model_route | goal_run_profile | workflow_template |
    harness_profile | agent_harness | skill_manifest | runtime_tool_contract |
    evaluator | policy | tool | mcp_server | connector | automation | service |
    environment_image | package | domain_app | fleet_policy
  baseline_version_ref: optional
  candidate_or_active_version_ref: string
  improvement_campaign_ref: improvement-campaign://... | null
  evaluation_epoch_ref: evaluation-epoch://... | null
  upgrade_proposal_ref: proposal://... | null
  detected_in:
    phase: offline_eval | shadow | canary | rollout | production | recall_review
    run_refs: []
    release_target_refs: []
  regression_class:
    quality | safety | privacy | cost | latency | authority | reliability |
    policy | security | compliance | maintainability | complexity |
    steerability | product_compatibility | monitorability |
    workgraph_integrity | irreversible_effect | marketplace_reputation
  severity: info | warning | blocking | critical
  evidence_refs:
    - receipt://... | artifact://... | gate://... | benchmark://...
  scorecard_refs: []
  maintainability_complexity_and_compatibility_refs: []
  monitorability_trace_quality_and_debuggability_refs: []
  aggregate_workgraph_effect_refs: []
  effect_recovery_posture:
    reversible_state_rollback_refs: []
    containment_refs: []
    compensation_refs: []
    reconciliation_refs: []
    irreversible_effect_refs: []
    residual_unrecoverable_effect_refs: []
  affected_scope_refs: []
  recommended_action:
    reject | hold | shadow_more | pause | rollback | recall | constrain |
    patch_and_retry | require_human_review
  adjudication_ref: receipt://... | optional
  learning_evidence_eligibility_ref: eligibility://... | optional
  future_eval_candidate_refs: []
  status:
    detected | adjudicating | blocked | rejected | shadowing | paused |
    rolled_back | recalled | constrained | converted_to_eval | closed
```

A regression record is evidence and lifecycle posture, not learning consent. It
may become a future holdout, eval case, or Foundry job only after the owning
governance surface records `LearningEvidenceEligibility`; the
training-compatibility profile never creates a parallel decision.
