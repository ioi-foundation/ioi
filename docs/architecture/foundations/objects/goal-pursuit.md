# Goal-Pursuit Profile, Orchestration, and Budget Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of GoalRun profiles, goal-run activations (the typed crossing that creates or joins goal identity from an existing context), orchestration constraints, orchestration policies, orchestration plans, and network goal budgets.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file; untyped `activation_evidence` payloads as a claimed activation contract.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial (a narrow software GoalRun profile path exists; GoalRunActivation, orchestration plan/policy objects, and NetworkGoalBudget remain planned — the current runtime carries only an untyped `activation_evidence` field where the activation object must land)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../domains/ioi-ai/control-plane.md`](../../domains/ioi-ai/control-plane.md);
this module does not restate them.

## GoalRunProfileEnvelope

`GoalRunProfileEnvelope` is the reusable pursuit specification missing between
product-facing Recipes/Packages and one durable `GoalRun`. It declares how a
class of adaptive goals should converge by composing existing owner-qualified
contracts. It is not a workflow graph, executable, authority holder, campaign
database, evaluator, or live state machine.

Each released revision is immutable and content-addressed. Hypervisor Core and
the daemon admit one selected revision plus run-specific constraints and only
those overrides permitted by its declared schema. The Goal Kernel interprets
that frozen resolution to form and revise `OrchestrationPlan` objects and to
operate the bounded pursue--verify--course-correct loop. Authoritative GoalRun
creation, mutation, and effect admission remain daemon-owned.

```yaml
GoalRunProfileEnvelope:
  schema_version: ioi.goal-run-profile.v1
  goal_run_profile_id: goal-run-profile://...
  revision_ref: goal-run-profile://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: goal-run-profile://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | domain://... | ioi://publisher/...
  display_name: string
  description: string
  applicable_goal_class_refs:
    - schema://... | ontology://... | profile://...
  compatible_domain_object_schema_refs:
    - schema://... | ontology://...
  orchestration_policy_ref: orchestration_policy://...
  constraint_derivation_policy_refs: []
  workflow_template_revision_refs: []
  role_topology_requirement_refs: []
  harness_requirement_refs: []
  pinned_harness_profile_revision_refs: []
  skill_requirement_refs: []
  pinned_skill_manifest_revision_refs: []
  worker_requirement_refs: []
  model_route_requirement_refs: []
  service_requirement_refs: []
  runtime_tool_contract_requirement_refs: []
  primitive_capability_requirements: []
  context_requirement_profile_refs: []
  input_contract_ref: schema://... | policy://...
  output_contract_ref: schema://... | policy://...
  acceptance_contract_refs: []
  verifier_requirement_refs: []
  budget_time_and_resource_ceiling_refs: []
  stop_policy_ref: policy://...
  recovery_policy_ref: policy://...
  escalation_policy_ref: policy://...
  learning_boundary_requirement_ref: policy://... | null
  pinned_learning_boundary_profile_ref: learning-boundary://... | null
  allowed_override_schema_ref: schema://... | null
  compatibility_refs: []
  provenance_refs: []
  evaluation_and_benchmark_refs: []
  promotion_policy_ref: policy://... | null
  revocation_and_recall_policy_ref: policy://... | null
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

Requirement refs allow admission to choose an eligible implementation.
`pinned_*` refs are reserved for reproducibility, certification, compatibility,
or explicit policy; ordinary profiles should not freeze one provider, model,
worker, or harness unnecessarily. The profile references
`OrchestrationPolicy`, constraint-derivation policy, `WorkflowTemplate`, topology,
skills, tools, verifiers, and output contracts without redefining their fields
or taking over their lifecycle.

The resolution receipt commits the exact admission-time dependency closure:
the selected profile revision and content hash, admitted overrides, effective
constraint envelope and hash, orchestration policy, optional workflow revision,
initial topology decision when one exists, skill revisions and active-set
snapshot, resolved tool contracts, learning boundary, all compatibility/policy
decisions, and every still-unresolved late-binding predicate expressly
permitted by the profile. Later worker/model/service/verifier/runtime choices
are not falsely called resolved; their owning plans, invocations, leases, and
receipts freeze them when selected. A top-level profile hash without this
resolved-component commitment is insufficient for replay.

`GoalRunProfilePatch` always proposes a successor revision. It cannot mutate a
released or in-use profile. A product may label a profile or package
composition a **Recipe**, but there is no generic canonical `RecipeEnvelope`.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash. A revoked profile remains replayable by its exact hash even when it is no
longer eligible for new admission.

## GoalRunActivationEnvelope

`GoalRunActivationEnvelope` is the typed crossing that carries work from an
existing context into an admitted GoalRun. It closes the product-boundary hole
this canon had recorded as an open gap: rich handoffs existed **out of** ioi.ai
(`IoiAiGoalChatHandoff`), but no object carried work **into** goal identity
from a Hypervisor Session, WorkRun, work item, room claim, or an ioi.ai draft.
Without it, nothing prevented an implementation from treating a correlation
id, UI link, subscription, MCP call, or facilitator selection as admission.

The rule the object exists to make testable:

> **Correlation is not admission.** A `goal_run_ref` pointer on a Session,
> work item, WorkRun, Mission presentation profile, projection row, or AIIP
> `correlation_ref` — and the `origin_surface` tag on a GoalRun — is
> navigation and provenance only. Goal identity is created or joined only by
> daemon admission of exactly one `GoalRunActivationEnvelope` (or by the
> retained direct creation lane below). Cites INV-16, INV-17, and INV-37 in
> [`../invariants.md`](../invariants.md).

```yaml
GoalRunActivationEnvelope:
  schema_version: ioi.goal-run-activation.v1
  activation_id: goal-run-activation://...
  activation_mode: create | join_existing
  source_context:
    source_kind:
      ioi_goal_draft | hypervisor_session | work_run | work_item |
      outcome_room_claim | automation_workflow_step | gateway_adapter_context
    source_ref:
      intent://... | session://... | work_run://... | run://... |
      work_item://... | work-claim://... | action://goal-run/activate/... |
      adapter://...
    source_owner_ref: org://... | project://... | system://... | user://...
  requested_goal_run_profile_revision_ref: goal-run-profile://.../revision/... | null
  requested_goal_run_profile_content_hash: hash | null
  existing_goal_ref: goal://... | null
  normalized_intent_ref: intent://... | prompt://... | null
  carried_context_refs: []
  requested_constraint_refs: []
  requesting_principal_ref: wallet://... | user://... | agent://... | system://...
  authority_decision_ref: grant://... | approval://...
  review_requirement: none | explicit_user | policy_gate
  review_decision_ref: receipt://... | approval://... | null
  idempotency_key: string
  admission_decision_ref: agentgres://object/... | null
  admitted_goal_ref: goal://... | null
  activation_receipt_ref: receipt://... | null
  refusal_reason_code: string | null
  expires_at: timestamp | null
  status: draft | submitted | admitted | refused | superseded | expired
  non_grants:
    authority_widening: none
    context_declassification: none
    room_membership: none
    budget_creation: none
```

Rules, each testable:

- **Exactly one typed source.** `source_kind` and `source_ref` are required and
  must agree; per-kind ref-scheme constraints are normative. `create` mode
  requires the profile revision ref and content hash together and a null
  `existing_goal_ref`; `join_existing` requires `existing_goal_ref` and null
  profile fields. A join targets a GoalRun whose current lifecycle admits
  joining under its declared policy; joining never rewrites the target's
  admission tuple.
- **The daemon admits; products draft.** ioi.ai facilitation, Goal Space
  surfaces, and Hypervisor clients may draft, render, review, and submit an
  activation. Only daemon admission — under the GoalRun admission contract in
  [`daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md)
  — transitions it to `admitted`, and the admission must resolve the authority
  decision, source-context existence, and profile resolution itself (INV-37);
  a route or product surface cannot satisfy those preconditions by supplying
  the values.
- **Receipt-backed and idempotent.** Admission mints an activation receipt
  binding the exact source context, authority decision, and admitted or joined
  `goal://` identity. Resubmission with the same `idempotency_key` and body
  converges on the same result; a changed body under a reused key is refused.
- **Carried context is candidacy, never authority.** `carried_context_refs`
  become ContextLease candidates under the receiving run's policy. The
  crossing widens nothing: no authority, visibility, custody, retention, or
  budget changes by activation alone (INV-16); carried participant input stays
  tainted until admitted (INV-17).
- **The automation lane keeps its owner.** `HypervisorGoalRunActivationContract`
  in [`core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md)
  remains the AutomationSpec workflow-step declaration and stays owned there;
  its resolution admits through this family as
  `source_kind: automation_workflow_step`. One crossing contract; the step
  binding is not a second admission path.
- **The attach lane graduates through the same crossing.** Work mediated by an
  IOI Authority Gateway adapter enters the work spine as
  `source_kind: gateway_adapter_context` with the adapter context as
  `source_ref`. Attach-lane receipts remain valid evidence linkable through
  `carried_context_refs`; they are never re-minted, and no attach-lane
  approval or grant carries into the admitted run implicitly — the run-on lane
  requests its own scopes (INV-1). The attach-lane doctrine itself is owned by
  [`daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md).
- **The direct lane is retained and narrow.** Creating a stand-alone GoalRun
  directly through the daemon API or the substrate New Goal surface needs no
  activation object — there is no source context to carry. Such a run records
  `origin_surface: api | hypervisor_new_session` and a null activation ref.
  Any creation that claims an originating Session, WorkRun, work item, room
  claim, automation step, or ioi.ai draft must cross this contract; an
  untyped `activation_evidence` payload is not a substitute.

`GoalRunEnvelope` binds the admitted crossing through its
`activation_ref` field (see
[`goal-run-execution.md`](./goal-run-execution.md)). Product-lane doctrine —
what ioi.ai may draft and must never admit — is owned by
[`control-plane.md`](../../domains/ioi-ai/control-plane.md).

## OrchestrationConstraintEnvelope

Captures the constraints that bind an outcome-conductor plan before a model,
harness, worker, or session receives private context or scoped tool access.
This is a plan-selection input, not an authority grant.

```yaml
OrchestrationConstraintEnvelope:
  constraint_id: constraint://...
  goal_ref: goal://... | task://...
  requester_ref: wallet://... | org://... | system://... | agent://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  privacy_posture_ref: policy://... | privacy_posture://... | null
  authority_posture_refs:
    - authority://... | grant://... | policy://...
  provider_trust_posture:
    local_only | redacted_remote | provider_allowed |
    customer_boundary | tee_required | no_provider_trust
  budget_refs:
    - budget://...
  latency_target: interactive | batch | background | deadline_bound
  quality_target_ref: benchmark://... | rubric://... | gate://... | null
  verification_strength:
    none | lightweight | standard | independent | adversarial |
    regulated | physical_safety
  data_use_eligibility_refs:
    - eligibility://... | policy://...
  allowed_route_classes:
    - local_model | provider_api | marketplace_worker | installed_worker |
      managed_agent | deterministic_tool | foundry_job
  disallowed_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - non_opted_in_training_trace
  user_or_org_preference_refs:
    - policy://... | profile://...
  status: draft | active | superseded | revoked
```

## OrchestrationPolicyEnvelope

Versioned policy for choosing among candidate plan shapes. It may use
deterministic rules, benchmark priors, contextual bandit updates, online
quality evidence, user/org preferences, or Foundry-produced conductor advisors.
It does not execute work or grant authority.

```yaml
OrchestrationPolicyEnvelope:
  policy_id: orchestration_policy://...
  owner_ref: org://... | system://... | domain://... | null
  policy_version: semver_or_hash
  applicable_goal_classes:
    - research | code | computer_use | connector_action | operations |
      foundry_build | marketplace_handoff | physical_action | custom
  supported_materializations:
    - single_path
    - verifier_backed_single_path
    - multi_model_answer
    - multi_harness_attempt
    - cross_session_branch_and_merge
    - collaborative_frontier
    - independent_replication
    - dynamic_specialist_mesh
    - open_challenge
    - marketplace_worker_delegation
    - foundry_job
  goal_execution_policy: auto | pinned | compare
  selection_source: user | org_policy | conductor_policy | fallback_policy
  topology_policy:
    fixed | conductor_mutable | frontier_driven | participant_proposed |
    market_allocated | governed_federation
  routing_signal_refs:
    - benchmark://... | receipt://... | ledger://... | gate://...
  conductor_advisor_refs:
    - conductor://...
  hard_policy_refs:
    - policy://...
  fallback_policy:
    ask_user | local_default | safest_private_route | cheapest_route |
    fail_closed
  collaboration_policy_refs:
    - policy://...
  marginal_value_stop_policy_ref: policy://... | null
  update_mode:
    static | operator_managed | bandit_assisted | foundry_promoted
  status: draft | active | shadow | deprecated | revoked
```

## OrchestrationPlanEnvelope

Candidate or selected plan shape for an outcome conductor. A plan may reference
model routes, harnesses, workers, verifier paths, sessions, and handoffs, but it
does not execute until Hypervisor/daemon admission accepts the relevant work.

```yaml
OrchestrationPlanEnvelope:
  plan_id: orchestration_plan://...
  revision_ref: orchestration_plan://.../revision/...
  predecessor_revision_ref: orchestration_plan://.../revision/... | null
  content_hash: hash
  goal_ref: goal://... | task://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  workflow_template_revision_refs: []
  constraint_envelope_ref: constraint://...
  materialization:
    single_path | verifier_backed_single_path | multi_model_answer |
    multi_harness_attempt | cross_session_branch_and_merge |
    collaborative_frontier | independent_replication |
    dynamic_specialist_mesh | open_challenge |
    marketplace_worker_delegation | foundry_job
  goal_execution_policy: auto | pinned | compare
  selection_source: user | org_policy | conductor_policy | fallback_policy
  model_route_requirement_refs: []
  resolver_requirement_refs: []
  worker_requirement_refs: []
  verifier_requirement_refs: []
  role_topology_requirement_refs: []
  selected_role_topology_revision_ref: role_topology://.../revision/... | null
  selected_role_topology_content_hash: hash | null
  routing_decision_refs: []
  proposed_session_topology:
    single_session | isolated_parallel_sessions | branch_and_merge |
    collaborative_frontier | federated_room | handoff_only | no_execution
  outcome_room_ref: outcome-room://... | null
  proposed_coordination_topology:
    none | hosted_admission | federated_admission
  expected_cost_ref: budget://... | null
  expected_latency_class: interactive | batch | background | deadline_bound
  evidence_basis_refs:
    - benchmark://... | receipt://... | ledger://... | gate://...
  selection_decision_receipt_ref: receipt://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: candidate | selected | rejected | superseded | admitted
```

Each plan revision is immutable and content-addressed. Course correction,
selection, or topology change creates or selects a revision and binds the
decision receipt; that receipt and registry lifecycle/status are excluded from
`content_hash` and the receipt binds the already-computed hash. Requirement
refs are nonbinding candidate constraints. A selected/admitted plan may bind an
exact RoleTopology revision/hash plus routing decisions; that topology owns the
role-to-actor/resolver mapping, and each HarnessInvocation owns the resolver
actually invoked. The plan never restates either mapping as parallel arrays. Product
surfaces may render the selected revision but cannot restate its selections as
a second truth owner.

## NetworkGoalBudgetEnvelope

`NetworkGoalBudgetEnvelope` is the explicit spend boundary for independent
Network/Open workers, verifiers, services, resource providers, challenges, and
settlement. It is separately funded and visible; it is not the ordinary Goal
Space Work Credit allowance, a pooled provider seat, a transferable credit, or
permission to spend without the declared authority and admission path. A
`ServiceOrder` may carry its own equivalent budget contract, but an OutcomeRoom
must reference which contract governs external spend.

```yaml
NetworkGoalBudgetEnvelope:
  network_goal_budget_id: goal-budget://...
  goal_ref: goal://... | task://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  sponsor_ref: system://... | user://... | org://... | project://... | service://...
  collaboration_terms_refs:
    - terms://...
  funding_mode: prepaid_cap | bounty | procurement_cap | service_order
  funding_source_ref:
    wallet://... | escrow://... | procurement://... | order://...
  denomination: string
  authorized_amount: decimal
  reserved_amount: decimal
  admitted_spend_amount: decimal
  remaining_amount: decimal
  quote_rate_card_and_cap_refs:
    - quote://... | rate-card://... | policy://...
  eligible_contributor_and_work_refs:
    - worker://... | service://... | participant-lease://... |
      frontier://... | verifier_path://... | resource-offer://...
  spend_authority_ref: grant://...
  allocation_and_reservation_refs:
    - allocation://... | receipt://... | ledger://...
  contribution_delivery_and_settlement_refs:
    - contribution://... | delivery://... | settlement-intent://... | receipt://...
  adjustment_refund_and_dispute_policy_refs:
    - policy://... | dispute://...
  ordinary_work_credit_substitution: prohibited
  expires_at: timestamp | null
  status:
    draft | funded | active | exhausted | paused | disputed |
    settling | settled | refunded | expired | revoked
```
