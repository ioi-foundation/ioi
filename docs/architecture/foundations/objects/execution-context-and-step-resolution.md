# Step-Resolution, Information-Flow, and Harness Execution Objects

Status: canonical low-level reference.
Canonical owner: this file for the substrate-shared object shapes of information-flow labels and declassification approvals, task brief payloads, harness invocations, harness adapter events, implementation result payloads, verifier paths, benchmarks, and routing decisions.
Supersedes: none.
Superseded by: none.
Last alignment pass: 2026-08-07.
Doctrine status: canonical
Implementation status: see [`../../_meta/canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md)

## Purpose

This module owns the object shapes above. They are **substrate-shared**: any
application domain may carry them, and no application owns them. Registered
contracts here carry `schema://ioi/foundations/*` or
`schema://ioi/components/*`.

Information-flow labels and declassification approvals are consumed across the
estate — the model router, connectors, platform operability, the default harness
profile, and the information-flow, platform-operability, and outcome-room
conformance suites all bind them. Harness invocation and adapter-event shapes
belong to the daemon step-resolution seam.

Envelope base types, ID conventions, and capability/authority tiers come from
[`../common-objects-and-envelopes.md`](../common-objects-and-envelopes.md).
Doctrine is owned by
[`../../components/daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md)
and
[`../../components/daemon-runtime/default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md).

## InformationFlowLabel and DeclassificationApproval

`InformationFlowLabel` is the versioned, multi-axis information-flow contract
carried by context, connector/tool outputs, memory imports, model outputs, and
their derivatives. Its registered v1 wire shape owns origin, integrity,
confidentiality, instruction authority, destination/data-class egress policy,
purpose, retention, and the transitive derivation-parent closure. Missing or
`unknown` axes fail closed at consequential-effect admission. Summarization,
model substitution, memory import, and tool-output transformation create a new
label by deterministic restrictive join; they never erase or weaken a parent
label.

Boundary production also cannot mint trust. Raw model-provider results are
`model_output + untrusted + none`; browser observations are
`external_untrusted + untrusted + none`; live MCP results are
`tool_output + untrusted + none`; and durable imported/summarized memory is
content-only while preserving the worst parent integrity and authority. A
separately admitted verifier may later create a successor label; the producing
boundary cannot do so implicitly.

`DeclassificationApproval` is the separate wallet/policy authority object for
one protected egress. It binds the exact RuntimeToolContract revision, label ref
and content hash, canonical effect hash, canonical request hash, exact reviewed-
representation hash, destination, purpose, declassification target, expiry,
grant, and approval receipt. Changing effect bytes, request content, destination,
reviewed representation, label, tool revision, purpose, status, or expiry makes
the approval unusable. Declassification changes neither provenance nor
instruction authority; it cannot make an untrusted instruction authoritative.

The canonical JSON Schema 2020-12 wire contracts, invariant profiles, and
cross-language fixtures are registered in
[`architecture-contract-registry.v1.json`](../../_meta/schemas/architecture-contract-registry.v1.json).
The Hypervisor Daemon owns pre-effect evaluation. `ContextCell`, memory,
connector/tool, and model owners carry refs to these labels rather than defining
parallel taint or privacy objects.

## TaskBriefPayloadEnvelope

Normalized payload for bounded implementation, research, review, repair,
specialist, resource, synthesis, or verification work. The conductor may
render this as a prompt for a specific harness, but the durable contract is
this task brief, not the rendered prompt. Software-specific fields are one
output profile rather than the generic result contract.

```yaml
TaskBriefPayloadEnvelope:
  task_brief_id: task_brief://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  handoff_ref: handoff://... | null
  objective: string
  objective_class:
    implement | repair | review | verify | inspect | research |
    reproduce | synthesize | curate | challenge | provide_resource |
    ontology_change | incident_response | service_delivery |
    physical_mission | refactor | ui_check | release_check | custom
  scope_refs:
    - project://... | file://... | route://... | surface://... |
      artifact://... | receipt://...
  canon_refs:
    - canon://... | doc://...
  constraints:
    - string
  do_not_touch_refs:
    - file://... | module://... | policy://...
  acceptance_refs:
    - rubric://... | test://... | gate://...
  verification_plan_refs:
    - verifier_path://... | test://... | script://...
  context_lease_refs:
    - context_lease://...
  output_contract:
    result_profile:
      software_implementation | research | ontology_mutation |
      incident_resolution | service_delivery | physical_mission |
      review | evaluation | custom
    work_result_required: boolean
    outcome_delta_required: boolean
    finding_refs_required: boolean
    changed_files_required: boolean
    diff_summary_required: boolean
    tests_required: boolean
    blocker_report_required: boolean
    receipt_refs_required: boolean
  status: draft | issued | superseded | revoked
```

## HarnessInvocationEnvelope

Daemon-mediated invocation of a selected HarnessProfile or Agent Harness
Adapter. This is the object that removes the human copy-paste relay: a
ContextHandoff becomes a HarnessInvocation, the adapter renders the harness
native prompt or command privately, and the daemon records normalized events,
artifacts, receipts, and final result.

```yaml
HarnessInvocationEnvelope:
  harness_invocation_id: harness_invocation://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  goal_run_ref: goal://... | null
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  handoff_ref: handoff://... | null
  context_cell_ref: context_cell://... | null
  task_brief_ref: task_brief://...
  resolver_kind: harness_profile | agent_harness_adapter
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/...
  resolver_content_hash: hash
  model_route_ref: model_route://... | null
  runtime_ref: runtime://... | environment://... | session://... | null
  external_invocation_bindings:
    - external_protocol_binding_ref: aiip-binding://... | mcp://... | schema://...
      protocol_version_or_extension_ref: string
      opaque_handle_commitment: hash
      encrypted_or_redacted_handle_ref: artifact://... | null
      status_projection_ref: event://... | artifact://... | null
  context_lease_refs:
    - context_lease://...
  adapter_rendering_ref: artifact://... | null
  event_refs:
    - harness_event://...
  work_result_ref: work-result://... | null
  profile_result_ref: implementation_result://... | artifact://... | null
  receipt_refs:
    - receipt://... | ledger://...
  status:
    queued | running | waiting_on_harness | waiting_on_conductor |
    completed | failed | cancelled | superseded
```

An MCP Task or another protocol-native asynchronous task remains an opaque
external invocation handle bound to this invocation and its exact
protocol/version adapter. IOI records its commitment and protected handle
reference; it does not mint an IOI identity that pretends to own the external
task. The handle never becomes the `GoalRun` identity or authoritative GoalRun
status. Completion is normalized into `WorkResult` / `OutcomeDelta` and remains
subject to the conductor's `VerifierPath`.

`resolver_kind` discriminates the exact resolver revision/hash. The invocation
also binds the accountable actor that owns the work and receipts; neither a
HarnessProfile, adapter, model route, nor runtime can stand in for that actor.
GoalRun/context-cell execution binds `goal_run_ref`, `handoff_ref`, and
`context_cell_ref` as applicable. A direct AutomationRun, WorkRun, module run,
claim, or attempt invocation may leave those goal-specific refs null, but still
requires an exact `work_subject_ref`, accountable actor, TaskBrief, resolver,
leases, and result/receipt path. Every event and result emitted by the
invocation must carry the same work subject.

A completed invocation requires `work_result_ref`. `profile_result_ref` is an
optional domain/profile payload and cannot replace the canonical WorkResult.
For software work it names an `ImplementationResultPayloadEnvelope`, which
must point back to the same WorkResult and be the WorkResult's
`result_payload_ref` (or its content-addressed payload). Failed or cancelled
invocations may leave both result refs null only when their terminal receipt
and failure/blocker evidence are present.

## HarnessAdapterEventEnvelope

Normalized event emitted by a harness adapter during a HarnessInvocation.
Harnesses may stream text, tool calls, terminal output, file writes, browser
events, or provider-specific state; the adapter must translate them into common
events before they become durable coordination evidence.

```yaml
HarnessAdapterEventEnvelope:
  harness_event_id: harness_event://...
  harness_invocation_ref: harness_invocation://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  event_kind:
    started | stdout | stderr | thought_summary | tool_proposed |
    tool_started | tool_completed | file_changed | patch_created |
    test_started | test_completed | blocker | decision_request |
    artifact_created | attempt_updated | finding_proposed |
    outcome_delta_proposed | verifier_challenge_proposed |
    resource_requested | frontier_update_proposed |
    receipt_emitted | completed | failed
  payload_ref: artifact://... | message://... | null
  normalized_observation_ref: observation://... | null
  receipt_refs:
    - receipt://...
  redaction_policy_ref: policy://... | null
  timestamp: iso8601
```

## ImplementationResultPayloadEnvelope

Software-implementation profile of `WorkResultEnvelope` returned from a
HarnessInvocation. The conductor consumes this object, not a copied chat
response. It is intentionally bounded: enough evidence to verify, repair,
continue, or close; not the implementer's full context. Research, ontology,
incident, service, physical-mission, review, and evaluation results use the
generic WorkResult/OutcomeDelta seam rather than overloading changed files.

```yaml
ImplementationResultPayloadEnvelope:
  implementation_result_id: implementation_result://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  harness_invocation_ref: harness_invocation://...
  handoff_ref: handoff://... | null
  work_result_ref: work-result://...
  attempt_ref: attempt://... | null
  status: completed | failed | blocked | partial | superseded
  changed_file_refs:
    - file://... | artifact://...
  patch_refs:
    - artifact://... | diff://...
  test_result_refs:
    - test://... | receipt://...
  blocker_refs:
    - blocker://... | handoff://...
  decision_request_refs:
    - handoff://...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://... | ledger://...
  summary_ref: message://... | artifact://... | null
  next_recommended_handoff_kind:
    none | repair | review | verify | ask_user | escalate
```

## VerifierPathEnvelope

Defines the selected verification shape for a plan, run, worker, route, or
package. Verifier paths are evidence contracts; model judges are allowed, but
they are not truth by themselves.

The default verifier path for ordinary goal work may be conductor-run
deterministic verification: tests, diffs, browser evidence, source checks,
receipt inspection, and acceptance-criteria reconciliation. Independent verifier
harnesses are escalation paths, not the default requirement.

```yaml
VerifierPathEnvelope:
  verifier_path_id: verifier_path://...
  owner_ref: org://... | system://... | domain://... | null
  applies_to:
    - goal://... | run://... | worker://... | model_route://... |
      package://... | orchestration_plan://... | outcome-room://... |
      attempt://... | finding://... | ontology-assertion://... |
      evidence://...
  verifier_rule_version_ref: rubric://... | policy://... | gate://...
  verification_kind:
    deterministic | test | static_analysis | browser_evidence |
    model_judge | verifier_worker | human_review | benchmark |
    regulated_review | physical_safety | hybrid
  required_evidence_refs:
    - artifact://... | receipt://... | gate://... | benchmark://...
  verifier_refs:
    - principal://... | worker://... | model://... | gate://... | org://... |
      system://... | domain://...
  acceptance_threshold_ref: rubric://... | gate://... | policy://...
  independence:
    minimum_independent_principals: nonnegative_integer
    subject_owner_may_self_verify: boolean
    required_distinct_independence_groups: nonnegative_integer
    affiliation_and_dependency_evidence_refs:
      - evidence://... | artifact://... | receipt://...
    correlated_failure_policy_ref: policy://... | null
  replay_required: boolean
  challenge_refs:
    - verifier-challenge://...
  status:
    draft | active | challenged | reverifying | satisfied |
    failed | superseded | revoked
```

For an independence requirement greater than zero, a verifier counts only when
its accountable principal, affiliations, upstream evidence dependencies, and
declared independence group satisfy the selected correlation policy. Missing
affiliation or dependency evidence is unknown and never counts as independence.

## BenchmarkEnvelope

```yaml
BenchmarkEnvelope:
  benchmark_run_id: benchmark://...
  worker_id: worker://...
  worker_composition_ref: package://... | ai://... | null
  model_route_ref: model_route://... | null
  resolver_kind: harness_profile | agent_harness_adapter | none
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  semantic_harness_profile_revision_ref:
    harness-profile://.../revision/... | null
  semantic_harness_profile_content_hash: hash | null
  runtime_profile_ref: runtime://... | profile://... | null
  privacy_posture_ref: privacy_posture://... | policy://... | null
  verifier_path_ref: verifier_path://... | null
  sparse_worker_category: string
  benchmark_profile_ref: benchmark://...
  environment_hash: hash
  manifest_hash: hash
  policy_hash: hash
  score_commitment: hash
  evaluator_id: worker://... | verifier://...
  evaluation_receipt_root: hash
  routing_eligibility_result: eligible | ineligible | suspended
```

The benchmark resolver discriminator follows the pairing rule above. An
adapter benchmark may additionally bind the exact HarnessProfile it realizes;
the score never treats an adapter family ref or semantic profile as proof of
the other. `none` requires all resolver/profile fields to be null unless the
benchmark profile explicitly names a non-harness deterministic path.

## RoutingDecisionEnvelope

`RoutingDecisionEnvelope` is the neutral, replayable selection record. It
commits not only to the candidate set but also to affiliations, first-party or
subsidized seed supply, the selected Worker composition and its mounted
dependencies, every admitted route attempt, fallback/escalation, and verifier
posture. A selection receipt can attest this decision boundary; it cannot prove
that the chosen route was globally optimal or independent without the declared
evidence.

```yaml
RoutingDecisionEnvelope:
  routing_decision_id: routing-decision://...
  task_id: task://...
  goal_and_room_refs:
    - goal://... | outcome-room://...
  router_id: worker://... | runtime://... | system://... | domain://...
  task_offer_ref: packet://... | null
  task_acceptance_refs:
    - packet://...
  selected_task_acceptance_ref: packet://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
  intent_hash: hash
  candidate_set_commitment: hash
  candidate_affiliation_commitment: hash
  candidate_affiliation_and_ownership_evidence_refs:
    - evidence://... | receipt://... | org://... | provider://...
  routing_policy_hash: hash
  selected_domain_or_worker: system://... | domain://... | worker://... | service://... | runtime://...
  selected_worker_composition_ref: package://... | ai://... | worker://... | null
  selected_model_provider_runtime_refs:
    - model://... | model_route://... | provider://... | runtime://... |
      node://... | model-route-contract://...
  attempted_route_refs:
    - route-attempt://... | route-chain://...
  actual_attempt_refs:
    - route-attempt://... | attempt://... | work-result://... | receipt://...
  authority_scope: []
  cost_bound_ref: cost://... | budget://... | quote://... | null
  reason_codes:
    - quality | cost | privacy | latency | locality | installed_status |
      benchmark_result | authority_fit | user_preference | safety |
      independence | affiliation | seed_supply | fallback_availability
  fallback_policy_ref: policy://... | null
  fallback_or_escalation_refs:
    - route-chain://... | route-attempt://... | decision://... | receipt://...
  verifier_escalation_refs:
    - verifier_path://... | verifier-challenge://... | worker://... |
      decision://... | receipt://...
  contributor_scope: my_workers | organization | network_open
  contribution_policy_ref: policy://...
  seed_supply_and_independence_evidence_refs:
    - evidence://... | receipt://... | benchmark://... | certification_claim://...
  receipt_obligations: []
  routing_decision_receipt_ref: receipt://... | null
  signature: optional
```

For an external solicitation, the decision binds every admitted response and
the selected response under one terms root. It explains selection but is not
an authority grant, executable award, accepted result, contribution allocation,
or payout right. The corresponding `WorkClaimLeaseEnvelope` is the bounded
award that must still satisfy participant, context, resource, budget, and
authority admission.

The `selected_task_acceptance_ref` must be a member of
`task_acceptance_refs`. For an external solicitation it is non-null, has
`status: accepted`, names `selected_domain_or_worker` as its accountable
responder, and binds the same collaboration terms root. The selected quote and
budget reservation must match the routing decision. Internal local routing may
leave offer/response refs null, but it cannot claim an external award.
