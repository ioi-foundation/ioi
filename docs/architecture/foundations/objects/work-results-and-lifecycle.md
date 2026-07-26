# Work Result and Work-Lifecycle Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of work results, outcome deltas, the shared work-lifecycle record, and work-lifecycle archive segments and snapshots.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial (work-result routes exist in the daemon; the shared work-lifecycle kernel persistence and routes remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md);
this module does not restate them.

## WorkResultEnvelope and OutcomeDeltaEnvelope

`WorkResultEnvelope` is the generic bounded result seam returned by a GoalRun,
claim, worker, harness, service, research attempt, ontology operation, incident
response, or embodied mission. `ImplementationResultPayloadEnvelope` is its
software-specific profile; it no longer defines the general pursuit model.

Profile-specific fields remain behind `result_profile_ref` and
`result_payload_ref`; research, ontology, incident, service, physical-mission,
review, and evaluation results are not forced through software file/diff/test
fields. The cross-domain invariants below are optional when irrelevant, but a
profile must preserve the applicable identities, method/lineage, claims and
uncertainty, evidence, cost/authority/verifier posture, rights, reproduction,
acceptance, challenge, and supersession state whenever the result crosses a
run, room, domain, contribution, dispute, or replay boundary.

```yaml
WorkResultEnvelope:
  work_result_id: work-result://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  produced_by_ref: system://... | participant-lease://... | worker://... | service://... | org://... | domain://...
  submitted_by_ref: system://... | participant-lease://... | worker://... | service://... | org://... | domain://...
  operator_and_affiliation_refs: []
  work_claim_ref: work-claim://... | null
  attempt_ref: attempt://... | null
  invocation_or_run_ref:
    harness_invocation://... | run://... | work_run://... | automation-run://... |
    service://... | null
  result_profile:
    software_implementation | research | ontology_mutation |
    incident_resolution | service_delivery | physical_mission |
    review | evaluation | custom
  result_profile_ref: schema://... | profile://... | null
  result_payload_ref:
    implementation_result://... | artifact://... | cid://... | encrypted_ref | null
  producer_component_resolution:
    resolved_component_set_snapshot_ref: artifact://... | null
    resolved_component_set_hash: hash | null
    component_resolution_receipt_ref: receipt://... | null
    resolver_kind: harness_profile | agent_harness_adapter | none
    resolver_revision_ref:
      harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | null
    resolver_content_hash: hash | null
  declared_method_and_lineage_refs:
    - method://... | attempt://... | finding://... | work-result://... |
      artifact://... | trace://...
  information_flow_label_refs:
    - ifc-label://...
  outcome_class:
    positive | negative | inconclusive | invalid | exploit_found | superseded
  status: completed | failed | blocked | partial | challenged | superseded
  outcome_delta_refs:
    - outcome-delta://...
  finding_refs:
    - finding://...
  claim_refs:
    - finding://... | ontology-assertion://... | evidence://...
  uncertainty: number | string | object | null
  supporting_evidence_refs:
    - artifact://... | evidence://... | receipt://... | ledger://...
  contradicting_evidence_refs:
    - finding://... | ontology-assertion://... | evidence://... | artifact://...
  artifact_receipt_and_trace_refs:
    - artifact://... | receipt://... | ledger://... | trace://...
  resource_and_cost_refs:
    - resource-lease://... | cost://... | quote://... | budget://... |
      ledger://... | receipt://...
  authority_and_policy_refs:
    - grant://... | scope:* | policy://... | receipt://...
  blocker_and_decision_request_refs:
    - blocker://... | handoff://... | proposal://...
  verifier_refs:
    - verifier_path://... | worker://... | gate://... | receipt://...
  license_disclosure_retention_and_export_refs:
    - license://... | policy://... | restricted_view://... | receipt://...
  reproduction_state:
    unreviewed | reproducible | not_reproduced | contradicted | invalidated | null
  reproduction_refs:
    - attempt://... | work-result://... | evidence://... | receipt://...
  acceptance_ref: acceptance://... | decision://... | receipt://... | null
  challenge_refs:
    - verifier-challenge://... | dispute://... | evidence://...
  supersedes_work_result_ref: work-result://... | null
  superseded_by_ref: work-result://... | outcome-delta://... | null
  summary_ref: message://... | artifact://... | null
  next_action:
    none | repair | review | verify | replicate | synthesize |
    ask_user | escalate | update_frontier
```

The producer component snapshot/receipt and resolver pair are null, with
`resolver_kind: none`, only for work whose declared profile has no executable
component resolution, such as an admitted direct human assertion. Any
WorkResult emitted by a HarnessInvocation, AutomationRun,
WorkRun, worker, service, model route, or RuntimeAssignment requires the exact
resolved-component snapshot/hash and its admission receipt. The snapshot
commits the exact worker, resolver, model-route, tool, skill, runtime, and other
applicable component revisions/hashes. `resolver_kind` independently
discriminates the exact resolver pair for projection and replay; family refs or
current registry heads are invalid provenance.

```yaml
OutcomeDeltaEnvelope:
  outcome_delta_id: outcome-delta://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  proposed_by_ref:
    work-result://... | attempt://... | finding://... | participant-lease://...
  target_ref:
    frontier://... | finding://... | ontology://... | state://... |
    capability://... | policy://... | routing-prior://... | service://...
  delta_kind:
    create | update | supersede | reject | merge | promote |
    rollback | course_correct | close
  payload_ref: artifact://... | patch://... | mapping://... | state-delta://...
  precondition_and_invariant_refs:
    - policy://... | gate://... | state://...
  expected_effect_ref: effect://... | null
  verifier_and_acceptance_refs:
    - verifier_path://... | rubric://... | gate://...
  information_flow_label_refs:
    - ifc-label://...
  status: proposed | evaluating | admitted | rejected | superseded | rolled_back
```

Information-flow labels are part of result lineage, not an assertion that the
result is true or authoritative. A room-scoped result preserves every label
that can influence its payload, summary, claims, or proposed delta. An
`OutcomeDelta` inherits the complete label set of the `WorkResult` or other
admitted proposer it derives from and may only add labels; it cannot drop,
replace, or weaken inherited labels. Summarization, verifier review, schema
validation, room admission, and agreement do not declassify content or upgrade
instruction authority. The label objects remain owned by their originating
artifact, context, receipt, or runtime boundary; these fields carry exact refs
so downstream effect admission can resolve and join them.

For `Attempt`, `Finding`, `VerifierChallenge`, `WorkResult`, and `OutcomeDelta`,
`outcome_room_ref != null` requires a non-null `room_admission` whose
`proposed_or_issued_by_ref` is the current room participant lease (or the room
system for a system-authored transition). Direct actor refs are permitted only
for non-room work subjects. Room-scoped `WorkResult.produced_by_ref` and
`submitted_by_ref` must resolve through that same participant lease, preserving
the accountable operator/affiliation lineage.

## WorkLifecycleRecordEnvelope

`WorkLifecycleRecordEnvelope` is the shared append-only mechanics layer for
bounded work. It does not own GoalRun, GoalGroundingLoop, WorkRun,
AutomationRun, HarnessInvocation, ContextCell, or external-protocol state and
does not flatten their phases into a universal business lifecycle. Each kind
keeps its own legal transition and transition-authority table; the target
shared kernel would supply content commitment, exact-head compare-and-swap,
object-scoped idempotency, append-only child references, replay, cancellation
planning, and snapshot/archive continuity. Current master does not implement
this shared kernel or its persistence/routes.

```yaml
WorkLifecycleRecordEnvelope:
  schema_version: ioi.work-lifecycle-record.v1
  record_id: work-lifecycle://...
  record_hash: hash
  record_type: phase_transition | child_reference
  object_kind:
    goal_run | goal_grounding_loop | work_run | automation_run |
    harness_invocation | context_cell | external_handle
  object_ref:
    goal://... | goal_loop://... | work_run://... | automation-run://... |
    harness_invocation://... | context_cell://... | opaque_external_handle_ref
  owner_ref: system://... | user://... | org://... | project://... | domain://...
  expected_head: hash | null
  resulting_head: hash
  idempotency_key: string
  authority_class:
    owner | goal_kernel | conductor | verifier | daemon | operator |
    reviewer | automation_controller | harness_adapter |
    external_protocol_adapter | reconciler | governance
  authority_ref: authority://... | actor://... | policy://...
  authority_grant_refs: [grant://...]
  decision_receipt_ref: receipt://... | null
  evidence_refs: [evidence://... | artifact://... | trace://...]
  receipt_refs: [receipt://...]
  phase_transition:
    from_phase: string | null
    to_phase: string
    cancellation_intent:
      requested_by_ref: actor://...
      reason: string
      drain_deadline_ms: integer_timestamp_ms
      compensation_policy_ref: policy://... | null
      ambiguous_effect_policy_ref: policy://... | null
    # null unless this transition initiates cancellation/revocation
  child_reference:
    operation: attach | detach
    relation_kind:
      context_cell | context_lease | runtime_assignment |
      harness_invocation | external_handle | child_goal_run |
      work_run | automation_run | work_result | receipt
    child_ref: typed_ref
    effect_recovery_class:
      none | reversible | compensatable | irreversible | ambiguous
  occurred_at_ms: integer_timestamp_ms
```

Exactly one of `phase_transition` and `child_reference` is non-null and must
match `record_type`. The content commitment covers every field except
`record_hash` and `resulting_head`; both excluded fields then equal that exact
commitment. Genesis has `expected_head: null` and one kind-specific initial
phase. Every successor binds the current head and may not regress
`occurred_at_ms`. Reusing the same object-scoped
idempotency key with identical bytes returns the original result; changed bytes
fail. A log containing duplicate genesis records, a fork, gap, orphan, invalid
hash, illegal transition, foreign owner, or unauthorized authority class fails
closed before its active-phase projection changes.

The kind-specific phase owners remain:

| Kind | Canonical phase family | Ordinary transition authority |
|---|---|---|
| GoalRun | `draft`, `active`, `paused`, `complete`, `superseded`, `revoked` | Goal Kernel; owner on declared pause/resume/revoke edges; governance on declared pause/revoke/supersede edges |
| GoalGroundingLoop | the canonical receive → ground → inspect → constrain → allocate → execute → verify → repair/reconcile → continue loop phases | Goal Kernel/conductor; verifier only on declared verify/challenge edges |
| WorkRun | `pending`, `running`, `waiting_for_input`, `ready_for_review`, `stopped`, `completed`, `failed`, `canceled` | daemon/operator; reviewer only on declared review exits |
| AutomationRun | `queued`, `running`, `waiting_for_approval`, `blocked`, `succeeded`, `failed`, `canceled`, `archived` | Automation controller/daemon; governance on declared cancellation edges |
| HarnessInvocation | `queued`, `running`, `waiting_on_harness`, `waiting_on_conductor`, `completed`, `failed`, `cancelled`, `superseded` | daemon, selected adapter, or conductor on the declared edge |
| ContextCell | `open`, `active`, `sleeping`, `waiting`, `handed_off`, `summarized`, `quarantined`, `closed`, `revoked` | conductor/daemon; governance on declared revocation edges |
| external handle | `requested`, `acknowledged`, `running`, `waiting`, `succeeded`, `failed`, `cancelled`, `expired`, `ambiguous`, `reconciled` | exact external-protocol adapter/daemon; reconciler on ambiguous settlement |

These rows name phase families, not permission to jump between arbitrary
members. The versioned legal-edge table is normative. Reference mutations have
their own kind-specific authority table and never mutate the child object; they
only append or retire the owning object's typed index entry. Thus a GoalRun's
ContextCell refs, a WorkRun's HarnessInvocation refs, and an invocation's
external handles are reconstructable without moving lifecycle ownership into
the shared kernel.

Cancellation/revocation is not a terminal string assignment. An admitted
`cancellation_intent` deterministically derives a `CancellationFanoutPlan` over
active typed children:

```yaml
CancellationFanoutPlanEnvelope:
  schema_version: ioi.cancellation-fanout-plan.v1
  object_ref: typed_ref
  source_head: hash
  requested_by_ref: actor://...
  reason: string
  compensation_policy_ref: policy://... | null
  effect_reconciliation_policy_ref: policy://... | null
  targets:
    - relation_kind: same_enum_as_above
      target_ref: typed_ref
      actions:
        - request_cancel | drain | fence | revoke_lease | close_context |
          wait_until_timeout | rollback | compensate |
          reconcile_ambiguous_effect | reconcile_irreversible_effect |
          preserve_receipt_lineage
      timeout_at_ms: integer_timestamp_ms | null
  requires_completion_receipt: true
```

The cancellation edge is refused when a compensatable active child has no
compensation policy or an ambiguous/irreversible active child has no effect-
reconciliation policy. Cancellation metadata is invalid on non-cancel edges.
The plan cannot claim child completion. Each child owner executes and receipts
its cancellation, drain, lease revocation, provider fence, timeout,
compensation, or ambiguous/irreversible-effect reconciliation. Unknown external
completion becomes `ambiguous`; it never becomes success merely because the
local wait ended.

## WorkLifecycleArchiveSegmentEnvelope and WorkLifecycleSnapshotEnvelope

```yaml
WorkLifecycleArchiveSegmentEnvelope:
  schema_version: ioi.work-lifecycle-archive-segment.v1
  archive_ref: work-lifecycle-archive://...
  object_kind: same_enum_as_record
  object_ref: typed_ref
  through_head: hash
  archive_root: hash
  records: [WorkLifecycleRecordEnvelope]
  receipt_lineage_refs: [receipt://...]
  created_at_ms: integer_timestamp_ms

WorkLifecycleSnapshotEnvelope:
  schema_version: ioi.work-lifecycle-snapshot.v1
  snapshot_ref: work-lifecycle-snapshot://...
  archive_ref: work-lifecycle-archive://...
  archive_root: hash
  through_head: hash
  resume_state:
    projection:
      schema_version: ioi.work-lifecycle-projection.v1
      object_kind: same_enum_as_record
      object_ref: typed_ref
      owner_ref: typed_ref
      active_phase: kind_specific_phase
      head: hash
      last_record_ref: work-lifecycle://...
      last_occurred_at_ms: integer_timestamp_ms
      record_count: integer
      active_children: typed_relation_index
      cancellation_intent: object | null
      receipt_lineage_refs: [receipt://...]
    idempotency_record_hashes: object
  receipt_lineage_refs: [receipt://...]
  created_at_ms: integer_timestamp_ms
```

Compaction first writes an immutable archive segment, then a snapshot bound to
that archive root and head. Resume plus an append-only tail must reconstruct the
same phase, child index, idempotency decisions, and object head as full replay.
Receipt lineage is retained even when individual hot-log records later leave
the active segment. Snapshot files are projections/checkpoints, never a license
to discard the immutable archive or owner-domain truth.
