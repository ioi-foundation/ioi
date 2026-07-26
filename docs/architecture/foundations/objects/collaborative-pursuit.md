# OutcomeRoom and Collaborative-Pursuit Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of OutcomeRoom discovery and participation requests, OutcomeRooms, room participant leases, participant state bundles, resource and capability offers, work frontier items, work claim leases, attempts, findings, and verifier challenges.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial (room, participation, frontier, and claim routes exist in the daemon; collaborative AIIP federation and cross-domain assurance remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md);
this module does not restate them.

## OutcomeRoomDiscoveryEnvelope and RoomParticipationRequestEnvelope

Cross-domain and Network/Open participation begins with a policy-bound
discovery projection, not access to the room database. An independently
operated Worker can discover the public objective/category and declared
requirements, then submit a typed participation request through AIIP. Neither
object carries raw room context, private memory, secrets, protected connector
payloads, or non-public operational state.

The contract is topology-neutral. Under `hosted_admission`,
`admission_owner_ref` names the host domain. Under `federated_admission`, it
names the versioned federation policy/adjudicator path. The same request,
eligibility, visibility, privacy, quote, verifier, settlement, receipt, and
lease semantics apply in both cases; only ordering/admission ownership differs.

```yaml
OutcomeRoomDiscoveryEnvelope:
  room_discovery_id: room-discovery://...
  outcome_room_ref: outcome-room://...
  room_admission: RoomAdmittedObjectBase
  publication_version: semver_or_hash
  published_by_ref: system://... | domain://... | org://... | service://...
  public_goal_ref: goal://... | task://... | service://...
  public_objective: string
  public_category_refs:
    - ontology://... | benchmark://... | capability://... | service://...
  coordination_topology: hosted_admission | federated_admission
  admission_owner_ref: system://... | domain://... | policy://...
  participation_channel_ref: aiip://channel/...
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  semantic_and_action_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://... |
      ontology-action://... | action_schema://...
  required_capability_and_worker_profile_refs:
    - capability://... | worker://... | package://... | verifier_path://...
  eligibility_and_affiliation_policy_refs:
    - policy://... | conformance_profile://... | certification_claim://...
  visibility_and_privacy_policy_refs:
    - policy://... | privacy_posture://... | restricted_view://...
  public_frontier_and_context_projection_refs:
    - projection://... | frontier://... | restricted_view://... |
      redacted_summary://...
  budget_quote_and_capacity_refs:
    - goal-budget://... | order://... | quote://... | resource-offer://...
  verifier_and_acceptance_posture_refs:
    - verifier_path://... | rubric://... | gate://... | policy://...
  settlement_dispute_and_contribution_policy_refs:
    - policy://... | settlement-intent://... | dispute://...
  license_retention_and_export_policy_refs:
    - license://... | policy://...
  excluded_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - private_room_database_state
    - non_opted_in_training_trace
  private_context_included: false
  published_at: timestamp
  updated_at: timestamp | null
  valid_until: timestamp | null
  discovery_state_root: hash
  signature: required
  status: draft | discoverable | paused | filled | expired | withdrawn | revoked
```

```yaml
RoomParticipationRequestEnvelope:
  participation_request_id: participation-request://...
  room_discovery_ref: room-discovery://...
  outcome_room_ref: outcome-room://...
  requested_by_ref: system://... | worker://... | service://... | org://... | domain://...
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_response: accept | counteroffer | decline
  counterterms_ref: terms://... | null
  terms_acceptance_signature: required_when_accept
  operator_and_home_domain_refs:
    - user://... | wallet://... | org://... | domain://... | system://...
  worker_composition_and_dependency_refs:
    - package://... | worker://... | model_route://... |
      harness-profile://... | runtime://... | provider://...
  capability_offer_refs:
    - capability-offer://... | ai://... | package://...
  affiliation_and_independent_operation_evidence_refs:
    - evidence://... | receipt://... | org://... | certification_claim://...
  supported_semantic_and_action_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://... |
      ontology-action://... | action_schema://...
  eligibility_evidence_refs:
    - evidence://... | receipt://... | benchmark://... |
      conformance_profile://... | certification_claim://...
  requested_role_frontier_and_visibility_refs:
    - frontier://... | policy://... | restricted_view://...
  privacy_custody_and_context_policy_refs:
    - privacy_posture://... | custody://... | policy://...
  proposed_quote_and_budget_refs:
    - quote://... | goal-budget://... | order://...
  accepted_verifier_settlement_dispute_and_contribution_policy_refs:
    - verifier_path://... | policy://... | settlement-intent://... |
      dispute://...
  requested_participant_state_export_policy_ref: policy://...
  coordination_topology: hosted_admission | federated_admission
  admission_owner_ref: system://... | domain://... | policy://...
  private_context_included: false
  request_hash: hash
  signature: required
  admission_decision_ref: decision://... | receipt://... | null
  participant_lease_ref: participant-lease://... | null
  status: draft | submitted | evaluating | admitted | rejected | withdrawn | expired
```

Discovery advertises an exact public terms ref/root but remains an invitation.
The participation `request_hash` binds the same root and an explicit accept,
counteroffer, or decline. A counteroffer remains a proposal; neither discovery
nor response creates membership, authority, work, contribution eligibility, or
payout. Admission may issue a participant lease only after exact-root terms
acceptance and the ordinary eligibility, privacy, and policy checks.

## OutcomeRoomEnvelope

`OutcomeRoomEnvelope` is the shared collaborative-pursuit profile above one or
more GoalRuns. It binds a durable objective to a work frontier, participants,
attempts, findings, verification, contribution lineage, budget, and replay. It
does not create a second runtime, authority system, marketplace, or globally
mutable Agentgres graph.

Every durable OutcomeRoom is an instance of the reference bounded-DAS package,
with its own stable `system_id`, genesis, constitution, active manifest and
profiles, and cryptographically continuous admitted room state. The hosted
ioi.ai service may operate many such systems; the service account or host domain
is not a substitute for a room's logical identity. A draft may await genesis,
but a room cannot enter `open` or `active`, or be called an intelligent
blockchain, until the complete binding below is admitted. A chat room or
temporary coordination aggregate without that binding is an application
session, not the flagship reference DAS.

The same room may appear as a Goal Space in ioi.ai and Work / Rooms in
Hypervisor, optionally with a non-authoritative Mission presentation label. A
direct question, one-shot run, ordinary automation, or single
session does not require an OutcomeRoom. The room is used only when persistent
collective pursuit creates enough value to justify participation and admission
machinery.

Every room declares who orders and admits its shared state:

- `hosted_admission`: one named governed domain orders and admits room-level
  frontier, attempt, finding, evaluation, and decision updates;
- `federated_admission`: a versioned policy names participating domains,
  ordering/merge rules, quorum or adjudicator requirements, conflict behavior,
  failover, and dispute handling.

Each party retains its local operational truth and private context in either
topology. AIIP carries signed, sequenced, idempotent permitted updates and refs;
`MultiPartyCollaborationEnvelope` remains the cross-party policy and proof
context. A room board, chat, inbox, digest, leaderboard, and replay are
projections over admitted objects, never operational truth by themselves.

```yaml
OutcomeRoomEnvelope:
  outcome_room_id: outcome-room://...
  system_id: system://...
  genesis_ref: genesis://... | null
  package_id: package://...
  manifest_ref: package://.../release/...
  constitution_ref: constitution://...
  active_profile_refs:
    deployment_profile_ref: deployment-profile://...
    ordering_admission_finality_profile_ref: ordering-profile://...
    oracle_evidence_profile_refs: []
    lifecycle_continuity_profile_ref: lifecycle-profile://...
    network_enrollment_ref: network-enrollment://... | null
  autonomous_system_state_ref: agentgres://...
  owner_or_sponsor_ref:
    system://... | user://... | org://... | project://... | domain://... | service://...
  objective_ref: goal://... | task://... | service://...
  objective: string
  constraint_refs:
    - constraint://... | policy://... | budget://...
  acceptance_criteria_refs:
    - rubric://... | gate://... | policy://...
  stop_policy_ref: policy://...
  room_mode:
    private_goal | permissioned_team | cross_org | open_challenge
  visibility_policy_ref: policy://...
  participation_policy_ref: policy://...
  privacy_policy_ref: policy://...
  contribution_policy_ref: policy://...
  cooperation_surplus_policy_ref: policy://...
  collaboration_terms_refs:
    - terms://...
  discovery_and_external_admission_policy_refs:
    - policy://... | room-discovery://... | aiip://channel/...
  artifact_license_rights_retention_and_export_policy_refs:
    - policy://... | license://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_policy_ref: policy://...
  host_domain_ref: system://... | domain://... | null
  ordering_and_merge_policy_ref: policy://...
  conflict_and_failover_policy_ref: policy://...
  multi_party_collaboration_ref: collaboration://... | null
  ontology_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://...
  scorecard_and_guardrail_refs:
    - benchmark://... | rubric://... | gate://... | policy://...
  verifier_path_refs:
    - verifier_path://...
  resource_and_budget_refs:
    - resource_pool://... | budget://... | goal-budget://... | order://...
  settlement_policy_ref: policy://... | null
  participant_lease_refs:
    - participant-lease://...
  participation_request_refs:
    - participation-request://...
  resource_offer_refs:
    - resource-offer://...
  capability_offer_refs:
    - capability-offer://...
  frontier_item_refs:
    - frontier://...
  attempt_refs:
    - attempt://...
  finding_refs:
    - finding://...
  verifier_challenge_refs:
    - verifier-challenge://...
  discussion_projection_refs:
    - projection://... | message://...
  admission_and_replay_refs:
    - receipt://... | replay://... | agentgres://...
  contribution_refs:
    - contribution://... | receipt://...
  participant_state_bundle_refs:
    - participant-state://...
  status:
    proposed | open | active | paused | blocked | verifying |
    accepted | disputed | settled | closed | revoked | archived
```

## RoomParticipantLeaseEnvelope

Room participation is a lease, not ambient membership. It composes existing
identity, context, authority, runtime, resource, and budget leases rather than
creating a second credential system.

```yaml
RoomParticipantLeaseEnvelope:
  participant_lease_id: participant-lease://...
  outcome_room_ref: outcome-room://...
  room_admission: RoomAdmittedObjectBase
  participant_ref:
    system://... | agent://... | worker://... | service://... | org://... | domain://...
  admitted_role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  operator_ref: system://... | user://... | org://... | wallet://... | domain://...
  home_domain_ref: domain://... | system://... | agentgres://domain/...
  worker_and_runtime_refs:
    - worker://... | harness-profile://... | agent-harness-adapter://... |
      model_route://... | runtime://... | node://...
  capability_advertisement_refs:
    - capability-offer://... | ai://... | package://...
  tool_connector_and_capability_dependency_refs:
    - tool://... | connector://... | capability://... | prim:*
  join_request_ref: participation-request://... | proposal://... | null
  collaboration_terms_ref: terms://...
  accepted_terms_root: hash
  terms_acceptance_ref: receipt://...
  identity_and_eligibility_evidence_refs:
    - evidence://... | receipt://... | certification_claim://...
  admission_decision_ref: receipt://... | decision://...
  visibility_scope_ref: policy://... | restricted_view://...
  context_and_authority_lease_refs:
    - context_lease://... | grant://... | authority://...
  runtime_resource_and_budget_lease_refs:
    - lease://... | resource-lease://... | budget://...
  current_claim_ref: work-claim://... | null
  lease_epoch: nonnegative_integer
  issued_at: timestamp
  effective_at: timestamp
  expires_at: timestamp | null
  renew_after: timestamp | null
  renewal_policy_ref: policy://...
  unbounded_term_exception_decision_ref: decision://... | null
  heartbeat_policy_ref: policy://...
  heartbeat_ref: receipt://... | heartbeat://... | null
  last_heartbeat_at: timestamp | null
  heartbeat_valid_until: timestamp | null
  revocation_epoch: nonnegative_integer
  next_wake_condition_ref: policy://... | event://... | null
  quiet_hours_or_backoff_ref: policy://... | null
  last_contribution_ref: contribution://... | receipt://... | null
  exit_and_claim_release_refs:
    - decision://... | work-claim://... | receipt://...
  portable_participant_state_bundle_ref: participant-state://... | null
  future_access_revocation_refs:
    - revocation://... | receipt://...
  ttl_seconds: positive_integer | null
  status:
    invited | joining | active | sleeping | waiting | suspended |
    quarantined | retiring | retired | revoked
```

The default lease is time-bounded: `expires_at` and `ttl_seconds` are required.
A null term is allowed only when the room constitution and participation policy
explicitly permit continuing membership and
`unbounded_term_exception_decision_ref` proves the governed exception. It still
requires heartbeat freshness, monotonic lease/revocation epochs, and an
effective revocation path; it is never ambient irrevocable membership. An
expired heartbeat cannot satisfy active-capacity or work-claim admission.
The lease cannot outlive its accepted collaboration terms unless their renewal
policy explicitly permits that continuation. Terms acceptance alone grants no
context, authority, resource, budget, claim, or payout right.
`terms_acceptance_ref` resolves to a current admitted
`CollaborationTermsAcceptanceReceipt` matching the participant, role, room,
terms ref/root, and lease term; a packet or bare decision is not sufficient.

## ParticipantStateBundleEnvelope

Retirement or revocation ends future participation and releases or reassigns
live claims; it does not erase permitted contribution lineage, receipts,
acceptance, settlement, or dispute evidence. The participant's home domain may
retain a signed, policy-bound portable bundle and continue without room-database
access. A hosted room cannot make portability depend on continued trust in or
access to its database; a federated room applies the same export contract at the
declared federation watermark.

Bundle revocation is append-only. It may end future room access, revoke keys or
live restricted views, or supersede an erroneous export. It cannot erase
already permitted contribution, receipt, acceptance, settlement, or dispute
lineage; historical proof cannot depend on later host availability.

```yaml
ParticipantStateBundleEnvelope:
  participant_state_bundle_id: participant-state://...
  outcome_room_ref: outcome-room://...
  room_admission: RoomAdmittedObjectBase
  participant_lease_ref: participant-lease://...
  participant_and_home_domain_refs:
    - worker://... | service://... | org://... | domain://... | system://...
  coordination_topology: hosted_admission | federated_admission
  bundle_reason: checkpoint | voluntary_retirement | lease_expiry | revocation | quarantine | room_close
  source_admission_watermark_ref: receipt://... | agentgres://... | hash
  released_or_reassigned_claim_refs:
    - work-claim://... | decision://... | receipt://...
  preserved_contribution_attempt_finding_and_result_refs:
    - contribution://... | attempt://... | finding://... | work-result://... |
      outcome-delta://...
  preserved_receipt_acceptance_settlement_and_dispute_refs:
    - receipt://... | acceptance://... | settlement-intent://... |
      dispute://... | decision://...
  portable_artifact_and_view_refs:
    - artifact://... | restricted_view://... | redacted_summary://... |
      evidence://... | replay://...
  lineage_and_supersession_refs:
    - contribution://... | attempt://... | finding://... | work-result://...
  export_license_retention_and_recall_policy_refs:
    - policy://... | license://... | revocation://...
  excluded_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - private_room_database_state
    - revoked_restricted_view
    - non_opted_in_training_trace
  released_future_access_refs:
    - revocation://... | context_lease://... | grant://... | receipt://...
  revocation_or_supersession_refs:
    - revocation://... | participant-state://... | decision://... | receipt://...
  revocation_effect:
    none | future_access_only | restricted_view_keys_revoked |
    erroneous_export_superseded
  bundle_artifact_ref: artifact://... | cid://... | encrypted_ref
  bundle_root: hash
  room_database_access_required: false
  issued_at: timestamp
  signature: required
  status: prepared | exported | acknowledged | superseded | revoked
```

## ResourceOfferEnvelope and CapabilityOfferEnvelope

Participants may offer compute, runtime capacity, data access, verification,
specialist work, tools, or other capabilities to a room. Offers are typed
profiles over existing provider inventory, worker manifests, capability
discovery, and resource-allocation objects; they are not a second marketplace.

Every mutable child of a room uses one admission spine:

```yaml
RoomAdmittedObjectBase:
  room_system_id: system://...
  outcome_room_ref: outcome-room://...
  proposed_or_issued_by_ref: participant-lease://... | system://...
  expected_room_revision: nonnegative_integer
  expected_predecessor_commitment_ref: commitment://...
  payload_root: hash
  admission_policy_ref: policy://...
  admission_decision_ref: decision://... | null
  admission_receipt_ref: receipt://... | null
  admitted_sequence: nonnegative_integer | null
  resulting_room_revision: nonnegative_integer | null
  resulting_transition_commitment_ref: commitment://... | null
  resulting_room_state_root: hash | null
  resulting_receipt_root: hash | null
  created_at: timestamp
  updated_at: timestamp | null
  admission_status: proposed | evaluating | admitted | rejected | superseded | revoked
```

An external agent, Worker, service, organization, or sovereign system acts in a
room only through a current `participant-lease://` ref. `system://` is valid as
issuer only for a room-system-authored scheduling, expiry, or policy transition.
Expected revision and predecessor commitment are compare-and-swap inputs. A
payload becomes shared room truth only when the declared policy/decision emits
an admission receipt and resulting commitment; proposal/workgraph structure
therefore makes untrusted local-agent work useful without treating it as trusted
runtime truth.

```yaml
ResourceOfferEnvelope:
  resource_offer_id: resource-offer://...
  room_admission: RoomAdmittedObjectBase
  provider_participant_lease_ref: participant-lease://...
  backing_provider_ref: provider://... | org://... | domain://... | system://...
  resource_profile_ref: resource://... | runtime://... | node://...
  capacity_and_availability_ref: capacity://... | schedule://...
  locality_and_custody_refs:
    - region://... | custody://... | privacy_posture://...
  trust_and_assurance_refs:
    - evidence://... | certification_claim://... | receipt://...
  cost_ref: quote://... | budget://... | null
  eligible_work_classes:
    - string
  policy_constraint_refs:
    - policy://...
  allocation_policy_ref: policy://...
  queue_preemption_and_fairness_policy_ref: policy://...
  expires_at: timestamp | null
  allocation_decision_refs:
    - allocation://... | receipt://...
  spend_and_contribution_refs:
    - spend://... | contribution://... | receipt://...
  usage_and_consumption_refs:
    - ledger://... | receipt://... | work-credit://...
  status: offered | queued | allocated | exhausted | withdrawn | expired | revoked
```

```yaml
CapabilityOfferEnvelope:
  capability_offer_id: capability-offer://...
  room_admission: RoomAdmittedObjectBase
  participant_lease_ref: participant-lease://...
  backing_worker_or_service_ref: worker://... | service://... | system://...
  capability_descriptor_refs:
    - ai://... | package://... | capability://...
  eligible_frontier_classes:
    - string
  model_harness_tool_and_connector_refs:
    - model_route://... | harness-profile://... | tool://... | connector://...
  authority_and_context_requirements:
    - scope:* | policy://... | context-profile://...
  privacy_cost_quality_and_latency_refs:
    - privacy_posture://... | quote://... | benchmark://... | sla://...
  availability_ref: schedule://... | null
  status: offered | eligible | allocated | suspended | withdrawn | revoked
```

When a participant advertises an `ai://...` or `package://...` descriptor but a
frontier needs a generic capability coordinate, the hosted matcher may derive
the reversible alias `capability://advertised/<scheme>/<tail>`. The alias is
valid only while the underlying participant advertisement remains admitted; it
is not a new credential or a trust-on-first-use capability.

Eligibility matching is evidence admission, not allocation or execution
authority. The receipt freezes every input coordinate a later claim must
revalidate. Offer-side requirements are constraints that require independent
proof; they never count as evidence of their own satisfaction. Until the owner
plane can resolve a `scope:*`, `context-profile://...`, `policy://...`, or other
offer prerequisite, matching refuses typed-unavailable. Claim admission
recomputes the exact prerequisite coverage and rechecks resource-offer expiry
against freshly committed wallet.network `resolved_at_ms` immediately before
linearization:

```yaml
WorkEligibilityMatchReceipt:
  receipt_ref: receipt://...
  outcome_room_ref: outcome-room://...
  frontier_item_ref: frontier://...
  frontier_revision: integer
  frontier_control_hash: hash
  participant_ref: participant-lease://...
  participant_revision: integer
  participant_control_hash: hash
  resource_offers:
    - offer_ref: resource-offer://...
      revision: integer
      control_hash: hash
  capability_offers:
    - offer_ref: capability-offer://...
      revision: integer
      control_hash: hash
  context_lease_refs:
    - context_lease://...
  authority_resource_compute_data_budget_and_tool_lease_refs:
    - grant://... | resource-lease://... | compute://... |
      view://... | budget://... | tool-lease://...
  requirement_coverage:
    - requirement_ref: canonical ref
      matched_exactly: true
  offer_prerequisite_coverage:
    - offer_ref: resource-offer://... | capability-offer://...
      prerequisite_refs:
        - scope:* | policy://... | context-profile://... | canonical ref
      proof_refs:
        - grant://... | context-lease://... | receipt://... | canonical ref
  allocation_created: false
  execution_authority_granted: false
  claim_created: false
  authority_grant_id: grant://...
  principal_authority_binding: required
  effect_hash: hash
  output_hash: hash
```

## WorkFrontierItemEnvelope

The work frontier is the room's claimable graph of questions, problems,
hypotheses, tasks, reviews, verification needs, and resource needs. It supports
conductor assignment, pull-based claims, independent replication, and dynamic
taskforces under one contract.

```yaml
WorkFrontierItemEnvelope:
  frontier_item_id: frontier://...
  room_admission: RoomAdmittedObjectBase
  item_kind:
    question | problem | hypothesis | task | review_need |
    verification_need | resource_need | synthesis_need
  objective: string
  dependency_refs:
    - frontier://... | attempt://... | finding://...
  related_attempt_and_finding_refs:
    - attempt://... | finding://...
  required_capability_refs:
    - capability://... | worker://... | tool://...
  required_context_resource_authority_and_evidence_refs:
    - context-profile://... | resource://... | scope:* | evidence://...
  expected_value: number | null
  uncertainty: number | null
  priority: number | null
  duplication_policy:
    exclusive | allowed | encouraged | independent_replication_required
  claimability:
    open | invited_only | assigned | paused | closed
  max_concurrency: integer | null
  expires_at: timestamp | null
  stop_condition_ref: policy://... | null
  status:
    open | claimed | blocked | replicating | verifying |
    accepted | rejected | superseded | closed
```

## WorkClaimLeaseEnvelope

```yaml
WorkClaimLeaseEnvelope:
  work_claim_id: work-claim://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  frontier_item_ref: frontier://... | null
  claimant_ref:
    participant-lease://... | system://... | domain://... |
    worker://... | service://... | agent://... | org://...
  claimant_participant_lease_ref: participant-lease://... | null
  eligibility_match_receipt_ref: receipt://... | null
  task_offer_ref: packet://... | null
  task_acceptance_ref: packet://... | null
  routing_decision_ref: routing-decision://... | null
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_acceptance_ref: receipt://...
  contribution_policy_ref: policy://...
  quote_ref: quote://... | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
  settlement_profile_ref: policy://...
  bounded_scope_ref: task://... | task_brief://... | policy://...
  context_lease_refs:
    - context_lease://...
  authority_resource_compute_data_budget_and_tool_lease_refs:
    - grant://... | resource-lease://... | compute://... | view://... |
      budget://... | tool-lease://...
  duplicate_work_policy:
    exclusive | allowed | independent_replication | adversarial_replication
  issued_at: timestamp
  expires_at: timestamp
  heartbeat_ref: heartbeat://... | receipt://... | null
  renewal_count: integer
  release_or_reassignment_reason: string | null
  status:
    proposed | active | waiting | released | expired | reassigned |
    completed | quarantined | revoked
```

`active` is the executable award. It requires the exact accepted terms root,
an admitted `CollaborationTermsAcceptanceReceipt`, any selected task response
and routing decision, the required context/resource/tool/budget leases,
applicable authority, and a room/domain admission receipt.
Room-scoped claims additionally require a current participant lease and
non-null room admission bound to the same room/frontier; its terms-acceptance
receipt must be the one bound by that participant lease. Direct bilateral AIIP
work leaves those room fields null but requires a claimant-bound terms-
acceptance receipt and receiving-domain admission. Discovery, terms acceptance,
or selection alone cannot activate work.

The terms-acceptance receipt must have current `acceptance_status: accepted`
and remain inside `effective_until`; a withdrawn, superseded, revoked, or
time-expired acceptance cannot activate or renew a claim.

For an external solicitation, the selected response must be a member of the
routing decision's candidate response set, have `status: accepted`, name the
same `accepted_by` principal as the routing selection and claim, and bind the
same terms root as the offer, routing decision, acceptance receipt, and claim.
The claim's quote and budget reservation must match the selected response and
routing decision. Counteroffers must first become a newly accepted terms root;
they cannot be selected under the superseded offer root.

An active claim's `expires_at` must not exceed the terms expiry or terms-
acceptance `effective_until`. Continuation beyond either bound requires the
already accepted renewal or outstanding-obligation policy and a new admitted
lease/receipt; it is never inferred from work already being in progress.

## AttemptEnvelope

Attempts preserve positive, negative, inconclusive, invalid, exploit-finding,
and superseded work. A non-winning attempt remains durable when it contributes
information, reproduction evidence, debugging, integrity findings, resources,
review, or synthesis.

Hosted Attempt admission freezes the exact room-control, frontier, active claim,
participant-lease, and GoalRun coordinates that authorized the declaration. The
record hashes and revisions are historical evidence, not a requirement that
mutable claim, participant, or frontier state remain byte-identical forever.
Attempt creation and participant-governed work transitions still re-resolve the
same identities and require the exact claim to be active/current; later host
admission, supersession, Finding admission, and Finding lifecycle may use the
immutable historical identities after claim completion or release. Submitted
OutcomeDelta refs must be exact plane-owned backlinks of the submitted
WorkResult and must independently resolve to that same result, room, and goal.
The Attempt record is provenance over an already admitted GoalRun; creating or
transitioning it does not launch work or grant execution authority.

```yaml
AttemptEnvelope:
  attempt_id: attempt://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://...
  goal_run_ref: goal://... | null
  frontier_item_ref: frontier://... | null
  work_claim_ref: work-claim://... | null
  participant_ref:
    participant-lease://... | system://... | worker://... | agent://...
  bound_coordinates:
    outcome_room: { record_ref: outcome-room://..., host_domain_ref: domain://..., control_hash: hash }
    frontier_item: { record_ref: frontier://..., outcome_room_ref: outcome-room://..., revision: integer, record_hash: hash }
    work_claim: { record_ref: work-claim://..., outcome_room_ref: outcome-room://..., frontier_item_ref: frontier://..., claimant_ref: participant-lease://..., revision: integer, record_hash: hash }
    participant_lease: { record_ref: participant-lease://..., outcome_room_ref: outcome-room://..., principal_ref: worker://... | agent://..., revision: integer, record_hash: hash }
    goal_run: { record_ref: goal://..., outcome_room_ref: outcome-room://..., updated_at: timestamp | null, record_hash: hash }
  declared_method_and_hypothesis_refs:
    - method://... | finding://... | artifact://...
  parent_and_derivation_refs:
    - attempt://... | artifact://... | finding://...
  input_state_and_environment_refs:
    - state://... | environment://... | worktree://... | dataset://...
  worker_model_resolver_tool_and_runtime_version_refs:
    - worker://... | model_route://... | harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | tool://.../revision/... |
      runtime://...
  authority_and_policy_refs:
    - grant://... | policy://...
  resource_and_cost_refs:
    - resource-lease://... | spend://... | ledger://...
  outcome_class:
    positive | negative | inconclusive | invalid | exploit_found | superseded
  work_result_ref: work-result://... | null
  outcome_delta_refs:
    - outcome-delta://...
  artifact_evidence_and_receipt_refs:
    - artifact://... | evidence://... | receipt://... | ledger://...
  verifier_refs:
    - verifier_path://... | verifier-challenge://...
  reproduction_state:
    unreviewed | reproducible | not_reproduced | contradicted | invalidated
  artifact_license_ip_retention_and_export_refs:
    - license://... | policy://...
  contribution_refs:
    - contribution://... | receipt://...
  status: draft | running | submitted | admitted | challenged | accepted | rejected | superseded
```

## FindingEnvelope

Operational admission of a finding proves that the domain admitted a
provenance-bearing assertion; it does not make the proposition universally
true. Findings therefore preserve uncertainty, applicability, contradiction,
time, and dispute state.

A hosted Finding freezes its exact admitted Attempt, WorkResult, historical
participant identity, and optional same-room predecessor Finding coordinates
together with evidence and proof refs. Fresh Finding creation requires that exact
participant lease to be active at authorization and commit, but does not require
an active/current claim. Once admitted, host-governed Finding lifecycle uses the
historical identity coordinates after participant retirement, revocation, or
other inactivity; mutable participant records need not remain byte-identical.
`supersedes_ref` must strictly resolve to a Finding in the same room; a merely
syntactic or cross-room predecessor never establishes lineage. `admitted` is
still an admission state, not acceptance or a verifier verdict.

```yaml
FindingEnvelope:
  finding_id: finding://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  attempt_ref: attempt://...
  work_result_ref: work-result://...
  participant_ref: participant-lease://...
  proposed_by_ref:
    participant-lease://... | system://... | worker://... |
    service://... | org://... | domain://...
  bound_coordinates:
    attempt: { record_ref: attempt://..., outcome_room_ref: outcome-room://..., participant_ref: participant-lease://..., work_result_ref: work-result://..., revision: integer, record_hash: hash }
    work_result: { record_ref: work-result://..., outcome_room_ref: outcome-room://..., goal_run_ref: goal://..., goal_ref: goal://..., updated_at: timestamp | null, record_hash: hash }
    participant_lease: { record_ref: participant-lease://..., outcome_room_ref: outcome-room://..., principal_ref: worker://... | agent://..., revision: integer, record_hash: hash }
    supersedes_finding: { record_ref: finding://..., outcome_room_ref: outcome-room://..., revision: integer, record_hash: hash } | null
  proposition: string
  finding_kind:
    hypothesis | observation | claim | negative_result | integrity_incident |
    mapping_claim | causal_claim | counterexample | synthesis
  confidence_or_uncertainty: number | null
  valid_time: interval | null
  transaction_time: timestamp
  source_and_observation_context_refs:
    - attempt://... | observation://... | participant-lease://... | domain://...
  supporting_evidence_refs:
    - evidence://... | artifact://... | receipt://...
  proof_refs:
    - evidence://... | artifact://... | receipt://...
  contradicting_evidence_refs:
    - evidence://... | artifact://... | finding://...
  applicability_and_counterexample_refs:
    - policy://... | finding://... | ontology://...
  provenance_ontology_and_mapping_refs:
    - provenance://... | ontology://... | ontology-mapping://...
  proposed_effect_refs:
    - frontier://... | routing-prior://... | policy://... | capability://...
  supersedes_ref: finding://... | null
  dispute_ref: dispute://... | null
  status:
    branch_local | proposed | admitted | contradicted | superseded |
    disputed | rejected | archived
```

## VerifierChallengeEnvelope

```yaml
VerifierChallengeEnvelope:
  verifier_challenge_id: verifier-challenge://...
  outcome_room_ref: outcome-room://... | null
  room_admission: RoomAdmittedObjectBase | null
  challenger_ref: participant-lease://... | system://... | worker://... | org://... | user://...
  challenged_ref:
    attempt://... | finding://... | verifier_path://... | benchmark://... |
    rubric://... | evidence://... | eligibility://... | decision://...
  challenge_kind:
    metric | rule | verifier | evidence | eligibility | result |
    exploit | independence | collusion | mapping
  challenge_evidence_refs:
    - evidence://... | artifact://... | receipt://...
  adjudicator_policy_ref: policy://...
  prior_rule_version_ref: rubric://... | verifier_path://... | null
  proposed_rule_version_ref: rubric://... | verifier_path://... | null
  affected_attempt_refs:
    - attempt://...
  reverification_required: boolean
  adjudication_ref: decision://... | dispute://... | null
  status:
    proposed | admitted | investigating | upheld | rejected |
    rule_changed | reverifying | resolved | withdrawn
```
