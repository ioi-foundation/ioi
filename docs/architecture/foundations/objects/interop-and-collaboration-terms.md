# Interop, Dispute, and Collaboration-Terms Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of AIIP bounded-execution-domain identity and standards bindings, the dispute rail object family, and conditional-cooperation collaboration terms.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-29.
Doctrine status: canonical
Implementation status: mixed (`DisputeRailBundle` v1 has a registered schema, invariants, fixtures, and generated projections; the dispute kernel, AIIP transport and bindings, and conditional-cooperation terms remain planned; the owner-qualified `UpgradeProposalEnvelope` target-owner shape is a canon shape change with no registered contract, projection, or runtime route behind it)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../aiip.md`](../aiip.md);
this module does not restate them.

## AIIP and Bounded Execution Domain Envelopes

AIIP is the interoperation protocol for handoffs between independently governed
autonomous systems identified by distinct admitted `system_id` values. Local
GoalRun/HarnessInvocation, installed-Worker, member-node, and embodied-unit
routing uses native L0 GoalRun, RuntimeAssignment, lease, state/evidence, and
Embodied Runtime contracts rather than AIIP. Internal and external paths may
reuse common typed work, authority, idempotency, evidence, and receipt
conventions without collapsing their sovereignty boundary. Consequential AIIP
packets must compile into typed envelopes with policy, authority, receipt,
recovery, and declared settlement semantics.

This file owns the canonical field-level `AIIPChannelEnvelope` and
`AIIPEnvelope` schemas because they are shared boundary objects. The AIIP owner,
[`aiip.md`](../aiip.md), owns packet semantics, processing rules, protocol
profiles, conformance, and evolution. Other documents reference these schemas;
they must not publish a competing reduced envelope.

```yaml
AIIPExternalProtocolBindingEnvelope:
  schema_version: ioi.aiip-external-protocol-binding.v1
  binding_id: aiip-binding://...
  aiip_profile_ref: profile://...
  protocol_kind: native_aiip | a2a | mcp | http_json_rpc | grpc | oasf_directory | erc_8004 | erc_8183 | other
  protocol_name: string
  protocol_version_or_commitment: string
  specification_ref: https://... | artifact://... | cid://...
  identity_mapping_ref: schema://...
  lifecycle_and_status_mapping_ref: schema://... | null
  message_and_artifact_mapping_ref: schema://... | null
  error_and_retry_mapping_ref: schema://... | null
  extension_profile_refs: []
  required_runtime_tool_contract_refs: []
  required_authority_scope_refs: []
  assurance_non_equivalences: []
  conformance_profile_refs: []
  compatibility_range: string
  status: draft | active | deprecated | revoked
```

The binding preserves protocol-version drift and explicitly records what does
not map. A remote task completion, tool response, registry entry, reputation
record, or evaluator decision never silently becomes an IOI verification,
acceptance, authority grant, adjudication, or settlement state.

### Shared Settlement Selection Contract

Every concrete settlement intent, obligation, resolution, or mirror uses the
same settlement-selection fields:

```yaml
settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
settlement_profile_ref: policy://...
network_enrollment_ref: network-enrollment://... | null
public_commitment_policy_ref: policy://... | null
```

The `settlement_mode` member set is owned by
[`canonical-enums.md`](../canonical-enums.md#settlement-modes-settlement_mode).

The profile owns settlement triggers such as an explicit request, accepted
delivery, adjudicated remedy, or contract condition; those triggers are not
alternate rails. Registry, rights, license, reputation, and handoff-finality
operations use the network-service contract below and are not settlement
actions merely because they may have a fee. `local_domain` is the default and requires a null
enrollment ref. `ioi_l1` requires an active connected or secured enrollment
that selected the named service. Missing, expired, suspended, or mismatched
enrollment fails closed. Consequentiality, a signature, a receipt, or an AIIP
handoff never silently selects a public rail.

Long-lived containers such as domains, channels, systems, and collaborations do
not select one rail for every future counterparty. They declare a default,
allowed modes, and profile refs; each `SettlementIntentEnvelope` or
`SettlementEnvelope` selects the concrete mode, rail, and applicable party
enrollment. Party-specific enrollments never become one ambiguous shared
enrollment.

```yaml
BoundedExecutionDomainEnvelope:
  domain_id: domain://...
  owner_ref: wallet://... | org://... | project://... | ioi://publisher/...
  domain_kind: local_runtime | installed_worker | marketplace_worker | outcome_provider | enterprise_runtime | robot_fleet | dao_operator | autonomous_system | as_l1 | appchain | sovereign_domain
  manifest_ref: ai://...
  capabilities: []
  policies:
    policy_root: hash
    dispute_policy_ref: optional
    privacy_policy_ref: optional
  authority_requirements:
    authority_scope_requirements: []
    grant_requirements: []
  receipt_schema_refs: []
  state_boundary:
    state_root: optional_hash
    state_ref: optional agentgres://... | cid://...
    public_commitment_policy_ref: policy://... | null
  runtime_profile:
    kind: local_daemon | in_process | local_http | grpc | json_rpc | nats | hosted_daemon | cloud_vm | tee | depin | customer_vpc | robot_controller | external_api
    endpoint_ref: optional
  settlement_behavior:
    settlement_account_ref: optional
    default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    allowed_settlement_modes: []
    settlement_profile_refs: []
    network_enrollment_refs: []
    public_commitment_policy_ref: policy://... | null
    escrow_supported: boolean
  aiip_profiles_supported: []
  status: draft | active | suspended | revoked | archived
```

The retired `local_microharness` discriminator may be accepted only by an
explicit compatibility adapter and must normalize to `local_runtime` before
admission. A GoalRunProfile or HarnessProfile is not itself an execution
domain; the admitted local runtime/domain executing its invocations is.
Likewise, a local or installed Worker, process, node, robot, or domain object
does not become an AIIP peer merely by having a distinct runtime endpoint. It
acts behind an independently governed System identity; routing within the same
`system_id` remains L0.

Robot fleets, robot controllers, drones, vehicles, facility systems, IoT
actuators, and other embodied domains are allowed bounded execution domains,
but they must not treat actuator effects as ordinary tool traffic. When a
domain can perform `physical_action`, its envelope should bind physical-action
safety posture explicitly:

```yaml
physical_action_safety:
  physical_action_policy_refs:
    - policy:...
  safety_envelope_refs:
    - safety:...
  emergency_stop_authority_ref: estop:...
  human_supervision_policy_ref: supervision:... | null
  incident_policy_ref: policy:...
  required_receipt_schema_refs:
    - schema:SensorEvidenceReceipt
    - schema:ActuatorCommandReceipt
```

The canonical owner for these objects is
[`physical-action-safety.md`](../physical-action-safety.md). AIIP may carry
handoffs and command envelopes, but actuator-affecting actions still require
safety envelope semantics, wallet.network authority, daemon gating, evidence,
and receipts.

```yaml
AIIPChannelEnvelope:
  channel_id: aiip://channel/...
  system_id_from: system://...
  system_id_to: system://... # required to differ from system_id_from
  endpoint_channel_enrollments:
    - system_id: system://... # exactly system_id_from
      governance_boundary_ref: constitution://... | policy://...
      operational_truth_ref: agentgres://...
      channel_enrollment_decision_ref: decision://...
      channel_enrollment_receipt_ref: receipt://...
    - system_id: system://... # exactly system_id_to
      governance_boundary_ref: constitution://... | policy://...
      operational_truth_ref: agentgres://...
      channel_enrollment_decision_ref: decision://...
      channel_enrollment_receipt_ref: receipt://...
  profile: marketplace_worker | outcome_service | autonomous_system | collaborative_pursuit | enterprise
  transport: in_process | daemon_ipc | unix_socket | local_http | grpc | json_rpc | nats | https | queue | chain_relay
  external_protocol_binding_ref: aiip-binding://... | null
  schema_version: ioi.aiip-channel.v1
  relay_policy_ref: optional
  authority_policy_ref: optional
  privacy_mode: public | private | encrypted | redacted | permissioned_evidence
  default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  allowed_settlement_modes: []
  settlement_profile_refs: []
  party_network_enrollment_refs:
    - party_ref: system://... | domain://...
      network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  sequence_root: optional_hash
  status: opening | active | paused | closing | closed | disputed
```

The two endpoint enrollment entries are mandatory, distinct, and exact: each
independently governed System admits its own participation in this channel
through its governance and truth paths. `in_process`, `daemon_ipc`,
`unix_socket`, and `local_http` remain legal AIIP transports only under that
two-System condition; use of the same transports inside one System is L0.
These endpoint channel enrollments are separate from the optional
`party_network_enrollment_refs` that select IOI Network services.

```yaml
AIIPEnvelope:
  schema_version: ioi.aiip-envelope.v1
  packet_id: packet://...
  message_type: capability_discovery | task_offer | task_acceptance | handoff |
    semantic_profile_negotiation | collaboration_terms_proposal |
    collaboration_terms_response | room_discovery | room_participation |
    frontier_update |
    work_claim | attempt_finding | verifier_challenge | room_admission |
    authority_query | authority_grant | receipt_commitment | delivery_update |
    acceptance_decision | settlement_intent | dispute | dispute_resolution |
    reputation_query
  system_id_from: system://...
  system_id_to: system://... # distinct from system_id_from and exact channel endpoints
  channel_id: aiip://channel/...
  external_protocol_binding_ref: aiip-binding://... | null
  sequence_or_nonce: string
  idempotency_key: string
  causation_ref: packet://... | event://... | receipt://... | null
  correlation_ref:
    goal://... | task://... | outcome-room://... | collaboration://... | null
  timestamp_or_slot: string
  profile: marketplace_worker | outcome_service |
    autonomous_system | collaborative_pursuit | enterprise
  policy_hash: hash
  authority_ref: optional grant://...
  collaboration_envelope_ref: collaboration://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  outcome_room_ref: outcome-room://... | null
  ontology_profile_refs:
    - ontology://... | semantic-profile://... | ontology-mapping://...
  action_schema_profile_refs:
    - ontology-action://... | action_schema://... | schema://...
  restricted_view_refs:
    - restricted_view://... | view://...
  verifier_challenge_refs:
    - verifier-challenge://...
  payload_hash: hash
  payload_ref: optional artifact://... | cid://... | encrypted_ref
  receipt_obligations: []
  verifier_and_acceptor_refs: []
  assurance_stage: optional attested | evidenced | verified | accepted |
    adjudicated | settled
  effect_recovery_class: optional replayable | checkpointable | compensatable |
    reconciliation_required | non_retryable
  settlement_terms:
    settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    settlement_profile_ref: policy://...
    network_enrollment_ref: network-enrollment://... | null
    public_commitment_policy_ref: policy://... | null
    settlement_account_ref: optional
    escrow_ref: optional
    dispute_window: optional
  signature:
    scheme: ed25519 | secp256k1 | ml-dsa | hybrid
    public_key_ref: string
    signature: base64
```

```yaml
CapabilityDescriptorEnvelope:
  descriptor_id: artifact://... | ai://...
  domain_id: domain://... | system://... | worker://...
  capabilities: []
  sparse_worker_category_refs: []
  receipt_schema_refs: []
  authority_scope_requirements: []
  runtime_profile_refs: []
  pricing_ref: optional
  reputation_context_refs: []
  signature: optional
```

```yaml
TaskOfferEnvelope:
  offer_id: packet://...
  task_id: task://...
  offered_by: system://... | domain://...
  offered_to: system://... | domain://... | worker://... | service://... | null
  collaboration_ref: collaboration://... | null
  outcome_room_ref: outcome-room://... | null
  frontier_item_ref: frontier://... | null
  solicitation_mode: directed | invited | open
  discovery_ref: room-discovery://... | null
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  task_payload_hash: hash
  constraints_ref: optional
  authority_requirements: []
  receipt_obligations: []
  quote_required: boolean
  counteroffer_allowed: boolean
  budget_and_funding_refs:
    - goal-budget://... | budget://... | escrow://... |
      procurement://... | order://...
  candidate_eligibility_policy_refs:
    - policy://... | conformance_profile://... | certification_claim://...
  selection_policy_ref: policy://...
  verifier_and_acceptance_refs:
    - verifier_path://... | rubric://... | gate://... | policy://...
  settlement_terms_ref: policy://... | terms://... | null
  expires_at: timestamp
  status: draft | open | withdrawn | expired | superseded
```

```yaml
TaskAcceptanceEnvelope:
  acceptance_id: packet://...
  offer_id: packet://...
  accepted_by: system://... | domain://... | worker://... | service://...
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  terms_response: accept | counteroffer | decline
  counterterms_ref: terms://... | null
  price_quote_ref: quote://... | null
  sla_ref: sla://... | null
  proposed_method_and_delivery_refs:
    - method://... | schedule://... | sla://... | artifact://...
  requested_scope_or_term_change_refs:
    - policy://... | terms://...
  authority_requirements: []
  receipt_obligations: []
  settlement_terms_ref: policy://... | terms://... | null
  valid_until: timestamp
  response_hash: hash
  signature: required
  status: accepted | rejected | counteroffered | expired
```

The response fields are conditional and fail closed on contradiction:

- `terms_response: accept` requires `status: accepted` until `valid_until` (and
  may become `expired` afterward), a null `counterterms_ref`, and the exact
  terms root advertised by the offer;
- `terms_response: counteroffer` requires `status: counteroffered` until
  `valid_until` (and may become `expired` afterward), a non-null
  `counterterms_ref` naming a new terms root, and
  `counteroffer_allowed: true` on the offer;
- `terms_response: decline` requires `status: rejected` and a null
  `counterterms_ref`;
- `quote_required: true` on the offer requires a non-null `price_quote_ref` on
  any accepted or counteroffered response; and
- `response_hash` binds the offer, responding party, response kind, original
  terms ref/root, counterterms ref when present, quote, SLA, method/delivery,
  requested changes, receipt obligations, settlement terms, and validity. The
  signature binds that response hash.

An open solicitation may receive many responses. A response is not selected
or executable merely because it is signed or accepted by its author.

```yaml
HandoffEnvelope:
  handoff_id: packet://...
  task_id: task://...
  from_domain: system://... | domain://...
  to_domain: system://... | domain://...
  predecessor_receipt_root: optional_hash
  authority_ref: optional grant://...
  handoff_policy_hash: hash
  settlement_intent_ref: optional settlement-intent://...
  status: proposed | accepted | in_progress | completed | rejected | disputed
```

```yaml
ReceiptCommitmentEnvelope:
  receipt_commitment_id: packet://...
  task_id: task://...
  domain_id: system://... | domain://... | worker://...
  receipt_root: hash
  inclusion_proof_ref: optional
  artifact_commitment_refs: []
  policy_hash: hash
  authority_ref: optional grant://...
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
```

```yaml
DeliveryUpdateEnvelope:
  delivery_update_id: packet://...
  task_id: task://...
  service_order_ref: optional service://... | order://...
  buyer_domain_ref: system://... | domain://... | wallet://...
  provider_domain_ref: system://... | domain://... | service://...
  delivery_refs: []
  milestone_ref: optional
  status: draft | partial | submitted | accepted | rejected | revision_requested | disputed | cancelled
  artifact_refs: []
  evidence_refs: []
  local_receipt_root: optional_hash
  remote_receipt_root: optional_hash
  disclosure_mode: public_root | private_body | encrypted_body | dispute_gated
  settlement_intent_ref: optional settlement-intent://...
  created_at: timestamp
```

```yaml
AcceptanceDecisionEnvelope:
  acceptance_decision_id: packet://...
  delivery_update_ref: packet://... | delivery://...
  decider_ref: system://... | wallet://... | org://... | policy://... | domain://...
  decision: accept | accept_partial | reject | request_revision | open_dispute
  acceptance_criteria_refs: []
  quality_refs: []
  evidence_refs: []
  settlement_intent_ref: optional settlement-intent://...
  dispute_ref: optional dispute://...
  status: drafted | submitted | admitted | challenged | final
```

```yaml
SettlementIntentEnvelope:
  settlement_intent_id: settlement-intent://...
  task_id: task://...
  claimant_ref: system://... | domain://... | worker://... | service://... | wallet://...
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  work_claim_ref: work-claim://... | null
  contribution_refs:
    - contribution://... | receipt://...
  acceptance_decision_refs:
    - acceptance://... | packet://... | decision://...
  budget_reservation_ref: budget://... | spend://... | escrow://... | null
  settlement_account_ref: optional
  receipt_condition_refs: []
  payment_terms_ref: optional
  reputation_event_refs: []
  dispute_window: optional
  settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  settlement_profile_ref: policy://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  status: drafted | submitted | accepted | challenged | settled | rejected | expired
```

## Dispute Rail Object Family

The dispute family keeps the policy, one owner-produced case snapshot, and one
admitted resolution distinct:

```text
versioned DisputeRailProfileEnvelope
  -> append-only DisputeEnvelope head
  -> DisputeResolutionEnvelope
  -> owner-executed remedy / bond distribution / receipts
```

V1 has one deliberately strict denomination rule. `disputed_value_units`,
`remedy_units`, both bond holds, the total bond pool, and every bond-allocation
leg use the same exact `DisputeValueUnitBinding`. There is no implicit
conversion, price oracle, decimal reinterpretation, or substitution between
money, Work Credits, tokens, points, or differently deployed forms of an
asset. A case needing separately denominated bonds or remedies requires a
future explicit conversion contract with version, rate source, rounding,
freshness, slippage, and authority rules; it cannot overload v1.

```yaml
DisputeValueUnitBinding:
  asset_ref: asset://...
  unit_ref: denomination://...
  unit_version: positive_integer
  unit_body_hash: sha256:...
  atomic_unit_code: string
  decimals: nonnegative_integer

DisputeRailProfileEnvelope:
  dispute_rail_profile_ref: policy://dispute/...
  profile_version: positive_integer
  profile_body_hash: sha256:JCS(profile body without this field)
  rail_kind:
    internal_review | marketplace_escrow | aiip_dispute | public_settlement
  value_unit: DisputeValueUnitBinding
  ordinary_verification_funding_ref: budget://... | null
  challenger_bond_units: nonnegative_integer
  respondent_bond_units: nonnegative_integer
  evidence_window_ms: positive_integer
  response_window_ms: positive_integer
  appeal_window_ms: positive_integer
  evidence_unavailable_default:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  respondent_timeout_default:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  allowed_remedies:
    - none | refund | partial_refund | payout | partial_payout | slash |
      retry | revise | escalate
  outcome_rules:
    - outcome:
        challenger_upheld | respondent_upheld | partial | no_fault | escalated
      remedy:
        none | refund | partial_refund | payout | partial_payout | slash |
        retry | revise | escalate
      maximum_remedy_bps_of_disputed_value: 0..10000
      bond_distribution:
        challenger_return_bps: 0..10000
        respondent_return_bps: 0..10000
        challenger_award_bps: 0..10000
        respondent_award_bps: 0..10000
        verifier_funding_bps: 0..10000
        treasury_bps: 0..10000
        burn_bps: 0..10000
        rounding_recipient:
          challenger_return | respondent_return | challenger_award |
          respondent_award | verifier_funding | treasury | burn

DisputeEnvelope:
  dispute_ref: dispute://...
  dispute_rail_profile_ref: policy://dispute/...
  dispute_rail_profile_version: positive_integer
  dispute_rail_profile_body_hash: sha256:...
  value_unit: DisputeValueUnitBinding
  challenged_ref: typed_ref
  challenger_ref: typed_ref
  respondent_ref: typed_ref
  opened_at_ms: integer
  evidence_retained_until_ms: integer
  disputed_value_units: nonnegative_integer
  challenger_bond_hold_ref: hold://... | null
  challenger_bond_held_units: nonnegative_integer
  respondent_bond_hold_ref: hold://... | null
  respondent_bond_held_units: nonnegative_integer
  escrow_ref: escrow://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: sha256:... | null
  settlement_profile_ref: policy://... | null
  network_enrollment_ref: network-enrollment://... | null
  case_head_hash: sha256:...

DisputeResolutionEnvelope:
  dispute_resolution_ref: dispute-resolution://...
  dispute_ref: dispute://...
  dispute_rail_profile_ref: policy://dispute/...
  dispute_rail_profile_version: positive_integer
  dispute_rail_profile_body_hash: sha256:...
  rail_kind:
    internal_review | marketplace_escrow | aiip_dispute | public_settlement
  value_unit: DisputeValueUnitBinding
  case_head_hash: sha256:...
  request_hash: sha256:JCS(exact resolution request)
  idempotency_key: string
  adjudicator_ref: typed_ref
  decided_at_ms: integer
  evidence_refs: []
  response_refs: []
  appeal_of_resolution_ref: dispute-resolution://... | null
  outcome:
    challenger_upheld | respondent_upheld | partial | no_fault | escalated
  remedy:
    none | refund | partial_refund | payout | partial_payout | slash |
    retry | revise | escalate
  remedy_units: nonnegative_integer
  bond_pool_units: nonnegative_integer
  bond_allocation:
    challenger_return_units: nonnegative_integer
    respondent_return_units: nonnegative_integer
    challenger_award_units: nonnegative_integer
    respondent_award_units: nonnegative_integer
    verifier_funding_units: nonnegative_integer
    treasury_units: nonnegative_integer
    burn_units: nonnegative_integer
  used_evidence_unavailable_default: boolean
  used_respondent_timeout_default: boolean
  appeal_deadline_ms: integer
  required_receipt_kinds:
    - dispute_resolution
    - bond_distribution
    - dispute_remedy_execution | dispute_escalation
  resolution_state:
    proposed | admitted | appealed | superseded | execution_pending |
    executed | execution_failed
```

Invariants:

- The case and resolution bind the exact profile ref, version, and canonical
  body hash. They also repeat the exact value-unit binding; any asset, unit ref,
  unit version, body hash, code, or decimal substitution fails closed.
- Portable numeric fields are fixed-point integers no greater than
  `9,007,199,254,740,991`. Floating-point bond, value, remedy, or allocation
  amounts are invalid.
- `internal_review` has zero bonds and no bond-hold refs.
  `marketplace_escrow` binds its escrow. `aiip_dispute` binds exact
  CollaborationTerms and ordinary verification funding.
  `public_settlement` binds its settlement profile and active network
  enrollment.
- Each required default names an outcome rule. Each rule's bond distribution
  totals exactly 10,000 basis points. Integer allocation assigns the remainder
  to the declared rounding recipient, and all allocation legs sum exactly to
  the held pool.
- Non-value remedies (`none`, `retry`, `revise`, `escalate`) have zero value
  cap and zero `remedy_units`. A selected value remedy cannot exceed its
  profile cap over `disputed_value_units`.
- Evidence retention covers the evidence, response, and actual resolution
  appeal windows. Unavailable-evidence and respondent-timeout defaults cannot
  run before their respective deadlines.
- Same idempotency key plus the same exact request hash replays the prior
  decision. Changed bytes conflict. A replay decision must still bind the same
  dispute, profile, value unit, rail, and case head.
- A resolution admits a decision and allocation plan only. It does not prove
  evidence truth, escrow custody, remedy execution, value movement, receipt
  emission, appeal finality, or public settlement inclusion.

The registered
`schema://ioi/foundations/dispute-rail-bundle/v1` contract carries one exact
profile/case/resolution projection without creating a second dispute owner.

```yaml
ReputationEventEnvelope:
  reputation_event_id: receipt://...
  subject_ref: system://... | domain://... | worker://... | service://...
  context_ref: benchmark://... | rubric://... | service://... | sparse_category | custom
  event_type: delivery_accepted | delivery_rejected | dispute_opened | dispute_resolved | slash | refund | benchmark_result | reliability_update | routing_quality
  score_commitment: optional_hash
  receipt_ref: receipt://...
  policy_hash: hash
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

AIIP envelopes may reference private or encrypted payload bodies. IOI L1 may
receive only commitments selected by an active enrollment and settlement
profile; private bodies remain off-chain.

## CollaborationTermsEnvelope

`CollaborationTermsEnvelope` is the exact ex-ante bargain for voluntary
cross-party work. It makes the objective, required parties, bounded work,
rights, disclosure, contribution eligibility, consideration, risk, exit, and
settlement conditions inspectable without requiring a party to reveal its raw
private valuation or outside option. Discovery, a shared goal, or a compatible
AIIP channel creates no duty to accept these terms.

```yaml
CollaborationTermsEnvelope:
  schema_version: ioi.collaboration-terms.v1
  collaboration_terms_id: terms://...
  version: semver_or_hash
  predecessor_terms_ref: terms://... | null
  terms_body_hash_profile: ioi.collaboration-terms-body.v1
  terms_body_root: hash
  scope:
    collaboration_ref: collaboration://... | null
    outcome_room_ref: outcome-room://... | null
    task_refs:
      - task://... | frontier://...
    order_or_service_refs:
      - order://... | service://...
    aiip_channel_refs:
      - aiip://channel/...
  proposed_by_ref:
    system://... | domain://... | org://... | service://... |
    participant-lease://...
  party_roles:
    - party_ref:
        system://... | domain://... | org://... | wallet://... |
        service://... | provider://...
      role:
        data_owner | worker_provider | compute_provider | coordinator |
        customer | auditor | regulator | insurer | verifier |
        settlement_counterparty
      acceptance_required: boolean
  activation:
    rule: bilateral | unanimous_required_parties | required_roles | threshold
    threshold:
      required: nonnegative_integer
      eligible: nonnegative_integer
    required_role_set: []
    activation_policy_ref: policy://...
    activation_decision_ref: decision://... | null
    acceptance_receipt_refs:
      - receipt://...
  cooperation_conditions:
    eligibility_policy_refs:
      - policy://... | conformance_profile://... | certification_claim://...
    required_evidence_refs:
      - evidence://... | receipt://...
    active_participant_lease_required: boolean
    required_context_and_view_policy_refs:
      - context-profile://... | restricted_view://... | policy://...
    authority_requirement_refs:
      - scope:* | policy://...
    deliverable_and_acceptance_refs:
      - schema://... | rubric://... | gate://... | policy://...
    verifier_and_independence_policy_refs:
      - verifier_path://... | policy://...
  rights_and_obligations:
    allowed_work_scope_refs:
      - task://... | frontier://... | policy://...
    artifact_license_and_ip_refs:
      - license://... | policy://...
    confidentiality_privacy_retention_and_export_refs:
      - policy://... | privacy_posture://... | restricted_view://...
    attribution_and_audit_policy_refs:
      - policy://... | audit_export://...
    challenge_dispute_and_remedy_policy_refs:
      - policy://... | dispute://...
    exit_and_outstanding_obligation_policy_refs:
      - policy://...
  contribution_terms:
    contribution_policy_ref: policy://...
    eligible_contribution_kinds: []
    negative_and_inconclusive_result_eligibility:
      excluded | attribution_only | reward_eligible_when_accepted
    attribution_and_derivation_policy_ref: policy://...
    minimum_reward_assurance_stage:
      evidenced | verified | accepted | adjudicated | settled
    reward_basis_ref: policy://... | rate-card://... | quote://... | null
    self_report_creates_payout_right: false
  economics:
    funding_and_budget_refs:
      - goal-budget://... | budget://... | escrow://... |
        procurement://... | order://...
    consideration_kinds:
      - payment | outcome_right | reciprocal_access | license | royalty |
        portable_reputation | reusable_learning | shared_risk_reduction |
        strategic_benefit
    quote_required: boolean
    allowed_settlement_modes: []
    settlement_profile_refs:
      - policy://...
    payout_condition_refs:
      - acceptance://... | receipt://... | policy://...
    ordinary_work_credit_substitution: prohibited
  participant_rationality:
    each_required_party_accepts_expected_net_benefit: true
    participation_decision_refs:
      - decision://... | receipt://...
    raw_private_valuation_disclosure: prohibited_by_default | optional
  term:
    effective_at: timestamp | null
    expires_at: timestamp | null
    renewal_policy_ref: policy://...
    suspension_policy_ref: policy://...
    termination_policy_ref: policy://...
  amendment:
    amendment_policy_ref: policy://...
    requires_new_terms_root: true
    existing_acceptance_carries_forward: false
    retroactive_rewrite: forbidden
  proposer_signature: required
  status:
    draft | proposed | active | suspended | superseded |
    expired | terminated | revoked
```

At least one scope ref must be non-null. `active` requires the declared
activation rule, exact-root acceptance by every required party or role, and
domain admission. Acceptance attests that the party's own governed decision
found participation permissible and worthwhile under its private policy; it
does not prove objective surplus, disclose a reservation price, grant
authority, award work, or create a payout. A new terms root requires new
acceptance and never rewrites already admitted contribution or reward bases.

`terms_body_root` uses the canonical
`ioi.collaboration-terms-body.v1` projection. It hashes the immutable normative
body: schema version, terms identity/version/predecessor, scope, proposer
identity, party roles,
activation rule/threshold/required roles/policy, cooperation conditions,
rights and obligations, contribution terms, economics, rationality rule, term,
and amendment rule. It excludes `terms_body_root` itself,
`activation.activation_decision_ref`,
`activation.acceptance_receipt_refs`,
`participant_rationality.participation_decision_refs`, `proposer_signature`,
and lifecycle `status`. The proposer signature signs the resulting root and
the proposer identity. Activation decisions, acceptance receipts, and status
transitions bind that root but never alter it.

Activation rules have one interpretation across implementations:

- `bilateral` requires exactly two distinct required parties and both accepted;
- `unanimous_required_parties` requires every distinct party with
  `acceptance_required: true`;
- `required_roles` requires at least one accepted distinct party for each
  `required_role_set` member, in addition to every explicitly required party;
- `threshold` requires `1 <= required <= eligible`, counts distinct parties
  rather than roles or keys, and never bypasses a party marked
  `acceptance_required: true`.

One principal may occupy several roles but counts once toward a distinct-party
threshold or independence rule. An invalid or zero threshold cannot activate
terms.

```yaml
MultiPartyCollaborationEnvelope:
  collaboration_id: collaboration://...
  goal_ref: goal://... | task://... | order://... | service://...
  outcome_room_ref: outcome-room://... | null
  coordinator_ref: domain://... | system://... | agent://... | org://...
  active_collaboration_terms_ref: terms://... | null
  active_collaboration_terms_root: hash | null
  party_terms_acceptances:
    - party_ref:
        system://... | domain://... | org://... | wallet://... |
        service://... | provider://...
      collaboration_terms_ref: terms://...
      accepted_terms_root: hash
      acceptance_ref: receipt://...
      accepted_at: timestamp
      status: accepted | withdrawn | superseded | revoked
  terms_amendment_refs:
    - terms://... | proposal://... | decision://...
  coordination_topology:
    hosted_admission | federated_admission
  coordination_and_ordering_policy_ref: policy://...
  shared_state_admission_owner_ref: system://... | domain://... | policy://...
  conflict_failover_and_adjudication_policy_refs:
    - policy://...
  party_refs:
    - party_ref: system://... | org://... | wallet://... | domain://... | service://... | provider://...
      role: data_owner | worker_provider | compute_provider | coordinator | customer | auditor | regulator | insurer | verifier | settlement_counterparty
      domain_ref: domain://... | system://... | agentgres://domain/... | null
      operator_and_affiliation_refs:
        - org://... | provider://... | wallet://...
      model_runtime_and_infrastructure_dependency_refs:
        - model_route://... | runtime://... | node://... | provider://...
      authority_provider_refs:
        - authority://... | wallet://... | policy://...
      revocation_ref: revocation://... | null
      status: invited | active | suspended | removed | revoked | observer_only
  allowed_shared_refs:
    - artifact://... | receipt://... | evidence://... | view://... |
      restricted_view://... | redacted_summary://... | aiip://channel/... |
      delivery://... | audit_export://...
  blocked_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - non_opted_in_training_trace
  policy_bound_data_view_refs:
    - view://...
  restricted_view_refs:
    - restricted_view://...
  aiip_channel_refs:
    - aiip://channel/...
  handoff_refs:
    - packet://...
  authority_refs_by_party:
    - party_ref: system://... | org://... | wallet://... | domain://...
      authority_refs:
        - grant://... | authority://... | policy://...
  evidence_bundle_refs:
    - evidence://... | assurance_evidence://...
  delivery_bundle_refs:
    - delivery://...
  contribution_refs:
    - contribution://... | receipt://...
  settlement_intent_refs:
    - settlement-intent://... | settlement://...
  audit_export_profile_refs:
    - audit_export://... | policy://...
  settlement_policy:
    default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
    allowed_settlement_modes: []
    settlement_profile_refs: []
    party_network_enrollment_refs:
      - party_ref: system://... | org://... | wallet://... | domain://...
        network_enrollment_ref: network-enrollment://... | null
    public_commitment_policy_ref: policy://... | null
  history_policy:
    party_removal_effect: no_new_access | revoke_live_access | tombstone_view |
      rotate_views
    historical_receipts: immutable | sealed | export_limited
  status:
    proposed | active | blocked | delivery_submitted | accepted |
    revision_requested | disputed | settled | revoked | archived
```

`MultiPartyCollaborationEnvelope` is the policy and proof context for multiple
organizations, domains, workers, providers, auditors, or regulators
collaborating on one autonomous outcome without collapsing ownership,
authority, or privacy boundaries. It is not a shared raw chat context and not a
new global database. It is an admitted context over refs, views, authorities,
AIIP handoffs, delivery state, contribution state, export profiles, and
immutable proof.

The collaboration may become `active` only when the referenced terms activation
rule is satisfied. A new terms version never carries forward party acceptance
silently. Party discovery, invitation, messaging, or presence in `party_refs`
creates no work obligation, context or authority right, award, contribution
eligibility, or payout.

Every `party_terms_acceptances[].acceptance_ref` resolves to an admitted
`CollaborationTermsAcceptanceReceipt` whose party, role, terms ref/root, scope,
and current acceptance status match the collaboration. A signed packet or bare
decision may be its cause but is not the admitted proof.

Multiplicity is not sufficient for this boundary. Several model routes,
workers, runtime nodes, clouds, or keys controlled by one operator remain one
party when one principal controls authority, revocation, operational truth,
risk, verification, and settlement. A model or cloud provider is normally a
disclosed dependency or subprocessor, not a room party, unless its owning
principal accepts room-level rights, obligations, challenge, evidence, or
settlement roles. `party_refs` and affiliation/dependency refs must make those
relationships visible.

Collaboration history is not rewritten when a party is removed. Revocation
stops future access, rotates or tombstones live views when policy requires it,
and preserves historical receipt roots, contribution refs, and dispute/audit
evidence under the relevant restricted-view and export policies.

```yaml
ServiceModuleManifestEnvelope:
  module_id: module://...
  manifest_ref: ai://...
  module_type: classifier | planner | router | policy | authority | execution_adapter | mutation | verifier | observer | evidence | settlement | projection | upgrade_proposal | other
  version: semver_or_hash
  publisher_id: ioi://publisher/...
  input_schema_ref: cid://... | artifact://...
  output_schema_ref: cid://... | artifact://...
  primitive_capabilities_required: []
  authority_scopes_required: []
  policy_profile_ref: optional
  receipt_obligations: []
  benchmark_profile_refs: []
  upgrade_policy_ref: optional
  status: draft | active | deprecated | revoked
```

```yaml
ModuleInvocationEnvelope:
  invocation_id: invocation://...
  module_id: module://...
  module_version: semver_or_hash
  system_id: system://...
  hypervisor_node_id: node://...
  acting_node_membership_ref: node-membership://... | null
  ordering_admission_finality_profile_ref: ordering-profile://...
  writer_epoch: nonnegative_integer | null
  ordering_or_finality_proof_ref: evidence://... | null
  sequence: nonnegative_integer | null
  expected_predecessor_commitment_ref: commitment://... | null
  operation_or_batch_commitment: hash | null
  resulting_transition_commitment_ref: commitment://... | null
  admission_proof_ref: evidence://... | receipt://... | null
  input_hash: hash
  predecessor_state_root: hash
  resulting_state_root: optional_hash
  policy_hash: hash
  authority_grant_refs: []
  receipt_refs: []
  transition_id: optional transition://...
  status: proposed | admitted | executed | verified | committed | rejected | failed
```

```yaml
UpgradeProposalEnvelope:
  proposal_id: proposal://...
  target_owner_ref: user://... | org://... | project://... | system://... | domain://...
  system_id: system://... | null
  originating_work_subject: TypedWorkSubjectBinding | null
  proposal_profile: standard | improvement_promotion | improvement_agenda_patch
  change_class: release_upgrade | ordinary_upgrade | constitutional_amendment | deployment_change | membership_change | lifecycle_transition | network_enrollment_change
  target_kind: package_release | policy_module | service_module | workflow_graph | goal_run_profile | workflow_template | harness_profile | skill_manifest | runtime_tool_contract | evaluator | improvement_agenda | improvement_governance_profile | contract | tool_binding | model_route | memory_schema | projection_schema | settlement_rule | dispute_rule | authority_envelope | constitution | deployment_profile | node_membership | failover_profile | ordering_admission_finality_profile | oracle_evidence_profile | lifecycle_continuity_profile | network_enrollment
  target_ref: string
  current_manifest_ref: package://.../release/... | null
  proposed_manifest_ref: package://.../release/... | null
  proposed_by: system://... | agent://... | worker://... | wallet://... | org://...
  diff_ref: artifact://... | cid://...
  predecessor_target_root: hash
  proposed_target_root: hash
  required_decision_profile_ref: policy://...
  expected_effects_ref: optional
  simulation_receipt_refs: []
  benchmark_receipt_refs: []
  improvement_promotion:
    campaign_ref: improvement-campaign://... | null
    agenda_revision_and_item_refs: []
    candidate_attempt_or_artifact_ref: attempt://... | artifact://... | null
    evaluation_epoch_ref: evaluation-epoch://... | null
    improvement_evidence_claim_refs: []
    improvement_order_cutoff_receipt_refs: []
    statistical_selection_decision_ref: decision://... | artifact://... | null
    selection_policy_and_observation_refs: []
    complexity_maintainability_and_monitorability_refs: []
    independent_reproduction_refs: []
    activation_mode: direct | shadow | canary | cohort | target_owner_defined | null
    activation_policy_ref: policy://... | null
    rollback_recall_containment_compensation_and_reconciliation_refs: []
    irreversible_effect_recovery_ref: policy://... | artifact://... | null
  policy_hash: hash
  status: drafted | submitted | approved | rejected | escalated | committed | rolled_back
```

`target_owner_ref` names the owner whose governance decides this change, and it
is the envelope's only owner field. Its admissible kinds are exactly the owner
kinds canon already recognizes for this family; the set introduces no new owner
kind. `user://...`, `org://...`, `project://...`, and `system://...` are the
`owner_ref` set of `ImprovementAgendaEnvelope`, `ImprovementCampaignEnvelope`,
and `ImprovementGovernanceProfileEnvelope`
([`bounded-improvement.md`](./bounded-improvement.md),
[`bounded-system-genesis.md`](./bounded-system-genesis.md)); `domain://...` is
admitted because `GoalRunEnvelope` and `WorkLifecycleRecordEnvelope` already
carry it in their own `owner_ref`
([`goal-run-execution.md`](./goal-run-execution.md),
[`work-results-and-lifecycle.md`](./work-results-and-lifecycle.md)). A proposal
never mints an owner, and an unlisted owner scheme fails admission.

`system_id` is non-null exactly when `target_owner_ref` is a `system://...`
ref, and it must then equal that ref. A `user://...`, `org://...`,
`project://...`, or `domain://...` target owner requires `system_id: null`.
Two shapes fail admission: a non-null `system_id` under a non-System target
owner, and a null `system_id` under a System target owner. This matches the
paired `owner_ref`/`system_id` shape its sibling Agenda, Campaign, and
improvement-governance-profile envelopes already use, and it matches the
decision side, where `UpgradeDecisionEnvelope.decided_by` already admits
`wallet://...`, `org://...`, `policy://...`, and `governance://...` deciders
alongside `system://...`. The proposal was the only member of the family that
required a System unconditionally.

`originating_work_subject` records which admitted work produced the candidate.
It carries the shared `TypedWorkSubjectBinding`
([`work-execution.md`](./work-execution.md)), so its `kind` and `ref` must
agree and it remains non-owning: it confers no authority, is never required to
equal `target_owner_ref`, and a proposer's work subject never becomes the
target owner. It is null when no admitted work subject produced the proposal.

A standalone GoalRun, direct Session, AutomationSpec run, or Project may
therefore file a proposal with no System in existence whenever the target it
names is owned by a non-System owner; proposing against a System-owned target
binds that System's existing `system_id` and still never requires the proposer
to mint one. Neither case forces System genesis, which is the promise stated by
[`core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md).
A Session reaches this path through the GoalRun it activates, whose
`source_context_binding.target_session_ref` retains the session; `session://`,
`goal://`, and `work_run://` are work subjects here, never owner kinds.

Whether a System is required is a property of the change class and target kind,
never of the envelope shape. Five change classes are System-scoped by
definition and admit only a `system://...` target owner with a matching non-null
`system_id`: `constitutional_amendment`, `deployment_change`,
`membership_change`, `lifecycle_transition`, and `network_enrollment_change`.
The same requirement follows the target: `constitution`, `deployment_profile`,
`node_membership`, `failover_profile`, `ordering_admission_finality_profile`,
`oracle_evidence_profile`, `lifecycle_continuity_profile`, and
`network_enrollment` resolve to bounded-System objects that each require their
own `system_id`, so naming one of them under a non-System target owner fails
admission. `release_upgrade` and `ordinary_upgrade` carry no System requirement
of their own and inherit whatever their named target requires. A System-scoped
proposal therefore keeps exactly the strength it held when `system_id` was
unconditional: the same bound `system_id`, the same constitution-declared
decision path, and the same protected-change routing.

Protected target kinds route through the decision path declared by the active
constitution when the target owner is a System, and otherwise through the owner
scope's declared governance path named by `required_decision_profile_ref`.
Ordinary upgrade approval is insufficient in either case. Agents may propose a
constitutional amendment only when the constitution permits it; they never
self-commit one, and no non-System owner has a constitutional-amendment path at
all.

Implementation status: this owner-qualified shape is canon only. No registered
schema, invariant set, fixture, generated projection, or runtime route emits or
accepts `target_owner_ref`, `originating_work_subject`, or a null `system_id`
on this envelope; the receipt registry in
[`events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md)
still publishes the `upgrade_proposal` receipt without them. A registered
contract revision must land before any wire consumer reads or writes the
owner-qualified shape.

`improvement_promotion` is non-null only when `proposal_profile` is
`improvement_promotion`; otherwise every nested field is null or empty. It
freezes the campaign/epoch evidence used to propose one target-owner change but
does not create another promotion decision. The proposal's
`predecessor_target_root` remains the optimistic-concurrency base. A stale base
fails admission: rebase, conflict resolution, or atomic composition creates a
new candidate lineage and requires fresh applicable evaluation rather than a
clerical update to an approved proposal. `improvement_agenda_patch` always
targets an immutable successor Agenda revision and can affect only future
campaign admissions.

```yaml
UpgradeDecisionEnvelope:
  decision_id: decision://...
  proposal_id: proposal://...
  decision: approve | reject | escalate | rollback
  decided_by: system://... | wallet://... | org://... | policy://... | governance://...
  approval_grant_ref: optional
  policy_hash: hash
  receipt_refs: []
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

```yaml
StateTransitionCommitmentEnvelope:
  state_transition_commitment_id: transition://...
  system_id: system://...
  hypervisor_node_id: node://...
  acting_node_membership_ref: node-membership://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  writer_epoch: nonnegative_integer | null
  ordering_or_finality_proof_ref: evidence://... | null
  sequence: nonnegative_integer
  expected_predecessor_commitment_ref: commitment://...
  operation_or_batch_commitment: hash
  resulting_transition_commitment_ref: commitment://...
  admission_proof_ref: evidence://... | receipt://...
  transition_kind: module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation
  operation_ref: agentgres://...
  predecessor_state_root: optional_hash
  resulting_state_root: hash
  receipt_root: hash
  external_settlement_ref: settlement://... | null
```

`writer_epoch` is required only when the active ordering profile declares
`writer_epoch_required: true`. Threshold/BFT/external-finality transitions bind
their declared ordering or finality proof instead; a null writer epoch never
means an untracked writer.

`system_id` is the only canonical logical-system field name. Legacy
`autonomous_system_id` and `autonomous_system_chain_id` keys may be accepted
only by a versioned migration adapter, must normalize to `system_id` before
admission, and must not be emitted by canonical v1+ envelopes or projections.

A proposed module invocation may leave acting membership and ordering proof
null before admission. An admitted or committed invocation must bind the acting
membership plus either the required writer epoch or the active profile's
ordering/finality proof; it cannot rely on the later transition commitment to repair
missing admission identity.
