# Billing, Settlement, and Contribution Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of managed-work billing, settlement, network service invocation, and contribution objects.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (`ManagedWorkBillingLedgerBundle` v1 has a registered schema, invariants, fixtures, and generated projections; the managed-work billing kernel, settlement, and contribution rails remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../economic-flywheel-and-pricing-boundaries.md`](../economic-flywheel-and-pricing-boundaries.md);
this module does not restate them.

## Managed Work Billing Object Family

Managed-work billing is one immutable, append-only product-budget chain:

```text
versioned RateCard + versioned Plan
  -> immutable WorkQuote
  -> finite CreditHold
  -> append-only UsageRecord entries
  -> typed OverrunDecision -> exact additional CreditHold or block
  -> one FinalDebit
  -> append-only BillingAdjustment records (refund or writeoff)
```

All money uses integer currency-minor units. Work Credits use integer
`micro_work_credit` units. Floating-point amounts, ambiguous decimal strings,
and implicit unit conversion are invalid. Money, Work Credits, and coarse OCU
telemetry are different dimensions and never share an amount field.

```yaml
WorkCreditAmount:
  unit: micro_work_credit
  units: nonnegative_safe_integer

ManagedWorkCostBreakdown:
  currency_code: ISO-4217-code
  provider_cost_minor: nonnegative_safe_integer
  broker_fee_minor: nonnegative_safe_integer
  participant_cost_minor: nonnegative_safe_integer
  verifier_cost_minor: nonnegative_safe_integer
  ioi_fee_minor: nonnegative_safe_integer
  excluded_customer_borne_provider_cost_minor: nonnegative_safe_integer
  supplier_reconciliation_state:
    not_applicable | estimated | supplier_statement_reconciled
```

`provider_cost_minor` records managed supplier cost only.
`broker_fee_minor`, `participant_cost_minor`, `verifier_cost_minor`, and
`ioi_fee_minor` remain separately attributable. BYOK, BYOA, customer-cloud,
self-hosted, and local execution put customer-borne provider cost only in
`excluded_customer_borne_provider_cost_minor`; that excluded amount cannot
enter the Work Credit debit. The Work Credit charge comes from the quoted
RateCard, not by adding these money fields.

```yaml
RateCard:
  rate_card_ref: rate-card://...
  version: positive_integer
  body_hash: canonical_exact_body_hash
  currency_code: ISO-4217-code
  meter_rates:
    - meter_class: string
      work_credit_micro_units_per_meter_unit: nonnegative_safe_integer
      charge_component:
        managed_model | managed_runtime | broker | participant | verifier |
        ioi_managed_service | non_billable_telemetry
  ioi_fee_policy_ref: fee-basis://...
  issued_at_ms: integer
  expires_at_ms: integer

Plan:
  plan_ref: plan://...
  version: positive_integer
  body_hash: canonical_exact_body_hash
  rate_card_ref: rate-card://...
  rate_card_body_hash: hash
  included_work_credits: WorkCreditAmount
  reset_policy:
    non_resetting | monthly_expiring | contract_term_expiring
  issued_at_ms: integer
  expires_at_ms: integer

WorkQuote:
  quote_ref: quote://...
  body_hash: canonical_exact_body_hash
  rate_card_ref: rate-card://...
  rate_card_body_hash: hash
  plan_ref: plan://...
  plan_body_hash: hash
  estimated_work_credits: WorkCreditAmount
  required_hold: WorkCreditAmount
  overrun_policy: block | exact_additional_hold
  max_attempt_count: positive_integer
  allowed_commercial_postures:
    - managed | customer_byok | customer_byoa | customer_cloud |
      self_hosted | local
  issued_at_ms: integer
  expires_at_ms: integer
```

A RateCard or Plan is a versioned immutable revision. A quote freezes their
exact refs and body hashes, its own finite expiry, permitted commercial
postures, route-attempt ceiling, hold amount, and exact overrun policy.
Quote admission fails when the RateCard or Plan is expired, the quote outlives
either input, or any referenced body hash differs. Reusing a quote ref with
different canonical bytes is a conflict, never an update.

```yaml
CreditHold:
  hold_ref: credit-hold://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  idempotency_key: string
  hold_kind: initial | exact_additional
  overrun_decision_ref: overrun-decision://... | null
  amount: WorkCreditAmount
  created_at_ms: integer
  expires_at_ms: integer
  status: active | consumed | released

UsageRecord:
  usage_ref: usage://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  sequence: positive_integer
  previous_usage_hash: hash | null
  runtime_receipt_refs: [receipt://...]
  supplier_statement_refs: [supplier-statement://...]
  meter_class: string
  quantity_units: nonnegative_safe_integer
  rate_work_credit_micro_units_per_meter_unit: nonnegative_safe_integer
  charged_work_credits: WorkCreditAmount
  commercial_posture:
    managed | customer_byok | customer_byoa | customer_cloud |
    self_hosted | local
  cost_breakdown: ManagedWorkCostBreakdown
  coarse_ocu_projection: boolean
  occurred_at_ms: integer
```

The first hold is positive, finite, no larger than the quote's required hold,
and no later than the quote expiry. An additional hold requires the exact
unconsumed `OverrunDecision`, amount, usage head, and quote. Same
idempotency-key plus same canonical command bytes replays the existing result;
same key plus different bytes is a conflict.

Every UsageRecord binds one or more owner-derived runtime receipts. Sequence
and `previous_usage_hash` form an unbroken append-only usage chain. A conforming
future kernel must re-resolve the frozen rate and compute
`quantity_units * work_credit_micro_units_per_meter_unit` with checked integer
arithmetic; a caller-supplied charge or stale usage head is invalid. Managed
provider cost can claim `supplier_statement_reconciled` only with matching
supplier-statement evidence. Customer-borne postures require
`provider_cost_minor: 0`. A coarse OCU projection is always
`non_billable_telemetry` and cannot mint invoice-grade usage or a Work Credit
debit.

```yaml
OverrunDecision:
  overrun_decision_ref: overrun-decision://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  usage_head_hash: hash | null
  held_work_credits: WorkCreditAmount
  projected_work_credits: WorkCreditAmount
  exact_overage_work_credits: WorkCreditAmount
  decision: block | exact_additional_hold
  additional_hold_amount: WorkCreditAmount
  created_at_ms: integer

FinalDebit:
  final_debit_ref: final-debit://...
  body_hash: canonical_exact_body_hash
  quote_ref: quote://...
  usage_head_hash: hash | null
  usage_record_refs: [usage://...]
  hold_refs: [credit-hold://...]
  debited_work_credits: WorkCreditAmount
  finalized_at_ms: integer

BillingAdjustment:
  adjustment_ref: billing-adjustment://...
  body_hash: canonical_exact_body_hash
  final_debit_ref: final-debit://...
  previous_adjustment_hash: hash | null
  adjustment_kind: refund | writeoff
  amount: WorkCreditAmount
  reason_code: string
  evidence_refs: [receipt://... | supplier-statement://... | decision://...]
  created_at_ms: integer
```

An overrun decision binds the current usage head, current active held amount,
and exact projected total. `block` requires zero additional amount.
`exact_additional_hold` is valid only when selected by the quote and requires
an additional hold equal to the checked projected-total-minus-held-total
overage. Usage cannot cross the active held amount before that hold is durably
appended.

FinalDebit is unique per quote, binds the current usage head and complete usage
and hold sets, and equals the checked sum of chargeable UsageRecords. Finalizing
twice, appending usage after finalization, or debiting more than active held
Work Credits fails closed. A BillingAdjustment is append-only and downward-only
in v1: refund and writeoff remain distinct reasons, bind the FinalDebit and
prior adjustment head, and their cumulative amount cannot exceed the one debit.
This record does not itself transfer money, replenish a credit balance, settle
a supplier invoice, or execute a refund rail.

```yaml
ManagedWorkBillingLedgerBundle:
  schema_version: ioi.foundations.managed-work-billing-ledger-bundle.v1
  bundle_ref: billing-bundle://...
  billing_account_ref: billing-account://...
  work_ref: goal://... | goal-run://... | automation-run://... |
    work-run://... | invocation://... | order://...
  rate_card: RateCard
  plan: Plan
  quote: WorkQuote
  holds: [CreditHold]
  usage_records: [UsageRecord]
  overrun_decisions: [OverrunDecision]
  final_debit: FinalDebit | null
  adjustments: [BillingAdjustment]
  ledger_head_hash: hash
  exported_at_ms: integer
  assurance_status:
    internal_event_log | supplier_partially_reconciled | supplier_reconciled
```

The bundle is a portable projection of the append-only ledger, not a mutable
invoice. Its `ledger_head_hash` commits the ordered entry chain. A conforming
future store must admit only owner-derived runtime, billing-account, and
supplier evidence; no public caller-authored supplier-usage mint is defined.
Supplier reconciliation is claimable only when the corresponding statement
refs have been resolved and verified by their owner. The registered v1 contract
is
[`managed-work-billing-ledger-bundle.v1.schema.json`](../../_meta/schemas/managed-work-billing-ledger-bundle.v1.schema.json).

## SettlementEnvelope

```yaml
SettlementEnvelope:
  schema_version: ioi.settlement.v2
  settlement_id: settlement://...
  system_id: system://... | null
  settlement_domain_ref: domain://...
  subject_ref: system://... | order://... | delivery://... | task://... | worker://... | service://... | package://... | license://... | contract://... | account://... | contribution://... | settlement-intent://... | network-service-invocation://...
  settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
  settlement_profile_ref: policy://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  rail:
    network_or_ledger_ref: agentgres://... | network://... | chain://... | invoice://... | null
    contract_ref: contract://... | null
    payer_account_ref: wallet://... | account://... | null
    payee_account_ref: wallet://... | account://... | null
    asset_kind: none | fiat | stablecoin | native_asset | service_credit
    asset_identifier: string | null
    amount: decimal_string | null
  product_budget_ref: budget://... | null
  work_credit_debit_ref: receipt://... | null
  action: obligation_create | obligation_update | payment_request | payment_record | payment_acknowledge | adjustment | escrow_lock | payout_release | partial_payout | refund | partial_refund | slash | bond_lock | bond_release
  related_delivery_ref: delivery://... | null
  related_acceptance_decision_ref: acceptance://... | decision://... | null
  related_adjudication_ref: decision://... | dispute://... | null
  related_settlement_intent_ref: settlement-intent://... | null
  related_receipt_root: hash | null
  receipt_condition_refs: []
  settlement_receipt_refs: []
  status: drafted | submitted | pending | settled | disputed | reversed | failed
  ledger_or_transaction_ref: optional
```

`local_domain` is the default. `ioi_l1` is valid only when an active
`IOINetworkEnrollmentEnvelope` selects the matching service; no other mode
silently upgrades to it. Work Credits remain non-transferable product budget
units: `work_credit_debit_ref` may prove an IOI product-budget charge or refund,
but Work Credits are not the provider payout asset, protocol token, or generic
settlement rail. External money and chain rails declare their actual asset,
network, contract, accounts, authority, and receipt lineage.

Action availability is profile-conditional. Local-domain, bilateral, and
invoice modes use obligation, request, record, acknowledgement, and adjustment
actions without pretending an escrow payout occurred. Escrow, external-chain,
and IOI-L1 modes may additionally use lock, release, refund, bond, and slash
actions only when their declared contract and authority path support them.

Acceptance and adjudication are prerequisites/conditions, not settlement
actions. `SettlementEnvelope` references their decisions and may release or
reverse value, bonds, or contractually due consideration only after the declared conditions pass; it cannot create
acceptance or resolve a dispute by relabeling a settlement action.

## NetworkServiceInvocationEnvelope

Selected registry, rights, license, reputation, and handoff-finality services
are orthogonal to the rail used to pay for them. They use this profile-neutral
contract rather than overloading `SettlementEnvelope`:

```yaml
NetworkServiceInvocationEnvelope:
  schema_version: ioi.network-service-invocation.v1
  network_service_invocation_id: network-service-invocation://...
  system_id: system://... | null
  subject_ref: system://... | domain://... | worker://... | service://... | package://... | license://... | delivery://... | contribution://... | commitment://...
  service_kind: registry | rights | reputation | finality
  service_subprofile: worker_license | artifact_license | dataset_license | handoff_finality | null
  operation: register | publish | commit | issue | transfer | revoke | finalize | challenge
  service_ref: service://...
  terms_ref: terms://...
  network_or_domain_ref: network://... | domain://...
  network_enrollment_ref: network-enrollment://... | null
  public_commitment_policy_ref: policy://... | null
  expected_predecessor_commitment_ref: commitment://... | null
  request_root: hash
  governing_decision_ref: decision://... | null
  authority_grant_refs: []
  resulting_commitment_ref: commitment://... | tx://... | null
  service_receipt_refs: []
  status: proposed | authorized | submitted | committed | challenged | rejected | failed
```

An IOI Network service invocation requires an active connected or secured
enrollment that selected the matching `service_kind`; a local or external
service names its own domain/network and leaves that enrollment null. The
service's selection and public-commitment policy govern the operation. Its fee
may settle through any allowed settlement mode, so `ioi_l1` settlement is
required only when IOI L1 is itself the selected economic rail.

## ContributionEnvelope

```yaml
ContributionEnvelope:
  contribution_id: contribution://...
  contributor_ref:
    system://... | participant-lease://... | worker://... | service://... | ioi://publisher/... | tool://... |
    org://... | domain://...
  contributor_role:
    autonomous_system | worker | service | publisher | tool | verifier | reviewer |
    resource_provider | semantic_mapper | organization
  operator_ref: user://... | wallet://... | org://... | domain://... | null
  affiliation_refs: []
  consumer_id: system://... | wallet://... | service://... | agent://...
  task_ref: task://... | null
  run_ref: run://... | null
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  task_offer_and_acceptance_refs:
    - packet://...
  work_claim_ref: work-claim://... | null
  room_admission: RoomAdmittedObjectBase | null
  attempt_finding_and_result_refs:
    - attempt://... | finding://... | work-result://... | outcome-delta://...
  contribution_kind:
    planning | execution | generation | worker_invocation | service_delivery |
    tool_use | model_use | dataset_use | workflow_use | resource_provision |
    debugging | review | verification | replication | negative_result |
    integrity_report | semantic_mapping | verifier_hardening | curation |
    synthesis | training_data | distilled_training_data | training_service |
    benchmark_submission | routing_selection | verifier_signal
  usage_hash: hash
  sparse_worker_category: optional
  benchmark_profile_ref: optional
  routing_decision_ref: routing-decision://... | null
  reward_basis_ref:
    policy://... | rate-card://... | quote://... | order://... |
    budget://... | null
  attributed_model_and_route_refs:
    - model://... | model_route://... | registry_version://...
  downstream_outcome_ref: optional
  derivation_refs:
    - contribution://... | attempt://... | artifact://... | finding://...
  assurance_stage:
    attested | evidenced | verified | accepted |
    adjudicated | settled
  dispute_status: none | pending | upheld | rejected | no_fault
  quality_delta: optional
  reward_claim: optional
  license_ref: optional
  receipt_ref: receipt://...
```

A model or model route may be attributed as a cognition dependency and
  `model_use` contribution kind, but it is not the accountable protocol or
economic actor by itself. `contributor_ref` therefore names the Worker,
system, service, publisher, tool, organization, or domain boundary that accepted the
contribution obligations; model and route identity remains in
`attributed_model_and_route_refs`.

When `outcome_room_ref` is non-null, `participant_lease_ref` and
`room_admission` are required and must bind that same room; `contributor_ref`
must resolve through the lease. A raw system, worker, service, organization, or
domain ref cannot claim a room contribution outside admitted participation or
the room's compare-and-swap commitment spine.

When external or multi-party terms apply, the contribution binds the exact
terms root, selected response, routing decision, claim, and reward basis in
force when work was awarded. Later amendments cannot retroactively change its
attribution, eligibility, license, or reward basis. A contribution or receipt
establishes attributable work under declared terms; it is not itself an
allocation, acceptance, or payout decision.
