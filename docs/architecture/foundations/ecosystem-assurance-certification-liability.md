# Ecosystem Assurance, Certification, and Liability

Status: canonical architecture authority.
Canonical owner: this file for ecosystem assurance profiles, conformance and
certification posture, jurisdiction and compliance policy packs, abuse and
quarantine posture, liability and claims routing, and commercial assurance
exports.
Supersedes: plan prose that scatters certification, compliance, insurance,
abuse response, billing assurance, or customer audit exports across runtime,
wallet, marketplace, and product docs without a shared boundary.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: speculative (assurance/certification layer design)
Last implementation audit: 2026-07-05

## Canonical Definition

**Ecosystem Assurance is the source-neutral trust layer that makes IOI's
machine-economy substrate institutionally legible, certifiable, insurable,
auditable, and abuse-resistant without becoming a runtime, authority wallet,
state database, marketplace, or settlement layer.**

It binds:

- certification and conformance profiles;
- jurisdiction, compliance, and retention policy packs;
- compliance audit export bundles;
- insurance, liability, and claims routing hooks;
- abuse response, quarantine, and ecosystem advisories;
- billing, invoice, cost-center, SLA, and customer audit exports.

Short form:

```text
Owners do the work.
Receipts attest declared boundary facts.
Evidence, verification, acceptance, adjudication, and settlement establish
progressively stronger assurance states.
Assurance profiles explain whether the work, package, client, runtime, or
service is eligible for a trust posture.
```

This layer exists because autonomous systems cannot scale into enterprises,
regulated markets, embodied environments, or high-value service outcomes with
only raw execution receipts. They need portable ways to answer:

- Which profile does this worker, runtime, wallet client, MCP gateway, service,
  or embodied domain conform to?
- Which jurisdiction, data, retention, eligibility, or regulated-action policy
  applies?
- Which evidence bundle supports an audit, customer export, dispute, claim,
  or insurance review?
- Which abuse, vulnerability, marketplace, or physical incident requires
  restriction, quarantine, delisting, revocation, or public advisory?
- Which billing, SLA, acceptance, refund, bond, tax, or procurement record is
  tied to the performed work?

## Does Not Own

Ecosystem Assurance does not own:

- daemon execution, runtime scheduling, or effect semantics;
- wallet.network identity, secrets, authority grants, payments, approvals,
  revocation, or step-up;
- Agentgres operational truth, object heads, state roots, or projections;
- IOI L1 settlement, registry, bond, dispute, or governance contracts;
- aiagent.xyz worker listings, routing, ranking, or marketplace delisting truth;
- sas.xyz service orders, SLAs, delivery acceptance, refunds, or provider truth;
- Foundry training, evaluation, simulation, model registry, or promotion jobs;
- storage backend payload bytes;
- robot firmware, hardware certification, venue rules, or legal advice.

Assurance is the connective tissue. It declares profiles, binds evidence
requirements, projects posture, and routes claims or advisories to the owner
that can act.

## Research-Informed Shape

The durable pattern across mature assurance systems is not a one-time checklist.
It is a continuous loop:

```text
declare profile
  -> map system, actor, data, jurisdiction, authority, and risk context
  -> measure evidence against profile requirements
  -> manage posture, exceptions, incidents, claims, and improvement
  -> export or anchor attestations when trust boundaries require it
  -> repeat as versions, evidence, threats, laws, workers, runtimes, and services change
```

IOI should implement this as:

- **profiles** for expected controls and evidence;
- **policy packs** for jurisdiction and regulated-action rules;
- **receipts and evidence bundles** for observed behavior;
- **versioned verification, acceptance, adjudication, and settlement state**
  so a signed receipt is never mistaken for correctness or value;
- **posture projections** for operators, customers, marketplaces, and auditors;
- **claim/advisory workflows** for incidents, liability, and abuse response;
- **public anchors** only when external trust, disputes, bonds, registry,
  marketplace eligibility, or governance require them.

## Ownership Boundaries

```text
Ecosystem Assurance
  -> declares assurance profiles, policy packs, evidence requirements,
     posture projections, advisory semantics, claim routes, and export shapes

Hypervisor / Daemon
  -> executes work, enforces runtime profile gates, emits runtime receipts,
     exposes operator posture views

wallet.network
  -> owns identity, authority, payment, KYC/eligibility factors, step-up,
     revocation, secret custody, decryption, and grant receipts

Agentgres
  -> admits assurance-relevant operations, refs, evidence bundles, receipts,
     incidents, posture projections, and export validity

Foundry
  -> builds eval suites, executable eval worlds, scorecards, simulations,
     worker/model/package tests, trajectory evidence, and
     certification-support evidence

aiagent.xyz
  -> consumes worker/package certification posture, benchmark evidence,
     abuse advisories, delisting state, routing eligibility, and attribution

sas.xyz
  -> consumes SLA, service-order, delivery, claim, refund, bond, and customer
     audit posture for autonomous service outcomes

IOI L1
  -> anchors selected public certification roots, registry claims, disputes,
     bonds, slashing, marketplace rights, or governance commitments
```

No assurance profile may grant authority by itself. No certification badge may
skip daemon, wallet.network, Agentgres, policy, receipt, or settlement gates.

## Assurance Object Families

### `EcosystemAssuranceProfile`

`EcosystemAssuranceProfile` is the parent profile for a trust posture.

```yaml
EcosystemAssuranceProfile:
  profile_id: assurance_profile://...
  profile_type:
    ioi_compatible_worker |
    hypervisor_runtime |
    wallet_authority_client |
    hypervisor_mcp_gateway |
    embodied_runtime |
    service_outcome |
    foundry_training_pipeline |
    executable_eval_suite |
    storage_backend |
    marketplace_listing |
    custom
  version: semver
  issuer_ref: org:... | domain:... | governance_ref:...
  subject_kind:
    worker_package | managed_worker_instance | runtime_node |
    authority_client | mcp_gateway_profile | service_order |
    service_package | foundry_job | embodied_domain |
    executable_eval_suite | eval_world | storage_backend | domain_kernel
  required_evidence:
    - receipt_type: string
      requirement: string
  required_policy_refs:
    - policy://...
  required_conformance_refs:
    - conformance://...
  allowed_exception_policy_ref: policy://... | null
  revocation_policy_ref: policy://...
  public_anchor_policy:
    never | on_public_listing | on_dispute | on_bond | always
```

Profiles are portable contracts. They define what must be proven; they do not
prove the thing themselves.

### `ConformanceProfile`

`ConformanceProfile` is a narrower profile for protocol or runtime
compatibility.

```yaml
ConformanceProfile:
  profile_id: conformance_profile://...
  family:
    worker_endpoint | harness_adapter | runtime_node |
    wallet_authority_client | mcp_gateway | ctee_private_workspace |
    hypervisoros_node | embodied_runtime | service_endpoint |
    executable_eval_world | storage_backend | agentgres_domain
  version: semver
  required_interfaces:
    - interface_ref: api://...
  required_events:
    - event_type: string
  required_receipts:
    - receipt_type: string
  negative_tests:
    - condition: string
      expected: reject | fail_closed | quarantine
  compatibility_level:
    experimental | compatible | certified | restricted | revoked
```

Conformance is about interface and behavior compatibility. Certification may
consume conformance results, but conformance alone is not a legal, insurance,
or safety guarantee.

### `CertificationClaim`

`CertificationClaim` binds a subject to a profile, evidence, issuer, expiry,
and revocation posture.

```yaml
CertificationClaim:
  claim_id: certification_claim://...
  subject_ref: worker://... | runtime://... | wallet-client://... | service://...
  profile_ref: assurance_profile://...
  issuer_ref: org:... | domain:... | governance_ref:...
  evidence_bundle_refs:
    - evidence://...
  conformance_result_refs:
    - conformance_result://...
  scorecard_refs:
    - scorecard://...
  issued_at: timestamp
  expires_at: timestamp | null
  status:
    draft | active | restricted | suspended | revoked | expired
  public_anchor_ref: l1://... | null
  revocation_receipt_ref: receipt://... | null
```

Claims should expire or refresh when the subject, profile, dependency,
jurisdiction pack, runtime posture, evidence base, or threat model changes.

### `JurisdictionPolicyPack`

`JurisdictionPolicyPack` declares jurisdiction, eligibility, retention,
regulated-action, tax, and customer-export obligations in a machine-readable
shape.

```yaml
JurisdictionPolicyPack:
  pack_id: jurisdiction_policy_pack://...
  jurisdiction:
    country: string | null
    region: string | null
    sector: string | null
  applies_to:
    - action_class: string
    - data_class: string
    - service_class: string
  identity_requirements:
    kyc_required: boolean
    business_verification_required: boolean
    sanctions_screening_required: boolean
    accredited_or_professional_status_required: boolean
  authority_requirements:
    required_scopes:
      - scope:...
    step_up_required: boolean
    guardian_required: boolean
  data_requirements:
    retention_policy_ref: policy://...
    deletion_policy_ref: policy://... | null
    export_policy_ref: policy://... | null
    residency_policy_ref: policy://... | null
  regulated_action_rules:
    prohibited_actions:
      - string
    approval_required_actions:
      - string
    disclosure_required_actions:
      - string
  tax_and_commercial_refs:
    tax_profile_ref: tax://... | null
    invoice_profile_ref: invoice://... | null
  audit_requirements:
    evidence_profile_refs:
      - assurance_profile://...
```

Policy packs compile into existing owners:

- wallet.network identity, eligibility, payment, step-up, and authority gates;
- daemon policy checks and runtime fail-closed behavior;
- Agentgres retention, receipt, state-root, and export validity;
- marketplace listing restrictions;
- sas.xyz SLA, refund, bond, and provider obligations;
- IOI L1 public anchors when required.

The pack is not legal advice and not a substitute for domain-specific review.

### `AssuranceEvidenceBundle`

`AssuranceEvidenceBundle` packages evidence refs without becoming payload
storage or operational truth.

```yaml
AssuranceEvidenceBundle:
  bundle_id: assurance_evidence://...
  subject_ref: string
  profile_refs:
    - assurance_profile://...
  agentgres_refs:
    - agentgres://...
  receipt_refs:
    - receipt://...
  artifact_refs:
    - artifact://...
  scorecard_refs:
    - scorecard://...
  policy_refs:
    - policy://...
  wallet_authority_refs:
    - authority://...
  l1_anchor_refs:
    - l1://...
  redaction_profile_ref: policy://...
  export_policy_ref: policy://...
  validity:
    valid | incomplete | stale | disputed | revoked
```

Bundles should contain refs, hashes, roots, scorecards, and redacted summaries.
Raw private payloads remain under storage and wallet authority.

### `AssurancePostureProjection`

`AssurancePostureProjection` is the operator/customer view over a subject's
current posture.

```yaml
AssurancePostureProjection:
  projection_id: assurance_posture:...
  subject_ref: string
  current_profiles:
    - assurance_profile://...
  certification_status:
    certified | compatible | restricted | suspended | uncertified | revoked
  jurisdiction_status:
    allowed | requires_step_up | restricted | blocked | unknown
  abuse_status:
    clean | watch | restricted | quarantined | delisted | disputed
  liability_status:
    none | covered | claim_open | disputed | uncovered | unknown
  commercial_status:
    active | payment_required | invoice_pending | sla_at_risk |
    sla_breached | refund_pending | tax_export_required
  evidence_watermark: string
  last_checked_at: timestamp
```

Projections are rebuildable from Agentgres operations, receipts, policy packs,
wallet refs, marketplace state, service-order state, and public anchors.

### `ComplianceAuditExportBundle`

`ComplianceAuditExportBundle` is the governed export package for customer,
auditor, regulator, counterparty, procurement, or internal review. It composes
policy-pack decisions, approvals/denials, receipts, replay refs, evidence
bundles, retention/restricted-view posture, redaction manifests, commercial
refs, and optional public commitments for a specific audience.

It is not a storage backend, screenshot bundle, legal opinion, or replacement
for Agentgres truth. It is an export manifest over existing evidence.

```yaml
ComplianceAuditExportBundle:
  export_id: audit_export://...
  export_type:
    customer_audit | auditor_review | regulator_request |
    counterparty_dispute | procurement_review | internal_control |
    tax_report | sla_report | incident_review
  subject_refs:
    - run://... | task://... | service://... | order://... |
      worker://... | runtime://... | domain://... | account://...
  audience:
    customer | external_auditor | regulator | counterparty |
    insurer | procurement | internal_auditor | public
  jurisdiction_policy_pack_refs:
    - jurisdiction_policy_pack://...
  regulated_action_refs:
    - action://... | receipt://... | agentgres://operation/...
  policy_decision_refs:
    - receipt://... | policy://...
  approval_receipt_refs:
    - receipt://...
  denial_receipt_refs:
    - receipt://...
  authority_refs:
    - authority://... | grant://... | lease://...
  evidence_bundle_refs:
    - assurance_evidence://... | evidence://...
  receipt_refs:
    - receipt://...
  replay_refs:
    - replay://... | trace://...
  retention_lock_refs:
    - retention_lock://... | policy://...
  restricted_view_refs:
    - view://... | restricted_view://...
  redaction_profile_ref: policy://...
  export_policy_ref: policy://...
  declassification_refs:
    - receipt://... | policy://...
  export_manifest:
    included_refs:
      - receipt://... | artifact://... | evidence://...
    redacted_refs:
      - artifact://... | trace://...
    protected_payload_refs:
      - artifact://...
    excluded_refs:
      - artifact://...
    exclusion_reasons:
      - retention_locked | restricted_view | no_export_authority |
        protected_plaintext | unrelated | expired | policy_blocked
  commercial_refs:
    invoice_refs:
      - invoice://...
    cost_center_refs:
      - cost_center://...
    sla_report_refs:
      - sla://...
    tax_export_refs:
      - tax://...
    purchase_order_refs:
      - procurement://...
  l1_anchor_policy:
    local_only | optional_anchor | dispute_only | required_public_root
  l1_anchor_refs:
    - l1://...
  generated_by_ref: agentgres://operation/... | runtime://...
  generated_at: timestamp
  validity:
    valid | incomplete | stale | disputed | revoked
  status:
    requested | generated | delivered | revoked | superseded | expired
```

Audit export bundles must make three things obvious:

- what was included and why;
- what was redacted, withheld, protected, or excluded and why;
- which policy, authority, retention, restricted-view, receipt, and state-root
  refs support the export.

Raw private payloads remain under storage, retention, restricted-view, and
authority policy. A replay or proof view must not bypass the export manifest.

## Default Profile Families

### IOI-Compatible Worker

An `ioi_compatible_worker` profile should require:

- worker manifest and version;
- endpoint or harness-adapter contract;
- benchmark/eval profile and recent results;
- declared model route, harness, tools, connector, and runtime requirements;
- privacy and training-data posture;
- authority scope declarations;
- receipt obligations;
- dependency and package provenance;
- marketplace attribution posture;
- abuse/quarantine handling;
- license and commercial terms.

aiagent.xyz uses this posture for listing, ranking, install, routing, and
managed-instance eligibility. The profile does not make aiagent.xyz the runtime.

### Hypervisor Runtime Profile

A `hypervisor_runtime` profile should require:

- daemon API compatibility;
- runtime-node enrollment;
- receipts and replay support;
- Agentgres admission path;
- wallet authority request path;
- environment lifecycle posture;
- support-bundle and log-export policy;
- cTEE, TEE, HypervisorOS, or provider-trust posture when claimed;
- fail-closed behavior for unsupported effects.

Hypervisor uses this for runtime-node eligibility, provider placement,
operator posture, and customer audit exports.

### wallet Authority Client

A `wallet_authority_client` profile should require:

- exact request hashes;
- scope, expiry, risk class, amount, recipient, and policy visibility;
- no raw secret custody;
- step-up and guardian support where required;
- revocation epoch handling;
- origin binding and last-use visibility;
- compromised-client fail-closed behavior;
- quarantine and replacement-client handling;
- blast-radius evidence for grants, leases, sessions, WorkRuns, connectors, and
  gateway profiles;
- approval, denial, and use receipts;
- refusal to widen authority without a new grant.

wallet.network remains the authority owner. A certified client cannot authorize
itself.

### Hypervisor MCP Gateway Profile

A `hypervisor_mcp_gateway` profile should require:

- declared tool and surface contracts;
- primitive capability mapping;
- risk class mapping;
- wallet authority requirements;
- policy preview and user-understandable approval text;
- daemon-mediated invocation;
- receipt and replay obligations;
- connector secret non-custody;
- bound authority-client, origin, grant, lease, and policy refs;
- quarantine propagation to dependent sessions, WorkRuns, connectors, and
  pending approvals;
- fail-closed behavior for unknown tools, missing scopes, or stale policy.

The gateway remains an adapter profile. It is not a master key, provider secret
broker, or peer runtime.

### Embodied Runtime Profile

An `embodied_runtime` profile should require:

- robot/fleet identity and controller binding;
- sensor and actuator registries;
- current world model, map, zone, calibration, and environment state;
- local control bridge and heartbeat/failsafe behavior;
- physical command queue semantics;
- emergency-stop and operator handoff;
- sim-to-real promotion gates;
- telemetry and physical replay;
- incident, liability, and claims routing hooks;
- physical-action safety receipts.

This profile consumes Embodied Runtime and Physical Action Safety semantics. It
does not certify hardware, firmware, venue safety, or mechanical design.

### Service Outcome Profile

A `service_outcome` profile should require:

- service package or service-order contract;
- acceptance criteria;
- SLA terms;
- delivery bundle requirements;
- verifier refs;
- refund, dispute, bond, and slashing rules;
- customer audit export policy;
- contribution and attribution receipts;
- jurisdiction and tax policy where applicable.

sas.xyz owns service-order truth. Ecosystem Assurance only defines the profile
and evidence shape.

### Collaborative Pursuit Profile

An `outcome_room` assurance profile should require:

- declared hosted or federated shared-state admission and ordering;
- participant identity, operator, affiliation, model/runtime/provider
  dependencies, and independent-party posture;
- participant/context/authority/resource/budget/work-claim leases with TTL,
  heartbeat, quarantine, and revocation;
- privacy, retention, artifact license/export, contribution, and settlement
  policies that contributor scope cannot widen;
- hostile-input taint and isolated execution before admission;
- positive, negative, inconclusive, invalid, exploit-finding, and superseded
  attempt retention;
- verifier independence, rule versions, challenge/adjudication,
  re-verification, and anti-collusion controls;
- Sybil/rate-limit/backpressure/fair-allocation posture;
- contribution/derivation lineage and an explicit assurance stage for every
  claimed outcome or payout;
- room replay that reconstructs participation, claims, resources, evidence,
  authority, spend, course correction, and admission.

This profile does not make the assurance layer the room coordinator, verifier,
authority provider, truth substrate, or settlement judge.

## Jurisdiction And Compliance Packs

Jurisdiction and compliance packs are declarative constraints over otherwise
portable autonomous work.

They should support:

- personal, team, enterprise, and regulated-account eligibility;
- KYC, business verification, sanctions, accreditation, professional status, or
  venue eligibility requirements;
- AML, market-integrity, anti-fraud, export-control, and prohibited-action
  policy where applicable;
- data residency, retention, deletion, declassification, and audit-export
  policy;
- sector-specific review rules for finance, health, insurance, employment,
  physical action, critical infrastructure, education, legal, and public-sector
  workflows;
- tax, invoice, billing, and procurement metadata.

Compliance packs are policy inputs, not independent authority. The same pack may
be consumed by wallet.network, Hypervisor, Agentgres, aiagent.xyz, sas.xyz,
ioi.ai, or IOI L1 depending on the action.

## Insurance, Liability, And Claims

Insurance and liability should be modeled as claim routing over evidence, not as
an assurance layer pretending to decide coverage.

```text
incident or service failure
  -> Agentgres incident/evidence refs
  -> wallet authority/payment refs where relevant
  -> runtime, marketplace, or service-order receipts
  -> AssuranceEvidenceBundle
  -> LiabilityClaimRoute
  -> insurer, counterparty, operator, marketplace, or dispute process
  -> IOI L1 anchor only when public trust, escrow, bond, or dispute requires it
```

```yaml
LiabilityClaimRoute:
  claim_route_id: liability_claim_route://...
  incident_ref: incident://...
  subject_refs:
    - worker://...
    - runtime://...
    - service_order://...
    - embodied_domain://...
  policy_refs:
    - policy://...
  evidence_bundle_refs:
    - assurance_evidence://...
  claimant_ref: account://...
  counterparty_refs:
    - account://...
  external_claim_ref: claim://... | null
  settlement_or_dispute_ref: l1://... | dispute://... | null
  status:
    draft | submitted | accepted | rejected | disputed | settled | closed
```

Physical incidents use Physical Action Safety and Embodied Runtime records.
Digital service failures use service-order, SLA, delivery, verifier, and
marketplace evidence. Both paths should stay receipted and replayable.

## Abuse, Threat, And Quarantine

Abuse response must be scoped, attributable, appealable where appropriate, and
receipted. It must not become an unbounded global kill switch.

Input signals may include:

- vulnerability reports;
- failed conformance tests;
- malware, exfiltration, spam, fraud, or phishing indicators;
- wallet misuse, stolen credentials, suspicious authority requests, or payment
  abuse;
- marketplace disputes, refund patterns, or verifier failures;
- OutcomeRoom spam, Sybil clusters, cross-review collusion, resource capture,
  poisoned artifacts/findings/mappings, evaluator exploits, or attempts to
  promote participant input directly into memory, ontology, routing,
  authority, or production;
- cTEE leakage receipts, canary/watermark hits, or provider-policy violations;
- physical-action incidents or emergency-stop events;
- sanctions, jurisdiction, or regulatory blocks.

```yaml
EcosystemAbuseSignal:
  signal_id: abuse_signal://...
  source_ref: account://... | domain://... | scanner://... | report://...
  subject_ref: string
  signal_type:
    vulnerability | malware | exfiltration | spam | fraud |
    unsafe_physical_action | policy_violation | credential_abuse |
    marketplace_abuse | collaboration_spam | sybil_cluster | collusion |
    poisoned_artifact | evaluator_exploit | resource_capture |
    conformance_failure | other
  severity: info | low | medium | high | critical
  evidence_refs:
    - receipt://...
    - artifact://...
    - assurance_evidence://...
  recommended_action:
    observe | warn | restrict | require_step_up | suspend |
    quarantine | delist | revoke | publish_advisory
  status:
    open | triaged | mitigated | disputed | false_positive | closed
```

```yaml
QuarantineAdvisory:
  advisory_id: quarantine_advisory://...
  subject_ref: string
  scope:
    local_domain | marketplace_listing | worker_version | runtime_node |
    authority_client | connector | mcp_gateway | service_package |
    participant | outcome_room | verifier_rule | frontier_item |
    embodied_domain | ecosystem
  restrictions:
    - string
  dependent_refs:
    - wallet_client://...
    - mcp_gateway://...
    - session://...
    - work_run://...
    - connector://...
    - worker://...
  reason_refs:
    - abuse_signal://...
  blast_radius_report_ref: receipt://... | artifact://... | null
  appeal_policy_ref: policy://... | null
  release_conditions:
    - string
  public_anchor_ref: l1://... | null
  status:
    draft | active | released | superseded | revoked
```

Action remains with the owner:

- wallet.network revokes or restricts authority;
- Hypervisor blocks runtime or connector invocation;
- aiagent.xyz delists or restricts routing;
- sas.xyz pauses service orders or dispute settlement;
- Agentgres records incident and posture truth;
- IOI L1 anchors public advisories, bonds, disputes, or governance commitments
  only when needed.

## Commercial Assurance

Commercial assurance converts work evidence into business-facing records without
making billing systems the source of runtime truth.

It should cover:

- subscription, usage, work-credit, and payment refs;
- cost centers, departments, projects, and purchase orders;
- invoices, tax exports, and receipts;
- SLA evidence and breach reports;
- support bundles and customer audit exports;
- compliance audit export bundles;
- procurement posture for certified workers, providers, and service packages;
- accepted-delivery, refund, and dispute records.

```yaml
CommercialAssuranceExport:
  export_id: commercial_export://...
  account_ref: account://...
  org_ref: org://... | null
  period:
    start: timestamp
    end: timestamp
  includes:
    - billing_summary
    - invoice_refs
    - cost_center_breakdown
    - sla_report
    - audit_evidence_refs
    - service_delivery_refs
    - marketplace_usage_refs
    - tax_export_refs
  redaction_profile_ref: policy://...
  evidence_bundle_refs:
    - assurance_evidence://...
  audit_export_refs:
    - audit_export://...
  generated_by_ref: agentgres://...
  status:
    generated | delivered | revoked | superseded
```

ioi.ai may coordinate account, entitlement, and remote-runtime visibility.
wallet.network authorizes payments and payment-adjacent authority. Agentgres
records accepted truth. sas.xyz and aiagent.xyz own marketplace domain records.
Assurance defines the export shape and evidence posture.

## Events And Receipts

Assurance-relevant events should be typed, attributable, and reconstructable.

```text
assurance.profile.declared
assurance.profile.versioned
assurance.conformance.started
assurance.conformance.passed
assurance.conformance.failed
assurance.certification.claimed
assurance.certification.activated
assurance.certification.restricted
assurance.certification.revoked
assurance.policy_pack.applied
assurance.policy_pack.blocked
assurance.audit_export.requested
assurance.audit_export.generated
assurance.audit_export.delivered
assurance.audit_export.revoked
assurance.evidence_bundle.created
assurance.posture.updated
assurance.abuse_signal.opened
assurance.quarantine.activated
assurance.quarantine.released
assurance.claim.opened
assurance.claim.routed
assurance.claim.closed
assurance.commercial_export.generated
```

Receipt families should include:

- `ConformanceRunReceipt`
- `CertificationClaimReceipt`
- `CertificationRevocationReceipt`
- `JurisdictionPolicyDecisionReceipt`
- `AssuranceEvidenceBundleReceipt`
- `ComplianceAuditExportBundleReceipt`
- `QuarantineAdvisoryReceipt`
- `AbuseSignalReceipt`
- `LiabilityClaimRouteReceipt`
- `CommercialAssuranceExportReceipt`

Compliance audit export receipts must bind export manifest hash, redaction
profile, retention/restricted-view refs, policy-pack decisions, approval/denial
receipts, audience, commercial refs, and public-anchor policy when relevant.

## Public Anchor Policy

Most assurance evidence should remain local or customer-private. IOI L1 receives
only selected commitments:

- public certification roots;
- marketplace listing eligibility roots;
- worker or service package release roots;
- bond, escrow, refund, slashing, and dispute commitments;
- public quarantine advisories;
- public governance decisions;
- cross-domain settlement or registry commitments.

Do not anchor raw private audit evidence, customer exports, protected payloads,
or internal compliance notes.

## Anti-Patterns

Do not model Ecosystem Assurance as:

- a second wallet authority system;
- a universal kill switch;
- a runtime scheduler;
- a marketplace ranking engine;
- a legal advice engine;
- an insurance coverage adjudicator;
- a storage backend for audit payloads;
- a shortcut around daemon execution or wallet approval;
- a claim that certified model cognition is safe;
- a one-time badge that never refreshes;
- a reason to put private customer audit data on IOI L1.
- audit export as screenshots, raw logs, or replay bypassing retention.

## One-Line Doctrine

> **Ecosystem Assurance makes autonomous systems legible to institutions:
> profiles declare expectations, receipts bind attributable facts, evidence and
> evaluation support verification, acceptance and adjudication remain explicit,
> owners act within their boundaries, and public settlement is used only when
> external trust requires it.**
