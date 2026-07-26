# Authority and Access Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of authority scope requests, approval ceremony context, authority grants, authority clients, access-point bindings, and step-up challenges.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (`AuthorityGrantEnvelope` v1/v2, `AuthorityKeySet` v1, and `AuthorityRevocationSnapshot` v1 have registered schemas, invariants, adversarial fixtures, and generated Rust/TypeScript projections; production portable-authority cryptographic verifiers and CLIs remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md);
this module does not restate them.

## AuthorityScopeRequestEnvelope

```yaml
AuthorityScopeRequestEnvelopeV2:
  schema_version: 2
  authority_request_id: authority-request://...
  principal_ref:
    principal://... | wallet://... | org://... | worker://... | service://... |
    domain://... | agentgres://domain/...
  product_session_ref: session://... | null
  origin_binding_ref: origin-binding://... | origin://... | null
  subject_id: system://... | agent://... | worker://... | runtime://...
  issuer_id: system://... | wallet://... | org://... | policy://...
  requesting_runtime_ref: runtime://... | null
  purpose: string
  requested_auth_factor_posture_refs:
    - policy://... | auth_factor://...
  requested_guardian_surface_refs:
    - guardian://...
  authorization_subject:
    kind: exact_effect | batch_manifest | standing_envelope
    subject_ref: effect://... | artifact://... | policy://...
    subject_hash: sha256:...
    validation_profile_ref: schema://... | policy://...
  primitive_capabilities_required:
    - prim:model.invoke
    - prim:fs.read
  authority_scopes_requested:
    - scope:gmail.read
    - scope:repo.write
  resource_scope:
    resources:
      - agentgres://project/hypervisor/*
      - file://workspace/src/**
    constraints:
      max_budget_usd: 10
      expiry: 2026-05-01T00:00:00Z
      approval_required_for:
        - external_message
        - commerce
  destination_refs: []
  risk_classes: []
  policy_hash: hash
  authority_request_body_hash: sha256:...
  authority_grant_id: grant://... | null
  status: requested | granted | denied | expired | revoked
```

The exact-action shape above is the target v2 successor. Current unversioned
request adapters remain compatibility inputs until a closed v2 schema,
fixtures, generated projections, migration rule, producer, and verifier land
together; this prose does not mutate their wire contract.

`product_session_ref` identifies a session owned by the product or deployment
identity plane; wallet.network binds it into the request but does not own that
session's lifecycle. `requested_auth_factor_posture_refs` and
`requested_guardian_surface_refs` declare requested or eligible approval
posture; they are not evidence that a factor or guardian participated. Observed
satisfaction belongs in wallet-minted review and ceremony evidence.

`authorization_subject` discriminates what the grant may ultimately authorize:
`exact_effect` commits one canonical typed effect, `batch_manifest` commits a
closed manifest/root whose members require proof, and `standing_envelope`
commits the constraint set under which later effects may be admitted. The
`subject_ref` is exact by kind: `exact_effect` uses `effect://`,
`batch_manifest` uses `artifact://`, and `standing_envelope` uses `policy://`.
It must resolve to kind-appropriate immutable content and
`subject_hash` must equal its canonical body hash. For `exact_effect`, that is
the exact payload hash the daemon recomputes at the final PEP; batch leaves use
the same effect-hash profile. Undefined canonicalization, membership, or
constraint semantics are inadmissible.

`authority_request_body_hash` is:

```text
SHA-256(
  "IOI-AUTHORITY-SCOPE-REQUEST-V2\0" ||
  RFC8785_JCS(the exact closed v2 object excluding
    authority_request_body_hash, authority_grant_id, and status)
)
```

It therefore binds `schema_version`, the principal, product
session, origin, acting subject/runtime, purpose, requested factors/guardian
posture, authorization subject, exact capabilities/scopes/resources/
destinations, budget/expiry constraints, risk, and policy. Review, grant
issuance, and effect admission resolve the same body and reject substitution.
No presentation surface, presentation-evidence profile, satisfied factor, or
decision is request input; policy selects and records those later.

## ApprovalCeremonyContextEnvelope

This is a target successor contract. Current master has no registered
`ApprovalCeremonyContextEnvelope` schema, generated projection, production
emitter, or verifier. It must land as one closed machine contract rather than
being inferred from a challenge URL or reconstructed from mutable review state.

```yaml
ApprovalCeremonyContextEnvelope:
  schema_version: 1
  approval_ceremony_context_ref: approval-ceremony-context://...
  authority_request_ref: authority-request://...
  authority_request_body_hash: sha256:...
  authority_review_ref: review://...
  authority_review_body_hash: sha256:...
  predecessor_authority_review_ref: review://... | null
  predecessor_authority_review_body_hash: sha256:... | null
  predecessor_authority_request_ref: authority-request://... | null
  predecessor_authority_request_body_hash: sha256:... | null
  predecessor_authority_review_receipt_ref: receipt://... | null
  predecessor_authority_review_receipt_hash: sha256:... | null
  reviewed_representation_hash: sha256:...
  principal_ref:
    principal://... | wallet://... | org://... | worker://... | service://... |
    domain://... | agentgres://domain/...
  acting_subject_ref: system://... | agent://... | worker://... | runtime://...
  product_session_ref: session://... | null
  origin_binding_ref: origin-binding://... | origin://... | null
  authorization_subject:
    kind: exact_effect | batch_manifest | standing_envelope
    subject_ref: effect://... | artifact://... | policy://...
    subject_hash: sha256:...
    validation_profile_ref: schema://... | policy://...
  presentation_surface_ref: wallet-client://... | guardian://... | surface://...
  presentation_evidence_profile_ref: policy://... | schema://...
  principal_authority_resolution_ref: artifact://... | null
  principal_authority_resolution_hash: sha256:... | null
  required_auth_factor_posture_refs:
    - policy://... | auth_factor://...
  required_guardian_surface_refs:
    - guardian://...
  posture_satisfaction_profile_ref: policy://... | schema://...
  interaction_mode: interactive | noninteractive_policy
  authentication_posture: baseline | step_up
  receipt_timing: before_effect | after_effect
  policy_decision_receipt_ref: receipt://...
  policy_decision_receipt_hash: sha256:...
  policy_hash: sha256:...
  risk_classes: []
  revocation_epoch: integer
  nonce_b64url: base64url_256_bits_or_more
  issued_at: timestamp
  expires_at: timestamp
  single_use: true
```

The context hash is:

```text
SHA-256(
  "IOI-APPROVAL-CEREMONY-CONTEXT-V1\0" ||
  RFC8785_JCS(ApprovalCeremonyContextEnvelope)
)
```

`authority_review_body_hash` is not the hash of a mutable review record that
already contains this context. It is:

```text
SHA-256(
  "IOI-AUTHORITY-REVIEW-PREPARATION-V1\0" ||
  RFC8785_JCS({
    schema_version,
    authority_review_ref,
    authority_request_ref,
    authority_request_body_hash,
    reviewed_representation_hash,
    predecessor_authority_review_ref,
    predecessor_authority_review_body_hash,
    predecessor_authority_request_ref,
    predecessor_authority_request_body_hash,
    predecessor_authority_review_receipt_ref,
    predecessor_authority_review_receipt_hash,
    principal_ref,
    acting_subject_ref,
    product_session_ref,
    origin_binding_ref,
    authorization_subject,
    presentation_surface_ref,
    presentation_evidence_profile_ref,
    principal_authority_resolution_ref,
    principal_authority_resolution_hash,
    required_auth_factor_posture_refs,
    required_guardian_surface_refs,
    posture_satisfaction_profile_ref,
    interaction_mode,
    authentication_posture,
    receipt_timing,
    policy_hash,
    risk_classes,
    expires_at
  })
)
```

That closed preparation object contains no ceremony-context ref/hash,
challenge, presentation/authenticator evidence, policy-decision receipt,
mutable status, or resulting decision/grant refs, so neither hash is
self-referential. The ceremony context binds the policy-decision ref/hash
directly beside the preparation hash. That policy-decision receipt is produced
over the request, review-preparation inputs, required posture, risk, and policy;
it must not include the later ceremony-context ref/hash in its own preimage.

The WebAuthn challenge is the base64url encoding of the raw
`approval_ceremony_context_hash` bytes, not the review-preparation hash. The
fresh random nonce inside the hashed body supplies unpredictability and makes
each ceremony unique; it is not replaced by a deterministic request or review
hash. The principal-authority resolution fields are both required when
`principal_ref` uses the registered portable grammar (`worker://`,
`service://`, `org://`, `domain://`, or `agentgres://domain/`) and both null
otherwise. The referenced artifact is the exact registered
`PrincipalAuthorityResolutionV1` object, without projection; its hash is
SHA-256 over the RFC 8785 JCS bytes of that exact object.

## AuthorityGrantEnvelope

The canonical v1 and portable v2 JSON wire shapes, cross-field invariant
profiles, and golden fixtures are registered by
[`architecture-contract-registry.v1.json`](../../_meta/schemas/architecture-contract-registry.v1.json).
That machine form owns field presence and validation for those versions; this
section retains semantic ownership. The `grant_id` spelling is a read-side
v1 compatibility-adapter alias only and is rejected on canonical writes.

```yaml
AuthorityGrantEnvelope:
  authority_grant_id: grant://...
  request_id: authority-request://...
  issuer_id: system://... | wallet://... | org://... | policy://...
  subject_id: system://... | agent://... | worker://... | runtime://...
  authority_scopes:
    - scope:gmail.read
    - scope:repo.write
  primitive_capability_constraints:
    - prim:fs.read
    - prim:fs.write
  resources:
    - agentgres://project/hypervisor/*
    - file://workspace/src/**
  constraints:
    max_budget_usd: 10
    expires_at: 2026-05-01T00:00:00Z
    max_calls: optional
    approval_required_for:
      - external_message
      - commerce
  revocation_epoch: integer
  status: active | expired | revoked
```

Portable v2 is the registered signed-wire successor for authority that must
cross a process, runtime, or sovereign-system boundary. It binds the exact holder identity and
holder key, audience, issuer key-set identity/version, validity interval,
revocation epoch, resources, primitive capabilities, authority scopes, caveats,
risk restrictions, parent proof, registered schema hash, and canonical body
hash. Its canonical encoding is RFC 8785 JCS. The Ed25519 signature preimage is
domain separated as `IOI-AUTHORITY-GRANT-ENVELOPE-V2\0` followed by the JCS
encoding of `body_hash`, `schema_hash`, and `signature_domain`.

`AuthorityKeySet` v1 and signed `AuthorityRevocationSnapshot` v1 are verification
inputs, not new authority owners. Verification fails closed on an untrusted or
mismatched key set, inactive key or grant, wrong audience/holder, stale or
invalid revocation snapshot, revoked grant/key, body/schema/signature mismatch,
missing parent proof, parent-link mismatch, delegation cycle, or widened child.
A delegated child must be issued by the parent holder key and may only narrow
scopes, primitive capabilities, resources, risk classes, budget, calls, and
validity while retaining or adding caveats and approval requirements.

A conforming verifier operates over a caller-supplied locally trusted key set
and bounded-freshness signed revocation snapshot. Current master registers the
wire contract, invariants, fixtures, and generated projections but does not
contain the portable Ed25519/JCS verifier or an offline CLI. Network key
discovery, trust-root acquisition, transparency infrastructure, and universal
revocation distribution remain separate planned work.

For consequential use, “locally trusted” does not mean caller-asserted
current. The operation must also bind an admitted
`TemporalVerificationProfile` and recomputable `TemporalValidityEvaluation`
covering the grant interval, key-set/revocation status-as-of horizon, and any
required owner-scoped continuity floors. An old authentic snapshot may support
a historical `valid_as_of` conclusion while present currentness remains
indeterminate. Portable v1/v2 stay immutable; this cross-plane evaluation is an
admission input rather than an inferred field in those envelopes.

Portable v3 is the target successor required before the embedded
sign-in-to-effect product proof. It retains the v2 portability and attenuation
contract and additionally signs:

```yaml
request_commitment:
  authority_request_id: authority-request://...
  authority_request_body_hash: sha256:...
  reviewed_representation_hash: sha256:...
  presentation_surface_ref: wallet-client://... | guardian://... | surface://...
  presentation_evidence_profile_ref: policy://... | schema://...
  presentation_evidence_refs:
    - receipt://... | evidence://... | attestation://...
  approval_ceremony_context_ref: approval-ceremony-context://...
  approval_ceremony_context_hash: sha256:...
  approval_ceremony_evidence_refs:
    - receipt://... | evidence://...
  authorization_subject:
    kind: exact_effect | batch_manifest | standing_envelope
    subject_ref: effect://... | artifact://... | policy://...
    subject_hash: sha256:...
    validation_profile_ref: schema://... | policy://...
  principal_ref:
    principal://... | wallet://... | org://... | worker://... | service://... |
    domain://... | agentgres://domain/...
  product_session_ref: session://... | null
  origin_binding_ref: origin-binding://... | origin://... | null
  required_auth_factor_posture_refs:
    - policy://... | auth_factor://...
  required_guardian_surface_refs:
    - guardian://...
  satisfied_auth_factor_refs:
    - auth_factor://...
  satisfied_guardian_surface_refs:
    - guardian://...
  posture_satisfaction_profile_ref: policy://... | schema://...
  posture_satisfaction_evaluations:
    - requirement_ref: policy://... | auth_factor://... | guardian://...
      requirement_kind: auth_factor | guardian_surface
      satisfied_by_refs:
        - auth_factor://... | guardian://...
      evidence_refs:
        - evidence://... | receipt://... | artifact://...
      evaluation_profile_ref: policy://... | schema://...
      decision: satisfied | unsatisfied | unknown
  posture_satisfaction_root: sha256:...
  interaction_mode: interactive | noninteractive_policy
  authentication_posture: baseline | step_up
  receipt_timing: before_effect | after_effect
  principal_authority_resolution_ref: artifact://... | null
  principal_authority_resolution_hash: sha256:... | null
  policy_decision_receipt_ref: receipt://...
  policy_decision_receipt_hash: sha256:...
  authority_review_receipt_ref: receipt://...
  authority_review_receipt_hash: sha256:...
  approval_evidence_profile_ref: schema://... | policy://...
  approval_evidence_leaf_refs:
    - receipt://... | evidence://... | artifact://...
  approval_evidence_root: sha256:...
```

The signed v3 grant is independently verifiable against the exact target
`AuthorityScopeRequestEnvelopeV2` body, authorization subject, reviewed
representation, presentation and ceremony evidence, required and satisfied
factor/guardian posture, policy decision, any principal-authority resolution
required by the portable principal contract, and authority-review receipt.
Request-side factor and guardian refs remain requested posture; only the
separately named `satisfied_*` refs and their wallet-minted evidence record
participation. `posture_satisfaction_evaluations` is the authoritative closed
mapping from policy requirements to evidence: every required factor/guardian
ref appears exactly once, no unrequired ref appears, and an approved grant
requires every entry to be `satisfied`. The `satisfied_*` arrays are exact,
sorted projections of those entries, not independently authored claims.
An `auth_factor` evaluation references only the required auth-factor set and
uses only `auth_factor://` satisfiers; a `guardian_surface` evaluation
references only the required guardian set and uses only `guardian://`
satisfiers.
`posture_satisfaction_root` is domain-separated by the named profile and commits
the canonical ordered evaluation set; both the review receipt and grant bind
the same profile and root.

`presentation_evidence_profile_ref` independently declares the presentation
operator/control boundary, exact representation binding, request/effect
linkage, enrollment and attestation evidence, UP/UV posture, freshness/replay
handling, and independence from the proposing client. These are orthogonal
properties, not a `same client` versus `independent trusted` assurance tier.
The profile and evidence may support only the claims they actually bind.

`approval_ceremony_context_ref` resolves the exact closed
`ApprovalCeremonyContextEnvelope`; its domain-separated hash commits the
request and reviewed-representation hashes, principal, acting subject, product
session, origin, nonce, expiry, authorization subject, required posture, policy
decision, risk, revocation epoch, and any principal-authority resolution
required by the portable principal contract.
`approval_evidence_profile_ref` defines ordered leaf types, canonical encoding,
hash algorithm, and domain-separated construction for
`approval_evidence_root`; an opaque root without that exact profile is
inadmissible. The root commits the request, review, presentation evidence,
ceremony evidence, satisfied posture, and decision receipt without making any
one leaf evidence of all the others. When
`principal_authority_resolution_ref` is non-null, that exact
artifact ref/hash is a required typed leaf. The posture-satisfaction profile,
closed evaluations, and root are bound directly by an approved grant; none may
be inferred from the satisfied-ref projections alone.

A subject, session, origin, request, representation, presentation surface or
profile, ceremony, factor, guardian, principal-authority coordinate or
snapshot, authorization-subject, resource, destination, budget, policy, risk,
or evidence-root substitution invalidates the commitment. A null session or
origin is permitted only when the selected non-browser/non-product policy
explicitly declares that posture; it is never inferred by omission. V1 and v2
remain immutable compatibility contracts. V3 requires a new registered schema,
fixtures, generated Rust/TypeScript projections, and verifier support rather
than silently changing either registered version.

## AuthorityClientEnvelope

```yaml
AuthorityClientEnvelope:
  authority_client_id: wallet-client://...
  client_kind:
    wallet_web | wallet_mobile | wallet_desktop | hypervisor_panel |
    cli_signer | mcp_server | sdk | enterprise_authority_service |
    browser_origin | local_signer
  owner_ref: wallet://... | org://...
  subject_ref: agent://... | worker://... | runtime://... | service://... | null
  origin_binding:
    origin_ref: origin://... | null
    device_ref: device://... | null
    public_key_ref: key://... | null
    attestation_ref: attestation://... | null
  allowed_operations:
    - request_authority
    - approve_challenge
    - inspect_grants
    - revoke_lease
    - list_receipts
  authority_scope_refs:
    - scope:...
  active_grant_refs:
    - grant://...
  active_lease_refs:
    - lease://...
  gateway_profile_refs:
    - mcp_gateway://...
  connector_refs:
    - connector://...
  session_refs:
    - session://...
  work_run_refs:
    - work_run://...
  risk_ceiling:
    read | draft | low_local_write | external_message | deploy |
    funds | secret_export | policy_widening
  expires_at: timestamp
  last_use_at: timestamp | null
  last_use_ref: event://... | null
  revocation_epoch: integer
  anomaly_state:
    clean | watch | origin_mismatch | expired_use | scope_excess |
    suspicious_frequency | policy_denied | leaked | compromised
  quarantine_advisory_refs:
    - quarantine_advisory://...
  replacement_client_ref: wallet-client://... | null
  status:
    active | expired | suspended | quarantined | rotating | rotated | revoked
```

Authority clients are surfaces and sessions that may request, inspect, approve,
or broker scoped authority. They are not raw secret custodians and cannot widen
authority without a new wallet.network grant. Origin mismatch, expired use,
scope excess, leaked key material, or quarantine must fail closed before any
effectful provider mutation.

## AccessPointBindingEnvelope

```yaml
AccessPointBindingEnvelope:
  binding_id: access_point://...
  owner_ref: wallet://...
  kind: sms | email | chat_app | voice | webhook | browser_session | local_app
  channel_hash: sha256:...
  display_label: optional
  agent_refs:
    - agent://...
  allowed_intents:
    - notify
    - status
    - pause
    - resume
    - request_summary
    - run_preapproved_workflow
    - request_step_up
  risk_ceiling: read | draft | low_local_write
  can_decrypt: false
  can_declassify: false
  can_hold_grant: false
  can_release_secret: false
  step_up_required_for:
    - external_message
    - commerce
    - funds
    - deploy
    - secret_export
    - policy_widening
    - private_workspace_view
    - private_workspace_declassification
  challenge_policy:
    single_use: true
    ttl_seconds: 300
    eligible_presentation_surface_classes:
      - wallet_network_web
      - hypervisor_app
      - enrolled_guardian_authority_client
      - enterprise_approval_surface
      - local_cli_signer
    eligible_auth_factor_kinds:
      - passkey
      - federated_identity
  expires_at: optional
  revocation_epoch: integer
  status: active | disabled | expired | revoked
```

## StepUpChallengeEnvelope

```yaml
StepUpChallengeEnvelope:
  challenge_id: challenge://...
  binding_id: access_point://...
  owner_ref: wallet://...
  approval_ceremony_context_ref: approval-ceremony-context://...
  approval_ceremony_context_hash: sha256:...
  challenge_bytes_b64url: base64url(raw_approval_ceremony_context_hash)
  action_summary: string
  challenge_url_ref: https://... | null
  status: issued | approved | denied | expired | consumed
  resulting_grant_ref: grant://... | null
  authority_review_receipt_ref: receipt://... | null
```

Low-assurance access points can carry a `challenge://...` pointer but must not
carry a `grant://...`, decryption key, credential, private workspace payload, or
durable secret.

The challenge resolves one immutable `ApprovalCeremonyContextEnvelope` and
repeats only its ref, hash, and challenge bytes. The mutable delivery status and
result refs are outside that context hash, avoiding a self-referential
preimage. Required factor posture and guardian surfaces live in the context as
requirements, not observed participation. Approval records actual presentation
and ceremony evidence plus satisfied factor/guardian refs in the resulting
`AuthorityReviewReceipt`; changing the request, representation, subject,
required posture, policy decision, any required authority resolution, nonce,
or expiry requires a successor context and challenge and invalidates
predecessor approval evidence.
