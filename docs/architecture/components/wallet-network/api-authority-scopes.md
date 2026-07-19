# wallet.network API and Authority Scopes

Status: canonical low-level reference.
Canonical owner: this file for wallet.network account, auth factor, guardian,
key-shard, provider credential binding, authority scope, grant, approval, secret
brokerage, payment, exchange, exposure, protection, receipt, wallet authority
client, and revocation APIs.
Supersedes: older wallet authority API wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: reference
Implementation status: partial (authority-client seams, lease APIs, portable principal-to-approval-authority binding resolution, and exact grant-hash-keyed effect consumption with immutable replayable receipts are live; account/factor, WebAuthn ceremony, device/session lifecycle, recovery, guardian, and shard surfaces are planned; the closed approval-ceremony context, temporal profile/evaluation input, review/effect-admission receipt profiles, context-bound v3 grant, and WalletReceipt v2 are target successor contracts with no registered schema, emitter, or verifier)
Last implementation audit: 2026-07-19

## Purpose

wallet.network is the canonical Web4 authority layer. It owns identity,
auth factors, guardian surfaces, key shards, secrets, BYOK keys, connector
credentials, provider credential bindings, authority scope grants, training-data
permissions, decryption leases, approvals, payments, exchange authority,
asset/route/security risk disclosure, sealed archive restore authority,
revocation, and emergency stops. Agents, workers, apps, and runtimes are
authority clients, not raw secret custodians.

## Contract Packaging Boundary

This file is the low-level API doctrine. The durable implementation contract
lives in IOI-owned protocol surfaces, not in the Wallet product UI.

Current concrete anchors:

```text
crates/types/src/app/wallet_network/
  Rust authority/session/connector/secret/receipt object types.

crates/services/src/wallet_network/
  wallet.network service transitions, validation, and receipt writes.

crates/services/src/wallet_network/tests/
crates/cli/tests/wallet_network_session_channel_e2e/
  receipt, lease, approval, secret-injection, connector, replay, and
  session-channel conformance evidence.
```

Current package shape:

```text
@ioi/wallet-protocol
  protocol objects, OpenAPI / JSON Schema, receipt fixtures, canonical
  examples, method metadata, and versioned compatibility metadata

@ioi/wallet-sdk
  typed client helpers for wallet.network apps, Hypervisor, agents, services,
  and third-party clients
```

Product repos such as `wallet-network` consume these package artifacts. They
may contain UI fixtures and prototypes, but they must not define canonical
scopes, grants, leases, secret-release policy, receipt schemas, exchange/trade
intent semantics, provider/resource authority semantics, or revocation behavior.

## Account, Factor, Guardian, and Session API

```http
POST /v1/auth/sign-in
POST /v1/auth/link-factor
GET  /v1/auth/factors
DELETE /v1/auth/factors/{factor_id}
POST /v1/auth/passkeys/registration/options
POST /v1/auth/passkeys/registration/verify
POST /v1/auth/passkeys/authentication/options
POST /v1/auth/passkeys/authentication/verify
GET  /v1/auth/passkeys
DELETE /v1/auth/passkeys/{factor_id}
POST /v1/guardians
GET  /v1/guardians
GET  /v1/guardians/{guardian_id}
POST /v1/guardians/{guardian_id}/challenge
POST /v1/guardians/{guardian_id}/disable
POST /v1/key-shards
GET  /v1/key-shards
POST /v1/key-shards/{shard_id}/rotate
GET  /v1/account
GET  /v1/account/security-level
POST /v1/account/upgrade-security
POST /v1/session
GET  /v1/sessions
DELETE /v1/session/{session_id}
DELETE /v1/sessions
POST /v1/account/recovery/start
GET  /v1/account/recovery/{recovery_id}
POST /v1/account/recovery/{recovery_id}/verify
POST /v1/account/recovery/{recovery_id}/complete
POST /v1/account/recovery/{recovery_id}/cancel
```

Stable sign-in and linked-factor kinds:

```text
federated_identity
passkey
web3_wallet
email_magic_link
totp
```

`federated_identity` binds a provider registry ref, protocol, issuer, and
provider-scoped subject. Apple, Google, Microsoft, GitHub, enterprise IdPs, and
future providers are adapters and product labels rather than permanent wire
enum members.

A frictionless login creates a Level 1 wallet.network account. TOTP is a linked
step-up factor, not a primary identity provider. High-risk authority scopes
require step-up.

Canonical factor taxonomy:

```text
AuthFactor
  Authenticates account access or step-up posture. It does not convey authority
  by itself. Federated identity, email magic link, Web3 wallet, passkey, and
  TOTP are auth factors. Provider identity is issuer/subject-bound metadata,
  not a separate authority family.

GuardianSurface
  Enrolled authority-client and presentation surface that can produce the
  presentation evidence required by policy and submit an approval or denial.
  It composes with one or more AuthFactors. A generic passkey or hardware
  credential is an AuthFactor, not a GuardianSurface by itself. Examples include
  enrolled mobile or desktop authority clients, local CLI signer surfaces,
  trusted wallet/Hypervisor apps, and enterprise approval surfaces.

KeyShard
  Cryptographic or threshold authority material such as MPC share, threshold
  key share, hardware-backed share, recovery share, or organization quorum share.
  Do not use "shard" for ordinary provider logins.

ProviderCredentialBinding
  OAuth refresh token, API key, model-provider key, wallet credential, cloud
  credential, or connector credential held or brokered by wallet.network.

AuthorityGrant
  Scoped `grant://...` or lease issued after policy review. Agents receive this
  object, not raw auth factors, raw credentials, or key shards.
```

Account posture should distinguish:

```text
federated_frictionless
trusted_device
out_of_band_guardian
sovereign_or_org_vault
```

TOTP may increase confidence but is phishable and cannot satisfy high-risk
authority alone. Local biometric or PIN verification may contribute to a
high-assurance posture only by unlocking a passkey, secure-enclave credential,
or equivalent cryptographic assertion under an enrolled-device policy.

### Auth Factor

```json
{
  "factor_id": "auth_factor://federated/user_123/default",
  "owner_ref": "wallet://user_123",
  "kind": "federated_identity | email_magic_link | web3_wallet | passkey | totp",
  "provider_ref": "identity-provider://apple | identity-provider://google | identity-provider://microsoft | identity-provider://github | identity-provider://enterprise/... | null",
  "authentication_protocol": "oidc | oauth2_profile | saml | webauthn | wallet_proof | email_magic_link | totp",
  "issuer": "https://issuer.example | null",
  "subject_binding_hash": "sha256:... | null",
  "assurance_level": "low | medium | high",
  "can_bootstrap_account": true,
  "can_satisfy_step_up": false,
  "can_hold_grant": false,
  "can_release_secret": false,
  "created_at": "2026-06-20T12:00:00Z",
  "last_used_at": "2026-06-20T12:30:00Z",
  "status": "active"
}
```

Kind/protocol legality is closed:

| `kind` | Allowed `authentication_protocol` | Required bindings |
| --- | --- | --- |
| `federated_identity` | `oidc`, `oauth2_profile`, or `saml` | provider ref, issuer, and provider-scoped subject binding |
| `passkey` | `webauthn` | credential/public-key, RP, origin-set, user-handle, and passkey lifecycle fields |
| `web3_wallet` | `wallet_proof` | wallet/account subject binding and admitted proof-policy ref |
| `email_magic_link` | `email_magic_link` | owner/account binding and single-use challenge policy |
| `totp` | `totp` | owner/account binding and enrolled-secret custody ref |

For non-federated kinds, `provider_ref` and federated `issuer` are null.
Irrelevant kind-specific fields are absent or null, and a kind/protocol
mismatch fails admission.

For `kind: passkey`, the same `AuthFactor` additionally records:

```json
{
  "credential_id": "base64url:...",
  "credential_public_key_ref": "wallet-internal://passkey-public-key/...",
  "rp_id": "wallet.network",
  "admitted_origin_set_hash": "sha256:...",
  "user_handle_hash": "sha256:...",
  "sign_count": 42,
  "transports": ["internal", "hybrid"],
  "discoverable_credential": true,
  "uv_initialized": true,
  "last_observed_user_presence": true,
  "last_observed_user_verification": true,
  "backup_eligibility_observed": true,
  "backup_state_observed": true,
  "attestation_and_trust_refs": ["attestation://..."],
  "guardian_ref": "guardian://device/user_123/phone | null",
  "revocation_epoch": 7,
  "replaces_factor_ref": "auth_factor://... | null",
  "status": "active | quarantined | revoked | replaced"
}
```

Registration and authentication `options` responses bind a cryptographically
random, single-use, expiring challenge to an always-present
`ceremony_context_hash`, the account or pre-account session, RP ID, admitted
origins, requested user-presence/user-verification policy, and operation kind.
The following exact-action commitments are null for ordinary registration or
login and independently populated for a consequential step-up:

```json
{
  "authority_request_body_hash": "sha256:...",
  "reviewed_representation_hash": "sha256:...",
  "approval_ceremony_context_ref": "approval-ceremony-context://...",
  "approval_ceremony_context_hash": "sha256:...",
  "authorization_subject": {
    "kind": "exact_effect | batch_manifest | standing_envelope",
    "subject_ref": "effect://... | artifact://... | policy://...",
    "subject_hash": "sha256:...",
    "validation_profile_ref": "schema://... | policy://..."
  }
}
```

The WebAuthn challenge is the base64url encoding of the raw
`approval_ceremony_context_hash` bytes; it is not replaced by a deterministic
request or representation hash. The closed ceremony context contains a fresh
random nonce of at least 256 bits and commits the authority request, reviewed
representation, principal, acting subject, product session, origin,
authorization subject, required posture, policy decision, expiry, revocation
posture, and, when the principal falls under the portable binding contract, the
exact principal-authority resolution artifact.

`verify` checks the expected `clientDataJSON.type`, exact challenge, origin and
applicable `crossOrigin`/`topOrigin` posture, `rpIdHash`, UP when required, UV
when required, credential owner and user handle, signature, BE/BS flag
combination, factor status, and selected attestation/trust policy. It rejects
replay, credential substitution, wrong owner, invalid signature, or a
stale/revoked factor. A zero or non-incrementing signature counter may be valid
for an authenticator; a regression is a policy-scored anomaly and does not by
itself prove cloning. Backup eligibility and backup state are authenticator
signals, not proof of a specific synchronization provider, hardware custody, or
device topology.

wallet.network stores the credential public key and metadata; it never receives
a private key, biometric sample or template, device PIN, or platform root
credential. It receives the WebAuthn assertion and user-presence/
user-verification flags needed to verify the ceremony. Required UP/UV belongs
to each ceremony and GuardianSurface policy, not as a permanent guarantee of
the credential.

A verified WebAuthn assertion is separate approval-ceremony evidence. It may
participate in application-defined consent when the challenge is bound as
above, but it does not independently prove which application-defined
representation a browser or authority client displayed, whether it displayed
that representation correctly, or whether the user understood it. Those are
separate presentation-evidence claims evaluated under
`presentation_evidence_profile_ref`.

### Guardian Surface

```json
{
  "guardian_id": "guardian://device/user_123/phone",
  "owner_ref": "wallet://user_123",
  "kind": "enrolled_mobile_authority_client | enrolled_desktop_authority_client | wallet_app | hypervisor_app | local_cli_signer | enterprise_approval_surface | secure_transaction_display",
  "display_label": "Personal phone",
  "auth_factor_refs": ["auth_factor://passkey/user_123/phone"],
  "enrollment_policy_ref": "policy://wallet/guardian/mobile-authority-client",
  "enrollment_receipt_ref": "receipt://...",
  "challenge_methods": ["webauthn", "qr", "push", "local_cli"],
  "presentation_evidence_profile_refs": [
    "policy://wallet/presentation/mobile-semantic-review"
  ],
  "user_verification_policy_ref": "policy://wallet/webauthn/guardian-uv-required",
  "attestation_and_trust_refs": ["attestation://..."],
  "allowed_risk_classes": [
    "external_message",
    "commerce",
    "funds",
    "system_destructive",
    "secret_export",
    "policy_widening"
  ],
  "revocation_epoch": 7,
  "status": "active | quarantined | revoked | replaced"
}
```

A GuardianSurface requires explicit enrollment under its bound policy and
receipt. It is an authority client and presentation surface composed with the
AuthFactors required by policy. A passkey, hardware key, or secure-enclave
credential remains an AuthFactor even when it authenticates a ceremony shown by
that surface. Every qualifying approval records fresh ceremony evidence and the
exact request, representation, authorization-subject, and resolved-authority
commitments; possession of an underlying AuthFactor alone is insufficient.

### Key Shard

```json
{
  "shard_id": "key_shard://user_123/mpc/device_a",
  "owner_ref": "wallet://user_123",
  "kind": "mpc_share | threshold_key_share | hardware_backed_share | recovery_share | org_quorum_share",
  "guardian_ref": "guardian://device/user_123/phone",
  "threshold_policy_ref": "policy://wallet/key-threshold/default",
  "can_export": false,
  "revocation_epoch": 7,
  "status": "active"
}
```

### Account Recovery and Device Lifecycle

Recovery is a receipted state machine over existing account, factor, guardian,
session, grant, and revocation owners:

```text
requested
  -> evidence_pending
  -> delay_or_guardian_review
      -> denied | cancelled | expired
      -> approved_at_declared_assurance
           -> affected_sessions_factors_and_grants_disposed
           -> completed_at_resulting_security_level
```

The recovery record binds the owner, initiating principal/session when known,
lost or compromised factors/devices, requested and maximum resulting security
level, policy, evidence, required independent factors/guardians/quorum,
cooldown, notifications, session disposition, credential rotation,
revocation-epoch transition, dependent-grant disposition, decision, and
completion receipts. Recovery never copies authority from the lost factor and
never lets a low-assurance provider login inherit higher-tier grants.
Denied, cancelled, and expired are terminal without rotation or restored
access. A pending recovery session is recovery-only: it cannot satisfy product
login, step-up, GuardianSurface approval, or effect authority.

Account linking and merge use exact provider issuer/subject bindings. An email
match is discovery evidence only. Factor link/unlink, recovery-policy change,
device replacement, session revoke-all, and account merge require the
applicable step-up and emit receipts.

## Access Point Binding API

Low-assurance channels such as SMS, email, chat apps, voice bridges, and
webhooks are access points. They can notify and initiate, but they are not
guardian surfaces and they do not carry grants, decryption keys, private
workspace payloads, credentials, or durable authority.

```http
POST /v1/access-points
GET  /v1/access-points
GET  /v1/access-points/{binding_id}
POST /v1/access-points/{binding_id}/challenge
POST /v1/access-points/{binding_id}/disable
DELETE /v1/access-points/{binding_id}
```

### Access Point Binding

```json
{
  "binding_id": "access_point://sms/user_123/default",
  "owner_ref": "wallet://user_123",
  "kind": "sms | email | chat_app | voice | webhook",
  "channel_hash": "sha256:...",
  "display_label": "Personal phone",
  "agent_refs": ["agent://morning-market-agent"],
  "allowed_intents": [
    "notify",
    "status",
    "pause",
    "resume",
    "request_summary",
    "run_preapproved_workflow",
    "request_step_up"
  ],
  "risk_ceiling": "read | draft | low_local_write",
  "can_decrypt": false,
  "can_declassify": false,
  "can_hold_grant": false,
  "can_release_secret": false,
  "step_up_required_for": [
    "external_message",
    "commerce",
    "funds",
    "deploy",
    "secret_export",
    "policy_widening",
    "private_workspace_view",
    "private_workspace_declassification"
  ],
  "challenge_policy": {
    "single_use": true,
    "ttl_seconds": 300,
    "eligible_presentation_surface_classes": [
      "wallet_network_web",
      "hypervisor_app",
      "enrolled_guardian_authority_client",
      "enterprise_approval_surface",
      "local_cli_signer"
    ],
    "eligible_auth_factor_kinds": [
      "passkey",
      "federated_identity"
    ]
  },
  "expires_at": "2026-05-01T12:00:00Z",
  "revocation_epoch": 7,
  "status": "active"
}
```

### Step-Up Challenge

```json
{
  "challenge_id": "challenge://sms/abc",
  "binding_id": "access_point://sms/user_123/default",
  "owner_ref": "wallet://user_123",
  "approval_ceremony_context_ref": "approval-ceremony-context://wallet/send_abc",
  "approval_ceremony_context_hash": "sha256:...",
  "challenge_bytes_b64url": "base64url(raw context hash bytes)",
  "action_summary": "Approve one vendor email draft",
  "challenge_url_ref": "https://wallet.network/step-up/challenge/abc",
  "status": "issued",
  "resulting_grant_ref": null,
  "authority_review_receipt_ref": null
}
```

This is the API rendering of the canonical `StepUpChallengeEnvelope`, not a
second challenge shape. Delivery transport and layout are client projections:
they may derive a link, QR, push, or CLI handoff and render the referenced
canonical review representation, but they do not add authority fields or mutate
the request, representation, presentation profile, ceremony, resolved
principal-authority tuple, or authorization subject.

The referenced closed ceremony context carries the request, representation,
principal/session/origin, authorization subject, required posture, policy
decision, risk, nonce, expiry, revocation posture, and any required authority
resolution. When the principal uses the registered portable grammar, its
resolution ref
must resolve to the exact closed `PrincipalAuthorityResolutionV1` object and
the resolution hash must equal SHA-256 over its RFC 8785 JCS bytes. No
abbreviated binding/snapshot projection is accepted. That exact artifact
retains `resolved_at_ms`, immutable coordinates, required and matched scope,
the complete `ApprovalAuthority` snapshot (`scope_allowlist`, expiry, and
revocation posture included), duplicated authority identity fields, and
mutation-audit coordinates. For nonportable account-local principals, both
resolution fields are null.

The challenge URL ref is a pointer to an authority session, not an authority
grant. Approval must use wallet.network, Hypervisor, an enrolled guardian
authority client, enterprise approval surface, local app, CLI signer, or another
policy-admitted presentation surface composed with AuthFactors satisfying the
required posture. The agent receives only a scoped `grant://...` or denial
receipt after the step-up flow completes.

QR or push delivery is not authority by itself. The GuardianSurface produces
presentation evidence under the named profile; the AuthFactor independently
authenticates the bound ceremony. A WebAuthn assertion may carry the
authenticator's signed user-verification flag and can participate in the
approval ceremony, but it does not independently prove what the application
surface displayed or that the user understood it. The agent never receives OTP
values, raw biometric samples or templates, provider tokens, raw key shards,
raw session material, or guardian secrets.

## Principal-to-Approval-Authority Binding API

This API is the wallet.network-owned identity-to-authority bridge for governed
runtime decisions. It does not authenticate a local user and it does not infer
authority from product roles. It resolves a canonical portable principal to the
exact registered `ApprovalAuthority` key allowed to sign for that principal.

```http
POST /v1/authority/principal-bindings
POST /v1/authority/principal-bindings/revoke
POST /v1/authority/principal-bindings/resolve
POST /v1/authority/principal-bindings/lookup
```

The corresponding wallet service methods are:

```text
issue_principal_authority_binding@v1
revoke_principal_authority_binding@v1
resolve_principal_authority@v1
lookup_principal_authority_binding@v1
```

Issue and revoke accept a complete `PrincipalAuthorityBindingProofV1`. Only the
initialized wallet control root may author those signed append-only versions.
Resolution and proof lookup require an initialized, registered wallet authority
client. The legacy uninitialized-wallet compatibility path is never authority
for this object family.

Canonical principal refs are exactly one of:

```text
^(worker|service|org|domain)://<canonical-segment>(/<canonical-segment>)*$
^agentgres://domain/<canonical-segment>(/<canonical-segment>)*$
```

Each segment starts and ends with an ASCII letter or digit; internal characters
may also be `.`, `_`, `-`, `~`, `:`, or `@`. Leading, trailing, and doubled
slashes are invalid.

The immutable proof shape is below; byte arrays are abbreviated only for
readability here, while the checked-in fixtures carry all bytes:

```json
{
  "schema_version": 1,
  "statement": {
    "schema_version": 1,
    "principal_ref": "agentgres://domain/acme.example",
    "authority_kind": "approval",
    "binding_version": 1,
    "status": "active",
    "authority_id": [11, 11, "... exactly 32 bytes"],
    "authority_public_key": [12, 12, "..."],
    "authority_signature_suite": -8,
    "approval_authority_snapshot_hash": [13, 13, "... exactly 32 bytes"],
    "signed_at_ms": 1781286400000,
    "expires_at_ms": 1812822400000,
    "issuer_root_account_id": [14, 14, "... exactly 32 bytes"]
  },
  "statement_hash": [15, 15, "... exactly 32 bytes"],
  "issuer_signature_proof": {
    "suite": -8,
    "public_key": [14, 14, "..."],
    "signature": [16, 16, "..."]
  },
  "binding_ref": "wallet.network://principal-authority-binding/<64-lowercase-hex-binding-hash>",
  "binding_hash": [17, 17, "... exactly 32 bytes"]
}
```

Version 1 has no predecessor. Every later version binds the exact previous
binding ref and hash. The revoke request repeats that predecessor ref in its
body, and the service requires byte-for-byte agreement with both the proof and
the current head. Revocation is a new `revoked` version with a trimmed, nonempty
reason; it never edits the active proof in place. Version 4095 is the final
active version and version 4096 is reserved for terminal revocation.

The mutable head is only a current-version pointer and carries the mutation
audit sequence plus event id/hash. Every accepted version also writes a separate
immutable index entry keyed by the exact principal hash and version. Resolution
requires the head to match that indexed ref/version/hash/status/audit tuple and
requires the next-version index slot to be absent. Restoring an authentic old
head together with its authentic old mutable mutation marker therefore refuses
whenever a later indexed version remains.

This rollback guarantee is relative to the currently committed wallet state
root. Preventing rollback of the complete state database, including every
immutable index entry, is the responsibility of the ledger/finality layer that
anchors and selects wallet state roots. The resolver does not claim to detect a
wholesale rollback to an older externally accepted state root.

Resolution may be unpinned or may require exact immutable coordinates:

```json
{
  "request_id": [22, 22, "... exactly 32 nonzero bytes"],
  "principal_ref": "agentgres://domain/acme.example",
  "authority_kind": "approval",
  "required_scope": "room_participation.admit",
  "expected_coordinates": {
    "binding_ref": "wallet.network://principal-authority-binding/<64-lowercase-hex-binding-hash>",
    "binding_version": 1,
    "binding_hash": [17, 17, "... exactly 32 bytes"]
  }
}
```

The resolution receipt returns those coordinates, `required_scope`, the exact
matched allowlist entry, the complete `ApprovalAuthority` snapshot, its exact
authority id/public key/signature suite, `approval_authority_snapshot_hash`,
resolve time, and the mutation audit event id/hash. The
`@ioi/wallet-protocol` receipt validator and `@ioi/wallet-sdk` client recompute
the exact Rust-compatible `serde_jcs` plus SHA-256 snapshot hash and byte-compare
it before evaluating any matched scope. Downstream consumers must also verify
the governed grant against that exact snapshot; signer identity alone never
authorizes an operation. `expected_coordinates`, lookup
`expected_binding_hash`, predecessor coordinates, expiry, and reason are omitted
when absent, matching the Rust ABI.

The resolver verifies control-root signature, statement/binding hashes,
predecessor lineage, immutable version index, current head, active status,
expiry, audit commitment, required operation scope through the canonical
authority matcher, and the current ApprovalAuthority registry entry. Registry
revocation, expiry, key/suite/snapshot drift, empty scope, or scope mismatch
invalidates resolution. Missing, stale, foreign,
ambiguous, malformed, or pin-mismatched state returns a typed refusal. There is
no fallback to local login, organization roles, session identity, caller fields,
copied receipt fields, or trust on first use.

Durable governed intents must retain the complete signed grant, complete
authority snapshot, frozen snapshot hash, required and matched operation scope,
and exact binding ref/version/hash returned here. Admission and boot recovery
reverify that complete tuple; they must not reconstruct authority from grant
fields or signer identity alone.

## Authority Scope Request API

```http
POST /v1/authority/scope-requests
GET  /v1/authority/scope-requests/{request_id}
POST /v1/authority/scope-requests/{request_id}/approve
POST /v1/authority/scope-requests/{request_id}/deny
GET  /v1/authority/grants
GET  /v1/authority/grants/{grant_id}
POST /v1/authority/grants/{grant_id}/revoke
GET  /v1/authority/capabilities
POST /v1/authority/capability-leases
GET  /v1/authority/capability-leases/{lease_id}
POST /v1/authority/capability-leases/{lease_id}/revoke
```

### Authority Scope Request

The following is the target exact-action v2 request. Current unversioned request
adapters remain unchanged until the v2 schema, fixtures, projections, migration,
producer, and verifier land as one cut.

```json
{
  "schema_version": 2,
  "authority_request_id": "authority-request://wallet/user_123/merge_456",
  "principal_ref": "agentgres://domain/acme.example",
  "product_session_ref": "session://ioi-ai/product_123",
  "origin_binding_ref": "origin-binding://wallet.example/app",
  "subject_id": "agent://change-integrator",
  "issuer_id": "wallet://user_123",
  "requesting_runtime_ref": "runtime://node_abc",
  "purpose": "Merge verified change set change://ioi/456 into main",
  "requested_auth_factor_posture_refs": [
    "policy://wallet/auth-factor/fresh-user-verification"
  ],
  "requested_guardian_surface_refs": [
    "guardian://device/user_123/phone"
  ],
  "primitive_capabilities_required": ["prim:fs.read", "prim:sys.exec"],
  "authority_scopes_requested": ["scope:repo.write"],
  "resource_scope": {
    "resources": ["git://repo/ioi", "change://ioi/456"],
    "constraints": {
      "max_budget_usd": 5,
      "expiry": "2027-05-01T12:00:00Z",
      "approval_required_for": ["repo_merge"]
    }
  },
  "destination_refs": ["git://repo/ioi/ref/main"],
  "authorization_subject": {
    "kind": "exact_effect",
    "subject_ref": "effect://repo/merge/change-456",
    "subject_hash": "sha256:...",
    "validation_profile_ref": "schema://ioi/repo-merge-effect/v1"
  },
  "risk_classes": ["write_reversible"],
  "policy_hash": "sha256:...",
  "authority_request_body_hash": "sha256:...",
  "authority_grant_id": null,
  "status": "requested"
}
```

`product_session_ref` is owned by the calling product or deployment identity
plane. wallet.network binds it into the authority request and review; it does
not create, renew, revoke, or otherwise own that product session.
`authority_request_body_hash` uses the target v2 profile
`SHA-256("IOI-AUTHORITY-SCOPE-REQUEST-V2\0" || RFC8785_JCS(closed_body))`,
where `closed_body` is the exact v2 object excluding only
`authority_request_body_hash`, `authority_grant_id`, and `status`.

Request-side AuthFactor and GuardianSurface fields express requested or eligible
posture only. They are not evidence that a factor or surface participated.
Wallet-owned review and ceremony processing records actual
`satisfied_auth_factor_refs`, `satisfied_guardian_surface_refs`, presentation
evidence, and authenticator or quorum evidence in the `AuthorityReviewReceipt`
and target v3 grant.

`authorization_subject.kind` determines effect admission:

- `exact_effect` commits one canonical effect payload and requires exact
  daemon-derived hash equality; its subject ref is `effect://`;
- `batch_manifest` commits a manifest root and requires a membership proof under
  `validation_profile_ref`; its subject ref is `artifact://`; and
- `standing_envelope` commits the complete reusable constraint envelope and
  requires every concrete effect to validate inside it; its subject ref is
  `policy://`.

The daemon records that final comparison in the target
`AuthorityEffectAdmissionReceiptV1`; a review receipt, grant, or generic tool
receipt does not prove effect admission. This receipt profile is planned and
must land with its schema, projection, emitter, and verifier before the
end-to-end claim is made.

Worker Training scope requests use the same envelope. Typical scopes include:

```text
scope:training.data.use
scope:training.trace.use
scope:training.dataset.decrypt
scope:training.remote_compute.request
scope:data.source.read
scope:data.recipe.run
scope:data.transform
scope:data.view.use
scope:data.train.use
scope:data.eval.use
scope:data.export
scope:data.publish
scope:ontology.publish
scope:connector.mapping.use
scope:benchmark.submit
scope:worker.publish
scope:mow.route
```

Protected autonomous-system transitions use separate scopes:

```text
scope:autonomous_system.genesis_admit
scope:autonomous_system.constitution_amend
scope:autonomous_system.deployment_profile_change
scope:autonomous_system.node_admit
scope:autonomous_system.node_role_change
scope:autonomous_system.writer_promote
scope:autonomous_system.authority_membership_change
scope:autonomous_system.consensus_membership_change
scope:autonomous_system.failover_profile_change
scope:autonomous_system.ordering_admission_finality_profile_change
scope:autonomous_system.oracle_profile_change
scope:autonomous_system.lifecycle_profile_change
scope:autonomous_system.recover
scope:autonomous_system.suspend
scope:autonomous_system.quarantine
scope:autonomous_system.migrate
scope:autonomous_system.fork
scope:autonomous_system.adopt
scope:autonomous_system.succeed
scope:autonomous_system.retire
scope:autonomous_system.dissolve
scope:autonomous_system.decommission
scope:autonomous_system.network_enrollment_change
```

`scope:autonomous_system.genesis_admit` is the one-time package-to-System
admission scope. It binds the exact compiled release, proposed instantiation,
System and genesis identities, proposal root, governing constitution authority,
and daemon-derived admission effect. The accepted wallet grant is consumed
statefully by exact grant hash before the System admission can become visible;
the immutable consumption receipt and remaining-use count are part of the
admission evidence. A review or recorded grant that has not crossed this
consumption boundary is not admission authority.

Requests for these scopes additionally bind `system_id`, active constitution
root, target profile or membership ref, predecessor and proposed roots,
required decision profile, evidence refs, and the exact transition. They are
not interchangeable and cannot be inferred from ordinary deployment,
improvement, or node access.

Training-data grants should bind purpose, reuse rights, retention policy,
privacy class, dataset commitment, domain ontology refs, data recipe refs,
policy-bound data view refs, allowed transformation methods, allowed runtime
environment, and expiry.

### Target Context-Bound Authority Grant

The following is a semantic excerpt of the planned
`AuthorityGrantEnvelope` v3 result for the request above, not a claim that a v3
wire contract is registered or built. The eventual wire object retains every
portable-v2 signature, holder, audience, parent, caveat, revocation, and
attenuation field in addition to this request commitment:

```json
{
  "authority_grant_id": "grant://wallet/user_123/merge_456",
  "request_id": "authority-request://wallet/user_123/merge_456",
  "issuer_id": "wallet://user_123",
  "subject_id": "agent://change-integrator",
  "authority_scopes": ["scope:repo.write"],
  "primitive_capability_constraints": ["prim:fs.read", "prim:sys.exec"],
  "resources": ["git://repo/ioi", "change://ioi/456"],
  "constraints": {
    "max_budget_usd": 5,
    "expires_at": "2027-05-01T12:00:00Z",
    "approval_required_for": ["repo_merge"],
    "max_calls": 1
  },
  "request_commitment": {
    "authority_request_id": "authority-request://wallet/user_123/merge_456",
    "authority_request_body_hash": "sha256:...",
    "reviewed_representation_hash": "sha256:...",
    "presentation_surface_ref": "guardian://device/user_123/phone",
    "presentation_evidence_profile_ref": "policy://wallet/presentation/semantic-review/v1",
    "presentation_evidence_refs": [
      "receipt://wallet/presentation/merge_456"
    ],
    "approval_ceremony_context_ref": "approval-ceremony-context://wallet/merge_456",
    "approval_ceremony_context_hash": "sha256:...",
    "approval_ceremony_evidence_refs": [
      "evidence://wallet/webauthn-assertion/merge_456"
    ],
    "authorization_subject": {
      "kind": "exact_effect",
      "subject_ref": "effect://repo/merge/change-456",
      "subject_hash": "sha256:...",
      "validation_profile_ref": "schema://ioi/repo-merge-effect/v1"
    },
    "principal_ref": "agentgres://domain/acme.example",
    "product_session_ref": "session://ioi-ai/product_123",
    "origin_binding_ref": "origin-binding://wallet.example/app",
    "required_auth_factor_posture_refs": [
      "policy://wallet/auth-factor/fresh-user-verification"
    ],
    "required_guardian_surface_refs": [
      "guardian://device/user_123/phone"
    ],
    "satisfied_auth_factor_refs": [
      "auth_factor://passkey/user_123/laptop"
    ],
    "satisfied_guardian_surface_refs": [
      "guardian://device/user_123/phone"
    ],
    "posture_satisfaction_profile_ref": "policy://wallet/posture-satisfaction/v1",
    "posture_satisfaction_evaluations": [
      {
        "requirement_ref": "policy://wallet/auth-factor/fresh-user-verification",
        "requirement_kind": "auth_factor",
        "satisfied_by_refs": ["auth_factor://passkey/user_123/laptop"],
        "evidence_refs": ["evidence://wallet/webauthn-assertion/merge_456"],
        "evaluation_profile_ref": "policy://wallet/posture-satisfaction/auth-factor/v1",
        "decision": "satisfied"
      },
      {
        "requirement_ref": "guardian://device/user_123/phone",
        "requirement_kind": "guardian_surface",
        "satisfied_by_refs": ["guardian://device/user_123/phone"],
        "evidence_refs": ["receipt://wallet/presentation/merge_456"],
        "evaluation_profile_ref": "policy://wallet/posture-satisfaction/guardian/v1",
        "decision": "satisfied"
      }
    ],
    "posture_satisfaction_root": "sha256:...",
    "interaction_mode": "interactive",
    "authentication_posture": "step_up",
    "receipt_timing": "before_effect",
    "principal_authority_resolution_ref": "artifact://wallet/principal-authority-resolution/merge_456",
    "principal_authority_resolution_hash": "sha256:...",
    "policy_decision_receipt_ref": "receipt://wallet/policy-decision/merge_456",
    "policy_decision_receipt_hash": "sha256:...",
    "authority_review_receipt_ref": "receipt://wallet/review/merge_456",
    "authority_review_receipt_hash": "sha256:...",
    "approval_evidence_profile_ref": "schema://ioi/wallet/approval-evidence/v1",
    "approval_evidence_leaf_refs": [
      "receipt://wallet/review/merge_456",
      "receipt://wallet/presentation/merge_456",
      "evidence://wallet/webauthn-assertion/merge_456",
      "receipt://wallet/policy-decision/merge_456",
      "artifact://wallet/principal-authority-resolution/merge_456"
    ],
    "approval_evidence_root": "sha256:..."
  },
  "revocation_epoch": 7,
  "status": "active"
}
```

The target v3 grant signs the commitments above in addition to every preserved
portable-v2 field. The approval-evidence root is usable only with its named
profile, whose versioned contract defines canonical leaf encoding, ordering,
domain separation, inclusion verification, and which evidence kinds policy
requires. A bare root, caller-authored factor ref, unbound review receipt, or
copied signer identity is not approval evidence.

The review receipt, presentation evidence, WebAuthn assertion or other
AuthFactor evidence, and principal-authority resolution remain separate leaves.
WebAuthn evidence authenticates the ceremony facts it covers; presentation
evidence records the application-defined representation claim under its own
profile; when a portable principal is used, the resolution proves which
registered authority was eligible for the exact operation. None silently
inherits another's claims.

### Capability Lease

Agents, apps, and runtimes act through leased capabilities, not durable
plaintext secrets or root accounts.

```json
{
  "lease_id": "lease://capability/gmail-send/abc",
  "grant_id": "grant_123",
  "issuer_id": "wallet://user_123",
  "subject_id": "agent://assistant",
  "capability": "scope:gmail.send",
  "object_scope": {
    "resources": ["gmail://account/user@example.com"],
    "max_calls": 25,
    "ttl_seconds": 3600
  },
  "secret_release_policy": {
    "mode": "brokered_execution",
    "can_view_secret": false,
    "can_use_secret": true,
    "step_up_required_for": ["new_recipient", "attachment", "external_domain"]
  },
  "review_recipe": "session_envelope",
  "authorization_subject_kind": "standing_envelope",
  "interaction_mode": "interactive",
  "authentication_posture": "baseline",
  "revocation_epoch": 7,
  "receipt_policy": "per_use | aggregate_with_after_the_fact_receipts",
  "status": "active"
}
```

Capability leases are the Wallet-native answer to credential orchestration:
the agent receives a scoped, expiring right to ask Wallet or a provider to use a
capability. It does not receive long-lived credentials by default.

### Provider Credential Binding

Provider credential bindings are brokered credentials managed by wallet.network.
They are not auth factors and not authority grants. A Google login may bootstrap
account access; a Google provider credential binding may later authorize Gmail,
Drive, or other provider scopes only after policy and grant issuance.

```json
{
  "credential_binding_id": "credential://google/user_123/workspace",
  "owner_ref": "wallet://user_123",
  "provider": "google | github | coinbase | aws | openai | anthropic | custom",
  "credential_kind": "oauth_refresh_token | api_key | wallet_credential | byok_model_key | cloud_role",
  "available_scopes": ["scope:gmail.send", "scope:drive.read"],
  "secret_ref": "wallet.network://secret/google-workspace-refresh-token",
  "default_release_policy": "brokered_execution",
  "can_export_secret": false,
  "revocation_epoch": 7,
  "status": "active"
}
```

### Capability Lease Revocation

Revocation is a typed authority action, not silent local state mutation. The
request should bind the lease, initiator, holder, scope, policy hash,
revocation epoch, timestamp, and receipt refs.

```json
{
  "revocation_id": "revocation://capability/gmail-send/abc",
  "schema_version": "ioi.wallet.protocol.v1",
  "lease_id": "lease://capability/gmail-send/abc",
  "initiator_id": "wallet://user_123",
  "holder_id": "account://primary",
  "capability_scope": "scope:gmail.send",
  "policy_hash": "sha256:...",
  "revocation_epoch": 8,
  "revoked_at": "2026-06-17T00:30:00Z",
  "reason": "User revoked the delegated Gmail send capability.",
  "receipt_refs": ["receipt://wallet/capability-lease/revoked/abc"]
}
```

After revocation, future capability use must fail unless a later policy review
issues a new lease under a newer revocation epoch.

## Secret and BYOK API

```http
POST /v1/secrets
GET  /v1/secrets/{secret_id}/metadata
POST /v1/secrets/{secret_id}/rotate
DELETE /v1/secrets/{secret_id}
POST /v1/byok/model-provider
GET  /v1/byok/model-provider/{provider_id}
POST /v1/byok/model-provider/{provider_id}/test
```

No agent receives raw secrets by default. The preferred mode is brokered execution.

## Secret Brokerage API

```http
POST /v1/secret-execution/request
GET  /v1/secret-execution/{execution_id}
```

Secret brokerage example:

```json
{
  "authority_scope": "scope:gmail.send",
  "subject_id": "agent://assistant",
  "runtime_id": "runtime://node_abc",
  "request_hash": "sha256:...",
  "input_ref": "artifact://email_draft_123",
  "mode": "brokered_execution | sealed_to_tee | local_only"
}
```

## Archive Restore Authority API

```http
POST /v1/archive-restore/request
GET  /v1/archive-restore/{restore_authority_id}
POST /v1/archive-restore/{restore_authority_id}/approve
POST /v1/archive-restore/{restore_authority_id}/deny
POST /v1/archive-restore/{restore_authority_id}/lease-key
POST /v1/archive-restore/{restore_authority_id}/revoke
```

Restore authority grants should bind:

```json
{
  "restore_authority_id": "restore_auth_123",
  "archive_cid": "cid://bafy...",
  "archive_sha256": "sha256:...",
  "agentgres_domain": "agentgres://domain/local-hypervisor-user",
  "state_root": "sha256:...",
  "requesting_runtime": "runtime://node_abc",
  "allowed_environment": "local | tee_enterprise | customer_vpc",
  "recipient": "wallet://user_or_org",
  "policy_hash": "sha256:...",
  "expires_at": "2026-05-01T12:00:00Z"
}
```

The archive may contain secret refs. It should not contain raw long-lived
secrets unless separately sealed under explicit policy.

## Approval API

```http
GET  /v1/approvals
GET  /v1/approvals/{approval_id}
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/deny
POST /v1/approvals/{approval_id}/edit-and-approve
POST /v1/authority/reviews
GET  /v1/authority/reviews/{review_id}
POST /v1/authority/reviews/{review_id}/render-profile
```

Target approval-grant projection (planned successor; not the current approval
API wire shape):

```json
{
  "approval_id": "approval_123",
  "principal_ref": "agentgres://domain/acme.example",
  "acting_subject_ref": "agent://assistant",
  "product_session_ref": "session://ioi-ai/product_123",
  "origin_binding_ref": "origin-binding://wallet.example/app",
  "authority_request_body_hash": "sha256:...",
  "reviewed_representation_hash": "sha256:...",
  "approval_ceremony_context_ref": "approval-ceremony-context://wallet/abc",
  "approval_ceremony_context_hash": "sha256:...",
  "authorization_subject": {
    "kind": "exact_effect",
    "subject_ref": "effect://gmail/send/abc",
    "subject_hash": "sha256:...",
    "validation_profile_ref": "schema://gmail/send/v1"
  },
  "authority_review_receipt_ref": "receipt://wallet/review/abc",
  "authority_review_receipt_hash": "sha256:...",
  "required_auth_factor_posture_refs": [
    "policy://wallet/auth-factor/fresh-user-verification"
  ],
  "required_guardian_surface_refs": [
    "guardian://device/user_123/phone"
  ],
  "satisfied_auth_factor_refs": [
    "auth_factor://passkey/user_123/laptop"
  ],
  "satisfied_guardian_surface_refs": [
    "guardian://device/user_123/phone"
  ],
  "posture_satisfaction_profile_ref": "policy://wallet/posture-satisfaction/v1",
  "posture_satisfaction_evaluations": [
    {
      "requirement_ref": "policy://wallet/auth-factor/fresh-user-verification",
      "requirement_kind": "auth_factor",
      "satisfied_by_refs": ["auth_factor://passkey/user_123/laptop"],
      "evidence_refs": ["evidence://wallet/webauthn-assertion/abc"],
      "evaluation_profile_ref": "policy://wallet/posture-satisfaction/auth-factor/v1",
      "decision": "satisfied"
    },
    {
      "requirement_ref": "guardian://device/user_123/phone",
      "requirement_kind": "guardian_surface",
      "satisfied_by_refs": ["guardian://device/user_123/phone"],
      "evidence_refs": ["receipt://wallet/presentation/abc"],
      "evaluation_profile_ref": "policy://wallet/posture-satisfaction/guardian/v1",
      "decision": "satisfied"
    }
  ],
  "posture_satisfaction_root": "sha256:...",
  "interaction_mode": "interactive",
  "authentication_posture": "step_up",
  "receipt_timing": "before_effect",
  "principal_authority_resolution_ref": "artifact://wallet/principal-authority-resolution/abc",
  "principal_authority_resolution_hash": "sha256:...",
  "policy_decision_receipt_ref": "receipt://wallet/policy-decision/abc",
  "policy_decision_receipt_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "scope": {
    "action": "gmail.send",
    "resource": "gmail://thread/abc",
    "expires_at": "2026-05-01T00:00:00Z"
  },
  "single_use": true
}
```

### Authority Review

`AuthorityReview` is the reusable Wallet authority surface behind the full
Wallet app, embedded approval cards, mobile sheets, CLI prompts, and advanced
operator consoles.

```json
{
  "schema_version": 1,
  "authority_review_ref": "review://wallet/abc",
  "predecessor_authority_review_ref": null,
  "predecessor_authority_review_body_hash": null,
  "predecessor_authority_request_ref": null,
  "predecessor_authority_request_body_hash": null,
  "predecessor_authority_review_receipt_ref": null,
  "predecessor_authority_review_receipt_hash": null,
  "authority_review_body_hash": "sha256:...",
  "authority_request_ref": "authority-request://wallet/user_123/merge_456",
  "authority_request_body_hash": "sha256:...",
  "principal_ref": "agentgres://domain/acme.example",
  "product_session_ref": "session://ioi-ai/product_123",
  "origin_binding_ref": "origin-binding://wallet.example/app",
  "acting_subject_ref": "system://... | agent://... | worker://... | runtime://...",
  "decision_actor_ref": "wallet://user_123",
  "authorization_subject": {
    "kind": "exact_effect | batch_manifest | standing_envelope",
    "subject_ref": "effect://... | artifact://... | policy://...",
    "subject_hash": "sha256:...",
    "validation_profile_ref": "schema://... | policy://..."
  },
  "reviewed_representation": {
    "representation_profile_ref": "schema://wallet/authority-review-representation/v1",
    "representation_version": "1",
    "locale": "en-US",
    "intent_ref": "intent://...",
    "intent_hash": "sha256:...",
    "object_refs": ["asset://...", "credential://...", "workload://..."],
    "capabilities_requested": ["scope:broker.place_order"],
    "simulation_ref": "simulation://...",
    "required_disclosure_set_ref": "policy://wallet/review-disclosures/trade",
    "required_disclosure_set_hash": "sha256:...",
    "risk_labels": [
      {
        "label": "Venue Risk",
        "level": "medium",
        "source": "adapter://decentralized.trade/hyperliquid",
        "coverage_state": "Assessed",
        "confidence": 0.82,
        "as_of": "2026-06-14T12:00:00Z",
        "expires_at": "2026-06-14T12:05:00Z",
        "evidence_refs": ["artifact://..."]
      }
    ],
    "eligibility_labels": [
      {
        "label": "Jurisdiction Restricted",
        "level": "high",
        "coverage_state": "Unknown",
        "source": "policy://venue-eligibility"
      }
    ],
    "policy_result": {
      "decision": "approve | deny | requires_step_up | edit_required",
      "blocking_reasons": ["requested leverage exceeds policy cap"],
      "required_changes": ["lower leverage", "add stop loss"],
      "safer_alternatives": ["paper mode"]
    },
    "allowed_review_recipes": [
      "one_shot_review",
      "step_up_review"
    ],
    "recommended_presentation_profile": "standard_wallet_review",
    "representation_artifact_ref": "artifact://wallet/review/abc"
  },
  "reviewed_representation_hash": "sha256:...",
  "approval_ceremony_context_ref": "approval-ceremony-context://wallet/review_abc",
  "approval_ceremony_context_hash": "sha256:...",
  "requested_auth_factor_posture_refs": [
    "policy://wallet/auth-factor/fresh-user-verification"
  ],
  "requested_guardian_surface_refs": [
    "guardian://device/user_123/phone"
  ],
  "required_auth_factor_posture_refs": [
    "policy://wallet/auth-factor/fresh-user-verification"
  ],
  "required_guardian_surface_refs": [
    "guardian://device/user_123/phone"
  ],
  "presentation_surface_ref": "guardian://device/user_123/phone",
  "presentation_evidence_profile_ref": "policy://wallet/presentation/semantic-review/v1",
  "presentation_evidence_refs": [
    "receipt://wallet/presentation/abc",
    "artifact://wallet/review/abc"
  ],
  "principal_authority_resolution_ref": "artifact://wallet/principal-authority-resolution/review_abc",
  "principal_authority_resolution_hash": "sha256:...",
  "policy_decision_receipt_ref": "receipt://wallet/policy-decision/review_abc",
  "policy_decision_receipt_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "risk_classes": ["write_reversible"],
  "posture_satisfaction_profile_ref": "policy://wallet/posture-satisfaction/v1",
  "posture_satisfaction_evaluations": [],
  "posture_satisfaction_root": null,
  "interaction_mode": "interactive | noninteractive_policy",
  "authentication_posture": "baseline | step_up",
  "receipt_timing": "before_effect | after_effect",
  "expires_at": "2027-05-01T12:00:00Z",
  "status": "prepared | presented | approved | denied | edit_required | expired | superseded"
}
```

`reviewed_representation_hash` is:

```text
SHA-256(
  "IOI-AUTHORITY-REVIEW-REPRESENTATION-V1\0" ||
  RFC8785_JCS(reviewed_representation)
)
```

It therefore covers the semantic intent, affected objects, requested
capabilities, simulation, risk and eligibility labels, policy result, allowed
recipes, canonical disclosures, and representation artifact, not incidental
layout or pixels. Presentation shells may derive different layouts from that
representation, but
`POST /v1/authority/reviews/{review_id}/render-profile` cannot mutate the
representation, request, authorization subject, ceremony context, or resolved
principal-authority tuple. Its result retains the same representation hash and
records the selected layout profile separately from
`presentation_evidence_profile_ref`.

`authority_review_body_hash` is the domain-separated hash of the closed
immutable review-preparation fields defined by the shared object canon. It
excludes the ceremony context itself, evidence, mutable status, decision, and
resulting grant refs; the context may therefore bind that preparation hash
without a cycle. The API uses the canonical field names
`schema_version`, `authority_review_ref`, `authority_request_ref`, all six
`predecessor_authority_*` fields, and `expires_at` directly; aliases such as
`review_id`, `predecessor_review_ref`, or `authority_request_id` do not
participate. Requested posture fields are exact projections of the resolved
request; no authority-relevant review field remains outside the request hash,
review-preparation hash, reviewed-representation hash, policy-decision receipt,
ceremony context, or final review receipt.

`presentation_evidence_profile_ref` identifies how evidence claims are
constructed and evaluated. It is accompanied by immutable evidence refs and
orthogonal dimensions for operator/surface, content binding,
request-versus-effect binding, enrollment/attestation, UP/UV,
freshness/replay, and proposer independence. It must never be collapsed into a
two-tier assurance enum. Missing evidence remains missing; one dimension does
not upgrade another.

### Authority Review Receipt

`AuthorityReviewReceiptV1` is a portable wrapper around the exact registered
closed `ReceiptEnvelope` v1, not a new authority primitive. The exhaustive
wrapper, hash rules, profile bindings, and claim limits are owned by
[`events-receipts-delivery-bundles.md`](../daemon-runtime/events-receipts-delivery-bundles.md#authority-review-receipt).
This API returns its `receipt://...` ref and wrapper hash; it does not define a
second receipt shape. The target profile binds the request, principal/session/
origin, acting subject, authorization subject, reviewed representation,
presentation surface/profile/evidence, ceremony and factor evidence,
per-requirement posture-satisfaction evaluations, exact principal-authority
resolution when required by the portable principal contract, policy decision,
independent interaction mode, authentication posture, receipt timing,
immutable result, expiry, and hash-bound predecessor lineage.

This API shape is planned. It becomes writable only after the receipt profile,
context-bound v3 grant, generated projections, and verifier are registered;
current v1/v2 authority and receipt contracts remain unchanged.

The product-level review recipes are not one wire enum. Cardinality is carried
by `authorization_subject.kind`; `interaction_mode` is `interactive` or
`noninteractive_policy`; `authentication_posture` is independently `baseline`
or `step_up`; receipt timing is `before_effect` or `after_effect`; and
approval/refusal is the decision. A recipe is a policy-selected projection over
those orthogonal fields.

The receipt distinguishes requested posture from satisfied posture. A WebAuthn
assertion-verification receipt is one possible `auth_factor_evidence_ref`; it
remains separate from presentation-evidence refs. The review receipt binds
their common ceremony context without claiming that either evidence source
proves the other's facts. Every required posture ref has exactly one
hash-bound evaluation; approved decisions require every evaluation to be
`satisfied`, and the satisfied-ref arrays are projections of those evaluations.

`edit-and-approve` never mutates a review in place. It creates a successor
authority request, authorization subject, canonical representation, challenge,
ceremony context, and review receipt. The successor receipt points back to the
predecessor request/review; no predecessor receipt is rewritten. The predecessor
review becomes `superseded`, and its challenge, assertion, decision, and
evidence root cannot authorize the successor.

Presentation profiles:

```text
lite_approval_card
standard_wallet_review
advanced_authority_console
cli_prompt
mobile_approval_sheet
```

Review recipes:

```text
one_shot_review
session_envelope
batch_review
silent_within_policy
after_the_fact_receipt
step_up_review
denied
```

Apps may request a presentation profile and review recipe, but Wallet derives
the authorization subject, interaction mode, authentication posture, receipt
timing, and allowed recipe from policy, risk, eligibility, account posture, and
active session state. For `one_shot_review`, daemon admission requires exact equality
between the authorized `exact_effect` hash and its own canonical effect hash.
For `batch_review`, each effect requires membership in the committed
`batch_manifest`. For a `session_envelope`, `silent_within_policy`, or
`after_the_fact_receipt` path, every effect must satisfy the committed
`standing_envelope`; receipts must state that the envelope, not the individual
effect, was reviewed. The target `AuthorityEffectAdmissionReceiptV1` records
that comparison and whether the invoker was called.

## Wallet Authority Client Surfaces

wallet.network may expose web, mobile, desktop, embedded Hypervisor panels, CLI,
SDK, MCP, enterprise authority service, and local signer surfaces. These are
clients of the same authority pipeline, not separate sources of authority.

```http
POST /v1/authority/client-sessions
GET  /v1/authority/client-sessions/{client_session_id}
POST /v1/authority/client-sessions/{client_session_id}/revoke
POST /v1/authority/client-sessions/{client_session_id}/rotate
POST /v1/authority/client-sessions/{client_session_id}/quarantine
GET  /v1/authority/client-sessions/{client_session_id}/blast-radius
POST /v1/authority/challenges/{challenge_id}/approve
POST /v1/authority/challenges/{challenge_id}/deny
POST /v1/authority/challenges/{challenge_id}/edit-and-approve
GET  /v1/authority/client-sessions/{client_session_id}/receipts
```

Client session example:

```json
{
  "client_session_id": "wallet-client://cli/user_123/session_abc",
  "client_kind": "wallet_web | wallet_mobile | wallet_desktop | hypervisor_panel | cli_signer | mcp_server | sdk | enterprise_authority_service",
  "owner_ref": "wallet://user_123",
  "subject_ref": "agent://external/runtime-auditor",
  "origin_binding": {
    "origin_ref": "origin://localhost/cli",
    "device_ref": "device://user_123/laptop",
    "public_key_ref": "key://wallet-client/session_abc",
    "attestation_ref": "attestation://optional"
  },
  "auth_factor_refs": ["auth_factor://passkey/user_123/laptop"],
  "guardian_refs": ["guardian://device/user_123/phone"],
  "allowed_operations": [
    "request_authority",
    "approve_challenge",
    "deny_challenge",
    "inspect_grants",
    "revoke_lease",
    "list_receipts"
  ],
  "authority_scope_refs": ["scope:project.read"],
  "active_grant_refs": ["grant://project-read/123"],
  "active_lease_refs": ["lease://project-read/456"],
  "gateway_profile_refs": ["mcp_gateway://project-auditor-readonly"],
  "connector_refs": ["connector://github"],
  "risk_ceiling": "funds | deploy | secret_export | policy_widening",
  "last_use_at": "2026-06-20T12:45:00Z",
  "last_use_ref": "event://authority-client-use/abc",
  "anomaly_state": "clean | watch | origin_mismatch | expired_use | scope_excess | suspicious_frequency | policy_denied | leaked | compromised",
  "quarantine_advisory_refs": [],
  "expires_at": "2026-06-20T13:00:00Z",
  "revocation_epoch": 7,
  "status": "active | expired | suspended | quarantined | rotating | rotated | revoked"
}
```

Compromised-client handling must fail closed. Origin mismatch, expired use,
scope excess, suspicious frequency, leaked key material, or policy-denied effect
requests must block mutation before any provider call. wallet.network owns
client-session revoke, rotation, quarantine, replacement binding, and grant/lease
revocation. Hypervisor and Agentgres consume those outcomes to pause or
quarantine dependent gateway profiles, sessions, WorkRuns, connector calls, and
pending approvals without treating UI state as authority truth.

### wallet.network CLI

The wallet.network CLI is a local operator and signer surface. It may support:

```text
sign in
link factor
enroll guardian
approve / deny / edit challenge
inspect grants
revoke grants or leases
broker secret execution
export receipts
```

The CLI must still call the same account, guardian, approval, grant, lease,
secret-brokerage, receipt, and revocation APIs. A local CLI signer can satisfy
policy only when it is enrolled as a guardian surface or required client session.

### wallet.network MCP

The wallet.network MCP surface is an agent-facing authority request and receipt
surface. It may expose tool equivalents of:

```text
wallet_authority_request
wallet_authority_status
wallet_capability_check
wallet_approval_request
wallet_payment_request
wallet_receipts_list
wallet_grant_revoke_request
```

It must not expose tools that reveal raw secrets, export provider tokens,
raw-sign arbitrary payloads, raise limits, disable step-up, enroll guardians, or
turn authentication into authority without policy, grant issuance, revocation
semantics, and receipts.

## Payment and Escrow API

```http
POST /v1/payments/authorize
POST /v1/escrows/fund
GET  /v1/escrows/{escrow_id}
POST /v1/escrows/{escrow_id}/release
POST /v1/escrows/{escrow_id}/dispute
```

wallet.network abstracts whether the user pays in IOI, stablecoin, fiat, or credits.

## Exchange and Route Authority API

Exchange is a first-class Wallet action. Route sources provide candidates;
wallet.network owns policy, approval, signing or denial, and receipts.

Wallet exchange APIs are authority APIs. In production, wallet-exchange may call
`decentralized.exchange` or other route-intelligence engines for candidates, but
Wallet must treat every returned route as untrusted input until policy,
simulation, risk labels, and approval bind it into an `ExchangeIntent`.

```http
POST /v1/exchange/route-candidates
POST /v1/exchange/intents
GET  /v1/exchange/intents/{intent_id}
POST /v1/exchange/intents/{intent_id}/simulate
POST /v1/exchange/intents/{intent_id}/approve
POST /v1/exchange/intents/{intent_id}/deny
POST /v1/exchange/intents/{intent_id}/execute
GET  /v1/exchange/intents/{intent_id}/receipt
```

Route candidate request:

```json
{
  "initiator_id": "user://123 | agent://trader",
  "account_id": "wallet://account/main",
  "from_asset": "asset://eth/mainnet/ETH",
  "to_asset": "asset://eth/mainnet/USDC",
  "amount_in": "1.0",
  "execution_mode": "best_price | lowest_risk | most_decentralized | no_bridges | pq_preferred | user_specified",
  "allowed_route_sources": [
    "decentralized_exchange",
    "direct_pool",
    "dex_router",
    "solver",
    "quote_api",
    "user_specified"
  ],
  "policy_hash": "sha256:...",
  "grant_id": "grant://... | null",
  "lease_id": "lease://... | null",
  "revocation_epoch": 7
}
```

Exchange intent:

```json
{
  "intent_id": "exchange_intent://...",
  "route": {
    "route_id": "route://...",
    "source": "decentralized.exchange | direct_pool | quote_api | user_specified",
    "path": ["pool://...", "pool://..."],
    "calldata_commitment": "sha256:..."
  },
  "from_asset": "asset://...",
  "to_asset": "asset://...",
  "amount_in": "1000.00",
  "min_amount_out": "997.50",
  "quote_expires_at": "2026-06-12T12:05:00Z",
  "simulation_hash": "sha256:...",
  "risk_labels": ["Bridge Exposure", "Oracle Risk"],
  "economics": {
    "expected_output": "998.10",
    "minimum_output": "997.50",
    "slippage_tolerance_bps": 25,
    "pool_fee_bps": 5,
    "protocol_fee": "0",
    "wallet_fee": "0",
    "gas_estimate": "0.003 ETH",
    "price_impact_bps": 7
  },
  "tx_intents": ["tx_intent://..."]
}
```

No route candidate is authority. Final execution requires an approved
`ExchangeIntent` and exact `TxIntent` binding.

## Trade, Prediction, and Position Authority API

Advanced trading is a high-risk wallet action. Perps, margin, leverage,
prediction markets, event contracts, strategy execution, and ongoing position
management are not ordinary Exchange routes.

Wallet trade APIs are authority APIs. In production, wallet-trade may call
`decentralized.trade` or other venue/market-intelligence engines for candidates,
but Wallet must treat every returned venue, order, position, or prediction
candidate as untrusted input until policy, risk, simulation, eligibility, and
approval bind it into a `TradeIntent` or `PredictionIntent`.

```http
POST /v1/trade/candidates
POST /v1/trade/intents
POST /v1/trade/intents/{intent_id}/simulate
POST /v1/trade/intents/{intent_id}/approve
POST /v1/trade/intents/{intent_id}/deny
POST /v1/trade/prediction-candidates
POST /v1/trade/prediction-intents
POST /v1/trade/prediction-intents/{intent_id}/simulate
POST /v1/trade/prediction-intents/{intent_id}/approve
POST /v1/trade/prediction-intents/{intent_id}/deny
GET  /v1/trade/positions
GET  /v1/trade/positions/{position_id}
GET  /v1/trade/positions/{position_id}/receipts
GET  /v1/trade/predictions
GET  /v1/trade/predictions/{prediction_id}/receipts
POST /v1/trade/positions/{position_id}/close
POST /v1/trade/positions/{position_id}/reduce-risk
```

Trade intent:

```json
{
  "intent_id": "trade_intent://...",
  "initiator_id": "user://123 | agent://trader",
  "account_id": "wallet://account/main",
  "venue": "venue://...",
  "market": "market://BTC-PERP",
  "side": "long | short | buy | sell",
  "collateral_asset": "asset://.../USDC",
  "collateral_amount": "100.00",
  "leverage": "1.5",
  "margin_mode": "isolated | cross",
  "order_type": "market | limit | stop | tp_sl",
  "liquidation_price_estimate": "61500.00",
  "funding_rate_snapshot": "0.0001",
  "oracle_source": "oracle://...",
  "mark_price_snapshot": "65000.00",
  "max_loss_policy": {
    "max_loss_amount": "25.00",
    "daily_loss_limit": "25.00",
    "stop_loss_required": true
  },
  "stop_loss": "order_condition://...",
  "take_profit": "order_condition://... | null",
  "policy_hash": "sha256:...",
  "grant_id": "grant://... | null",
  "lease_id": "lease://... | null",
  "revocation_epoch": 7,
  "simulation_hash": "sha256:...",
  "risk_labels": [
    "Leverage Risk",
    "Liquidation Risk",
    "Funding Rate Risk",
    "Agent Trading Limited"
  ],
  "venue_intents": ["venue_intent://..."],
  "tx_intents": ["tx_intent://..."]
}
```

Prediction intent:

```json
{
  "intent_id": "prediction_intent://...",
  "initiator_id": "user://123 | agent://analyst",
  "account_id": "wallet://account/main",
  "venue_candidate_id": "venue_candidate://...",
  "market_id": "market://event/...",
  "question": "Will X happen by DATE?",
  "outcome": "yes | no | outcome://...",
  "side": "buy | sell",
  "price_limit": "0.63",
  "shares": "100",
  "max_loss": "63.00",
  "max_payout": "100.00",
  "resolution_source": "resolution_source://...",
  "resolution_time": "2026-12-31T23:59:59Z",
  "market_rules_hash": "sha256:...",
  "liquidity_snapshot": "liquidity_snapshot://...",
  "policy_hash": "sha256:...",
  "grant_id": "grant://... | null",
  "lease_id": "lease://... | null",
  "revocation_epoch": 7,
  "simulation_hash": "sha256:... | null",
  "risk_labels": [
    "Resolution Risk",
    "Insider Information Risk",
    "Jurisdiction Restricted",
    "Agent Trading Limited"
  ]
}
```

Agent live trading must be denied by default or constrained by explicit policy:
paper mode, max collateral or max loss, max leverage where applicable, isolated
margin, market/category allowlist, required stop loss where applicable, max
daily loss, no collateral add or new live event market without step-up, lease
expiry, and immediate revocation.

## Asset Exposure and Protection API

```http
GET  /v1/assets/exposure
GET  /v1/assets/{asset_id}/exposure
GET  /v1/accounts/{account_id}/exposure
GET  /v1/protection/recommendations
POST /v1/protection/actions
GET  /v1/protection/actions/{action_id}
POST /v1/protection/actions/{action_id}/approve
POST /v1/protection/actions/{action_id}/deny
```

Exposure records should describe cryptographic regime, public-key exposure,
bridge dependency, admin-key dependency, oracle dependency, approval exposure,
agent-access exposure, protection level, and recommended actions.

## Wallet Receipt and Activity API

```http
GET /v1/activity
GET /v1/receipts
GET /v1/receipts/{receipt_id}
```

Receipt types include send, receive, exchange, approval, delegation,
revocation, agent action, capability use, step-up, secret execution, risk event,
protection, cloud execution, and policy change receipts.

## Approval Inbox API

```http
GET  /v1/approval-inbox
GET  /v1/approval-inbox/{approval_item_id}
POST /v1/approval-inbox/{approval_item_id}/approve
POST /v1/approval-inbox/{approval_item_id}/deny
POST /v1/approval-inbox/{approval_item_id}/edit-and-approve
```

Approval inbox items should include initiator, requested action, authority risk
class, risk labels, eligibility labels, coverage states, affected
assets/secrets/data/workloads, budget or amount, destination, policy diff,
policy explanation, simulation result, candidate evidence, expiry, allowed
review recipes, recommended presentation profile, and available approve/edit/deny
actions. Every review also binds the authenticated principal, acting subject,
product session and origin, `authority_request_body_hash`,
`reviewed_representation_hash`, ceremony-context ref/hash, discriminated
`authorization_subject`, any principal-authority resolution required by the
portable principal contract, requested and required posture, actually satisfied
AuthFactor and GuardianSurface refs, one evaluation per required posture ref,
presentation evidence, policy-decision receipt, resulting grant or denial, and
authority receipt. A review
authenticated for one principal, session, origin, request, representation,
ceremony, authorization subject, or required authority resolution cannot be
replayed for another.

## Revocation and Emergency Stop

```http
POST /v1/revocations
POST /v1/emergency-stop
GET  /v1/revocation-epoch
```

Emergency stop must revoke active grants, pause pending runs, and notify relevant Agentgres domains.
It must also invalidate or quarantine affected authority clients, gateway
profiles, connector leases, pending WorkRuns, and approval challenges according
to the active blast-radius report.

## Non-Negotiables

1. Agents never hold root keys or long-lived connector secrets.
2. Secret export is a high-risk authority scope and disabled by default.
3. Target `AuthorityGrantEnvelope` v3 grants bind the separate
   `authority_request_body_hash`, `reviewed_representation_hash`,
   `approval_ceremony_context_hash`, discriminated `authorization_subject`, any
   principal-authority resolution required by the portable principal contract,
   principal, externally owned product session, origin, subject,
   resources/destination, policy, risk, scope, budget, and expiry. Current
   registered v1/v2 grants remain unchanged and do not satisfy this successor
   proof.
4. Authority grants are revocable and must include revocation epoch.
5. TEE secret release requires verified attestation matching policy.
6. SMS, email, chat, voice, and webhook access points may carry step-up
   challenge pointers, but not grants, decryption keys, private workspace
   payloads, credentials, or durable authority.
7. Exchange route sources, venue sources, and cloud resource candidates are
   candidates only; they are not approval, signing authority, receipt truth, or
   execution trust roots.
8. Presentation shells are UI profiles over the same authority review contract;
   the full Wallet console is not required for every Web3/Web4 app.
9. Unknown, unassessed, stale, and conflicting-source risk or eligibility states
   must be surfaced as caution states, not hidden as absent warnings.
10. Auth factors, provider credential bindings, guardian surfaces, key shards,
    and authority grants are distinct objects and must not be collapsed.
11. TOTP or federated login alone cannot authorize high-risk agent authority.
12. wallet.network MCP and CLI clients can request, inspect, approve, deny, or
    receipt authority only through the same policy pipeline; they cannot bypass
    step-up, export secrets, raise limits, or raw-sign arbitrary payloads.
13. Protected autonomous-system changes require the exact transition scope and
    constitutionally declared governance path; no worker may approve its own
    constitutional, writer, authority-membership, lifecycle, or enrollment
    change.
14. WebAuthn type/challenge/RP-hash/origin/cross-origin mismatch, credential or
    owner/user-handle substitution, absent required UP/UV, invalid signature,
    cross-account factor linking, stale revocation epoch, and
    principal/session replay fail closed.
15. Account recovery may restore access at an equal or lower declared security
    level; it never widens, reconstructs, or silently preserves consequential
    authority, and affected high-risk grants remain revoked or quarantined
    until explicitly reauthorized. A pending recovery session cannot log in,
    step up, approve, or execute.
16. The portable embedded sign-in-to-effect claim requires the target
    context-bound `AuthorityGrantEnvelope` v3 successor to be registered and
    implemented. Green v1/v2 and legacy AuthorityReview checks do not satisfy
    that product proof.
17. A GuardianSurface is an enrolled authority-client/presentation surface
    composed with required AuthFactors. A generic passkey or hardware credential
    is not a GuardianSurface by itself.
18. WebAuthn assertion evidence may participate in a bound application approval
    ceremony, but it is not substituted for presentation evidence and does not
    independently prove that the application-defined representation was
    displayed correctly or understood.
19. Presentation evidence uses a named
    `presentation_evidence_profile_ref`, immutable evidence refs, and orthogonal
    operator/surface, content-binding, request-versus-effect,
    enrollment/attestation, UP/UV, freshness/replay, and proposer-independence
    dimensions. No two-tier assurance enum may replace those facts.
20. Request-side factor and guardian refs express requested posture only.
    Satisfied refs and actual factor/presentation evidence are wallet-minted
    review-receipt and v3-grant facts. Every required ref appears exactly once
    in the hash-bound satisfaction evaluations; approval requires all entries to
    be satisfied.
21. A bare approval-evidence root is insufficient. The v3 grant binds its
    versioned root profile and typed leaf refs so encoding, ordering, domain
    separation, inclusion, and required evidence kinds are verifiable.
22. `exact_effect` requires `exact_equality` and daemon-derived hash equality;
    `batch_manifest` requires `batch_membership` and a non-null membership proof;
    `standing_envelope` requires `standing_constraint` and a non-null constraint
    evaluation. Every other proof field is null. The exact
    `TemporalVerificationProfile`, recomputable `TemporalValidityEvaluation`,
    current revocation evidence, and any required outside-rollback-domain
    continuity floors are resolved before the invoker; no scalar timestamp or
    clock-health flag substitutes for them.
23. `edit-and-approve` creates a successor request, review, representation,
    authorization subject, challenge, and ceremony. Predecessor approval
    evidence is invalid for the successor.
