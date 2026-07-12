# wallet.network API and Authority Scopes

Status: canonical low-level reference.
Canonical owner: this file for wallet.network account, auth factor, guardian,
key-shard, provider credential binding, authority scope, grant, approval, secret
brokerage, payment, exchange, exposure, protection, receipt, wallet authority
client, and revocation APIs.
Supersedes: older wallet authority API wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: reference
Implementation status: partial (authority-client seams and lease APIs live; guardian/shard surfaces planned)
Last implementation audit: 2026-07-05

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
DELETE /v1/session/{session_id}
```

Sign-in providers and linked factors:

```text
google
github
passkey
web3_wallet
email_magic_link
enterprise_sso
totp
```

A frictionless login creates a Level 1 wallet.network account. TOTP is a linked
step-up factor, not a primary identity provider. High-risk authority scopes
require step-up.

Canonical factor taxonomy:

```text
AuthFactor
  Authenticates account access or step-up posture. It does not convey authority
  by itself. Google, GitHub, email/OIDC, enterprise SSO, Web3 wallet, passkey,
  and TOTP are auth factors.

GuardianSurface
  High-assurance authority surface that can render an exact action and sign or
  approve a challenge. Examples include enrolled mobile approver, passkey device,
  local CLI signer, hardware key, trusted wallet/Hypervisor app, and enterprise
  approval surface.

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
authority alone. Biometrics only count as high-assurance when bound to a
passkey, secure enclave, enrolled device, or equivalent signed assertion.

### Auth Factor

```json
{
  "factor_id": "auth_factor://google/user_123/default",
  "owner_ref": "wallet://user_123",
  "kind": "google | github | email_oidc | enterprise_sso | web3_wallet | passkey | totp",
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

### Guardian Surface

```json
{
  "guardian_id": "guardian://device/user_123/phone",
  "owner_ref": "wallet://user_123",
  "kind": "enrolled_mobile | passkey_device | hardware_key | local_cli_signer | hypervisor_app | enterprise_approval",
  "display_label": "Personal phone",
  "challenge_methods": ["qr", "push", "local_cli"],
  "can_render_exact_intent": true,
  "can_sign_request_hash": true,
  "allowed_risk_classes": [
    "external_message",
    "commerce",
    "funds",
    "system_destructive",
    "secret_export",
    "policy_widening"
  ],
  "revocation_epoch": 7,
  "status": "active"
}
```

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
    "requires_surface": [
      "wallet_network_web",
      "hypervisor_app",
      "enrolled_guardian_device",
      "passkey",
      "enterprise_idp",
      "local_cli_signer"
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
  "request_hash": "sha256:...",
  "risk_class": "external_message",
  "action_summary": "Approve one vendor email draft",
  "challenge_url": "https://wallet.network/step-up/challenge/abc",
  "challenge_delivery": "link | qr | push | local_cli",
  "guardian_surface_required": "guardian://device/user_123/phone | passkey | enterprise_approval | local_cli_signer",
  "must_display": {
    "subject": "agent://assistant",
    "action": "gmail.send",
    "resources": ["gmail://thread/abc"],
    "budget_or_amount": null,
    "expires_at": "2026-05-01T12:05:00Z",
    "policy_hash": "sha256:...",
    "request_hash": "sha256:..."
  },
  "single_use": true,
  "expires_at": "2026-05-01T12:05:00Z"
}
```

The challenge URL is a pointer to an authority session, not an authority grant.
Approval must authenticate on wallet.network, Hypervisor, an enrolled guardian
device, passkey, enterprise IdP, local app, CLI signer, or another
high-assurance authority surface. The agent receives only a scoped
`grant://...` or denial receipt after the step-up flow completes.

QR or push delivery is not authority by itself. The guardian surface must render
the exact action and sign or approve the bound request hash. The agent never
receives OTP values, biometric results, provider tokens, raw key shards, raw
session material, or guardian secrets.

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

```json
{
  "subject_id": "agent://runtime-auditor",
  "requesting_runtime": "runtime://node_abc",
  "purpose": "Run weekly runtime audit",
  "primitive_capabilities_declared": ["prim:fs.read", "prim:sys.exec", "prim:model.invoke"],
  "authority_scopes_requested": ["scope:repo.read"],
  "resource_scope": {
    "resources": ["git://repo/ioi", "file://workspace/**"],
    "expiry": "2026-05-01T12:00:00Z",
    "max_budget_usd": 5
  },
  "risk_class": "write_reversible",
  "request_hash": "sha256:...",
  "policy_hash": "sha256:..."
}
```

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

Training-data grants should bind purpose, reuse rights, retention policy,
privacy class, dataset commitment, domain ontology refs, data recipe refs,
policy-bound data view refs, allowed transformation methods, allowed runtime
environment, and expiry.

### Authority Grant

```json
{
  "grant_id": "grant_123",
  "issuer_id": "wallet://user_123",
  "subject_id": "agent://runtime-auditor",
  "authority_scopes": ["scope:repo.read"],
  "primitive_capability_constraints": ["prim:fs.read"],
  "constraints": {
    "resources": ["git://repo/ioi"],
    "expires_at": "2026-05-01T12:00:00Z",
    "max_calls": 100
  },
  "revocation_epoch": 7,
  "status": "active"
}
```

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
  "approval_mode": "session_envelope",
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

Approval grant:

```json
{
  "approval_id": "approval_123",
  "request_hash": "sha256:...",
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
  "review_id": "review://wallet/abc",
  "intent_ref": "intent://...",
  "subject_id": "agent://trader | app://game | user://123",
  "object_refs": ["asset://...", "credential://...", "workload://..."],
  "capabilities_requested": ["scope:broker.place_order"],
  "simulation_ref": "simulation://...",
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
  "allowed_approval_modes": [
    "one_shot_review",
    "step_up_review"
  ],
  "recommended_presentation_profile": "standard_wallet_review"
}
```

Presentation profiles:

```text
lite_approval_card
standard_wallet_review
advanced_authority_console
cli_prompt
mobile_approval_sheet
```

Approval modes:

```text
one_shot_review
session_envelope
batch_review
silent_within_policy
after_the_fact_receipt
step_up_review
denied
```

Apps may request a presentation profile and approval mode, but Wallet must derive
the allowed mode from policy, risk, eligibility, account posture, and active
session state.

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
  "client_session_id": "wallet_client://cli/user_123/session_abc",
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
approval modes, recommended presentation profile, and available approve/edit/deny
actions.

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
3. Approval grants bind exact request hash, policy hash, scope, and expiry.
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
