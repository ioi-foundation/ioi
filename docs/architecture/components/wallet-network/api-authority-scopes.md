# wallet.network API and Authority Scopes

Status: canonical low-level reference.
Canonical owner: this file for wallet.network account, authority scope, grant, approval, secret brokerage, payment, and revocation APIs.
Supersedes: older wallet authority API wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-05-14.

## Purpose

wallet.network is the canonical Web4 authority layer. It owns identity, secrets, BYOK keys, connector credentials, authority scope grants, training-data permissions, decryption leases, approvals, payments, sealed archive restore authority, revocation, and emergency stops. Agents, workers, apps, and runtimes are authority clients, not raw secret custodians.

## Account and Session API

```http
POST /v1/auth/sign-in
POST /v1/auth/link-factor
GET  /v1/account
GET  /v1/account/security-level
POST /v1/account/upgrade-security
POST /v1/session
DELETE /v1/session/{session_id}
```

Sign-in providers:

```text
google
github
passkey
web3_wallet
email_magic_link
enterprise_sso
```

A frictionless login creates a Level 1 wallet.network account. High-risk authority scopes require step-up.

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
  "risk_class": "external_message | funds | secret_export | private_workspace_view",
  "action_summary": "Approve one vendor email draft",
  "challenge_url": "https://wallet.network/step-up/challenge/abc",
  "single_use": true,
  "expires_at": "2026-05-01T12:05:00Z"
}
```

The challenge URL is a pointer to an authority session, not an authority grant.
Approval must authenticate on wallet.network, Hypervisor, an enrolled guardian
device, passkey, enterprise IdP, local app, CLI signer, or another
high-assurance authority surface. The agent receives only a scoped
`grant://...` or denial receipt after the step-up flow completes.

## Authority Scope Request API

```http
POST /v1/authority/scope-requests
GET  /v1/authority/scope-requests/{request_id}
POST /v1/authority/scope-requests/{request_id}/approve
POST /v1/authority/scope-requests/{request_id}/deny
GET  /v1/authority/grants
GET  /v1/authority/grants/{grant_id}
POST /v1/authority/grants/{grant_id}/revoke
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
  "risk_class": "read | write_reversible | external_message | commerce | funds | secret_export",
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
  "agentgres_domain": "agentgres://domain/local-autopilot-user",
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

## Payment and Escrow API

```http
POST /v1/payments/authorize
POST /v1/escrows/fund
GET  /v1/escrows/{escrow_id}
POST /v1/escrows/{escrow_id}/release
POST /v1/escrows/{escrow_id}/dispute
```

wallet.network abstracts whether the user pays in IOI, stablecoin, fiat, or credits.

## Revocation and Emergency Stop

```http
POST /v1/revocations
POST /v1/emergency-stop
GET  /v1/revocation-epoch
```

Emergency stop must revoke active grants, pause pending runs, and notify relevant Agentgres domains.

## Non-Negotiables

1. Agents never hold root keys or long-lived connector secrets.
2. Secret export is a high-risk authority scope and disabled by default.
3. Approval grants bind exact request hash, policy hash, scope, and expiry.
4. Authority grants are revocable and must include revocation epoch.
5. TEE secret release requires verified attestation matching policy.
6. SMS, email, chat, voice, and webhook access points may carry step-up
   challenge pointers, but not grants, decryption keys, private workspace
   payloads, credentials, or durable authority.
