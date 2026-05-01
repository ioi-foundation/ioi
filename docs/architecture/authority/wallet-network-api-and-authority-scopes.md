# wallet.network API and Authority Scopes

Status: canonical low-level reference.
Canonical owner: this file for wallet.network account, authority scope, grant, approval, secret brokerage, payment, and revocation APIs.
Supersedes: older wallet authority API wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

wallet.network is the canonical Web4 authority layer. It owns identity, secrets, BYOK keys, connector credentials, authority scope grants, approvals, payments, revocation, and emergency stops. Agents, workers, apps, and runtimes are authority clients, not raw secret custodians.

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

Example:

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
