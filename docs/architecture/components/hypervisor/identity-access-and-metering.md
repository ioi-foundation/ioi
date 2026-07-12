# Hypervisor Identity, Access, Secrets, and Metering

Status: canonical architecture authority.
Canonical owner: this file for the Hypervisor Daemon's **deployment-local**
identity/access plane (principals, sessions, authentication, SSO/OIDC login,
SCIM provisioning, invites, domain verification, principal-scoped capability
leases), the secrets and API-access-token management surfaces, and the metering
& cost plane.
Supersedes: prose that treats org login/SSO/SCIM/secrets/metering for a
self-hosted Hypervisor deployment as having no daemon-side plane, or that treats
identity roles as machine authority.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (principals, sessions, OIDC SSO, SCIM, and enforcement built; receipt-derived coarse OCU projection built; invoice-grade provider reconciliation, Work Credit debiting, and SaaS billing planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-05

## Canonical Definition

Placement note: this file lives under `components/hypervisor/` because it
is estate/product-facing governance, but the plane it specifies is owned
and enforced by the Hypervisor Daemon (a deployment-local daemon
governance and admission plane). Read it as daemon-runtime governance projected into the
product estate; it was deliberately not moved to avoid churn on
cross-references.

The Hypervisor Daemon owns a **deployment-local governance plane** that answers
*who is operating this deployment, what org-surface access they hold, what
secrets and inbound tokens exist, and what the deployment is consuming.*

This plane **composes with — it does not replace — local/domain governance or
the applicable authority provider.** The split is strict:

```text
Identity / access  answers: WHO is this principal, and what org-surface
                   (settings, membership) access do they hold?
Policy/authority   answers: MAY this principal/agent/client perform this
                   specific consequential crossing?
wallet.network     is mandatory for portable delegated authority and the
                   designated high-risk external effects assigned to it.
Hypervisor Daemon  admits and enforces authorized work.
Agentgres          records admitted operational truth.
```

The decisive rule: **identity and org roles are never machine authority.** A
role (`admin`, `member`) governs which app/settings surfaces a principal may
see and manage; it does **not** authorize a push, a connector use, spend,
declassification, an external message, or any other consequential crossing.
Those still require the policy/authority evidence named by the domain and risk
profile. For a connector profile assigned to wallet.network, an authenticated
admin session is still refused — 403 — when the wallet grant is absent.

This is the deployment-local layer; **wallet.network remains the
protocol-level portable delegated-authority/SSO plane** (cross-app,
"powered-by"). A principal authenticated locally here still crosses a boundary
only under the authority profile applicable to that action; authentication
never substitutes for it.

## Owns

### Identity & access (principals + sessions)
- **Principals** — human / service-account / agent identities with email, name,
  role (`admin` | `member`), status (`active` | `deactivated`), and source
  (`local-operator` | `local` | `sso:<id>` | `scim` | `invite`). A single
  bootstrap operator is un-removable.
- **Sessions** — opaque session tokens (hash-at-rest, expiring), established by a
  login method and resolvable from a session cookie or a bearer token.
- **Authentication methods** — local credential (passwords hashed with Argon2id
  via the workspace crypto library — one-way, never reversible), SSO/OIDC login,
  inbound API access tokens, and a one-time bootstrap.
- **Gated, fail-safe enforcement** — an inbound auth ring with modes
  `auto | always | never` (default `auto`). `auto` enforces when the deployment
  is **exposed** (bound non-loopback, or reached via a forwarded host); loopback
  stays open. An exposed deployment with no login configured stays enforced and
  emits a one-time bootstrap token (operator sets the first password). The gate
  exempts only the login-flow endpoints, so an unauthenticated caller can never
  disable enforcement or manage principals.

### Federated login & provisioning
- **SSO / OIDC connections** — BYO OIDC IdP for org login (client secret sealed
  at rest). Login is Authorization Code + PKCE; the id_token is verified
  (signature against the IdP JWKS, issuer/audience/expiry, and a per-login
  nonce) before the identity is trusted; principals are provisioned-on-login
  with an emailDomain auto-join gate.
- **SCIM 2.0 provisioning** — a standard SCIM server an external IdP drives to
  provision/deprovision Users (mapped onto principals) and Groups, authenticated
  by a SCIM bearer token (hash-only at rest, plaintext returned once).
- **Invites** — a standing org invite that provisions a member on acceptance
  (fail-closed on a stale/rotated link).
- **Domain verification** — DNS-TXT challenge (checked over DoH) to prove
  email-domain ownership for auto-join; plus an optional vanity custom domain.

### Principal-scoped capability leases
- Every connector/crossing invocation **attributes the calling principal** on
  its receipt. A connector may be made **principal-scoped**, requiring the caller
  to hold an explicit per-principal lease grant for `(connector, tool)` *before*
  authority evaluation. This is an additional least-privilege ring; it is an
  explicit grant, never a role. A wallet.network grant is additionally required
  when the connector/action profile assigns authority to wallet.network.

### Secrets & API-access-token management
- **Secrets** (org / user / project scope) — the value is **sealed at rest**
  (the same key-store as other sealed credentials), stored separately from the
  metadata; every read returns metadata only. The daemon HOLDS the sealed value;
  consuming it at runtime is the downstream injection path, and any consequential
  use crossing remains gated by applicable policy and authority.
- **API access tokens** (inbound) — high-entropy tokens that authenticate calls
  to the Hypervisor API; only a hash + metadata are stored, the plaintext is
  surfaced exactly once, and a token resolves to its principal through the auth
  ring.

### Metering & cost
- **Current consumption projection** — derived from admitted daemon receipts
  (Agentgres records → an economic projection) and bucketed per day. Runtime
  duration contributes compute hours; the current model slice contributes a
  flat `0.1` OCU per model-backed receipt. That is honest coarse telemetry, not
  token-, route-, supplier-, or invoice-reconciled commercial usage.
- **Budget** — a ceiling + a **wallet-backed auto-funding policy** (replenish
  from wallet.network when the balance crosses a threshold), applied to the
  current OCU projection and recorded as ledger entries.
- **Target commercial reconciliation** — route-attempt receipts must bind
  endpoint, provider, model/version, price-schedule version, detailed billed
  usage classes, fallback chain, estimated and finalized supplier cost, broker
  fee, IOI fee basis/amount, Work Credit reservation/debit, adjustment/refund,
  and provider-statement reconciliation before the projection can support a
  paid included managed-work allowance.

This file owns the deployment-local meter and budget enforcement projection.
[`economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md)
owns the Goal Space subscription, Work Credit, fee-legitimacy, and stack-wide
pricing doctrine. ioi.ai owns account/subscription experience; Hypervisor owns
managed-work execution and metering; Agentgres records the economic facts.

## Does Not Own

- Portable delegated authority or domain-specific consequential-action
  authority. wallet.network owns the portable grants, leases, approvals,
  declassification, designated high-risk effects, and protocol-level SSO
  assigned to it; other profiles retain their named authority owner.
- The protocol-level identity/authority that crosses apps and deployments
  (that is wallet.network's; this plane is deployment-local).
- Agentgres admitted truth, state roots, or receipt validity (metering and
  provisioning *read/record through* Agentgres; they do not define truth).
- Runtime execution semantics (the daemon executes; this plane only identifies
  the caller and scopes surface access).
- Payment/settlement mechanics. The current implementation has no SaaS billing;
  the target meter projects billing/entitlement refs owned by ioi.ai and the
  applicable billing, invoice, marketplace, service-order, or settlement plane.
- Product pricing, Goal Space plan design, Work Credit semantics, marketplace
  payout, or IOI fee policy.
- Multi-tenant federation beyond the deployment (cross-org SSO trust, directory
  federation) unless modeled explicitly elsewhere.

## Composition Order

A request resolves through rings, outer to inner:

```text
authentication (who)            session / API token / SSO — gated when exposed
  -> principal scope (may this principal request this crossing?)   optional
  -> org/app policy (allow-list, risk posture)
  -> applicable authority (is THIS crossing authorized?)
       local/domain governance where canon permits
       wallet.network for portable delegation and designated high-risk effects
       another named authority provider only where the domain profile permits
  -> daemon admits, enforces, and executes or mediates
  -> receipt (attributes the principal + the authority refs)
```

Authentication and scope can only *narrow*; they never grant a crossing. The
applicable policy/authority ring authorizes. wallet.network is mandatory for
portable delegated authority and the high-risk external effects assigned to it;
it is not required merely to represent every deployment-local product action.

## Conformance Checks

- Identity/roles must never authorize a consequential crossing by themselves.
  Every crossing requires the policy/authority evidence named by its domain and
  risk profile; portable delegation and designated high-risk external effects
  require a wallet.network grant or capability lease regardless of role/session.
- Passwords and inbound tokens (API access tokens, SCIM tokens, SSO client
  secrets) must be hashed/sealed at rest; plaintext is surfaced at most once and
  never recoverable from a list/read.
- Secret values must be sealed at rest and never returned by any list/get; only
  metadata is projected.
- Enforcement must be fail-safe: an exposed deployment authenticates by default;
  the auth gate must exempt only login-flow endpoints (never policy or principal
  management); a no-login exposed deployment must offer a one-time bootstrap, not
  silent open access.
- SSO login must cryptographically verify the IdP id_token (signature vs JWKS,
  issuer/audience/expiry, nonce) before trusting the identity; userinfo alone is
  a fallback only.
- Principal-scoped connectors must refuse a caller lacking an explicit
  `(connector, tool)` lease grant before authority evaluation. A wallet crossing
  must additionally apply when the connector/action profile requires it.
- Metering consumption must derive from recorded receipts; coarse OCU must be
  labeled as coarse and must not be sold as provider-invoice truth. Budget
  auto-funding must record wallet-sourced ledger entries and must not itself
  authorize any crossing.
- A sellable Work Credit debit must reconcile route-attempt receipts to the
  applicable supplier price schedule and final statement, preserve fallbacks,
  adjustments, BYOK/local exclusions, broker fees, and IOI fee basis, and fail
  closed when required billing evidence is absent.
- The deployment-local identity plane must compose with, and never shadow, the
  applicable local/domain or protocol authority; it must preserve wallet.network
  wherever portable delegation or a designated high-risk action requires it.

## Anti-Patterns

Avoid:

```text
admin role = permission to push / spend / use a connector
session/login = machine authority
org membership = authority grant
secret value returned in a list response
API/SCIM token stored in plaintext or recoverable after creation
SSO identity trusted from userinfo without id_token signature + nonce
enforcement off while the deployment is exposed
/auth/policy or principal management reachable unauthenticated under enforcement
metering numbers fabricated instead of derived from receipts
flat per-receipt OCU presented as token-, supplier-, or invoice-grade usage
retail chat subscription limits treated as managed worker capacity
customer BYOK provider spend charged again as IOI model cost
budget auto-fund treated as crossing authorization
deployment-local identity replacing wallet.network protocol authority
```

Correct:

```text
identity answers who + scopes org-surface access
local/domain governance or the applicable authority provider authorizes
wallet.network authorizes portable delegation and designated high-risk effects
roles/scopes only narrow; they never grant a crossing
secrets + tokens sealed/hashed at rest, surfaced at most once
SSO id_token verified (JWKS + nonce) before trust
enforcement is fail-safe (auto-on when exposed) with a lockout bootstrap
coarse OCU is a labeled projection of recorded receipts, not invoice truth
commercial Work Credits wait for route-attempt and supplier-statement reconciliation
direct BYOK/local provider cost is not double charged
wallet funds the deployment budget without granting crossing authority
the daemon admits/enforces authorized work; Agentgres records admitted truth
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`providers-and-environments.md`](./providers-and-environments.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../wallet-network/api-authority-scopes.md`](../wallet-network/api-authority-scopes.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
