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
Last alignment pass: 2026-06-27.

## Canonical Definition

The Hypervisor Daemon owns a **deployment-local governance plane** that answers
*who is operating this deployment, what org-surface access they hold, what
secrets and inbound tokens exist, and what the deployment is consuming.*

This plane **composes with — it does not replace — wallet.network protocol
authority.** The split is strict:

```text
Identity / access  answers: WHO is this principal, and what org-surface
                   (settings, membership) access do they hold?
wallet.network     answers: MAY this principal/agent/client perform this
                   specific consequential crossing?
Hypervisor Daemon  enforces both rings.
Agentgres          records both.
```

The decisive rule: **identity and org roles are never machine authority.** A
role (`admin`, `member`) governs which app/settings surfaces a principal may
see and manage; it does **not** authorize a push, a connector use, spend,
declassification, an external message, or any other consequential crossing.
Those still require a wallet.network grant / capability lease. (Proven in the
done-bars: an authenticated admin session is still refused — 403 — on a
connector crossing with no wallet grant.)

This is the deployment-local layer; **wallet.network remains the protocol-level
authority/SSO** (portable, cross-app, "powered-by"). A principal authenticated
locally here still crosses boundaries only under wallet authority.

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
  the wallet crossing. This is an additional least-privilege ring; it is an
  explicit grant, never a role, and the wallet grant is still required after it.

### Secrets & API-access-token management
- **Secrets** (org / user / project scope) — the value is **sealed at rest**
  (the same key-store as other sealed credentials), stored separately from the
  metadata; every read returns metadata only. The daemon HOLDS the sealed value;
  consuming it at runtime is the downstream injection path, and any consequential
  use crossing remains wallet/lease-gated.
- **API access tokens** (inbound) — high-entropy tokens that authenticate calls
  to the Hypervisor API; only a hash + metadata are stored, the plaintext is
  surfaced exactly once, and a token resolves to its principal through the auth
  ring.

### Metering & cost
- **Consumption** — derived from the daemon's actual recorded receipts
  (agentgres records → an economic projection), bucketed into per-day compute
  units by kind; never fabricated.
- **Budget** — a ceiling + a **wallet-backed auto-funding policy** (replenish
  from wallet.network when the balance crosses a threshold), reconciled against
  real consumption and recorded as ledger entries.

## Does Not Own

- wallet.network authority itself — the authorization of any consequential
  crossing, capability-lease issuance, secret-use approval, spend approval,
  declassification, or protocol-level SSO/portable authority.
- The protocol-level identity/authority that crosses apps and deployments
  (that is wallet.network's; this plane is deployment-local).
- Agentgres admitted truth, state roots, or receipt validity (metering and
  provisioning *read/record through* Agentgres; they do not define truth).
- Runtime execution semantics (the daemon executes; this plane only identifies
  the caller and scopes surface access).
- Payment/settlement mechanics — there is no SaaS billing; the wallet is the
  funding rail and there is no credit-card/invoice plane.
- Multi-tenant federation beyond the deployment (cross-org SSO trust, directory
  federation) unless modeled explicitly elsewhere.

## Composition Order

A request resolves through rings, outer to inner:

```text
authentication (who)            session / API token / SSO — gated when exposed
  -> principal scope (may this principal request this crossing?)   optional
  -> org/app policy (allow-list, risk posture)
  -> wallet.network authority (is THIS crossing authorized?)       always, for crossings
  -> daemon executes
  -> receipt (attributes the principal + the authority refs)
```

Authentication and scope can only *narrow*; they never grant a crossing. The
wallet ring is the sole authorizer of consequential crossings.

## Conformance Checks

- Identity/roles must never authorize a consequential crossing; every such
  crossing still requires a wallet.network grant / capability lease, regardless
  of the caller's role or session.
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
  `(connector, tool)` lease grant *before* the wallet crossing, and the wallet
  crossing must still apply afterward.
- Metering consumption must derive from recorded receipts (no fabricated usage);
  budget auto-funding must record wallet-sourced ledger entries and must not
  itself authorize any crossing.
- The deployment-local identity plane must compose with, and never shadow,
  wallet.network protocol authority.

## Anti-Patterns

Avoid:

```text
admin role = permission to push / spend / use a connector
session/login = machine authority
org membership = capability grant
secret value returned in a list response
API/SCIM token stored in plaintext or recoverable after creation
SSO identity trusted from userinfo without id_token signature + nonce
enforcement off while the deployment is exposed
/auth/policy or principal management reachable unauthenticated under enforcement
metering numbers fabricated instead of derived from receipts
budget auto-fund treated as crossing authorization
deployment-local identity replacing wallet.network protocol authority
```

Correct:

```text
identity answers who + scopes org-surface access
wallet.network authorizes every consequential crossing
roles/scopes only narrow; they never grant a crossing
secrets + tokens sealed/hashed at rest, surfaced at most once
SSO id_token verified (JWKS + nonce) before trust
enforcement is fail-safe (auto-on when exposed) with a lockout bootstrap
metering is an economic projection of recorded receipts; wallet funds the budget
the daemon enforces both rings; Agentgres records both
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`providers-and-environments.md`](./providers-and-environments.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../wallet-network/api-authority-scopes.md`](../wallet-network/api-authority-scopes.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
