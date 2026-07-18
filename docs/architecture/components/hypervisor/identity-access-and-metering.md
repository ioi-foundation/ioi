# Hypervisor Identity, Access, Secrets, and Metering

Status: canonical architecture authority.
Canonical owner: this file for the Hypervisor Daemon's **deployment-local**
identity/access plane (principals, sessions, authentication, SSO/OIDC login,
SCIM provisioning, invites, domain verification, principal-scoped capability
leases), local-agent pairing sessions, the secrets and API-access-token
management surfaces, and the metering & cost plane.
Supersedes: prose that treats org login/SSO/SCIM/secrets/metering for a
self-hosted Hypervisor deployment as having no daemon-side plane, or that treats
identity roles as machine authority.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: mixed (principals, sessions, OIDC SSO, SCIM, enforcement, and receipt-derived coarse OCU projection are built; the registered managed-work billing schema, invariants, fixtures, and generated projections are present as contract substrate, while the quote/hold/usage/debit/adjustment kernel, durable billing store, `LocalAgentPairingSessionEnvelope`, local-agent pairing APIs, room-admitted gateway issuance, public Work Credit billing APIs, supplier-statement reconciliation, and SaaS billing remain planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-16

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

### Local-agent pairing sessions

Hypervisor owns the pairing and adapter boundary that lets an already-running
local agent or harness become an authenticated candidate participant without
making the agent a Hypervisor client, room member, marketplace listing, or
authority holder. ioi.ai may embed the user-facing **Connect local agent** flow
inside a Goal Space. Hypervisor creates and resolves the pairing session,
candidate key, origin binding, adapter, daemon ingress, and scoped gateway
boundary. aiagent.xyz owns any later private reusable Worker record or public
package, benchmark, listing, routing-eligibility, reputation, and settlement
projection/refs; wallet, Agentgres, and IOI settlement owners retain authority,
operational truth, and finality.

The screenshot-simple product flow is:

```text
Connect local agent
  -> choose room_guest, private_worker, or organization_worker target
  -> declare agent/harness and optional display profile
  -> create one-time pairing challenge/device code
  -> copy a bootstrap command or prompt into the local agent
  -> candidate proves possession and binds its public key plus origin
  -> bootstrap_bound authenticates a candidate only
  -> submit the target-specific WorkerComposition proposal
  -> for room_guest, read discovery and submit RoomParticipationRequestEnvelope
  -> completed records the required bootstrap submissions only
  -> registry or room admission separately accepts, rejects, or quarantines
  -> room_guest: after room admission, issue an expiring gateway profile bound
     to participant lease, candidate key, origin, room, and policy
  -> private_worker / organization_worker: after registry admission, a later
     direct call, Session, Automation, or WorkRun obtains its own invocation,
     context, tool, resource, budget, and authority admission before gateway use
```

[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#localagentpairingsessionenvelope)
owns the exact `LocalAgentPairingSessionEnvelope` schema, target, transport,
closed bootstrap-action, failure-code, contribution-lane, assurance, and status
enums. This file owns the deployment-local creation, challenge storage,
attempt/rate limiting, claim/binding, expiry, cancellation/revocation, and API
authentication around that object. It must not republish a deployment-specific
competing envelope. Downstream admission decisions, participant leases,
gateway profiles, Worker records, and contributions keep their own refs and
lifecycle rather than being collapsed into pairing status.

The challenge/device code is high entropy, single use, short lived, stored only
as a hash, and displayed exactly once. The candidate creates the signing key;
Hypervisor never returns or stores its private key. A successful challenge
proves possession of the bootstrap value and candidate key at the bound origin.
It does not prove the agent's model, hidden reasoning, correctness,
independence, room eligibility, or right to perform an effect.

Pairing authenticates a candidate; it never authorizes. A `room_guest` may
receive only its signed policy-bound discovery projection and narrow
composition/participation submission path before room admission. Admission may
create a participant lease and then a scoped, expiring, revocable gateway
profile. A `private_worker` or `organization_worker` may instead receive a
private registry admission; each later direct invocation, Session, Automation,
WorkRun, or room participation still requires its own policy, context, tools,
resources, budget, and authority admission. No reusable worker inherits a room
lease, and no direct invocation requires a fictitious room lease.

A `prompt_only` agent still generates or presents a bootstrap-client public key
and binds its origin. What it cannot bind is a native adapter and instrumented
daemon execution path. It therefore remains a low-assurance proposal source:
its messages and artifacts stay tainted, it gets no ambient context or
effectful tools, and it cannot acquire portable reputation, payout eligibility,
or public marketplace status from pairing alone.

Target API shape (planned):

```http
POST /v1/hypervisor/local-agent-pairings
GET  /v1/hypervisor/local-agent-pairings/{pairing_ref}
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/claim
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/complete
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/cancel
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/revoke
```

The create response may contain the plaintext one-time device code and copyable
bootstrap text exactly once. Later reads return only the policy-permitted
hashes, refs, expiry, assurance posture, failure code, and exact pairing status.
Completion cannot mint a participant lease, private Worker registration, or
gateway profile. A separate room or registry admission may later admit the same
candidate identity, key, origin, composition, and policy posture. Gateway use
then requires the concrete room-participant or invocation/session/run admission
applicable to that use.

### Metering & cost
- **Current consumption projection** — derived from admitted daemon receipts
  (Agentgres records → an economic projection) and bucketed per day. Runtime
  duration contributes compute hours; the current model slice contributes a
  flat `0.1` OCU per model-backed receipt. That is honest coarse telemetry, not
  token-, route-, supplier-, or invoice-reconciled commercial usage.
- **Budget** — a ceiling + a **wallet-backed auto-funding policy** (replenish
  from wallet.network when the balance crosses a threshold), applied to the
  current OCU projection and recorded as ledger entries.
- **Internal managed-work ledger** — a separate fixed-point chain freezes a
  versioned RateCard and Plan into an immutable WorkQuote, requires finite
  idempotent holds, appends receipt-derived UsageRecords against the current
  usage head, enforces the exact quote overrun policy, admits one exact
  FinalDebit, and permits only append-only downward adjustments. It separates
  provider, broker, participant, verifier, IOI-fee, and excluded
  customer-borne cost fields. The kernel/store seam requires owner-resolved
  authority and evidence and has no public route that can mint supplier usage.
  It is product-accounting machinery, not payment settlement or proof that an
  estimated supplier charge appeared on an invoice.
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
- OutcomeRoom admission, Worker publication, benchmark/routing eligibility, or
  marketplace reputation. Pairing only authenticates a deployment-local
  candidate and binds its adapter ingress; the room owner admits participation,
  and aiagent.xyz owns optional reusable/private or public Worker records.
- Payment/settlement mechanics. The internal managed-work ledger can quote,
  reserve, meter, debit, refund, or write off product credits, but the current
  implementation has no SaaS purchase/top-up surface, processor integration,
  cash ledger, payout, or settlement rail. The meter projects
  billing/entitlement refs owned by ioi.ai and the applicable billing, invoice,
  marketplace, service-order, or settlement plane.
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
  closed when required billing evidence is absent. An internal-event-log debit
  with estimated provider cost is not a supplier-reconciled commercial claim.
- Managed-work accounting must use integer minor/micro-credit units, exact
  RateCard/Plan/quote body bindings, finite holds, same-key/same-body replay,
  changed-body conflict, append-only usage and adjustment heads, exact overrun
  amounts, one FinalDebit, and checked arithmetic. Coarse OCU must remain
  zero-rate and outside that billable chain.
- The deployment-local identity plane must compose with, and never shadow, the
  applicable local/domain or protocol authority; it must preserve wallet.network
  wherever portable delegation or a designated high-risk action requires it.
- `LocalAgentPairingSessionEnvelope` challenge/device-code material must be
  single-use, expiring, hash-only at rest, and returned in plaintext at most
  once. The candidate must generate its own signing key and prove possession at
  the recorded origin; Hypervisor must never generate or retain the candidate's
  private key.
- Pairing must produce only an authenticated candidate. It must not grant room
  membership, context, tools, org read/write access, authority, reputation,
  payout eligibility, or marketplace publication. A room guest gateway profile
  requires matching typed room admission and participant lease; a reusable
  private/organization worker gateway profile requires active registration plus
  concrete invocation, Session, Automation, or WorkRun admission and leases.
- A prompt-only pairing must remain visibly low assurance and proposal-only.
  Its output stays tainted until the normal isolation, verification, and
  room/domain admission path accepts it.

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
shared organization read/write token pasted into a local agent
pairing challenge stored in plaintext or reusable after completion
pairing success = room admission, authority grant, or marketplace publication
agent private key generated or retained by Hypervisor
prompt-only agent presented as daemon-instrumented or independently verified
local-agent bootstrap containing raw provider credentials or ambient room context
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
LocalAgentPairingSessionEnvelope = authenticated candidate ingress only
room admission -> participant lease -> scoped expiring gateway profile
private/org registration -> admitted invocation/session/run -> scoped gateway profile
prompt-only local agent = tainted low-assurance proposal source
aiagent.xyz publication or reusable Worker record = separate explicit handoff
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`../connectors-tools/doctrine.md`](../connectors-tools/doctrine.md)
- [`../connectors-tools/contracts.md`](../connectors-tools/contracts.md)
- [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md)
- [`providers-and-environments.md`](./providers-and-environments.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../wallet-network/api-authority-scopes.md`](../wallet-network/api-authority-scopes.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
