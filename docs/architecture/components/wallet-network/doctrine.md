# wallet.network Authority Layer Specification

Status: canonical architecture authority.
Canonical owner: this file for wallet.network authority doctrine; wallet product, exchange, route-source, exposure, protection, approval-inbox, and receipt doctrine lives in [`product-exchange-risk.md`](./product-exchange-risk.md); low-level scope APIs live in [`wallet-network-api-and-authority-scopes.md`](./api-authority-scopes.md).
Supersedes: older generic capability-grant wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: partial (capability-lease authority, sealed credentials, approval gates, and the principal-to-approval-authority resolver are live; embedded account/factor/passkey/recovery APIs, guardian surfaces, key shards, and MPC vault are planned; the closed approval-ceremony context, temporal profile/evaluation input, review/effect-admission receipt profiles, context-bound v3 grant, and WalletReceipt v2 are target successor contracts)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
  - `crates/types/src/app/wallet_network/principal_authority.rs`
  - `crates/services/src/wallet_network/handlers/principal_authority.rs`
Last implementation audit: 2026-07-14

## Canonical Definition

**wallet.network is the canonical Web4 authority layer: the identity, secret,
authority-scope, approval-token, payment, exchange-authority, portable
data-use authority, decryption-lease, and revocation control plane for
autonomous software.**

It owns identity, secrets, authority scope grants, session authority,
approval-token issuance, payments, revocation, and audit lineage for delegated
machine power. It is the authority wallet and control cockpit for autonomous
agents. It is not merely a crypto wallet.

Within canonical Web4, wallet.network is the machine-authority issuer and
revocation plane. It converts human, organization, domain, contract, and policy
intent into machine-readable authority requests, leases, denials, challenges,
spend limits, declassification decisions, data-use permissions, payment
authority, and revocation events.

wallet.network must not become the owner of every product permission in the
system, and it does not need to be a visible destination for every permission
flow. Hypervisor application surfaces, Foundry, the Ontology and Data applications
(with the ODK developer kit beneath them), Automations, generated domain
apps, and Agentgres may own local governance state,
project/org policy, eligibility records, workflow permissions, and admission
decisions. wallet.network becomes the authority substrate when that local
decision requires portable, revocable, secret-bearing, spend-bearing,
declassification, provider-trust, cross-domain, or autonomous-agent-executable
power.

## Core Doctrine

> **The Hypervisor Daemon runs autonomous work. Hypervisor App, Hypervisor Web,
> CLI/headless clients, optional TUI views, and application surfaces let humans
> operate it. Agentgres remembers and settles what changed. wallet.network
> decides what power workers are allowed to use.**

Put more sharply:

> **wallet.network authorizes power. It does not do the work, store the app, or
> become the chain.**

Product doctrine:

> **Agents do not get secrets. They get authority leases.**

Raw secrets, refresh tokens, provider credentials, key shards, decryption keys,
and BYOK provider keys remain brokered by wallet.network or approved authority
clients. Agents, workers, runtimes, connectors, and application surfaces receive
scoped, revocable, policy-bound leases with expiry, purpose, receipts, and
revocation paths.

Machine authority means a worker can prove what power it requested, what power
it received, under which policy, for what purpose, for how long, against which
resources, and with which receipts. It does not mean the worker holds raw
secrets or can widen its own scope.

## Autonomous Work Authority Gateway

For Hypervisor, wallet.network is the authority gateway for autonomous work.
It controls the user-visible and organization-visible decision path for:

```text
agent and worker identity
delegated authority
capability leases
connector and tool authority
approval queues
secret leases
spend limits
data-use permission
declassification
private workspace authority
provider and GPU spend
revocation and panic controls
policy simulation inputs
gateway decisions
risk labels
authority receipts
```

Local application permissions are allowed to live in Hypervisor and Agentgres.
Examples include project role membership, surface settings, dataset eligibility
state, Foundry job configuration, workflow draft permissions, and ontology
proposal review state. These become wallet.network authority only when they
need a delegated lease, secret brokerage, spend approval, decryption,
declassification, provider-trust acceptance, external connector access,
publication/export, cross-domain reuse, or portable revocation.

An `InstitutionalLearningBoundaryProfile` does not itself grant any of those
powers. Hypervisor and domain governance may compile the applicable learning
rules, and Agentgres may record the admitted profile and decisions, but
wallet.network remains involved only where an execution needs its owned
delegated machine power: credentials, decryption, provider-trust acceptance,
spend, declassification, external export, cross-domain reuse, or portable
revocation. Ordinary internal eligibility remains with its source/data,
training, and system-governance owners.

The gateway must be portable, revocable, policy-bound, receipted, and visible
across local, hosted, enterprise, cTEE/private-workspace, DePIN, cloud, model,
connector, marketplace, and domain-application routes.

This is how Web4 moves autonomous-work authority outside provider trust by
default. Model providers, cloud providers, connector providers, venues, and
managed services can perform work or expose capabilities, but wallet.network
keeps the authority lease, secret brokerage, step-up, revocation, and authority
receipt path outside provider custody unless policy explicitly accepts a
provider-trust route.

It may render as a Wallet console, embedded approval panel, mobile/passkey
step-up, CLI signer, enterprise authority service, or Hypervisor authority
panel. The presentation can vary; the authority contract cannot.

## Product Presentation

wallet.network should usually appear to end users as SSO, account security,
permissions, connected access, recovery, or approval review inside the product
they are already using. Hypervisor, aiagent.xyz, ioi.ai, sas.xyz, and domain
apps may embed wallet-powered permission flows without sending the user to a
separate wallet.network destination for routine setup.

The wallet.network name belongs in advanced, high-trust, or protocol contexts:

- portable authority and cross-app account control;
- security factors, guardians, key shards, recovery, and panic revoke;
- CLI, MCP, SDK, local signer, or enterprise authority-client setup;
- audit export, compliance review, and authority receipt drilldowns;
- external effects, declassification, spend, provider credentials, and other
  high-risk approvals that require an explicit authority provider.

User-facing copy should prefer:

```text
Sign in with SSO
Connect GitHub
Connect Slack
Allow weekly scheduled runs
Require approval before sending
Review evidence
Revoke access
```

Protocol and audit views may disclose the underlying authority provider, grant,
lease, receipt, revocation epoch, and signature path.

## Canonical Embedded Sign-In-to-Effect Journey

The default first-party managed-product journey compiles familiar account access
and consequential machine authority into one experience:

```text
Continue with Apple / Google / Microsoft / GitHub / enterprise SSO / passkey
  -> create or link one native wallet.network identity without requiring
     wallet, key, chain, or cryptographic terminology
  -> establish an ordinary low-risk product session; authentication grants no
     consequential authority
  -> a product or agent proposes one consequential action
  -> wallet.network derives separate commitments to the immutable authority
     request, canonical reviewed representation, single-use approval ceremony,
     and exact effect, batch, or standing authorization subject
  -> an enrolled authority client presents the canonical review under a
     declared presentation-evidence profile
  -> a passkey or other admitted AuthFactor authenticates the fresh ceremony;
     Face ID, Touch ID, Windows Hello, device PIN, or equivalent may perform
     local user verification, and no biometric sample or template leaves the
     device
  -> wallet.network issues a scoped, expiring, revocable AuthorityGrant or
     CapabilityLease bound to the request, review, ceremony, authorization
     subject, resolved approval authority, and revocation epoch
  -> Hypervisor Daemon derives the actual effect at its policy-enforcement
     point, verifies equality, membership, or standing constraints, and
     executes or refuses
  -> WalletReceipt plus Agentgres effect/evidence records make the decision and
     result inspectable, replayable, challengeable, and revocable where possible
```

This is an experience contract, not a second identity or authority plane.
Product adapters may name familiar providers, while the protocol records a
provider-neutral federated factor and its issuer/subject binding. A platform
biometric unlocks a local authenticator; Face ID, Touch ID, or Windows Hello is
never itself an identity, authority grant, signature object, exported biometric
result, or key shard.

The calling product or deployment identity plane owns the product session.
wallet.network binds that session ref and origin into the exact authority
request and review without creating a second session lifecycle. Before this
journey is claimable as portable end-to-end authority, the target
`AuthorityGrantEnvelope` v3 successor must sign the exact authority-request
body hash, reviewed-representation hash, approval-ceremony context hash,
authorization subject, principal, product-session/origin binding, satisfied
factor/guardian posture, complete principal-authority resolution coordinates
and snapshot whenever portable-principal authority is claimed, review receipt,
and typed approval-evidence root; immutable v1/v2 contracts are not silently
extended.

Self-hosted, offline, air-gapped, and sovereign deployments may use
deployment-local identity and another locally permitted authority provider.
They retain the same authentication-versus-authority separation and
effect-boundary admission rule without being forced through a hosted
wallet.network login.

## Exact-Action Evidence Separation

The exact-action path contains four distinct commitments:

```yaml
authority_request_body_hash: sha256:...
reviewed_representation_hash: sha256:...
approval_ceremony_context_ref: approval-ceremony-context://...
approval_ceremony_context_hash: sha256:...
authorization_subject:
  kind: exact_effect | batch_manifest | standing_envelope
  subject_ref: effect://... | artifact://... | policy://...
  subject_hash: sha256:...
  validation_profile_ref: schema://... | policy://...
```

`authority_request_body_hash` commits the immutable machine authority request.
`reviewed_representation_hash` commits the canonical, application-defined
semantic representation presented for approval, including its required
disclosures; it is not a hash of incidental pixels or layout.
`approval_ceremony_context_hash` is the domain-separated JCS hash of the closed
`ApprovalCeremonyContextEnvelope`. It commits the request and representation
hashes, principal, acting subject, product session, origin, authorization
subject, required factor/guardian posture, policy decision, single-use random
nonce, expiry, revocation posture, and the exact wallet.network
principal-authority resolution artifact used by the ceremony when the
principal falls under the portable binding contract.
`authorization_subject` states what later execution must prove:

- `exact_effect` requires equality with the daemon-derived canonical effect
  payload hash;
- `batch_manifest` requires membership in the committed manifest under the
  named validation profile; and
- `standing_envelope` requires the concrete effect to satisfy every committed
  scope, resource, destination, budget, call-count, time, and policy constraint.

These commitments prove different facts and must not be collapsed:

```text
AuthorityReviewReceipt
  records the canonical reviewed representation, decision, and presentation
  evidence accepted under policy plus one hash-bound satisfaction evaluation
  for every required factor or guardian posture ref

AuthFactor / WebAuthn assertion evidence
  authenticates the credential ceremony, challenge, RP/origin posture, and
  observed UP/UV facts required by policy

AuthorityGrantEnvelope v3
  signs the request, review, ceremony, posture-satisfaction profile/root,
  authorization subject, typed approval-evidence root, and any required
  resolved authority snapshot and coordinates

AuthorityEffectAdmissionReceipt
  binds the daemon-derived actual effect, equality/membership/constraint proof,
  the exact TemporalVerificationProfile and TemporalValidityEvaluation,
  revocation evidence, continuity-floor evidence when required, and the
  pre-invocation admission decision

execution/effect receipts
  bind only the invocation and effect facts their profiles declare
```

The closed ceremony context, `AuthorityReviewReceiptV1`, context-bound
`AuthorityGrantEnvelope` v3, `AuthorityEffectAdmissionReceiptV1`, and target
`WalletReceipt` v2 are successor contracts. Current registered v1/v2 grants,
the current WalletReceipt v1, and generic execution receipts remain unchanged
and do not by themselves establish the end-to-end exact-action proof.

A WebAuthn assertion can be evidence in an application consent or approval
ceremony when its fresh server challenge is bound to
`approval_ceremony_context_hash`. It remains distinct from presentation
evidence and does not independently prove that an application-defined
representation was displayed, displayed correctly, or understood. Likewise, a
surface statement that it rendered a review does not authenticate the user, and
a daemon execution receipt does not prove that the executed effect was approved
unless the request, review, ceremony, grant, authorization subject, resolved
authority when required, and actual effect are linked and revalidated.

Presentation evidence is declared through a versioned
`presentation_evidence_profile_ref` plus immutable evidence refs. Its assurance
is not a two-tier label. Policy evaluates the orthogonal facts the selected
profile records:

```yaml
presentation_evidence:
  presentation_evidence_profile_ref: policy://wallet/presentation/...
  presentation_evidence_refs:
    - receipt://...
    - artifact://...
    - attestation://...
  dimensions:
    operator_and_surface: object
    content_binding: object
    request_vs_effect_binding: object
    enrollment_and_attestation: object
    user_presence_and_verification: object
    freshness_and_replay: object
    proposer_independence: object
```

An ordinary embedded browser surface may provide a policy-accepted semantic
presentation receipt without claiming a trusted display. A separately enrolled
or attested authority client may support stronger statements only for the exact
facts its evidence proves. No presentation profile, AuthFactor, device class,
or attestation upgrades comprehension into a cryptographic fact.

Interaction mode (`interactive` or `noninteractive_policy`) and authentication
posture (`baseline` or `step_up`) are independent. A step-up review remains an
interactive ceremony with stronger required authentication; it is not a third
interaction mode. Required posture, satisfied posture, and actual evidence are
also distinct: every requirement receives exactly one wallet-derived
`satisfied`, `unsatisfied`, or `unknown` evaluation, and approval requires all
evaluations to be satisfied.

`edit-and-approve` always creates a successor authority request, review,
representation hash, authorization-subject commitment, and approval ceremony.
The predecessor challenge and assertion cannot authorize the edited successor.
For noninteractive or after-the-fact execution under a standing envelope,
receipts must say that the envelope, not the individual effect, was reviewed.

## Boundary Statement

wallet.network does not execute work, store app-domain operational truth, or
serve as the marketplace database. It may authenticate the user and release
bounded viewing/decryption authority for private user/app state, but the
state's canonical meaning remains in Agentgres refs and the encrypted bytes
remain in storage backends.

- Hypervisor Daemon executes work as the autonomous-execution hypervisor/control plane.
- Hypervisor App, Hypervisor Web, CLI/headless clients, optional TUI views, and
  Developer Workspace, Automations, Foundry, Applications, Environments views,
  and domain surfaces request, approve, and inspect work as operator clients,
  application surfaces, and projections.
- Agentgres records operational state, runs, receipts, projections, delivery,
  and contribution accounting.
- Selected settlement services handle registry, rights, escrows, bonds,
  disputes, and public commitments; IOI L1 provides the optional shared IOI
  Network service set.
- wallet.network authorizes scopes, protects secrets, controls payments, and
  issues approval/session grants.

Authority receipts flow through the operational substrate:

```text
wallet.network authority receipt
→ Agentgres domain operation/evidence/delivery bundle
→ optional IOI L1 commitment when economically or security relevant
```

## What wallet.network Owns

wallet.network owns:

- user identity;
- authentication factors and account security posture;
- high-assurance guardian surfaces;
- MPC, threshold, hardware-backed, or organization key shards;
- low-assurance access-point bindings and step-up challenge policy;
- agent/app/domain authority grants;
- root-signed, versioned, revocable principal-to-approval-authority bindings;
- root secrets;
- API keys;
- OAuth refresh tokens;
- connector credentials;
- provider credential bindings;
- BYOK model provider keys;
- sealed archive decryption authority;
- cTEE guardian identity, key-share, and declassification authority;
- restore key leases;
- training-data access approvals;
- training artifact decryption leases;
- model-provider and GPU spend authority for training/evaluation jobs;
- Private Workspace node `AutonomyLease` grants;
- authority scope leases;
- approval tokens;
- session grants;
- policy envelopes;
- revocation epochs;
- payment authorization;
- exchange authority and exact exchange-intent approval;
- asset, route, and security risk disclosure for wallet actions;
- protection-action authority such as approval revocation, spend limits,
  account migration, and agent-fund isolation;
- panic/emergency controls;
- capability-exit signing and revocation for protected remote work;
- wallet CLI, MCP, SDK, mobile, web, embedded, and enterprise authority-client
  contracts;
- audit lineage.

## What wallet.network Does Not Own

wallet.network does not own:

- rich application state;
- workflow graphs;
- worker marketplace listings;
- service order operational state;
- full run traces;
- Agentgres projections;
- artifact payload bytes;
- model inference execution;
- training, benchmark, or evaluation execution;
- IOI L1 registry, settlement, or dispute state;
- sealed state archive bytes.
- liquidity, route proposals, quote truth, DEX/bridge execution mechanics, and
  chain finality.

## Worker Training Authority

Worker Training improves capability; it does not grant power. Hypervisor,
Foundry, ODK/data/ontology surfaces, and Agentgres may own the local training
governance objects: PolicyBoundDataViews, DataRecipes, dataset eligibility,
Foundry job settings, eval suites, scorecards, and admitted lineage.

wallet.network owns the portable authority path that those objects may require:

- access to private source documents, traces, examples, and corrections;
- delegated data-use authority for training, evaluation, benchmark, or
  publication when that use requires portable authority;
- authority grants referenced by training evidence eligibility records;
- authority to run DataRecipes over PolicyBoundDataViews when the run needs
  connector access, decryption, external compute, or delegated machine power;
- authority to use connector mappings against source systems and accounts when
  connector access or account-scoped delegated power is required;
- authority to publish or reuse DomainOntologies, ontology packs, canonical
  object models, and evaluation datasets when they contain governed material;
- decryption leases for sealed training datasets and artifacts;
- BYOK model-provider keys used by planner, generator, verifier, or trainer
  jobs;
- approval for remote GPU, hosted, DePIN, TEE, or customer-VPC training
  execution;
- payment approval for benchmark submissions, training compute, and service
  settlement.

Training archives should contain wallet.network secret refs and data-use refs,
not raw long-lived secrets. Reuse of training material must request the
appropriate authority scope again unless the original grant explicitly permits
reuse.

## Multi-Party Authority Boundary

For multi-organization collaboration, wallet.network supplies portable
delegated authority only for the party, subject, resource, scope, expiry,
request hash, and policy hash named by the grant. One organization's grant,
guardian, connector lease, or decryption lease must not authorize another
organization's connector, worker, policy-bound data view, protected payload, or
settlement account.

Collaboration surfaces may aggregate the separate authority outcomes in a
`MultiPartyCollaborationEnvelope`, but wallet.network still issues, denies,
revokes, or rotates each portable delegated authority path independently.
App-local governance, restricted views, delivery state, contribution state, and
audit/export manifests remain with their owning Hypervisor, domain, Agentgres,
or service surfaces unless the action crosses into delegated authority,
decryption, connector access, spend, publication/export, settlement, or another
high-risk machine power.

## Availability Profiles

wallet.network is the trusted authority plane. It may be always-on locally,
hosted, mobile-assisted, enterprise-managed, or wakeable depending on profile.

Examples:

- Hypervisor desktop may use a background local wallet authority service.
- Hosted workers may use delegated wallet authority with narrow standing
  grants.
- High-risk actions may require mobile/passkey/security-key step-up before
  sealed secret release, payment authorization, or policy widening.

## Sealed Archive Restore Authority

When Agentgres exports dormant or idle runtime state to a sealed archive,
wallet.network owns the restore authority path:

```text
restore requested
→ wallet.network verifies account/org/device/policy authority
→ scoped decryption key lease or sealed key release is granted
→ daemon/domain kernel decrypts archive in the approved environment
→ Agentgres records restore/import receipts
→ lease expires or is revoked
```

Archives should contain secret refs such as
`wallet.network://secret/openai-key`, not raw long-lived secrets, unless a
separately sealed exceptional policy explicitly permits it.

## Account Abstraction

User-facing onboarding should hide wallet complexity.

A user may create a wallet.network account through:

- Apple, Google, Microsoft, GitHub, or another admitted federated provider;
- passkey;
- Web3 wallet linking;
- email/OIDC provider;
- enterprise SSO.

A frictionless login creates a native wallet.network account with a Level 1 authority profile.

The external login is an authentication factor, not the root identity.
Provider brands are adapter and product metadata; the stable protocol kind is a
provider-neutral federated identity factor bound to an exact issuer and subject.

## Account Security and Authority Factor Taxonomy

wallet.network separates account access from authority. A user may enter through
a simple provider login, but consequential agent authority must pass through
policy, step-up, grant issuance, revocation semantics, and receipts.

Canonical terms:

```text
AuthFactor
  A credential or login method that helps authenticate the user or device.
  Examples: Google, GitHub, email/OIDC, enterprise SSO, passkey, Web3 wallet,
  TOTP. An AuthFactor is not an authority grant.

LowAssuranceAccessPoint
  A notification or initiation channel such as SMS, email, chat, voice, or
  webhook. It may carry a challenge pointer, but not grants, raw credentials,
  decryption keys, or durable authority.

GuardianSurface
  An enrolled authority-client and presentation surface that can produce the
  presentation evidence required by policy and submit an approval or denial.
  It composes with one or more AuthFactors; a generic passkey or hardware
  credential is an AuthFactor, not a GuardianSurface by itself. Examples:
  enrolled mobile or desktop authority clients, local CLI signer surfaces,
  enterprise approval surfaces, and trusted Hypervisor/wallet apps.

KeyShard
  Actual MPC, threshold, hardware-backed, or organization quorum key material.
  "Shard" is reserved for cryptographic or threshold authority, not ordinary
  provider login.

ProviderCredentialBinding
  A brokered OAuth refresh token, API key, wallet credential, model-provider key,
  cloud credential, or connector credential managed by wallet.network.

AuthorityGrant
  The scoped `grant://...` or lease object an agent, app, worker, service, or
  runtime receives. It is the only object that conveys power.
```

Google, GitHub, email, or enterprise SSO can bootstrap a wallet.network account
and satisfy low-risk access. They should not be sufficient by themselves for
funds, secret release, policy widening, persistent agent authority,
declassification, production deploys, high-value compute spend, or organization
administration.

TOTP is a supplemental factor and may raise confidence, but it is phishable and
must not be treated as a sovereign authority shard. Face ID, Touch ID, Windows
Hello, or another local verification mechanism can unlock a passkey or
secure-enclave credential under an enrolled-device policy; the resulting
cryptographic assertion, not the biometric, crosses the boundary.

Out-of-band guardian approval should be available for high-risk actions. A QR,
push, or CLI challenge is only a transport. The enrolled authority client
produces presentation evidence for the exact review, and the separately
admitted AuthFactor or organization approval mechanism authenticates the bound
ceremony. Together they bind:

```text
subject
action
resources / destination
budget or amount
expiry
risk class
policy hash
authority request body hash
reviewed representation hash
approval ceremony context hash
authorization subject ref and hash
```

The agent never receives provider tokens, OTP values, raw biometric samples or
templates, guardian secrets, raw key shards, or root session material. A
WebAuthn assertion may carry the authenticator's signed user-verification flag;
that flag is not the underlying biometric. The agent receives only a scoped
grant, denial receipt, revocation epoch, or authority receipt.

## Frictionless-to-Fortress Security Ladder

### Level 1: Federated / Frictionless Account

- federated OIDC/OAuth/SAML, Web3, email, or passkey login;
- native wallet.network identity created automatically;
- low-risk authority scopes;
- managed recovery;
- limited autonomy.

### Level 2: Trusted Device / Passkey

- passkey;
- cryptographic passkey assertion unlocked by required local user verification
  and bound to an enrolled-device policy;
- mobile approver;
- local wallet or Hypervisor app;
- higher risk limits;
- stronger approval flows.

### Level 3: Out-of-Band Guardian

- enrolled external GuardianSurface authority client;
- QR, push, or CLI transport for a challenge bound to the approval ceremony
  context;
- hardware-key or passkey AuthFactor composed with that surface where policy
  requires it;
- local CLI signer surface;
- enterprise approval surface;
- persistent agent authority;
- funds, secrets, deploys, policy widening, and declassification.

### Level 4: Sovereign / Organization Vault

- MPC or threshold key shards;
- hardware-backed key shares;
- quorum or role-based organization approvals;
- high-value assets;
- high-value compute and production environments;
- policy widening;
- institutional autonomy.

## Portable Principal-to-Authority Binding

wallet.network exclusively owns the portable binding from a declared principal
to the exact approval authority allowed to sign governed decisions for that
principal. The canonical principal grammar is deliberately narrow:

```text
worker://<path>
service://<path>
org://<path>
domain://<path>
agentgres://domain/<path>
```

`<path>` contains one or more nonempty slash-separated ASCII segments. Each
segment starts and ends with a letter or digit; internal characters may also be
`.`, `_`, `-`, `~`, `:`, or `@`. Leading, trailing, or doubled slashes, query
strings, fragments, wildcards, percent encoding, alternate schemes,
whitespace, and caller-chosen aliases are not canonical principal identity.

Each `PrincipalAuthorityBindingProofV1` is an immutable, wallet control-root
signed version. Its signed statement binds the canonical principal ref, the
exact `ApprovalAuthority` id/public key/signature suite, the hash of that
authority snapshot, predecessor ref/hash, lifecycle status, issue/expiry time,
and control-root issuer. A stable mutable head may point at the current version
and binds the exact mutation audit sequence/id/hash; it must never replace or
rewrite an immutable proof. Rotation appends a new active version. Revocation
appends a revoked successor with a reason.

Resolution returns the exact `binding_ref`, `binding_version`, and
`binding_hash` together with the resolved key, suite, authority id, snapshot
hash, and mutation audit commitment. A caller may pin all three coordinates.
Missing, malformed, stale, expired, revoked, ambiguous, hash-mismatched, or
key-drifted bindings fail typed-unavailable. Resolution never falls back to a
local login, Hypervisor session identity, organization role, request caller
field, trust-on-first-use key, or copied grant field.

Governed durable intents must retain the complete signed approval grant plus
the binding ref, version, and hash used to authorize it. Restart recovery must
reverify the grant signature, immutable binding proof, current binding head,
authority snapshot, and revocation/expiry posture before reconstructing the
exact successor. A copied `authority_id`, public key, or decision receipt is
not sufficient authorization evidence.

## Account Recovery and Device Lifecycle

Recovery restores account access. It never reconstructs, widens, or silently
preserves consequential authority.

- A federated provider login by itself cannot recover Level 3, Level 4, or
  organization-vault authority.
- High-assurance recovery uses a predeclared independent authenticator,
  GuardianSurface, organization quorum, hardware-backed factor, or delayed
  reviewed recovery path appropriate to the active policy.
- Losing or compromising a factor or device revokes or quarantines the factor,
  dependent GuardianSurface, affected account sessions, and dependent grants;
  applicable revocation epochs rotate before future authority is issued.
- Linking or unlinking a factor, changing a recovery route, replacing a trusted
  device, and merging account identities are consequential transitions with
  exact review and receipts. Equal email strings never merge identities;
  issuer/subject bindings and an authorized linking flow do.
- A single-device passkey requires another enrolled authenticator or an
  approved recovery route. Authenticator BE/BS signals expose single- versus
  multi-device eligibility and current backed-up posture. They do not identify
  a synchronization provider or prove device-bound custody; either claim
  requires additional admitted evidence, and policy must not guess it.
- Recovery may deliberately restore a lower security level. Standing high-risk
  grants remain revoked or quarantined until the user or organization
  re-establishes the required factors and explicitly reauthorizes them.

A passkey is an `AuthFactor`, not a presentation surface. A policy may require an
enrolled GuardianSurface to produce presentation evidence and a passkey to
authenticate the separately bound approval ceremony. The resulting review
receipt records which surface and presentation-evidence profile were accepted;
the AuthFactor evidence records the WebAuthn ceremony facts. Authentication and
recovery produce posture evidence; only the resulting `AuthorityGrant` or
`CapabilityLease` conveys machine power (`INV-3`).

## wallet.network Authority Surfaces

wallet.network may expose web, mobile, desktop, embedded Hypervisor panels, CLI,
SDK, MCP, enterprise authority service, and local signer surfaces. All surfaces
are clients of the same authority pipeline:

```text
intent
-> simulation / evidence
-> risk and eligibility labels
-> policy
-> canonical reviewed representation and presentation evidence
-> step-up or denial
-> approval ceremony evidence
-> scoped grant / lease
-> execution handoff
-> daemon-derived effect binding and admission
-> receipt
-> revocation path
```

The wallet.network CLI is a local operator and signer surface. It may sign in,
link factors, enroll guardian devices, approve or deny challenges, inspect
grants, revoke leases, broker secret execution, and export receipts. It must not
become a second authority source.

The wallet.network MCP surface is an agent-facing authority request and receipt
surface. It may let agents request authority, check capability posture, create
approval requests, request policy-bound payments, inspect receipts, and request
revocation. It must not export raw secrets, reveal provider tokens, raw-sign
arbitrary payloads, raise limits, disable step-up, enroll guardians, or convert
authentication into authority without policy and receipts.

## Authority Scope Request Flow

```text
agent/runtime requests authority scope
→ wallet.network evaluates policy
→ if allowed, issues scoped authority grant/session/approval token
→ runtime executes operation without raw secret exposure where possible
→ receipt emitted
→ Agentgres records effect state/evidence
```

## Authority Scope Examples

```text
scope:model.openai.chat
scope:model.anthropic.messages
scope:gmail.read
scope:gmail.draft
scope:gmail.send
scope:calendar.create
scope:slack.post
scope:github.comment
scope:instacart.cart_create
scope:instacart.order_submit
scope:wallet.transfer_under_limit
```

Autonomous-system control uses distinct high-assurance scopes rather than one
generic deployment or improvement grant:

```text
scope:autonomous_system.constitution_amend
scope:autonomous_system.node_admit
scope:autonomous_system.node_role_change
scope:autonomous_system.writer_promote
scope:autonomous_system.authority_membership_change
scope:autonomous_system.consensus_membership_change
scope:autonomous_system.oracle_profile_change
scope:autonomous_system.migrate
scope:autonomous_system.succeed
scope:autonomous_system.dissolve
scope:autonomous_system.decommission
scope:autonomous_system.network_enrollment_change
```

Bounded improvement uses distinct scopes for campaign governance rather than a
generic self-improvement grant:

```text
scope:improvement.campaign_admit
scope:improvement.epoch_freeze
scope:improvement.cutoff_issue
scope:improvement.upgrade_submit
scope:improvement.campaign_stop
```

These scopes do not include target activation. A selected candidate still uses
the target owner's ordinary release, amendment, deployment, or protected-change
authority. Search authority cannot freeze its own evaluator, Judgment authority
cannot activate the candidate it scored, and Campaign admission cannot mint a
replacement authority root. Concurrent candidate or descendant work binds
atomic, disjoint resource reservations; a branch, generation, or target-order
change cannot re-spend the ancestor's unreserved balance.

These scopes are examples of the canonical `scope:*` family; deployment does
not imply node admission, ordinary upgrade does not imply constitutional
amendment, and node admission does not imply writer or authority membership.
Each request binds the active constitution/profile roots, exact transition,
system and membership IDs, evidence, budget/effect posture, expiry, revocation
epoch, and the external governance decision required by that system. A worker
may propose the request but cannot approve its own protected transition.

## Risk Classes

The canonical risk-class ladder is owned by
[`../../foundations/canonical-enums.md`](../../foundations/canonical-enums.md);
this section applies it, it does not redefine it. Excerpt (canonical order,
lowest to highest required assurance):

```text
read → draft → local_write → write_reversible → external_message → commerce
→ funds → credential_access → policy_widening → secret_export
→ identity_change → system_destructive
(physical_action: peer top-tier class; requires the Physical Action Safety envelope)
```

Higher classes require stronger approval or security tier (INV-1,
[`../../foundations/invariants.md`](../../foundations/invariants.md)).

## Product, Exchange, and Risk Doctrine

Wallet's product doctrine is canonical, but separate from this authority-layer
doctrine to avoid turning the authority spec into a route router, exchange
backend, or app database.

See [`product-exchange-risk.md`](./product-exchange-risk.md) for:

- Wallet product surface doctrine;
- Exchange and Route Authority;
- relationship to `decentralized.exchange`;
- Trade, Prediction, and Position Authority;
- relationship to `decentralized.trade`;
- relationship to `decentralized.cloud`;
- `ExchangeIntent`, `RouteCandidate`, `TradeIntent`, `PredictionIntent`,
  `PositionReceipt`, `PredictionReceipt`, `WalletReceipt`, and
  `AssetExposureRecord`;
- authority risk classes versus asset/route/security risk labels;
- protection actions;
- approval inbox;
- exchange, trade, and provider economics disclosure;
- organization authority;
- wallet SDK event protocol.

Core invariant:

> **wallet.network owns authority. Route, venue, and resource sources produce
> candidates. Liquidity lives in pools and venues. Provider resources live with
> selected providers. Hypervisor executes runtime/provider lifecycle. Execution
> lives onchain, in the chosen venue, or at the selected provider boundary.
> Agentgres records receipts and evidence. No quote, route source, venue
> source, or resource candidate is a trust root.**

## Repository and Contract Boundary

The wallet.network product may live in its own application repository. That is
the preferred product boundary for rapid UI, website, design-system, mobile,
extension, and marketing iteration.

The wallet.network authority contracts must remain anchored in the IOI protocol
repository and exported outward. Product repositories consume the contracts;
they do not define authority truth.

```text
IOI protocol monorepo
  owns:
    Rust wallet.network types
    wallet.network service transition logic
    authority scope and receipt API doctrine
    `@ioi/wallet-protocol`
    `@ioi/wallet-sdk`
    OpenAPI / JSON Schema artifacts
    receipt fixtures and conformance tests

wallet-network product repo
  owns:
    Wallet app UI
    website/product surfaces
    design system
    screenshots and product prototypes
    app-specific frontend state
    fixture data only when clearly marked as non-authoritative
```

Current implementation anchors:

```text
crates/types/src/app/wallet_network/
  Rust authority/session/connector/secret/receipt object types.

crates/services/src/wallet_network/
  Native wallet.network service transition logic and validation.

crates/services/src/wallet_network/tests/
  Service-level wallet authority, lease, connector, receipt, and replay tests.

crates/cli/tests/wallet_network_session_channel_e2e/
  End-to-end session channel, lease, approval, secret injection, and mail
  capability tests.

scripts/conformance/hypervisor-conformance.mjs
  Cross-runtime conformance hooks for wallet.network authority boundaries.

packages/wallet-protocol/
  Versioned TypeScript protocol objects, method registry, JSON Schema,
  OpenAPI, fixtures, and package tests tied back to the Rust wallet anchors.

packages/wallet-sdk/
  Typed client helpers over wallet.network authority reviews, capability
  leases, receipts, and protocol method calls. The SDK imports
  `@ioi/wallet-protocol`; it does not author wallet authority semantics.
```

Package artifacts:

```text
@ioi/wallet-protocol
  Versioned protocol objects, method metadata, schemas, OpenAPI/JSON Schema,
  receipt fixtures, and canonical examples tied to IOI-owned contracts.

@ioi/wallet-sdk
  Typed client helpers over wallet.network APIs, receipts, grants, leases,
  exchange/trade intents, capability exits, and revocation.
```

The Rust `ioi_types::app::wallet_network` module and
`WalletNetworkService` remain the lower service/type anchors. The TypeScript
protocol and SDK packages are the distributable app/developer boundary over
those anchors. Product apps may mock Wallet flows, but they must not become the
source of truth for scopes, grants, leases, receipts, exchange/trade intents,
secret-release semantics, or capability-use policy.

## Marketplace Role

wallet.network authorizes:

- worker installation;
- worker authority grants;
- WorkerInvocation escrow;
- ContributionReceipt payment;
- UsageReceipt settlement;
- service escrow funding;
- ServiceOrder escrow;
- SLA bond approval;
- payment release;
- payout authorization;
- refund/dispute authorization;
- recurring worker standing orders;
- BYOK model calls;
- connector OAuth usage;
- policy widening;
- revocation/panic.

## Relationship to IOI L1

wallet.network may interact with IOI L1 for:

- gas payments;
- escrow funding;
- SLA bond posting;
- license/installation rights;
- payout acceptance;
- disputes;
- identity commitments.

wallet.network abstracts gas and payment complexity from the user.

IOI L1 is not the wallet database. When explicitly selected, IOI L1 stores
registry, economic, settlement, dispute, and sparse public commitments.
wallet.network stores
authority state locally or in a secure authority deployment profile, and
Agentgres stores operational receipts and projections.

Private user/app metadata should follow the same boundary:

```text
wallet.network
  authenticates the user and grants viewing/decryption/mutation authority

Agentgres
  stores canonical refs, policy, receipts, state roots, and restore/import truth

storage backends
  store encrypted profile, preference, app-state, workspace, and service bytes

IOI L1
  stores selected public/economic commitments only
```

## Relationship to Agentgres

wallet.network emits authority artifacts:

```text
PolicyEnvelope
RootGrant
SubGrant
AuthorityScopeLease
ApprovalToken
RevocationEvent
SecretExecutionReceipt
StepUpReceipt
```

Agentgres records the effect of these in domain state, but does not own the raw secrets.

## Hypervisor Daemon / Guardian Profile Boundary

Public architecture names the execution boundary as the Hypervisor Daemon. A hardened
Guardian profile may exist inside that boundary for policy gates, attestation,
tool execution, and authority mediation.

```text
wallet.network ↔ Hypervisor Daemon / Guardian execution profile
```

The daemon requests authority scopes and receives bounded grants, approval
tokens, or operation-scoped secret execution. It does not become a key
custodian.

## Low-Assurance Access Points

SMS, email, chat apps, webhooks, voice bridges, and other low-assurance
messaging channels are notification and initiation rails. They are not guardian
surfaces and they are not wallet.network authority grants by themselves.

Low-assurance access points may:

- notify the user about blockers, status changes, candidate outputs, or pending
  approvals;
- wake, pause, resume, or steer an agent inside preconfigured low-risk bounds;
- start preapproved workflows under an existing `AutonomyLease`;
- carry a short-lived, single-use step-up challenge pointer.

They must not:

- decrypt private workspace state;
- declassify protected files, PII, strategy logic, private memory, credentials,
  or sealed outputs;
- receive durable keys, OAuth credentials, broker keys, or wallet secrets;
- approve funds, trades, deploys, secret export, policy widening, private
  workspace viewing, or other high-risk actions without step-up;
- be treated as the cTEE guardian or authority view.

The correct escalation path is:

```text
SMS or low-assurance channel receives blocker/approval notice
  -> user opens short-lived challenge link
  -> wallet.network, Hypervisor, enrolled guardian device, passkey,
     enterprise IdP, local app, or CLI signer authenticates the user
  -> exact action, risk, data, budget, recipient, and expiry are shown
  -> wallet.network issues a scoped grant or denial receipt
  -> daemon/agent continues using only the grant ref and receipt
```

An SMS reply such as `YES` may acknowledge or request a step-up flow, but it is
not sufficient authority for sensitive action unless a prior wallet policy
explicitly bound that exact low-risk command, risk ceiling, budget, expiry, and
recipient. Even then, it must not release protected plaintext or durable
secrets.

Canonical invariant:

> **Low-assurance access points can wake, steer, pause, and notify agents. They
> cannot decrypt, declassify, or authorize high-risk actions without step-up into
> wallet.network, Hypervisor, an enrolled guardian device, enterprise IdP, local
> app, CLI signer, or another high-assurance authority surface.**

## Runtime Privacy Profiles

wallet.network should support authority-release policy by runtime privacy
profile.

### Mutual Blind Profile

- no raw secrets;
- no final effects solely from untrusted execution;
- opaque, narrow, operation-scoped authority only;
- receipts must prove what was requested, released, used, and revoked.

### Private Workspace cTEE Profile

- rented hosted/provider/DePIN GPU nodes may stay online and run the daemon,
  Hypervisor Node shell, public inference, encrypted persistence, and redacted
  workspace work;
- Plaintext-Free Runtime Mounting exposes public/redacted context and private
  handles to the node for tools and models, while wallet-controlled authority
  decides key release, declassification, and capability exits;
- Candidate-Lattice Private Decoding is the default protected-agency path:
  rented nodes generate candidate lattices while wallet-controlled guardian,
  AlphaSeal, or private operators select, deny, declassify, or sign;
- Counterfactual Lattice Execution may spend additional public token volume to
  reduce online private-choice leakage when the wallet policy or leakage budget
  requires it;
- `CustodyProof` binds the custody derivation, mount graph, lattice commitments,
  receipts, leakage budget, and state roots for verifier-facing
  no-plaintext-custody claims;
- model routes that send sensitive plaintext to third-party APIs are
  provider-trust routes, not base cTEE no-plaintext-custody routes;
- wallet policy should require an `ExecutionPrivacyPosture` disclosure when a
  worker, service, or outcome engine may use third-party model APIs over private
  workspace data;
- the Cryptographic Operator Plane routes protected scoring, selection,
  retrieval, and policy checks through FHE/MPC/garbled/ORAM/local/threshold
  paths when public/redacted execution is insufficient;
- the authenticated authority surface is the default second logical party for
  private operators: browser/device session, mobile guardian, CLI signer,
  wallet.network policy/key path, or enterprise key service;
- managed non-colluding committees are optional escalation paths for higher
  assurance or unattended enterprise workflows, not the ordinary user-facing
  topology;
- protected classes such as PII, strategy source, broker keys, live portfolio
  state, private memory, and final action logic are not released as plaintext to
  the provider-rooted node by default;
- `AutonomyLease` grants define what the node may do while the user is offline;
- the cTEE authority view, implemented by wallet.network, authenticated
  browser/device session, local Hypervisor, CLI signer, customer authority
  service, mobile approval path, or threshold committee, participates in key
  release, private-head selection, declassification, and capability exits;
- `ModelMountReceipt`, `PrivateInferenceReceipt`,
  `CounterfactualLatticeReceipt`, `PrivateOperatorReceipt`,
  `DeclassificationReceipt`, capability-exit receipts, and
  deterrence/detection receipts attest the declared boundary facts about what
  was mounted, computed, privately operated, revealed, denied, signed,
  watermarked, or canary-checked; verification and external-effect acceptance
  remain separate.

### Enterprise Secure Profile

- TEE or equivalent attestation required before sealed secret or authority
  release;
- authority release binds to code identity, request hash, policy hash, expiry,
  and revocation epoch;
- Agentgres records the resulting authority and execution receipts.

## Private Workspace Authority

For Private Workspace backed by cTEE, wallet.network owns the authority
membrane that keeps a persistent rented GPU useful without making it the
plaintext custody workspace.

wallet.network controls:

- authority-view identity and quorum policy;
- key shares, masks, decryption leases, viewing keys, and revoke/panic state;
- `AutonomyLease` creation, renewal, narrowing, and revocation;
- declassification policy for protected outputs;
- action limits for broker, API, payment, message, deploy, or connector exits;
- step-up rules for widening risk, disclosing private material, or exporting
  protected memory.

The default flow is:

```text
Private Workspace node produces protected output commitment
  -> Agentgres records refs and private-inference receipt
  -> wallet.network checks AutonomyLease, policy hash, risk, and revocation
  -> authority view decrypts, reconstructs, selects, or denies if allowed
  -> declassification gate approves, denies, or escalates
  -> capability exit signs only bounded actions
  -> DeclassificationReceipt and capability-exit receipt are recorded
```

wallet.network must not release durable raw broker keys, unrestricted OAuth
tokens, strategy source, live portfolio plaintext, full private memory, or root
secrets to a root-controlled rented node. The node may receive opaque,
operation-scoped capability exits and encrypted or masked state under policy.

## Cryptography Positioning

The target profile is hybrid classical + post-quantum authority, not a blanket
claim that every connected legacy system becomes post-quantum safe.

Appropriate claims:

- hybrid signatures for policy envelopes, grants, and approval records;
- hybrid KEM for control-plane handshakes;
- authenticated encryption such as XChaCha20-Poly1305 for vault storage;
- legacy-chain custody remains constrained by the legacy chain's own
  cryptographic limits.

## Anti-Patterns

Do not model wallet.network as:

```text
the execution runtime
the application database
the worker marketplace
the Agentgres state store
the L1 settlement chain
a place where agents receive raw root secrets
a place that releases plaintext alpha or PII to a rented GPU because the node
passed a boot measurement
a centralized exchange
a single liquidity router
a mandatory dependency on decentralized.exchange
a mandatory dependency on decentralized.cloud
a broker or custodian for decentralized.trade
a cloud control plane or provider account owner
a place where perps, margin, leveraged positions, prediction markets, or event
contracts are treated as ordinary swaps
a place where agents get open-ended trading authority by default
a place where route candidates become approval
a place where cloud resource candidates become spend approval
a quote API trust root
a blanket post-quantum safety wrapper for legacy chains
a generic login provider with no autonomous-work semantics
a blanket claim that legacy systems become post-quantum safe
```

Correct model:

```text
wallet.network owns portable delegated authority, secrets, approvals, payment
scopes, decryption leases, revocation, and audit lineage
local/domain governance owns local policy decisions that do not cross portable,
external, decryption, spend, declassification, or high-risk boundaries
daemon executes work
Agentgres records operational truth
the system settles locally unless its declared enrollment and settlement
profiles select external services such as IOI L1
```

## Related Canon

- [`product-exchange-risk.md`](./product-exchange-risk.md): Wallet product,
  exchange, route-source, risk, protection, approval-inbox, and receipt doctrine.
- [`api-authority-scopes.md`](./api-authority-scopes.md): scope API and grant
  shapes.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  daemon-executed action proposal, gate, and execution path.
- [`../daemon-runtime/private-workspace-ctee.md`](../daemon-runtime/private-workspace-ctee.md):
  Private Workspace backed by cTEE, persistent private nodes, `AutonomyLease`,
  declassification gates, and private strategy execution.
- [`../daemon-runtime/api.md`](../daemon-runtime/api.md): action mediation and
  approval API.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): where authority
  outcomes become operational truth.
- [`../../foundations/security-privacy-policy-invariants.md`](../../foundations/security-privacy-policy-invariants.md):
  broader security and policy invariants.

## Non-Negotiables

1. Agents never receive raw root secrets.
2. Apps and runtimes are authority clients, not key custodians.
3. Policy widening requires step-up.
4. Sensitive actions bind the exact authority-request body, reviewed
   representation, approval-ceremony context, authorization subject, policy,
   scope, expiry, and revocation epoch.
5. Panic/revocation must kill active grants.
6. BYOK keys live in wallet.network, not workflow node configs.
7. Agent execution accounts are not default for every agent; they are required
   only when the agent needs on-chain execution power.
8. High-risk on-chain actions require wallet.network step-up and/or
   smart-account module enforcement.
9. Principal-authority rollback resistance is relative to the externally
   selected wallet state root; ledger finality must prevent wholesale rollback
   of the complete state root, while the resolver detects coupled mutable-head
   rollback inside the selected root through immutable per-version indexes.
10. The principal-authority binding ref, version, hash, complete
    `ApprovalAuthority` snapshot and hash, required and matched scope, and
    mutation-audit coordinates remain linked to the grant and durable replay
    evidence.
11. WebAuthn assertion evidence, presentation evidence, and daemon execution
    evidence must not be substituted for one another.
12. `exact_effect` approval requires daemon-derived hash equality;
    `batch_manifest` requires membership proof; `standing_envelope` requires
    complete constraint validation.
13. Editing any reviewed consequential field creates a successor request,
    review, and approval ceremony and invalidates predecessor approval evidence.
14. A point timestamp, owner epoch, signed revocation snapshot, or
    `clock: healthy` flag does not establish current authority. Consequential
    use resolves the exact `TemporalVerificationProfile` and recomputable
    `TemporalValidityEvaluation`; wallet.network retains grant/revocation
    ownership while Platform Operability qualifies temporal claims.

## One-Line Doctrine

> **Do not make users create a wallet. Let them create an account that can grow into a vault.**

## wallet.network Product Context Module

The wallet.network v3.2 product module (Sovereign IAM Hub product spec:
personas, UX surfaces, module boundaries, and the 2025-era phase roadmap)
is archived verbatim at
[`../../_archive/specs/wallet-network-product-context-v3-2.md`](../../_archive/specs/wallet-network-product-context-v3-2.md).
It is product-positioning context, not authority doctrine; the canonical
authority model above and
[`product-exchange-risk.md`](./product-exchange-risk.md) own the live
product surface. Its phase dates predate this canon and are historical.
