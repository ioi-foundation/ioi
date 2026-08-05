# Settings — implementation brief

Canonical route: `/settings` · Owner: core workspace Settings (projection-only, writes-through-owners)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- Settings is a `core_workspace` registered at `/settings`; `/sign-in` is its
  authentication entry, not an application registration
  (core-clients-surfaces.md:994-995; route-ledger rows :890-891).
- Its charter caveat is in the core-workspace block itself: "scoped user and
  organization projections; no independent identity, connector, provider, policy, or
  billing truth" (:831-832).
- The owner-record rule verbatim: "Identity, membership, SSO/SCIM, secrets, tokens,
  connectors, providers, policies, retention, billing, usage, memory, skills, delivery,
  and learning-boundary records remain with their canonical owners. Settings persists
  only admitted preferences and owner-backed administrative mutations" (:995-999).
  "Open menus, focus, scroll, unsubmitted drafts, and other transient UI state remain
  local to the client" (:999-1000).
- Scoped slices are enumerated: User settings = personal connected apps, personal
  memory and skill preferences, delivery/contact channels, personal BYOK/BYOA defaults
  (:979-983). Organization settings = organization connectors and service accounts,
  connector allowlists and provider policies, SSO/OIDC + retention/audit/export/
  shared-memory policy, Enterprise Learning Boundary defaults + provider secondary-use
  + custody/region + capability-exit posture, workspace defaults and administrative
  enrollment (:985-991).
- Boundary vs. neighbors: Developer Console defines/validates integration
  registrations; Environments and Operations own provider runtime; "settings own
  personal or organization credential and policy defaults" (:970-974).
- Learning boundary: primarily configured in Governance and organization/project/
  system settings (:1051-1053); "a later organization-default change creates a governed
  upgrade proposal rather than silently changing the system" (:1067-1070). User choices
  are policy requests, "never toggles that override source rights or the compiled
  system boundary" (:1096-1099).
- Registration record: `HypervisorCoreWorkspaceRegistration` — `workspace_kind` enum
  includes `settings`; `registration_is_projection_only: true`,
  `writes_through_canonical_owners: true` (:3468-3478). Core workspaces register via
  the sibling record so one product-surface compiler serves nav/catalog (:1791-1794).
- May never: a core workspace is never an application registration (anti-pattern
  :4727); no client writes canonical truth outside the daemon + Agentgres admission
  path (:4541-4542); route/workspace identities unique, aliases fail closed
  (:4575-4580).
- **Canon defect (the five-vs-six count drift), for the W4 one-line PR** — five
  locations enumerate the core workspaces WITHOUT Settings: :819 ("Home, Systems,
  Projects, Applications, and Work are core workspaces"), :1793-1794 ("without
  pretending Home, Systems, Projects, Applications, or Work is an application"),
  :4545-4546 ("Home, Systems, Projects, Applications, and Work must register as core
  workspaces"), :4582-4583 ("Home, Systems, Projects, Applications, and Work derive
  from core workspace registrations"), :4803 ("Home/Systems/Projects/Applications/Work
  = core workspaces") — while :824-832 (six-entry block), :890, :994, and :3470 include
  Settings. There is also no dedicated `## Hypervisor Settings` canon section (heading
  scan: New Session :1478, Home :1545, Projects :1592, Systems :1634, Work :1675,
  Applications :1733 — no Settings sibling).
- Layering (C-1..C-4): no Settings pane serves session data; no `subject_attachments`
  bindings arise on this surface, and no named app-family session fields exist in the
  settings lane (checked: ioi-api-adapter.mjs, serve-product-ui.mjs settings paths).

## 2. Schema map

| Canon object / contract | Registry / canon anchor | Daemon route(s) today |
|---|---|---|
| HypervisorPreferenceRecord (admitted prefs: theme, density, favorite, recent, default_organization, default_project, surface_preference) | registry entry `schema://ioi/components/hypervisor/preference-record/v1` + fixtures (architecture-contract-registry.v1.json:3466-3503; hypervisor-preference-record.v1.schema.json) | GET `/v1/hypervisor/preferences` hypervisor-daemon.rs:1064; PUT `/v1/hypervisor/preferences/:id` :1068 — principal+org scoped list, CAS `expected_revision`, returns `ioi.hypervisor.mutation_receipt.v1` (lifecycle_routes.rs:6127-6223, receipt :6213) |
| Mutation receipt (`ioi.hypervisor.mutation_receipt.v1`) | registry :3426 + fixtures | emitted by preference PUT; NOT by secret/api-token creates (see §3 corrections) |
| HypervisorCoreWorkspaceRegistration | canon :3468-3478; **registry-missing** (no `core_workspace` contract id in architecture-contract-registry.v1.json — part of the known M6 six-family gap; W0.2 dependency, not a Settings route) | compiler inputs exist: `/v1/hypervisor/core-taxonomy` :1056, POST `/v1/hypervisor/product-surface-projections` :1060 |
| Principals / membership (members pane) | owner: identity plane (canon :995-996) | `/v1/hypervisor/principals` :3369 (+`/:id` :3374, `/:id/password` :3378); whoami :3352; auth policy GET/PUT :3356 |
| Per-principal capability-lease grants (connected-apps authority scope) | canon :976-983 | `/v1/hypervisor/principals/:id/lease-grants` :3383 (+revoke :3388); `/v1/hypervisor/capability-leases` :2976 |
| Secrets (user/org/project scoped, sealed) | owner: secrets plane (canon :996) | `/v1/hypervisor/secrets` :2981; value :2985; delete :2989 — value sealed in a separate never-read record (lifecycle_routes.rs:13594-13597) |
| API access tokens (inbound PATs) | owner: identity plane | `/v1/hypervisor/api-tokens` :2994; delete :2999 — plaintext returned once (lifecycle_routes.rs:13694+) |
| Metering & budget (billing + credit-usage panes) | owner: metering/economic plane (canon :996 "billing, usage") | `/v1/hypervisor/usage/consumption` :3004; `/v1/hypervisor/budget` :3008; reconcile :3012 |
| OIDC login config | owner: identity plane | `/v1/hypervisor/oidc-config` :3017 (GET+PUT, secret sealed) |
| SSO configurations | owner: identity plane | `/v1/hypervisor/sso-configurations` :3393 (+delete :3397; login flow :3401-3405) |
| SCIM provisioning | owner: identity plane | `/v1/hypervisor/scim-configurations` :3410 (+delete :3415); SCIM server `/scim/v2/*` from :3447 |
| Org invite / domain verification / custom domain | owner: identity plane | org-invite :3420 (+accept :3425); domain-verifications :3429 (+verify :3434, delete :3438); custom-domain :3442 |
| Git authentications (SCM host credentials) | owner: SCM connector plane | `/v1/hypervisor/scm-connectors` :2962 (+credential bind/revoke :2967); `/v1/hypervisor/scm-connect/github` :3069 |
| Connectors / MCP integrations (connected apps) | owner: Developer Console records (canon :961-968) | `/v1/hypervisor/connectors` :3022 (+credential :3027, delete :3032, policy :3036, invoke :3040, mcp/tools :3044, oauth discover/start/callback/device :3049-3065) |
| Memory / skill preferences (user pane) | owner: intelligence plane (canon :981, :996-997) | memory-spaces :1652; memory-entries :1657/:1662 (+lifecycle :1687); skill-entries :1667/:1672 (+lifecycle :1691) |
| Providers (runners pane projection) | owner: Environments/Operations (canon :971-973) | `/v1/hypervisor/providers` :2790; provider-accounts :2798-2814 (BYOK defaults substrate) |
| Environment classes (environments pane) | owner: substrate catalog | `/v1/hypervisor/environment-classes` :1141 |
| Org identity record (name/tier/membership header) | owner: identity plane; `ioi.hypervisor.organization-identity.v1` | **LANDED W0.6**: `GET /v1/hypervisor/organization` hypervisor-daemon.rs:3445 (handler lifecycle_routes.rs:15352) — projects ONLY what the daemon persists (org://local scope, custom domain, verified domains, principal count, SSO/SCIM/OIDC posture, invite-configured flag, auth-policy mode); `display_name` is null with the gap NAMED (no org display-name/tier record exists — nothing fabricated). W0.5's adapter-side constant identity deletes against this route |
| Org policy defaults (env quotas, archive windows, sharing/veto/agent policy — the `policies` + `agent-policies` panes) | canon :987 "connector allowlists and provider policies" | `route-missing` — **W3** (org-policy record family) |
| Preference scope+schema listing (render panes generically) | none — new enabler | `route-missing` — **W3** (extend the preferences family; registry schema evolves `preference_kind` at the same PR) |
| Delivery / contact channels | canon :982; delivery paths belong to Automations (:1032-1034) | `route-missing` — **W3** (Automations-owned family; Settings projects) |
| Enterprise Learning Boundary org defaults | canon :989-990, change = governed upgrade proposal :1067-1070 | `route-missing` — **W3** (Governance-owned record; no learning-boundary route exists in the daemon router) |
| Terms of Service record | no canonical owner names ToS records | none — adapter constant → **delete** (honest absence) |

## 3. UI seed map

Shell today: SPA Settings index at `/settings` — census: 27 controls, 1 disabled,
renders (census: tier_t1_core_workspace_shell "Settings index"). The 20 capture panes
(census key `tier_t1_settings_panes`), all served through the vendor SPA + adapter:

- **User panes (5):** `account`, `secrets`, `git-authentications`,
  `personal-access-tokens`, `integrations`.
- **Org panes (15):** `manage-organization`, `terms-of-service`, `members`,
  `organization-secrets`, `org-integrations`, `policies`, `billing`, `credit-usage`,
  `runners`, `environments`, `agent-policies`, `agent-skills`, `login`, `scim`,
  `security-oidc`.
- Bundle bytes confirm the slugs as `/settings/<slug>` route fragments and carry six
  more not in the census (`announcements`, `hooks`, `profile`, `preferences`,
  `security`, `agents`) — grep of `product-ui/owned/public/static/assets/*.js`
  (settings bundle `SegmentProvider-CXCNBY9U.js`).

Serving stack: serve layer proxies the SPA and rewrites proxied HTML/JSON through
`IDENTITY_REWRITES` (["Levi Josman"→"John Doe"], ["josmanlevi"→"johndoe"] —
serve-product-ui.mjs:6753-6761) and renames the PAT pane copy to "API access tokens"
by buffering exactly the settings bundle (`API_TOKEN_RENAMES` :6780-6793,
`SETTINGS_BUNDLE_RE` :6794). `/api/*` is intercepted by the 97-literal-endpoint
adapter (`adapter.handle` serve-product-ui.mjs:10367; plus 5 dynamic ProjectService
ops, ioi-api-adapter.mjs:707-788); unhandled RPCs proxy to the mock lane, which serves
one of 55 fixture files or a wildcard `{}` mock (server.cjs:1561-1573). The two static
fixture trees (`product-ui/public/api`, `product-ui/owned/public/api`) are
byte-identical (diff-verified) — one dies at W4.

Pane wiring classes at the bytes (adapter = ioi-api-adapter.mjs):

- **Wired (daemon-backed reads + real writes):** members (principals projection,
  :811-822 — falls back to the single-operator constant row when the daemon list is
  empty), secrets + organization-secrets (:1165-1211), git-authentications
  (:611-632, :840-856, :1212-1236), personal-access-tokens (:1249-1287), integrations
  + org-integrations (MCP-connector projection :149-174, :1073-1136), billing +
  credit-usage (budget/usage :886-925), login/SSO (:958-989), scim (:990-1023),
  security-oidc (:938-957), plus domain verification / custom domain / org invite
  (:1024-1071).
- **Partial:** account (whoami-backed with constant-identity fallback :371-381);
  runners (daemon providers projected as runners :253-256, :633-642, but phase/
  capabilities/kind are dressing constants :240-252, runner-managers list is a
  constant :665-668, runner-logs token is minted locally :670-675); environments
  (ListEnvironmentClasses daemon-backed :424-435; the pane's
  `RunnerConfigurationService/GetEnvironmentClass` is fixture-only).
- **Constant-backed (identity lies):** manage-organization (`GetOrganization`
  :389-391 + `GetAccount` :383-385 over the `IDENTITY` block :75-85; the SPA's org
  UPDATE RPC is unhandled → wildcard `{}` mock, a silent-success lie),
  terms-of-service (:392-394), policies + agent-policies (`GetOrganizationPolicies`
  :395-397 — quotas, archive windows, sharing/veto/agent policy all fabricated),
  service-accounts row inside manage-organization/members flows (:794-807).
- **Dead/empty:** agent-skills (no adapter handler; wildcard mock), the SPA
  preferences pane persists to the app-local JSON store, not the daemon (:34-35,
  :343-368).

Census ceilings (recorded 2026-07-30, still true at the bundle): the org-secrets pane
is an Enterprise upsell baked into the SPA bundle — rows never render regardless of
backend; SSO/SCIM/custom-domain/domain-verification/org-invite UI panes were deferred
as an epic pending multi-user federated login (the daemon side exists — §2).

### Corrections vs v0

- v0 said: "5 fixture-only RPCs (Project/Insights/RunnerConfiguration families)" —
  bytes show only TWO are truly fixture-only: `InsightsService/GetProjectInsightsStatus`
  (fixture body is literally `{}`) and `RunnerConfigurationService/GetEnvironmentClass`.
  The other three fixture files (`ProjectService/ListProjects`, `GetProject`,
  `ListProjectEnvironmentClasses`) are shadowed by the adapter's dynamic
  `startsWith("/api/ioi.v1.ProjectService/")` branch, which is daemon-backed
  (ioi-api-adapter.mjs:707-788 → `/v1/hypervisor/projects` hypervisor-daemon.rs:1128);
  a literal-string census misses it. Residual Project-family fallthroughs are
  `UpdateProject`/`UpdateProjectEnvironmentClasses` (deliberate, no write plane —
  adapter :786-787), which hit the wildcard `{}` mock.
- v0 said: "runners/integrations lists are local lies" — bytes show `ListRunners`
  projects daemon providers (adapter :253-256, :633-642) and
  `IntegrationService/ListIntegrations` projects daemon MCP connectors (:149-174,
  :1073-1077). The actual local constants are narrower: `ListSCMIntegrations`
  (:832-838), `ListAvailableRunnerManagers` (:665-668), `CreateRunnerLogsToken`
  (:670-675), the runner phase/capability dressing (:240-252), and
  `ListServiceAccounts` (:794-807).
- v0 said: reads "mostly daemon-backed (members/secrets/PATs/billing/SSO/SCIM/OIDC/
  service accounts)" — service accounts is NOT daemon-backed; it is one hardcoded
  system row (adapter :794-807).
- v0 said: "preferences backend is GET+PUT-by-id only" — confirmed
  (hypervisor-daemon.rs:1064, :1068) — AND the sharper fact: nothing calls it. The
  SPA's preference RPCs write an app-local JSON file (`PREF_STORE`, adapter :34-35,
  :343-368); grep finds zero UI callers of `/v1/hypervisor/preferences`. Two disjoint
  preference stores exist today; the daemon one is the keeper (registered schema,
  CAS, receipts).
- v0 said: "writes partial" — most admin writes are daemon-real (SSO/SCIM/OIDC/
  secrets/PATs/domains/invites), but secret and api-token creates return no receipt
  (lifecycle_routes.rs:13534-13599, :13694-13760), unlike preference PUT (:6213). The
  gap is receipts, not writes.
- Census corrections: `canon_owner: null`, "zero occurrences of 'Settings' in
  core-clients-surfaces.md", and `mirror_backed_rpcs_measured: 0` are all stale —
  canon now owns Settings (:831, :890, :994-1000, :3470) and the settings RPC families
  are mirror-backed per the adapter cites above.

## 4. Schema→UI binding table

Reads use the W0.3 read-projection client; every administrative mutation routes to its
owner and surfaces that owner's receipt. None of these routes carries the 403/428
wallet-lease ladder today (they are identity-plane, session-auth gated via
`hypervisor_request_identity`); if an owner route later demands a crossing, the W0.3
authority client already encodes it. No row binds session-serving data (no
`subject_attachments` sites on this surface).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| account (profile identity) | whoami :3352 | partial (constant fallback :371-381) | wired-read (honest absence when unauthenticated) |
| manage-organization: org name/tier header | org identity record — route-missing (W0.5) | constant lie :389-391, :383-385 | wired-read after W0.5 org route |
| manage-organization: org update action | no daemon write | wildcard-mock silent success | disabled-named-gap until the W0.5 route grows PUT |
| terms-of-service pane | none (no canonical ToS owner) | constant :392-394 | delete |
| members list + roles | principals :3369 | wired :811-822 | wired-read |
| members: invite / remove / password | principals :3369-3378, org-invite :3420 | wired (invite), unwired rows | wired-action-receipted |
| service-accounts rows | no daemon family | constant :794-807 | disabled-named-gap (or fold into principals if the owner grows a kind) |
| secrets + organization-secrets CRUD | secrets :2981-2989 | wired, receiptless | wired-action-receipted (add receipt to create/update/delete) |
| org-secrets pane rendering | — | dead (SPA Enterprise upsell ceiling) | wired via v2 pane shell (drop the vendor upsell branch) |
| git-authentications connect/revoke | scm-connectors :2962-2967, scm-connect :3069 | wired fail-closed :840-856, :1225-1236 | wired-action-receipted |
| API access tokens (PAT pane) | api-tokens :2994-2999 | wired, receiptless; copy renamed at serve :6780-6794 | wired-action-receipted; rename moves into owned pane code |
| integrations / org-integrations (MCP) | connectors :3022-3065 | wired read+create+DCR | wired-action-receipted; registrations remain Developer Console records, Settings projects (canon :970-974) |
| connected-apps authority scope rows | lease-grants :3383-3388, capability-leases :2976 | absent in SPA (native `/__ioi/connections` owns it today, serve :1468) | wired-read projection + revoke as wired-action-receipted |
| billing (budget, auto-fund, reconcile) | budget :3008-3012 | wired :886-925 | wired-read + reconcile wired-action-receipted |
| subscriptions row | none (self-hosted posture) | constant :926-930 | delete (replace with honest deployment-posture line from auth/policy :3356) |
| credit-usage time series | usage/consumption :3004 | wired :897-910 | wired-read |
| runners list | providers :2790 | partial (dressing constants :240-252) | wired-read with honest provider fields; drop RUNNER_* dressing |
| runner managers / runner-logs token | none | constants :665-675 | delete (single-node truth) / disabled-named-gap |
| environments (env classes) | environment-classes :1141 | partial; `GetEnvironmentClass` fixture-only | wired-read (project the daemon catalog for both RPCs) |
| policies + agent-policies panes | org-policy family — route-missing (W3) | constant :395-397 | disabled-named-gap until W3; then wired-action-receipted via owner |
| agent-skills pane | skill-entries :1667-1672 | dead (wildcard mock) | wired-read over intelligence plane; lifecycle actions wired-action-receipted (:1691) |
| memory prefs (new user pane) | memory-spaces/entries :1652-1662 | absent | wired-read + entry lifecycle wired-action-receipted (:1687) |
| delivery channels (new user pane) | Automations-owned family — route-missing (W3) | absent | disabled-named-gap until W3 |
| BYOK/BYOA defaults (new user pane) | provider-accounts :2798-2814 + connectors; default = admitted preference | absent | wired-read + default-selection via preferences PUT :1068 (receipted) |
| learning-boundary defaults (new org pane) | Governance-owned record — route-missing (W3); change = governed upgrade proposal (canon :1067-1070) | absent | disabled-named-gap until W3; then projection + proposal-on-change, never a live toggle |
| login (SSO) + scim + security-oidc panes | sso :3393-3397, scim :3410-3415, oidc-config :3017 | wired :938-1023 | wired-action-receipted |
| custom domain + domain verification + invite link | :3420-3445 | wired :1024-1071 | wired-action-receipted |
| theme/density/favorites/defaults (client prefs) | HypervisorPreferenceRecord :1064-1068 | app-local JSON store (adapter :343-368) | wired-action-receipted against the daemon preferences plane; transient UI state stays client-local (canon :999-1000) |
| announcements/hooks/profile leftovers (bundle-only fragments) | none | vendor residue | delete at cutover |

## 5. Ordered PR list

1. **W0.5** — Delete `IDENTITY_REWRITES` (serve-product-ui.mjs:6753-6761); account
   pane renders whoami truth or honest absence (drop the `IDENTITY` fallback for
   display identity).
2. **W0.5** — Small daemon org-identity read route (name/tier/created; memberships
   from principals); rewire `GetOrganization`/`GetAccount` to it; org-update becomes
   disabled-named-gap. Serial on hypervisor-daemon.rs (router hotspot).
3. **W0.5** — Fixture-only RPC disposition: `GetProjectInsightsStatus` →
   disabled-named-gap (Insights has no daemon family);
   `RunnerConfigurationService/GetEnvironmentClass` → project
   `/v1/hypervisor/environment-classes` :1141. Record the ProjectService correction
   (already daemon-backed) in the census follow-up.
4. **W0.5** — Constants to honest posture: ToS pane deleted; `ListServiceAccounts`,
   `ListSCMIntegrations`, `ListAvailableRunnerManagers`, `CreateRunnerLogsToken`,
   subscriptions row, runner phase/capability dressing → daemon truth where a route
   exists, otherwise honest absence; `GetOrganizationPolicies` renders named-gap.
5. **W1** — `/settings` v2 pane shell on the canonical route (W0.1 router): rehome the
   wired read planes (members, secrets, PATs, billing, credit-usage, SSO, SCIM, OIDC,
   git-auth, integrations, domains, invite) through the W0.3 read client; user/org
   pane sets per canon :979-991; org-secrets pane rendered by owned code (kills the
   bundle upsell ceiling).
6. **W1** — New read-first panes over existing routes: connected-apps authority scope
   (lease-grants :3383, capability-leases :2976), memory/skill prefs
   (:1652-1672), BYOK/BYOA defaults read (provider-accounts :2798).
7. **W2** — Receipts on every administrative mutation: secret/api-token/SSO/SCIM/
   OIDC/domain/invite handlers return the owner's mutation receipt
   (`ioi.hypervisor.mutation_receipt.v1`, registry :3426, pattern
   lifecycle_routes.rs:6213); UI surfaces receipt refs; unwired member-admin rows
   (create/delete/password) enabled through the authority client.
8. **W3** — Preferences plane finish: scope+schema listing route so panes render
   generically; `preference_kind` schema evolution (registry :3466-3503) for
   byok_default/delivery/pane kinds; migrate the SPA preference RPCs off `PREF_STORE`
   onto GET :1064 / PUT :1068 (CAS + receipt); delete the app-local store.
9. **W3** — Owner-family builds Settings projects (backend-first, each with its owner):
   org-policy defaults family (policies/agent-policies panes); delivery-channels
   family under Automations (canon :1032-1034); learning-boundary org-default record
   under Governance with governed-upgrade-proposal on change (canon :1067-1070).
10. **W4** — Cutover: vendor settings residue deleted (API_TOKEN_RENAMES buffer,
    settings fixtures in both static copies, wildcard-mock lane per server.cjs:1561);
    bundle-only pane fragments retired; canonical `/settings/*` panes are the only
    lane.
11. **W4** — One-line canon PR: fix the five five-count locations (:819, :1793-1794,
    :4545-4546, :4582-4583, :4803) and add the dedicated `Hypervisor Settings` section
    beside the other core-workspace sections.
