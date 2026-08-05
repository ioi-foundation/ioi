# Developer Console — implementation brief

Canonical route: `/developer-console` · Owner: Developer Console (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- Owner job: "extension surface: connector, connected-app, MCP, tool, and provider-
  integration registrations; APIs and OAuth/service registrations; function, widget,
  and extension registries; conformance; and developer-kit on-ramps (scaffolds,
  templates, generated SDKs). Environments and Operations own provider lifecycle,
  placement, health, capacity, and spend" (core-clients-surfaces.md:1392-1397).
  Nav identity: "Developer Console (connectors, MCP, APIs, OAuth clients, SDK
  on-ramps, conformance — Developer & Integrations family; UI touchpoint of the
  developer kit)" (:853-854). Route `/developer-console`, no aliases (:876-880, :903).
- "The primary product venue for the full integration estate is Developer Console"
  — connectors and connected apps; MCP servers and surface MCPs; connector/tool/
  provider-integration registrations; APIs, OAuth clients, SDKs, ADK, webhooks,
  service registrations; conformance and developer app registration; developer-kit
  on-ramps (:957-967).
- **Registrations, never runtime**: "Developer Console defines and validates
  integration/configuration registrations; it does not own provider runtime
  lifecycle, placement, health, capacity, or spend. Environments and Operations own
  those projections and actions, while settings own personal or organization
  credential and policy defaults" (:970-974).
- Records stay with their canonical owners: "Identity, membership, SSO/SCIM, secrets,
  tokens, connectors, providers, policies … remain with their canonical owners";
  Settings persists only admitted preferences + owner-backed administrative mutations
  (:994-1000); user/org settings expose only scoped slices (:976-992). The
  identity/access plane (principals, SSO/OIDC, SCIM, invites, domain verification,
  secrets, API access tokens, principal lease-grants) has its own owner doc
  (identity-access-and-metering.md:61-112).
- MCP Gateway: authority-scoped profiles; exposes selected capabilities from
  Applications/Projects/Sessions/Automations/Foundry/**Developer Console**/Provenance/
  operator plane; every tool compiles to RuntimeToolContract or surface/operator
  contract refs; fails closed on expired/revoked/quarantined bindings; "never a
  durable API key or master MCP" (:597-635).
- Tool / Function Builder is housed primarily in Automations and Developer Console;
  outputs compile into RuntimeToolContract + authority scopes + receipt obligations
  (:2210-2215). ODK is NOT an app — its "developer tooling [surfaces] through
  Developer Console and the kit itself" (:935-940).
- Contextual placements: Create/import wizard row (:301); Networks/storage/devices
  row shared with Environments/Governance (:304); Systems "Interfaces" mode (:1653);
  Build lifecycle verb (:1120-1122); learning-boundary facet — "Models and Developer
  Console expose the registered bidirectional provider/customer learning terms,
  retention, ZDR, custody, fallback, and provider-exposure configuration" (:1081-1083).
  May project automation readiness but never cannibalize Automations (:1036-1042);
  templates/snippets may appear (:1029-1034); integration primitives are not
  permanent rail items (:951-955).
- Data consumes connector bindings, never owns them (:1319-1323) — Console is the
  registration inventory Data/Sources reads from.
- Layering (C-1..C-4): nothing here serves a HypervisorSession — connector and
  gateway records are registrations + leases, not sessions; no `subject_attachments`
  rows arise and no named app-family session fields exist in these modules (checked:
  lifecycle_routes connector/gateway families carry connector/lease/receipt refs
  only).

## 2. Schema map

Registry: `RuntimeToolContract` is registered
(`schema://ioi/components/connectors-tools/runtime-tool-contract/v1`, canon home
`connectors-tools/contracts.md#runtimetoolcontract`) and `ScmPublicationEffect`
v1+v2 likewise (architecture-contract-registry.v1.json). NO registry schema exists
for connector-registration, MCP-server registration, OAuth flow records, or API
tokens (grep: `editor|mcp|oauth|token` → zero registry hits) — those planes are
daemon-declared shapes only. Extension-surface registration records DO have schemas:
`hypervisor-application-surface-registration.v1`,
`hypervisor-product-surface-projection.v1`, `hypervisor-surface-release-record.v1`,
`hypervisor-surface-installation-binding.v1`, `hypervisor-surface-serving-binding.v1`.

| Canon object / contract | Registry / canon anchor | Daemon route(s) today |
|---|---|---|
| Connector registration (generic estate: any service as use-only lease, declared tools only) | canon :962-964; registry-absent | list/register hypervisor-daemon.rs:3020-3025; delete :3031-3034; policy :3035-3038 |
| Connector credential bind/revoke (sealed; value never returned) | canon :3232-3236 posture; registry-absent | :3026-3030 |
| Connector invoke (the test/crossing lane; gateway order 428 credential → 403 wallet → receipted) | RuntimeToolContract (registry) carried in `allowed_tools`; gateway comment lifecycle_routes.rs:11899-11942 | :3039-3042 |
| Connector MCP tool discovery (grant-free discovery; tools/call leased — lifecycle_routes.rs:13273-13274) | canon "MCP servers and surface MCPs" :963 | :3043-3046 |
| OAuth-native connect (Authorization Code + PKCE, device flow, DCR discovery) | canon "OAuth clients" :853, :965 | discover :3047-3051; start :3052-3055; callback :3056-3059; device start/poll :3060-3067 |
| BYOA GitHub App (user-owned app via manifest flow) | canon "connected-app … registrations" :1393 | scm-connect/github :3068-3071; github-app manifest :3072-3075; conversion :3076-3079; installation :3080-3083 |
| SCM connector registry + credential + abandon-PR | canon :962-965 | :2960-2974 |
| SCM destination bindings / publication proposals / effects (registration + proof rows; the publish crossing itself fires from an env — Developer Workspace brief §2) | ScmPublicationEffect v2 (registry) | bindings :3092-3096; proposals :3097-3100; effects :3101-3104 |
| MCP gateway declared tool contracts + invoke | canon :597-635 | tools :2700-2703; tools/:tool invoke :2704-2707; discover status `/v1/mcp` :871 |
| Capability leases (read roster — issued authority, the "Authority Clients" view) | canon :613-619 | list :2975-2978 |
| API access tokens (inbound; hash+metadata, plaintext once) | identity-access-and-metering.md:109-112 (identity-owned; Console = developer-facing surface, Settings pane = projection) | list/create :2992-2997; delete :2998-3001 |
| Secrets (sealed org/user/project) | identity-access-and-metering.md:103-108 — identity-owned; Settings projects; Console links only | :2979-2991 |
| SSO/OIDC login config, SCIM provisioning, org-invite, domain verification, custom domain | identity-access-and-metering.md:81-93 — identity-owned, projected in Settings org panes (canon :985-991); NOT Console estate rows | oidc-config :3015-3019; sso :3392-3399; auth/oidc :3400-3407; scim config :3408-3417; scim server :3446-3469+; org-invite :3419-3427; domain-verifications :3428-3440; custom-domain :3441-3445 |
| Principal-scoped lease grants (least-privilege ring per connector/tool) | identity-access-and-metering.md:95-101 | :3381-3390 |
| Extension/surface registration reads (function/widget/extension registries' nearest existing truth) | the five surface-record schemas above; canon :1435-1441 | surface-descriptors :1634-1638 (+ ODK :1613-1618); product-surface-projections :1060-1063; domain-apps :1854-1894 |
| Conformance / developer app registration | canon :966, :1395 | **`route-missing` → W3** (grep `conformance` in daemon: zero routes) |
| Developer-kit on-ramps (scaffolds, templates, generated SDKs) | canon :966-967, :935-940 | **`route-missing` → W3** (no SDK/scaffold routes; `/v1/agent-sdk` endpoints info only, hypervisor-daemon.rs:3846-3871) |
| Webhook/service registrations (inbound) | canon :965 | **`route-missing` → W3** (automation webhooks exist under Automations ownership; no Console-side inbound-service registry) |

## 3. UI seed map

Backend-rich / UI-thin, but NOT UI-absent. What serves today (bytes):

- **T2 `/__ioi/connections` — the Connections cockpit** (census: 200, 10 controls,
  `nat-connections`): composes SIX daemon reads — connectors, scm-connectors,
  capability-leases, mcp-gateway/tools, auth/policy, SCIM ServiceProviderConfig probe
  (serve-product-ui.mjs:10105-10121). Renderer (:549-700+):
  - connector registry grouped by category with per-connector detail drawer — tool
    contracts, auth posture, scopes, issued leases; sanitized ("sealed
    credentials … never leave the daemon-side render", :553-556). **Wired read.**
  - "Authority Clients" roster from lease records (credential source × authority
    provider, active/expired/receipted/revocable) (:640-665). **Wired read.**
  - a "Developer Console" card block already exists IN THIS READOUT — API spine
    posture, MCP gateway declared tools, identity/SCIM endpoints, "every posture
    pill is a live probe" (:666-681). **Wired read.**
  - Tool Analytics facet: leased-vs-declared tool volume (:682-688). **Wired read.**
  - The Home tile for this readout is already NAMED "Developer Console" (:1468).
- **T2 `/__ioi/connections/add`** (census: 200, 4 controls): registration FORMS that
  post real daemon mutations — add MCP server → `POST /v1/hypervisor/connectors`
  (kind mcp) + auto `oauth/discover`; add API-key service → connector register +
  sealed credential bind (serve:10123-10163). **Wired action (ungoverned POST —
  no lease flow, see §4).**
- **T2 OAuth connect lane**: `/__ioi/integrations/connect/:id` launcher +
  `/__ioi/integrations/oauth/callback` driving connectors/:id/oauth/* (serve:8247-8319);
  `/__ioi/slack/setup` (:571, :614). **Wired action.**
- **T2 BYOA GitHub App flow**: `/__ioi/github-app/start` → manifest;
  `/callback` → conversion; `/installed` → installation (serve:8181-8232). **Wired
  action** — this is v0's "BYOA connect button".
- **T1 Settings panes (adapter-backed, projections of these families)**:
  PATs — `UserService/List|Create|DeletePersonalAccessTokens` → daemon api-tokens,
  plaintext surfaced once (ioi-api-adapter.mjs:1237-1283); Secrets —
  `SecretService/*` → daemon secrets (:1137-1206); Integrations panes —
  `IntegrationService/*` projects daemon MCP connectors into the vendor shape
  (:145-149, :1073-1131); `RunnerConfigurationService/ListSCMIntegrations` is a
  CONSTANT (:832-839) — local lie. Census pane set: user
  `git-authentications`/`personal-access-tokens`/`integrations`/`secrets`; org
  `org-integrations`/`scim`/`security-oidc`/`login` (tier_t1_settings_panes).
- **T4 dormant seed**: `ux-seeds/widgets` is census-assigned
  `canonical_owner: "Developer Console"`, proposed route
  `/__ioi/developer-console/widgets` (tier_t4_dormant_ux_seeds; tree at
  `apps/hypervisor/ux-seeds/widgets/`).
- Census deltas: `/developer-console` `resolves: false`; no T3 registered surface
  (14 slugs, none console-shaped). Census "SSO/SCIM/domain-verification
  deferred-as-epic" ceiling note is STALE — the daemon routes exist and serve
  (§2), only SPA panes lag.

### Corrections vs v0

- v0 said: "UI absent (only the BYOA connect button + `/__ioi/connections`)" — bytes
  show a substantially larger wired estate: the connections cockpit composes six
  daemon reads with a per-connector contract/lease drawer, an Authority Clients
  roster, live-probe Developer Console cards, and a Tool Analytics facet
  (serve:549-700, 10105-10121); PLUS working registration forms
  (`/__ioi/connections/add`, serve:10123-10163), a full OAuth connect/callback lane
  (serve:8247-8319), Slack setup, and daemon-backed Settings panes for
  PATs/secrets/MCP-integrations (adapter:1073-1283). The build is consolidation
  under the canonical route, not first-light.
- v0 listed "secrets, … SSO/SCIM/OIDC config, domain verifications" as Console
  backend families — the routes exist as cited, but their canonical OWNER is the
  identity/access plane (identity-access-and-metering.md:61-112) with Settings as
  the projection surface (core-clients-surfaces.md:985-1000). Console's owned estate
  is connector/MCP/OAuth-client/tool/extension registrations + conformance + kit
  on-ramps (:1392-1397). The console links to identity records; it must not become
  their second owner. (API tokens stay on the Console surface as the
  developer-credential touchpoint, mirroring v0's target list, with the Settings
  pane remaining the identity-owner projection.)
- v0 said "MCP gateway" as one family — bytes split it in two: the estate's MCP
  gateway (`/v1/hypervisor/mcp-gateway/tools[/:tool]` :2700-2707, canon :597-635)
  vs Foundry's model-mount MCP import/invoke (`/v1/model-mount/mcp*` :754-756),
  which is model-tooling and NOT Console estate. The census/cockpit probe uses only
  the former.
- Census-vs-bytes: census T2 lists the cockpit at 10 controls — the live renderer
  now also carries the drawer script + three probe cards (serve:618-688), so the
  census count is stale-low; verify at cutover.

## 4. Schema→UI binding table

Authority-crossing actions ride the W0.3 authority client (403 wallet challenge →
428 credential → receipted; gateway order verified at
lifecycle_routes.rs:11899-11942). Reads ride the W0.3 read client. No session-serving
elements exist on this surface (no `subject_attachments` rows).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Connector registry (grouped list + drawer: tools, posture, scopes, leases) | connectors :3020-3025 + capability-leases :2975-2978 | wired (`/__ioi/connections`) | `wired-read` at `/developer-console` |
| Register connector (MCP url / bearer service) | :3020-3025 (+ oauth/discover :3047-3051) | wired but ungoverned form POST (serve:10144-10163) | `wired-action-receipted` via authority client |
| Bind / revoke credential (sealed) | :3026-3030 | wired (add-form binds; no revoke control) | `wired-action-receipted`; revoke control added |
| Delete connector / set org policy | :3031-3038 | dead (server-only) | `wired-action-receipted` |
| Invoke-test console (declared tool, live 428/403/receipt walk) | :3039-3042 | dead (server-only) | `wired-action-receipted` — the flagship registration-validation control (canon "defines and validates" :970) |
| Connector MCP tools panel (discovered contracts) | :3043-3046 | dead | `wired-read` |
| OAuth connect / device-code walk | :3047-3067 | wired (`/__ioi/integrations/connect/:id`) | `wired-action-receipted` |
| BYOA GitHub App connect | :3068-3083 | wired (`/__ioi/github-app/*`) | `wired-action-receipted` |
| SCM connector rows + credential posture | :2960-2974 | wired read (cockpit + `/__ioi/code`) | `wired-read`; credential bind/revoke `wired-action-receipted` |
| SCM destination bindings / publication effects trail | :3092-3104 | partial (`/__ioi/code` shows publish trail) | `wired-read` (effects are proof rows; publish itself fires from Developer Workspace) |
| MCP gateway tools + try-tool | :2700-2707 | read wired (cockpit probe card); invoke dead | tools `wired-read`; invoke `wired-action-receipted` (leased, canon :608-611) |
| Authority Clients roster | leases :2975-2978 | wired | `wired-read` (lease browser deep-link → Governance, which owns authority scopes :1325-1331) |
| API tokens panel (create/reveal-once/delete) | api-tokens :2992-3001 | wired via Settings PAT pane (adapter:1237-1283) | `wired-action-receipted` on Console; Settings pane remains the identity-owner projection |
| Extension/surface registrations (read inventory) | surface-descriptors :1634-1638; product-surface-projections :1060-1063; domain-apps :1854-1894; five surface-record schemas | partial (odk/domain-app readouts elsewhere) | `wired-read` (registration browser; launch stays with Applications catalog :1435-1441) |
| Conformance panel | none (§2 W3 row) | absent | `disabled-named-gap` — placeholder naming the missing family |
| Developer-kit on-ramps (scaffold/template/SDK) | none (§2 W3 row) | absent | `disabled-named-gap` |
| Webhook/service registration | none (§2 W3 row; Automations owns automation webhooks) | absent | `disabled-named-gap` |
| Identity links block (SSO/SCIM/OIDC/domains status) | :3392-3469 etc. | wired probe pills (cockpit) | `wired-read` links out to Settings org panes — never owner-mutations here (canon :994-1000) |
| `ListSCMIntegrations` constant (adapter:832-839) | none | local lie | `delete` (W0.5: wire to :2960-2963 or honest absence) |
| Provider runtime state (health/capacity/spend) | Environments/Operations routes | not present | **stays absent by canon** (:970-974) — never build here |

## 5. Ordered PR list

1. **W1** — Register Developer Console + serve `/developer-console` read-first:
   rehome the connections cockpit composition (six reads, drawer, Authority Clients,
   probe cards, Tool Analytics) under the canonical route; Home tile repointed
   (serve:1468 already carries the name). `/__ioi/connections` keeps serving until
   cutover.
2. **W1** — Registration browser read view: surface-descriptors +
   product-surface-projections + domain-apps as the extension-registry inventory;
   SCM bindings/effects trail folded in from `/__ioi/code`'s data contract.
3. **W2** — Governed registration verbs via the authority client: register connector
   (MCP/bearer), credential bind/revoke, delete, org policy — replacing the
   ungoverned `/__ioi/connections/add` form POSTs; receipts surfaced on completion.
4. **W2** — Invoke-test console: declared-tool picker → live crossing showing the
   428 credential / 403 wallet-challenge / receipt sequence verbatim (the
   registration-validation loop, canon :970).
5. **W2** — MCP gateway panel: declared contracts + leased try-tool invoke
   (:2704-2707); OAuth + device-code + BYOA flows rehomed onto the canonical route
   (existing serve lanes reused, not rebuilt).
6. **W2** — API tokens panel on Console (create/reveal-once/delete) over
   :2992-3001; identity-links block reads SSO/SCIM/OIDC/domain status with
   links out to Settings org panes (no owner-mutations here).
7. **W3** — File the missing backend families from §2 with owner sign-off:
   conformance/developer-app registration; developer-kit on-ramp records;
   inbound webhook/service registry (scope against Automations' webhook ownership
   :1029-1034 first). UI lands in the same wave, replacing the three
   `disabled-named-gap` placeholders.
8. **W3** — Adapter honesty: delete the `ListSCMIntegrations` constant
   (adapter:832-839); IntegrationService projection reviewed so Settings
   integrations panes read Console-owned records (master-guide Settings chapter
   dependency, not owned here).
9. **W4** — Cutover per the 6-step rule: `/__ioi/connections`,
   `/__ioi/connections/add`, `/__ioi/integrations/*`, `/__ioi/github-app/*`,
   `/__ioi/slack/setup` retired with typed 410s; ux-seeds/widgets disposition
   (adopt under `/developer-console` or archive) decided in the same PR; census
   control-count refresh recorded.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Developer Console gains signed webhook registration, secret rotation,
provider permissions/events, repo selection, and delivery/reconciliation
health; it owns signed, replay-protected, idempotent webhook ingestion
(epic §3 C4). Epic P0-4 — the GitHub App manifest registers no webhook and
subscribes to no events (`lifecycle_routes.rs:16948`, `:16984`) — is this
owner's repair, wired at the epic's P2 leg.
