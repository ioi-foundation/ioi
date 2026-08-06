# Environments — implementation brief

Canonical route: `/environments` · Owner: substrate (`substrate_application`, substrate lane — not an owner application, not a core workspace)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- **Class**: Environments is one of exactly two substrate applications ("type 1 + 2 face"), a lane beside the twelve owner applications and distinct from the six core workspaces (`core-clients-surfaces.md:856-859`, `:1756-1765`). Registration discriminator is `substrate_application` (`core-clients-surfaces.md:1781-1786`); every durable surface uses exactly one registration class (`:4555-4560`). Canonical route `/environments`, no aliases; retired paths die with a typed refusal (`:874-905`).
- **Owns (product/control view)**: cross-session environment inventory, provider integrations/accounts/connector posture, environment classes, evidenced project-discovery proposals, development environment recipes, environment lifecycle + lifecycle observations, session access leases, services/tasks/ports/route-bindings/logs/support posture, SCM auth requirements, snapshots/backups/staged restore/archive material, cleanup obligations, cost/health/utilization/placement views, target-vs-observed state, change-plan posture, zero-to-idle and restore posture (`providers-and-environments.md:102-130`). The daemon owns lifecycle *execution* semantics (`:132-136`).
- **Does not own**: authority (wallet.network scopes), secrets, Agentgres admission, restore validity, artifact meaning, storage payload bytes, provider infrastructure, L1 settlement. Provider state is evidence; Agentgres state is truth; encrypted blobs are restore material, not restore truth (`providers-and-environments.md:138-158`).
- **Local lifecycle ownership**: "environment create/start/readiness/idle/archive/restore/delete, provider placement, ports, services, tasks, logs, restore posture" (`core-clients-surfaces.md:1184-1186`).
- **Environment-ops contract families** the surface must display/initiate: create / create_from_project / create_from_context_url; discovery propose/inspect/accept; recipe validate/admit/resolve; start/stop/mark_active; service and task start/stop; port share/revoke; route-binding propose/attach/renew/cut-over/detach/observe-drift/reconcile; SCM-auth satisfaction; snapshot/backup; archive/unarchive/restore prepare/apply/cancel/delete; stop/idle/lifetime policy; activity posture; access/log/support leases; observation timeline; failure classify → recovery-candidate preview → recovery attempt; cleanup obligation inspect/retry/quarantine/close; capacity/allocation and catch-up (`providers-and-environments.md:522-547`; object roster `:459-520`; same contracts in `core-clients-surfaces.md:3211-3253`).
- **Status object**: `HypervisorEnvironmentStatus` with component sub-phases (recipe, provisioner, workspace_content, sandbox, resource_isolation, connectivity, secrets, automations, agent_work, model_mount, harness) over the shared `pending…failed` taxonomy — sessions render real provisioning, never a timed animation (`providers-and-environments.md:564-611`). `HypervisorEnvironmentLifecycleObservation` is the append-only timeline behind that projection (`:1676-1739`).
- **Recovery is first-class**: observation → `HypervisorProviderFailureIncident` → `HypervisorEnvironmentRecoveryCandidate[]` (preview with authority/cost/expected-lost) → `HypervisorEnvironmentRecoveryAttempt` → receipts; environment recovery never implies external-effect recovery (per-WorkRun recovery classes) (`providers-and-environments.md:1741-1887`; required UX fields `:1889-1903`).
- **BYO provider plane**: four placement choices, never provider-mode plumbing (`byo-provider-plane.md:38-89`); `ProviderAccount` `pacc_*` records with sealed credential binding + preflight (`:237-260`); per-op ordering = budget discovery BEFORE provider mutation, then a real wallet capability-lease grant (403 challenge; presence-check `grant_ref` strings do not pass) (`:262-271`); every op — including refusals — mints a provider receipt (`:273-280`); snapshot/restore custody admits only daemon-recorded `sha256` state roots, restore fails closed on mismatch (`:282-289`); `EnvironmentClass.enabled` is computed honestly at read time (`:304-320`, INV-38).
- **Surface split ruling**: "Environments shows the account catalog with credential/preflight/spend posture; Operations shows provider health and the recent receipt trail — both stating customer-borne spend plainly" (`byo-provider-plane.md:322-327`). Developer Console owns integration *registrations*, never provider runtime/placement/health/capacity/spend — those belong to Environments and Operations (`core-clients-surfaces.md:970-974`, `:1392-1397`).
- **Learning boundary facet**: Environments shows actual placement, keys, custody, egress enforcement, and proof posture (`core-clients-surfaces.md:1091-1092`); Environments views share Core session/authority/receipt/replay/projection contracts (`:4618-4620`).
- **Never**: a separate provider-management product or cloud-console clone (`providers-and-environments.md:25-29`, `:97-100`); a fake generic cloud — unsupported provider ops fail closed with a named reason (`:340-345`); effectful tooling without contract refs + authority posture + receipt obligations (`core-clients-surfaces.md:4610-4612`); containers as the sole isolation boundary for untrusted agents (`providers-and-environments.md:353-378`).
- **Embodied Systems**: nothing of its registration rehomes here — its own `planned` nonlaunchable row already exists in the daemon taxonomy alongside the two substrate rows (`hypervisor_core_taxonomy.json` served at `GET /v1/hypervisor/core-taxonomy`, `hypervisor-daemon.rs:1055-1058`; canon `core-clients-surfaces.md:906`, `:921-933`).

## 2. Schema map

Registry = `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`. Daemon-minted `schema_version` strings without a registry JSON Schema are marked *(daemon-literal)*.

| Canon object / contract | Registry entry or canon block | Daemon route(s) today |
| --- | --- | --- |
| Environment record + `HypervisorEnvironmentStatus` (components) | canon block `providers-and-environments.md:574-611` *(no registry schema)* | `GET/POST /v1/hypervisor/environments` (`hypervisor-daemon.rs:1144-1148`); `GET /v1/hypervisor/environments/:id` (`:1154-1157`); `POST /v1/hypervisor/environments/:id/:action` with actions `start·stop·archive·restore·delete·inject-failure·recover` (`:1158-1161`; dispatch `environment_routes.rs:2213-2770`) |
| Environments read projection (counts + paged slim slice) | daemon-local | `GET /v1/hypervisor/environments-summary` (`hypervisor-daemon.rs:1150-1153`) |
| `HypervisorEnvironmentClass` (honest `enabled`) | `ioi.hypervisor.environment-class.v1` *(daemon-literal; doctrine `byo-provider-plane.md:304-320`)* | `GET /v1/hypervisor/environment-classes` (`hypervisor-daemon.rs:1140-1143`) |
| `HypervisorDevelopmentEnvironmentRecipe` (+resolution) | `hypervisor-development-environment-recipe(.resolution).v1.schema.json` (registry) | `GET/POST /v1/hypervisor/recipes`, `GET /v1/hypervisor/recipes/:id` (`hypervisor-daemon.rs:1222-1229`); config workflow `POST /v1/hypervisor/env-config` (open/validate/rebuild/apply_automations, `:1184-1187`) |
| Lifecycle observations + live transitions | canon `providers-and-environments.md:1676-1739` | embedded in the env record (`environment_routes.rs` `observe()`); SSE `GET /v1/hypervisor/env-events/:id` (`hypervisor-daemon.rs:1188-1192`) — legacy per-resource SSE, wrap on the M5 plane (`/v1/event-streams*`, `/v1/subscriptions*`, `hypervisor-daemon.rs:2350-2379`), do not extend |
| Environment logs | — | `GET /v1/hypervisor/environments/:id/logs` (`hypervisor-daemon.rs:2688-2691`) |
| `HypervisorEnvironmentPort` (lease-gated exposure) | canon `providers-and-environments.md:625-640` | `GET /v1/hypervisor/environments/:id/ports`, `POST …/ports/:port/expose|unexpose` (`hypervisor-daemon.rs:2928-2939`) |
| Session access lease / env-ops plane | `HypervisorSessionAccessLease` (canon `providers-and-environments.md:480`; token/policy doctrine `core-clients-surfaces.md:3360-3390`) | `POST /v1/hypervisor/environments/:id/ops-lease`, `GET /v1/hypervisor/ops-lease/:token`, `POST /supervisor/:env/supervisor.v1.EnvironmentOpsService/:method` (`hypervisor-daemon.rs:2914-2925`) |
| Snapshot / backup / restore validity | `hypervisor-environment-backup.v1.schema.json` (registry) | `GET/POST /v1/hypervisor/snapshots`, `POST /v1/hypervisor/snapshots/:id/restore`, `POST /v1/hypervisor/backups` (`hypervisor-daemon.rs:1208-1220`) |
| Stop/idle policy sweep | `HypervisorEnvironmentStopPolicy` (canon `providers-and-environments.md:474`) | `POST /v1/hypervisor/maintenance/idle-sweep` (`hypervisor-daemon.rs:1203-1206`) |
| `HypervisorProviderFailureIncident` / `RecoveryAttempt` | canon `providers-and-environments.md:1787-1879` | `GET /v1/hypervisor/incidents`, `GET /v1/hypervisor/recovery-attempts` (`hypervisor-daemon.rs:1194-1201`); recover verb via `:action` `recover` (`environment_routes.rs:2758-2760`) |
| `ProviderAccount` `pacc_*` + credential + preflight | `ioi.hypervisor.provider-account.v1` *(daemon-literal; `byo-provider-plane.md:237-251`)* | `GET/POST /v1/hypervisor/provider-accounts`, `GET/PATCH/DELETE …/:id`, `POST/DELETE …/:id/credential`, `POST …/:id/preflight` (`hypervisor-daemon.rs:2797-2816`); adapters×accounts catalog `GET /v1/hypervisor/providers` (`:2789-2792`) |
| Provider ops (wallet-gated mutations) + evidence | `ioi.hypervisor.provider-receipt.v1` / `provider-operation.v1` *(daemon-literal; `byo-provider-plane.md:273-280`)* | `POST /v1/hypervisor/provider-ops` (`hypervisor-daemon.rs:2793-2796`); `GET /v1/hypervisor/provider-materials|provider-receipts|provider-operations` (`:2817-2824`, `:2833-2836`); ladder `GET /v1/hypervisor/provider-ladder(+/resolve)` (`:2709-2716`) |
| Placement venues/policy/preview | `ioi.hypervisor.placement-venue-policy.v1` *(daemon-literal; `byo-provider-plane.md:145-157`)* | `GET /v1/hypervisor/placement/venues`, `GET|PUT …/venue-policy`, `GET …/preview`, `POST …/resolve`, `GET …/metrics` (`hypervisor-daemon.rs:2590-2610`) |
| `PlacementDecision` `pld_*` | `ioi.hypervisor.placement-decision.v1` *(daemon-literal; `placement_failover_routes.rs:227-273`)* | `GET/POST /v1/hypervisor/placement/decisions`, `GET …/:id` (`hypervisor-daemon.rs:2611-2619`) |
| Cloud candidate plane (advisory, never authority) | doctrine `byo-provider-plane.md:149-154` | `POST/GET /v1/hypervisor/cloud-candidates/intents(:id)`, `GET/POST …/candidates(+refresh)`, `GET …/candidate-sources`, `GET …/placement-advisory` (`hypervisor-daemon.rs:2649-2672`) |
| Failover plans `fpl_*` / runs `for_*` | `ioi.hypervisor.failover-plan.v1` / `failover-event.v1` *(daemon-literal; `placement_failover_routes.rs:420-462`, `:586`)* | `GET/POST /v1/hypervisor/failover/plans`, `POST …/run`, `GET …/runs(:id)`, `POST …/plans/:id/arm|disarm`, `POST …/evaluate` (`hypervisor-daemon.rs:2620-2648`) |
| Warm pools (pre-started env supply) | daemon records | `GET/POST /v1/hypervisor/warm-pools`, `POST …/:id/claim` (fail-closed on exhausted) (`hypervisor-daemon.rs:2673-2681`; `orchestration_routes.rs:2108-2181`) |
| WorkRun materialization in env workspaces | canon `core-clients-surfaces.md:4615-4617` | `GET/POST /v1/hypervisor/workruns`, `GET …/:id`, `POST …/:id/execute`, `POST /v1/hypervisor/exec` (`hypervisor-daemon.rs:1163-1181`) |
| Watch-state / PR draft / SCM publish crossing | — | `GET /v1/hypervisor/environments/:id/watch-state`, `POST …/pull-request-drafts` (`hypervisor-daemon.rs:2942-2949`); `POST /v1/hypervisor/environments/:id/scm/publish` (`:3089`) |
| `HypervisorEnvironmentRouteBinding` (external route attach/renew/cutover/detach) | `hypervisor-environment-route-binding.v1.schema.json` (registry); canon `providers-and-environments.md:642-660` | **route-missing — W3** (only unrelated `model_route_bindings_list` exists, `hypervisor-daemon.rs:2124`) |
| Service / task start-stop as ops verbs | canon `providers-and-environments.md:529-530` | **route-missing — W3** (services/tasks appear read-only inside the env status record) |
| `mark_active` lifecycle verb + activity signals | canon `providers-and-environments.md:528`, `:479` | **route-missing — W3** (adapter fabricates success today — §3) |
| Evidenced project discovery propose/inspect/accept; `create_from_context_url` | canon `providers-and-environments.md:525-526`, `:795-860` | **route-missing — W3** (no `discovery`/`context_url` handling in `environment_routes.rs`) |
| `HypervisorResourceCleanupObligation` inspect/retry/quarantine/close | `hypervisor-resource-cleanup-obligation.v1.schema.json` (registry) | partial: obligations are recorded on delete (`environment_routes.rs:2704-2712`) and surfaced in status; no standalone inspect/retry/quarantine/close routes — **W3** |
| `HypervisorScmAuthRequirement` at env scope | canon `providers-and-environments.md:485` | partial: SCM connectors + credential + abandon exist (`hypervisor-daemon.rs:2961-2974`); env-scoped requirement objects **route-missing — W3** |

## 3. UI seed map

Today's traversable estate for this surface (census 2026-07-30 used as seed; bytes win):

- **T2 native readout `/__ioi/environments`** — wired, read-first, and already most of the cockpit (`serve-product-ui.mjs:8822-8838`, render `:2128-2237`). Panes: substrate posture chips from environment-classes; placement venue cards + venue policy + spend posture (`renderPlacementVenues`, composed at `:2170`); placement decisions + failover readiness tables (`:2171-2182`); provider-accounts table (kind/target/sealed-credential/preflight/customer-borne spend) (`:2138-2157`); archive custody (per-env sealed archives × backends × state root) (`:2158-2169`); master-detail lifecycle console — paged env rows selecting into a drawer that client-fetches the real `GET /v1/hypervisor/environments/:id` record and renders component phases, ports/services/tasks, isolation/connectivity, last-8 lifecycle observations, raw record (`:2186-2235`). All reads; zero mutation forms. Census: 200, 182 controls, 0 disabled (`census: tier_t2_native_readouts.nat-environments`) — the "controls" are navigation links/chips, not authority controls.
- **T1 SPA / adapter lane** — `EnvironmentService` in the 97-RPC adapter is daemon-projected: List/Get/Classes/Create/CreateFromProject/Start/Stop/Delete/Update(desiredPhase→start|stop + port expose/unexpose)/Archive/Unarchive→`restore`/AccessToken→real ops-lease (`ioi-api-adapter.mjs:399-487`). ~~Two dishonest RPCs: `CreateEnvironmentLogsToken` returns a fabricated constant token (`ioi-api-adapter.mjs:479-480`) and `MarkEnvironmentActive` returns `{}` with no daemon effect (`:481-482`).~~ **DONE at W0.5 (2026-08-05): both refuse typed (`environment_logs_token_route_missing`, `environment_mark_active_route_missing`); the env block's daemon-down mock fallthrough is also gone — env-plane failures refuse typed (404 not_found / `environment_daemon_unavailable`), never fixture rows.** The workbench console at `/details/:env` consuming these rehomes to **Developer Workspace**, not here (master-guide lane; the split is canon `core-clients-surfaces.md:299-303`: substrate overview = Environments, live console = Developer Workspace).
- **T3 registered surfaces** — none owned by Environments; the 14-slug registry (`scripts/surface-registry.mjs:50-63`) has no environments/operations entry.
- **Shell/catalog seeds** — the native Applications catalog tile links Environments → `/__ioi/environments` (`serve-product-ui.mjs:1471`); Workbench header cross-links "Environment posture →" (`:2352`).
- **Canonical route `/environments`** — does not resolve in any client (census: `canonical_target_routes` row `{"route":"/environments","resolves":false}`; no hit for it in `apps/hypervisor/src`). The daemon taxonomy row for the compiler already exists (§1 last bullet).
- **Mock lane** — `product-ui/server.cjs` fixture `ListEnvironments` (`server.cjs:529-531`) is fixture-only; dies at Wave 4 cutover.

### Corrections vs v0

- v0 said: "env CRUD/lifecycle/logs/ports/snapshots + provider accounts/candidates/placement/failover all exist" — bytes show the lifecycle verb set is `start·stop·archive·restore·delete·inject-failure·recover` only; canon's `mark_active`, service/task start/stop, route-binding attach/renew/cutover/detach, project discovery, and `create_from_context_url` have **no daemon routes** (`environment_routes.rs:2213-2770`; no matches for `discovery`/`context_url`/`mark_active` in `hypervisor-daemon.rs`). "CRUD" also overstates: there is no env update/PATCH route.
- v0 said: "UI = env native readouts today" — bytes show `/__ioi/environments` is already a composed read-first cockpit (venues, placement decisions, failover readiness, provider accounts, archive custody, master-detail lifecycle drawer — `serve-product-ui.mjs:2128-2237`), so the W1 job is a *rehome* of an existing cockpit to `/environments`, not a build-from-readouts.
- v0/census framing implied identity truthfulness aside, env-facing adapter RPCs are daemon-projected — bytes confirm, with two exceptions to kill in W0.5-style cleanup: fabricated `CreateEnvironmentLogsToken` and no-op `MarkEnvironmentActive` (`ioi-api-adapter.mjs:479-482`).
- Census said 14 registered T3 surface directories — live tree has 6 module dirs (`apps/hypervisor/surfaces/`: approvals, missions, object-explorer, ontology-manager, pipeline, sources); all 14 registry entries persist in `scripts/surface-registry.mjs:50-63`. No impact on this surface (none are Environments-owned), recorded as census drift.

#### Addendum 2026-08-06 (mesh packet 3 — cite refresh at `ba9e2ea0a`)

§3 gave the readout handler as `serve-product-ui.mjs:8822-8838`. At the bytes,
**`:8838` is the `/__ioi/operations` handler** and `/__ioi/environments` begins at
**`:8858`**; the two adjacent handlers were conflated. The renderer cite
(`:2128-2237`) and the nine composed reads are unchanged, and the reads resolve at
`:8858-8871`:

```text
environments-summary · environment-classes · provider-accounts
placement/venues · placement/venue-policy · placement/decisions
failover/plans · storage-archives · provider-spend/reconciliation
```

Census re-read from the audit inventory: `nat-environments` = **182 controls, 0
disabled, HTTP 200**. §3's "Census: 200, 182 controls" reads the HTTP status and
the control count as one figure; they are separate.

## 4. Schema→UI binding table

Authority actions use the W0.3 authority client (403 wallet challenge → 428 credential → receipted); reads use the W0.3 read-projection client. No session-serving elements on this surface bind work subjects; any future "sessions on this environment" rollup must resolve via `subject_attachments[]` reads, never named app-family fields (`core-clients-surfaces.md:3971-3990`).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Substrate posture chips (classes, honest enabled/disabled + reason) | environment-classes (`hypervisor-daemon.rs:1140`) | wired (readout) | `wired-read` at `/environments` |
| Environment inventory table (paged, phase/readiness/class/counts) | environments-summary (`:1150`) | wired (readout) | `wired-read` |
| Lifecycle detail drawer (component phases, observations, isolation/connectivity, raw record) | env record `GET /environments/:id` (`:1154`) | wired (readout drawer) | `wired-read` |
| Live status stream on detail | `env-events/:id` SSE (`:1188`) | not consumed by readout | `wired-read`, wrapped through the M5 event client (W0.4) — wrap, don't extend legacy SSE |
| Start / Stop / Archive / Restore / Delete verbs | `POST /environments/:id/:action` (`:1158`) | adapter-only (SPA compose flow); absent from readout | `wired-action-receipted` — NOTE: these handlers cross no wallet gate today (`environment_routes.rs:2213-2770` has no lease admission); route through the authority client only after the daemon adds admission, else ship as plain daemon actions with the gap named in-surface |
| Recover flow (incident → candidate preview → attempt) | incidents/recovery-attempts reads (`:1194-1201`) + `:action recover` | reads unrendered here (Operations readout shows incidents); recover unexposed | `wired-read` for incident/candidate panes; recover = `wired-action-receipted` behind candidate preview naming authority + expected-lost (`providers-and-environments.md:1819-1843`) |
| Ports pane (observe, expose behind lease, unexpose) | ports routes (`:2928-2939`) | wired in workbench lane, not in readout | `wired-action-receipted` (expose/unexpose are lease-crossing) |
| Snapshot / backup / restore controls | snapshots/backups (`:1208-1220`) | daemon-only (verifier-driven) | `wired-action-receipted`; restore must display state-root validation refusal states |
| Idle-sweep / stop-policy control | `maintenance/idle-sweep` (`:1203`) | daemon-only | `wired-action-receipted` (org-scoped op) |
| Provider accounts pane (list, detail, credential bind/revoke, preflight) | provider-accounts family (`:2797-2816`) | list wired (readout, read-only) | reads `wired-read`; create/patch/delete/credential/preflight = `wired-action-receipted` via authority client (credential bind is the sealed-vault crossing, `byo-provider-plane.md:252-260`) |
| Provider lifecycle ops (create/start/stop/snapshot/restore/recover/teardown per account) | `provider-ops` (`:2793`) | daemon-only (verifier-driven) | `wired-action-receipted` — budget-before-mutation + wallet grant already enforced daemon-side (`byo-provider-plane.md:262-271`); UI renders 409 `budget_blocked` and 403 challenge honestly |
| Placement venue picker + venue policy | venues/venue-policy (`:2599-2606`) | wired read (readout) | reads `wired-read`; `PUT venue-policy` = `wired-action-receipted` |
| Placement preview (pre-launch, `receipts_expected`) | `placement/preview` (`:2607`) | unrendered | `wired-read` |
| Placement decisions table (selected + alternatives + rejected, no fee minted) | decisions `pld_*` (`:2611-2619`) | wired read (readout) | `wired-read`; `POST decisions` = `wired-action-receipted` |
| Cloud-candidate advisory pane (intents, candidates, refresh, sources) | cloud-candidates (`:2649-2672`) | unrendered in readout | `wired-read` + refresh/intent-create as `wired-action-receipted` (advisory only — never authority, `byo-provider-plane.md:149-154`) |
| Failover readiness pane (plans, arm/disarm, evaluate, runs) | failover family (`:2620-2648`) | plans/readiness wired read (readout); runs rendered on Operations | reads `wired-read`; arm/disarm/run = `wired-action-receipted` (runs park at `awaiting_authority_*` gates — resumable, `serve-product-ui.mjs:1812`) |
| Warm-pool pane (pools, claim) | warm-pools (`:2673-2681`) | unrendered | `wired-read`; claim = `wired-action-receipted` |
| Archive custody pane (per-env sealed archives, backends, state roots) | storage-archives read (`:2866-2869`) | wired read (readout) | `wired-read` (custody *health* stays on Operations per the split ruling) |
| External route bindings (attach/renew/cutover/detach) | registry schema only | absent | `disabled-named-gap` → W3 row in §2 |
| Service/task start-stop controls | canon only | absent | `disabled-named-gap` → W3 |
| Mark-active / activity signal | canon only; no daemon route | **typed refusal (W0.5)** `environment_mark_active_route_missing` — fabricated success deleted | `disabled-named-gap` until W3 route — done for the adapter leg |
| Project discovery / create-from-context-URL wizard | canon only | absent | `disabled-named-gap` → W3 |
| Logs-token RPC (`CreateEnvironmentLogsToken`) | no daemon logs-token route | **typed refusal (W0.5)** `environment_logs_token_route_missing` — fabricated constant deleted | done (re-back with ops-lease if the logs plane grows a token route) |
| Mock `ListEnvironments` fixture (`server.cjs:529`) | fixture | fixture-only | `delete` at W4 cutover |

## 5. Ordered PR list

1. **W0** — v2 shell route `/environments` renders the rehomed readout body (shell route table entry; legacy `/__ioi/environments` keeps serving until cutover). Depends on W0.1 only.
2. **W1** — Rehome the composed cockpit reads through the W0.3 read client: summary, classes, provider accounts, venues+policy, decisions, failover plans, archives (the nine reads `serve-product-ui.mjs:8824-8833` already compose). Honest per-plane unavailability kept.
3. **W1** — Add the unrendered read panes: placement preview, cloud-candidate advisory, warm pools, incidents/recovery-attempts, provider receipts trail (deep-link to Operations for health per the split ruling).
4. **W1** — Detail drawer: consume `env-events/:id` through the M5 event-client wrapper (W0.4) for live phase/observation updates.
5. **W0.5-class cleanup — DONE 2026-08-05** — the two adapter lies are deleted (`CreateEnvironmentLogsToken` constant, `MarkEnvironmentActive` no-op → typed refusals); env-plane daemon failures refuse typed instead of proxying to the fixture lane.
6. **W2** — Env lifecycle verbs (start/stop/archive/restore/delete) + recover-behind-candidate-preview from the surface; port expose/unexpose via lease flow.
7. **W2** — Provider-account actions: create/patch/delete, credential bind/revoke, preflight; then provider-ops verbs with 403/409/428 states rendered as canon requires.
8. **W2** — Placement/failover actions: venue-policy PUT, decision create, plan create/arm/disarm/run, warm-pool claim.
9. **W3** — Backend builds + UI in same wave: route-binding family; service/task start-stop; `mark_active` + activity signals; project discovery + `create_from_context_url`; cleanup-obligation verbs; env-scoped SCM-auth requirement objects (§2 route-missing rows).
10. **W4** — Cutover: `/__ioi/environments` retired with typed 410 per the 6-step rule; delete `server.cjs` environment fixtures; catalog tile (`serve-product-ui.mjs:1471`) repointed by the compiler projection.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 3 (registered surfaces): none.** The 14-slug registry has no Environments
entry (`scripts/surface-registry.mjs:54-67`), so Environments contributes **0 of
the 563 baseline controls**. **Tier 4: none** — no vault names Environments as
owner. Both are honest absences: this surface was built native, not harvested.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T2 substrate cockpit** — `/__ioi/environments` (serve `:8858`, renderer `:2128-2237`) | T2 census `nat-environments`: **182 controls, 0 disabled**, HTTP 200. Nine composed daemon reads; **zero mutation forms** | substrate overview is Environments; the live console is Developer Workspace (:299-303) | **rehome** — the W1 job is moving an existing cockpit to `/environments`, not building one from readouts | W1 |
| ↳ posture + classes pane | part of the 182; env-class chips | env classes read-only | **rehome** | W1 |
| ↳ placement venues + venue policy + spend posture (`renderPlacementVenues`, composed `:2170`) | part of the 182 | placement/venue canon per §1 | **rehome** | W1 |
| ↳ placement decisions + failover readiness (`:2171-2182`) | part of the 182 | same | **rehome** | W1 |
| ↳ provider accounts (kind/target/sealed-credential/preflight/customer-borne spend) (`:2138-2157`) | part of the 182 | sealed-credential posture stays read-only until the lease client lands | **rehome** | W1 · W2 (actions) |
| ↳ archive custody (per-env sealed archives × backends × state root) (`:2158-2169`) | part of the 182 | custody **health** stays with Operations per the split ruling (§4) | **rehome** (custody rows) — the health rollup is Operations' | W1 |
| ↳ master–detail lifecycle drawer (paged env rows → client-fetched `GET /v1/hypervisor/environments/:id`; component phases, ports/services/tasks, isolation/connectivity, last-8 observations, raw record) (`:2186-2235`) | part of the 182 | lifecycle console over honest daemon records | **rehome** — live phase/observation updates move onto the W0.4 event client | W1 |
| **T1 adapter lane** — `EnvironmentService` in the 97-RPC adapter (`ioi-api-adapter.mjs:399-487`) | not census controls | daemon-projected RPCs only | **rehome** (the daemon-projected verbs) · the two former lies are **already retired at W0.5**: `CreateEnvironmentLogsToken` and `MarkEnvironmentActive` now refuse typed, and the daemon-down mock fallthrough is gone | done · W2 |
| **T5 `/__apps/map`** — harvest capture, owner Environments (`harvest-seed-inventory.mjs:76`), class `reference_capture`, capture state **`blocked_missing_capture`**, grammar `editor_canvas`, tier aux, `reboundLane: null`, note "geospatial map canvas; unbound" | not in the 563 (captures are not registered surfaces) | **no canon pane.** Environments' canon panes are posture, venues, decisions, failover, accounts, custody, and the lifecycle console — none is geospatial | **blocked-missing-capture** — and even if the capture booted, there is no canon end state to mesh it against. Recorded twice over: no inspectable capture, no canonical home | — |
| **Catalog tile** — Applications catalog links Environments → `/__ioi/environments` (serve `:1471`); Workbench header cross-link "Environment posture →" (`:2352`) | not census controls | canonical route `/environments` (census: `resolves: false` today) | **retire-at-cutover** — the tile is repointed by the compiler projection, not hand-edited | W4 |
| **Mock lane** — `product-ui/server.cjs:529-531` fixture `ListEnvironments` | fixture | no fixture data may reach a surface | **retire-at-cutover** — deleted at W4; already unreachable from the env plane since W0.5 removed the fallthrough | W4 |

**Census reconciliation.** Environments holds **0 of the 563** T3 baseline controls
(no registered surface). Its single T2 readout carries **182 controls, 0 disabled**,
outside that baseline. The zero-disabled count is not a claim of completeness: the
readout has no mutation forms at all, so there is nothing to disable — the missing
authority controls are absent, not disabled, and §4 already names each one.

**Disposition summary.** 8 rehome · 0 rebind · 0 pattern-harvest ·
2 retire-at-cutover · **1 blocked-missing-capture** (`/__apps/map`).

## 7. Ontology wiring

**None — not object-bound, across the whole surface.**

Environments is substrate: its objects are environments, classes, provider
accounts, venues, placement decisions, failover plans, and archives. None is a
`CanonicalObjectModel` instance, none is admitted through an ontology, and none
appears in the semantic plane. The nine reads the cockpit composes are all
platform-substrate routes (`/v1/hypervisor/environments-summary`,
`…/environment-classes`, `…/provider-accounts`, `…/placement/*`,
`…/failover/plans`, `…/storage-archives`, `…/provider-spend/reconciliation`) — not
one `/v1/hypervisor/odk/*` route.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Every pane | **none — not object-bound** | nine substrate reads (`serve:8858-8871`) | Read | substrate objects, not semantic-plane objects |
| **Write side — whole surface** | **none** | — | — | today there are no mutation forms at all; when W2 adds lifecycle verbs they cross the CapabilityLease client into daemon admission, never a semantic write |

The adjacency worth recording so a later packet does not invent a binding: an
environment can *host* work that reads ontology objects, and a `DataRecipe` run
executes *somewhere*. Neither makes the environment ontology-bound. The link runs
the other way — a `TransformationRun` names its environment; the environment names
no ontology.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Substrate posture + classes | `monitoring_console` | **exempt — no bindable primitive** | shape matches; substrate objects are not ontology-bound (§7), so invariant 11's required fields have nothing to name |
| Placement venues / decisions / failover readiness | `dashboard` | **exempt — no bindable primitive** | same |
| Provider accounts table | `list_detail` | **exempt — no bindable primitive** | same; the sealed-credential column is also authority-crossing chrome |
| Archive custody table | `list_detail` | **exempt — no bindable primitive** | same |
| Master–detail lifecycle drawer | `object_view` | **exempt — no bindable primitive** | same; "object" here is a platform environment record |

Zero panes descriptor-expressible, zero descriptor-rendered. This is the
**platform-object blocking finding** from `work.md` §8 recurring exactly as
predicted — third surface, same cause. Substrate surfaces will all land here; the
finding is filed once (X-2) and referenced, not re-filed per surface.

### (b) This surface as primitive exposer

**n/a.** Environments owns no stage of the composable-application journey
(`odk-extension-apps.md` §2), exposes no ODK primitive, and holds no descriptor.

One boundary, because it is the plausible mistake: a generated domain app runs
somewhere, and the Domain App mount ladder's `mount` rung is admission-gated —
but **mounting is not provisioning**. The ladder explicitly starts no process and
creates no ingress (`domain_apps_routes.rs:489-491`), so it never reaches this
surface. Environments neither admits nor hosts any rung of the extension lane.
