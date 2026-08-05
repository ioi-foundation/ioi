# Projects — implementation brief

Canonical route: `/projects` · Owner: core workspace (Projects)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted

## 1. Canon digest

- Projects are persistent build and work-context containers; a Project is NOT
  the live identity of a bounded autonomous System
  (core-clients-surfaces.md:1592-1595; identity table :3279-3281).
- Route rule: `/projects` — **"existing Project context is preserved"**
  (core-clients-surfaces.md:887); canonical routes preserve typed Project
  context, query, hash, and back-stack (core-clients-surfaces.md:910-913).
- A Project may bind repositories, files, branches, packages, assets,
  environments, adapter preferences, linked Systems, automations, GoalRuns,
  sessions, policies, secrets scopes, artifacts, receipts, and Agentgres
  domain links. Developer Workspace is the IDE-grade owner name inside or
  attached to a Project; the Project is the durable context object
  (core-clients-surfaces.md:1597-1602).
- Project-owned product state is still admitted through canonical owners:
  daemon/Core for execution semantics, wallet.network for authority/secret
  release, Agentgres for operational truth, storage backends for bytes
  (core-clients-surfaces.md:1604-1607).
- Create/import may begin with a reviewable
  `HypervisorProjectDiscoveryProposal`; candidates stay drafts until the
  operator accepts one exact proposal/candidate/override set. Detection never
  creates a Project, executes repository code, installs a dependency, or
  starts an environment (core-clients-surfaces.md:1609-1615).
- Anti-patterns: Project = editor folder with no Agentgres identity;
  Workbench = parent product; editor adapter = project truth; Project = live
  System identity (core-clients-surfaces.md:1626-1632).
- Projects as contextual surface exposes project memory, project connectors,
  environment recipes, learning-boundary build policy, policy defaults
  (core-clients-surfaces.md:1014-1017); org/project settings supply
  learning-boundary build defaults compiled by Studio
  (core-clients-surfaces.md:1067-1073).
- Project scope is orthogonal to work kind; Project work remains valid
  without a parent System (core-clients-surfaces.md:1699-1702).

## 2. Schema map

| Canon object / contract | Registry entry or canon block | Daemon route(s) today |
| --- | --- | --- |
| Project record (durable context container) | no schema in `docs/architecture/_meta/schemas/` — canon block core-clients-surfaces.md:1592-1607; daemon record shape from kernel planner (`plan_hypervisor_project_create`, lifecycle_routes.rs:6755; projection literals `PROJECT_STATE_PROJECTION_SCHEMA_VERSION` + `PROJECT_BOUNDARY_INVARIANT`, lifecycle_routes.rs:6794-6801) | GET/POST `/v1/hypervisor/projects` (hypervisor-daemon.rs:1128); GET/DELETE `/v1/hypervisor/projects/:id` (hypervisor-daemon.rs:1135) |
| Project ids are `project:<slug>` | lifecycle_routes.rs:6768-6771 (default `project:repository`), :6793 (`strip_prefix("project:")`) | DELETE takes the FULL `project:<id>` ref as `:id` (environment_routes.rs:1729-1735 removes by record key) |
| Project-first automations (an automation must hang off a Project) | orchestration_routes.rs:149-166 — `project_ref` (alias `project_id`) REQUIRED, refusal code `automation_project_ref_required` | POST `/v1/hypervisor/automations` (hypervisor-daemon.rs:1268); list scoped by `?project_ref=` (orchestration_routes.rs:250) |
| Environment classes a Project can launch into | environment-class records, `ioi.hypervisor.environment-class.v1` (environment_routes.rs:1744-1790, enablement measured honestly per read) | GET `/v1/hypervisor/environment-classes` (hypervisor-daemon.rs:1142) |
| `HypervisorProjectDiscoveryProposal` | canon block core-clients-surfaces.md:1609-1615 only — no schema, no registry entry | `route-missing` — no discovery/import proposal route exists. **W3** |
| Project update (rename, refs, policy defaults) | — | `route-missing` — no PATCH; the plane is List/Create/Get/Delete only (hypervisor-daemon.rs:1128-1140). **W3** |
| Receipts on project create/delete | standing effectful-tooling gate (canon :1156-1256 family) | route exists but the mutation is receiptless: create returns a state projection (lifecycle_routes.rs:6794-6803), delete returns `{ok, removed}` (environment_routes.rs:1729-1735). Receipt emission = small daemon build. **W3** (backend), consumed in W2 |
| Linked Systems for a Project | System projection (see systems.md brief) | GET `/v1/hypervisor/autonomous-systems/projection` (hypervisor-daemon.rs:2177) filtered client-side — no project→system link field yet; link storage is part of the W3 update plane |

`route-missing` W3 build-list: (a) `HypervisorProjectDiscoveryProposal`
family (schema + admission route + review flow); (b) project update/PATCH
plane incl. typed link refs (linked Systems, policy defaults); (c) receipt
emission on project create/delete.

## 3. UI seed map

- **T1 shell — the one canonical route that already resolves.** census:
  `canonical_target_routes` shows `/projects` `resolves: true`, and the T1
  inventory lists "Projects" at `/projects`, HTTP 200, 54 controls, 0
  disabled (census: inventory.v1.json). Bytes agree: the vendored SPA
  sidebar carries a Projects rail item (`href="/projects"`,
  apps/hypervisor/product-ui/owned/public/index.html:339) and the sessions
  sidebar has a per-Project filter (`data-testid="sessions-filter-label"`
  renders "Project", same line).
- **Adapter plane — daemon-backed, not fixture.** The 97-RPC adapter's
  ProjectService block is real daemon truth end-to-end
  (ioi-api-adapter.mjs:703-767): `ListProjects` → GET
  `/v1/hypervisor/projects` (with client-side search filter), `GetProject` →
  GET `:id` with honest 404 branch, `CreateProject` → translated camelCase →
  snake_case create body → POST, `DeleteProject` → DELETE. Daemon-down
  renders honest empty/502 — "never the mock's rows"
  (ioi-api-adapter.mjs:763-766). `ListProjectEnvironmentClasses` reads the
  daemon substrate catalog (ioi-api-adapter.mjs:768+). The daemon record
  carries the automation-ready hooks (`automation_refs` / `*_policy_ref`)
  server-side, not in the SPA projection (ioi-api-adapter.mjs:703-706).
- **Stale bytes to delete**: ~~the adapter's tail comment still claims
  "Remaining …: ProjectService (daemon needs a project-list GET)"
  (ioi-api-adapter.mjs:1292-1294) — contradicted by its own :703-767.
  Unmatched RPCs (e.g. `InsightsService`, an SPA rail item) fall through to
  the mock product-ui bundle (ioi-api-adapter.mjs:1295).~~ **DONE at W0.5
  (2026-08-05): the stale tail comment is deleted; unmatched `ioi.v1.*` RPCs
  refuse typed (501 `unimplemented`, streaming calls get the in-band error
  frame) — the fixture/wildcard-mock lane is unreachable through the RPC
  surface; `InsightsService` refuses `insights_family_route_missing`.**
- **T2**: no dedicated `/__ioi` Projects readout; project context appears
  operationally through the workbench (`/details/:env`) and the
  project-scoped automations plane.
- Classification: list/create/get/delete + env-class picker = wired;
  project-scoped sessions filter = partial (filter exists, sessions view is
  the vendor lane pending `/work/sessions`); automations-of-this-project,
  linked-Systems, memory/connector/policy panes = absent; Insights rail item
  = dead-by-fixture (mock fallthrough).

### Corrections vs v0

- v0 W0.5 says "Kill the 5 fixture-only RPCs (Project/Insights/
  RunnerConfiguration) by wiring or by disabled-named-gap" — bytes show the
  Project RPCs are ALREADY wired to the daemon with honest daemon-down
  behavior (ioi-api-adapter.mjs:703-767). What remains fixture-shaped near
  this workspace: the hand-shaped `ListSCMIntegrations` github row
  (ioi-api-adapter.mjs:832-839) and the unmatched-RPC fallthrough to the
  mock bundle (:1292-1295) that serves `InsightsService`.
- v0 §1 "Actual" counts "5 fixture-only RPCs (Project/Insights/
  RunnerConfiguration)" among the adapter's backing classes — stale for the
  Project family, per the same bytes.
- census: `/projects` is one of only 2 canonical routes that resolve — but
  the census does not record that its rows are daemon-truth; bytes show this
  workspace is the closest-to-done of the six (shell + adapter + daemon all
  live). The Projects work is context-enrichment, not bring-up.
- The daemon core taxonomy already registers the workspace
  (`hypervisor-workspace://projects`, canonical_route `/projects`,
  hypervisor_daemon_routes/hypervisor_core_taxonomy.json `core_workspaces`).

## 4. Schema→UI binding table

Session-serving elements (project-scoped sessions/work rows) bind through
`subject_attachments` (`subject_kind` + `subject_ref`) — never a named
app-family field (core-clients-surfaces.md:2683-2687, :3971-3990). No such
named-field sites were found in the Project lanes audited here.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Projects list (rows, search) | `ListProjects` → GET `/v1/hypervisor/projects` (ioi-api-adapter.mjs:714-725; hypervisor-daemon.rs:1128) | wired | `wired-read` (read client; keep) |
| Project detail page | `GetProject` → GET `:id` (ioi-api-adapter.mjs:727-732; hypervisor-daemon.rs:1135) | wired, honest 404 | `wired-read` |
| Create project flow | `CreateProject` → POST `/v1/hypervisor/projects` (ioi-api-adapter.mjs:733-755; kernel planner lifecycle_routes.rs:6751-6803) | wired (no receipt emitted) | `wired-action-receipted` once W3 receipt emission lands; until then stays wired with the gap named in-page |
| Delete project (actions dropdown) | `DeleteProject` → DELETE `:id` with full `project:<id>` ref (ioi-api-adapter.mjs:756-760; environment_routes.rs:1729-1735) | wired, honest no-op `{removed:false}` | `wired-action-receipted` (same W3 dependency) |
| Env-class picker on detail | GET `/v1/hypervisor/environment-classes` (ioi-api-adapter.mjs:768+; hypervisor-daemon.rs:1142) | wired, honestly-measured `enabled` | `wired-read` |
| Project-scoped sessions (sidebar filter + lists) | `/work/sessions` typed view filtered by Project scope; rows via `subject_attachments` | partial (vendor filter over the legacy sessions lane) | `wired-read` (lands with the Work brief's W1 views; Projects deep-links with context preserved) |
| Automations of this Project pane | GET `/v1/hypervisor/automations?project_ref=…` (orchestration_routes.rs:250; hypervisor-daemon.rs:1268) | absent | `wired-read` (W1); create-from-project prefills the REQUIRED `project_ref` (orchestration_routes.rs:149-166) |
| Linked Systems row | System read projection (hypervisor-daemon.rs:2177) | absent | `wired-read` links into `/systems/{system_id}`; durable project→system link ref is W3 (update plane) |
| Import/discovery flow (repo scan → proposal → accept) | `HypervisorProjectDiscoveryProposal` (canon :1609-1615) | absent | `disabled-named-gap` → W3 family |
| Project memory / connectors / policy-default panes | memory-spaces + connector routes exist under their owners (canon :1014-1017) | absent | `wired-read` projections (W2); writes route to owners via authority client or stay `disabled-named-gap` |
| Rename/edit project metadata | no PATCH route | absent | `disabled-named-gap` → W3 update plane |
| Insights rail item (SPA) | no daemon family | **typed refusal (W0.5)** — `InsightsService/*` answers `insights_family_route_missing`; mock fallthrough unreachable | `disabled-named-gap` — done (pane deletion decided at cutover) |

## 5. Ordered PR list

1. **W0** — `/projects` joins the v2 shell route table as the already-working
   workspace; verify typed Project context (query/hash/back-stack) survives
   the v2 router; rail entry from compiler `workspace_entries`
   (lifecycle_routes.rs:6042-6057). Smallest step of the six workspaces.
2. **W0 (W0.5 slice) — DONE 2026-08-05** — adapter hygiene: stale tail comment
   deleted; `InsightsService` refuses typed (`insights_family_route_missing`);
   `ListSCMIntegrations` decided: backed by the daemon SCM connector read
   (`/v1/hypervisor/scm-connectors`, PAT capability = the real
   `/v1/hypervisor/scm-connect/github` route), typed refusal when the daemon
   is down.
3. **W1** — Project detail context panes, read-first: automations-of-project
   (`?project_ref=`), linked-Systems (projection read, client-side link),
   env-class picker retained; honest empty states throughout.
4. **W1** — Project-scoped deep links into `/work` views once they land
   (sessions/goals rows via `subject_attachments`), replacing the vendor
   sessions filter lane; Projects itself stays a container, not a work view.
5. **W2** — Contextual panes over owner routes (project memory, connectors,
   learning-boundary build-policy defaults) read-first; any write routes
   through the authority client to the owning plane and returns that owner's
   receipt.
6. **W3** — Backend builds, one PR each (central router file serializes):
   (a) receipt emission on project create/delete; (b) PATCH
   `/v1/hypervisor/projects/:id` update plane incl. durable link refs;
   (c) `HypervisorProjectDiscoveryProposal` schema + admission route; then
   the import wizard UI in the same wave.
7. **W4** — Cutover residue: remove the mock bundle's project fixtures with
   the fixture-lane deletion; confirm `/projects` carries zero fallthrough.
