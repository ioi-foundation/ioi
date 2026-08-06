# Hypervisor Bring-To-Life Run — multi-session starter prompt

This file IS the starter prompt. Any fresh session begins by reading this file
top to bottom, then the master guide, then the Run State ledger at the bottom
of this file, and resumes at the first unchecked item. No other context is
required or assumed. Update the ledger in every landing PR — the file is the
handoff channel between sessions.

## Mission

Bring the currently mostly-shell Hypervisor product to life: every canonical
surface operational, logic wired to UI, per canon. **This run CREATES its own
master guide first, then executes it.**

**Phase A — author the per-surface implementation briefs (first sessions).**
The guide is not one large file. It is one markdown file PER APPLICATION
SURFACE under `internal-docs/implementation/surfaces/`:

```
internal-docs/implementation/surfaces/
  studio.md · automations.md · ontology.md · data.md · governance.md ·
  provenance.md · evaluations.md · improvement.md · foundry.md ·
  packages.md · developer-workspace.md · developer-console.md ·
  environments.md · operations.md
  home.md · systems.md · projects.md · applications.md ·
  work.md (owns the Sessions view) · settings.md
  _index.md (one-page map: file list, wave assignments, shared plumbing)
```

Each surface file has the same five sections, all derived from bytes:

1. **Canon digest** — what this surface owns/must display/may never do, with
   `file:line` cites into `core-clients-surfaces.md` and owner docs.
2. **Schema map** — the canon objects and registered contracts this surface
   projects (registry entries, `_meta/schemas/*`, canon object blocks), each
   mapped to the daemon route(s) that carry it today, or marked
   `route-missing` (feeds the backend build-list).
3. **UI seed map** — what is traversable TODAY but not functional: the
   shell captures/registered surface/native readouts serving this surface,
   every pane and control cluster, classified wired / partial / dead, from
   the live tree (v0 census as starting point, bytes win).
4. **Schema→UI binding table** — the heart: each traversable UI element ↦
   the schema+route that must back it ↦ current state ↦ target state
   (wired-read | wired-action-receipted | disabled-named-gap | delete).
   Session-serving elements bind through `subject_attachments`, never named
   app fields (C-1..C-4).
5. **Ordered PR list** — smallest viable wiring steps, read-first then
   actions, with cutover/410 retirement last.

Seed input, verified at the bytes and absorbed or corrected — never trusted
blind: `internal-docs/overhaul/2026-08-05-hypervisor-full-functionality-master-guide.md`
(v0 synthesis of the 2026-08-05 three-lane audit: canon requirements,
~663-route daemon inventory, UI wiring census). Where v0 and the bytes
disagree, the bytes win and the surface file records the correction. Phase A
ends when `_index.md` and all twenty surface files are landed and the Run
State ledger below is regenerated to one row per surface file.

**Phase B — execute the briefs.** Before building each surface, the session
refreshes that surface's file against the bytes, then executes its PR list.
Each landing PR updates the surface file's binding table — the files grow
from map to record as the run proceeds.

## Ground truths (do not re-litigate; re-verify bytes when relied on)

- Target taxonomy: 12 owner applications (Studio, Automations, Ontology,
  Data, Governance, Provenance, Evaluations, Improvement, Foundry, Packages,
  Developer Workspace, Developer Console) + substrate Environments and
  Operations + 6 core workspaces (Home, Systems, Projects, Applications,
  Work, Settings) on the 23 canonical v2 routes
  (`docs/architecture/components/hypervisor/core-clients-surfaces.md:874-906`).
  Legacy app names (Approvals, Issues, Pipeline, Upgrade Assistant,
  Connections, Missions-as-app) are retired labels for tool surfaces or Work
  views.
- Sessions = `/work/sessions`, a typed Work view, never a peer application.
  Bare `/sessions` gets the typed 410 the daemon already emits; the shell
  stops advertising it.
- Settings = core workspace at `/settings`, projection-only,
  writes-through-owners. Its panes project canonical owner records.
- Strategy is REHOME, NOT REBUILD: existing wired planes (24 governed
  controls, ODK planes, goal-orchestration reads, the workbench) move into
  their canonical owners. The ported-seed-preservation invariant
  (`apps/hypervisor/ported-seed-preservation.v1.json`) and the 6-step per-app
  cutover rule (`apps/hypervisor/AGENTS.md`) are in force.
- New UI event consumption rides the M5 plane (`/v1/event-streams`,
  `/v1/subscriptions`); per-resource SSE is legacy, wrapped not extended.
- All authority-crossing actions go through the CapabilityLease client flow
  (403 wallet challenge → 428 credential → receipted lease); reads go through
  the uniform read-projection client.

## Regime — fully preauthorized, no stops

Ordinary branches off master, small PRs, `gh pr merge --auto --squash` at
open; if auto-merge is refused, leave the PR open and continue — open PRs are
never blockers. Per-PR bar: build + test + lint green; description names the
wave item and states in one paragraph what became operational. No proof
apparatus of any kind is built. Every contingency maps to a default action;
none is a stop:

| Contingency | Default action |
|---|---|
| Guide/audit claim stale at the bytes | Trust the bytes, correct the guide in the same PR, continue |
| A control's backing route doesn't exist | Disabled-with-named-gap in UI; add the route to the Wave 3 build-list in the guide; continue |
| A change would contradict accepted canon or a recorded owner ruling | Canon wins automatically; implement the remainder; note the deviation in the PR |
| Test failure you caused | Fix it |
| Test failure not attributable after ≤30 min | Record as pre-existing with evidence; continue |
| `hypervisor-daemon.rs` merge conflict (central flat router) | Backend-route PRs serialize; rebase and continue |
| Fixture/mock data encountered | Replace with daemon truth or honest absence — never fixture presented as runtime truth |
| Anything else ambiguous | Resolve with the guide + canon text, record the choice in the PR, continue |

Standing surface rules on every PR: read truth or honest absence · local UI
state stays local · existing authority only, with receipts · every other
control disabled with a named gap · serve with no test flags · one
daemon-backed lane per capability, no forked truth.

## Layering rulings already landed in canon (2026-08-05 — implement, don't re-decide)

Four schema/canon conflations between the sessions platform, the thread
orchestration primitives, and the ioi.ai products (GoalRuns, OutcomeRooms)
were FIXED in `core-clients-surfaces.md` on 2026-08-05:

- **C-1/C-2 — app-family fields out of the platform schema.**
  `HypervisorSession` no longer names `goal_run_ref`, `outcome_room_ref`,
  `room_participant_lease_ref`, `work_claim_lease_ref`, `attempt_ref` (nor
  `automation_run_ref`/`work_item_ref` as dedicated fields). The one
  mechanism is `subject_attachments[]` — owner-registered `subject_kind` +
  `subject_ref` + `attachment_role`, the same typed-subject discipline Work
  rows use; application kinds (the ioi.ai goal/room family per ADR 0022)
  register in the owning application's canon. Adding an application never
  edits the platform schema. The must-bind list matches.
- **C-3 — one execution substrate.** Thread/thread-fork/managed-session/
  launch-recipe/harness-binding records are declared one daemon-internal
  generation-in-consolidation with Session as the single platform object
  over them; product surfaces compose by read; nothing treats the thread
  plane as a second public spine. Consolidation remains the standing M5
  thread-orchestration seam obligation — not this run's job.
- **C-4 — kinds are mechanical, workloads are attachments.**
  `foundry_eval_training` is retired from `session_kind`; training/eval/
  goal/room workloads are subject attachments on ordinary kinds.

Run consequences: every session view, route, and record this run builds uses
`subject_attachments` — never a named app field; Wave 3's session
overview/lineage backend is designed against the attachment model from day
one; any daemon/UI code still carrying the old named fields gets migrated at
the PR that touches it, with the guide recording remaining sites.

## The waves (full definitions in the master guide §2–§6)

- [ ] **Wave 0 — plumbing**: W0.1 v2 route shell · W0.2 product-surface
  compiler v1 · W0.3 read client + authority client · W0.4 event client on
  the M5 plane · W0.5 identity truth (delete adapter constants,
  IDENTITY_REWRITES, 5 fixture-only RPCs) · W0.6 backend enablers
  (sessions/overview, unified approvals inbox, /v1 index, scheduler status).
  - **W0 client addenda (from 2026-08-05 audit)** — gaps in the landed W0
    clients, each closed in the wave that consumes it (the W0 checkmarks are
    not re-opened): grant-ACQUISITION journey on the authority client
    (connect/sign/resubmit; today `crossWithLease` only transports a supplied
    grant — `apps/hypervisor/surfaces/authority-client.mjs:137`) → **W2**;
    schema-version negotiation + pagination + cancellation on the read client
    (untyped JSON transport today — `apps/hypervisor/surfaces/read-client.mjs:57`)
    → **W1**; central dynamic deep-link grammar in the route shell (exact
    root lookup today — `apps/hypervisor/scripts/v2-route-shell.mjs:328`)
    → **W1** (epic C12); `/sign-in` has a shell route row
    (`v2-route-shell.mjs:129`) but no binding/cutover row anywhere → **W2**
    (identity/authority leg).
- [ ] **Wave 1 — read-first launches**: Work + Sessions views · Provenance ·
  Environments · Operations · Governance reads + inbox · Ontology · Data ·
  Automations · Foundry · Developer Workspace rehome. Exit per app: canonical
  route renders daemon truth end-to-end, honest empty/degraded states, zero
  fixture data.
- [ ] **Wave 2 — actions**: authority-crossing controls via the lease client
  across Governance, Data, Ontology, Automations, Foundry, Developer Console,
  Environments/Operations. Exit: every enabled control receipted; the rest
  disabled-with-named-gap.
- [ ] **Wave 3 — backend builds + UIs**: Packages registry family · Studio
  blueprints · Evaluations epochs/holdouts/challenges · Improvement
  agendas/campaigns · session lineage (after L-1) · anything accumulated on
  the Wave 3 build-list.
- [ ] **Wave 4 — cutover + execution loop**: Sessions execution loop (daemon
  "Cut #2") · per-app legacy `/__ioi/*` retirement with typed 410s · delete
  server.cjs mocks, fixture API lane, duplicate static copy · Settings
  completion · canon nits (5-vs-6 workspace count, Settings section).

## Session protocol

1. Read this file, the master guide, `git log master -15`, and the Run State
   ledger below.
2. Take the first unchecked item (or continue a partially-checked wave's next
   sub-item). In Phase A that means authoring the next missing surface file;
   in Phase B, refresh the target surface's file against the bytes before
   building it.
3. Execute in small auto-merging PRs. Every PR that completes a ledger item
   also updates the ledger in this file (same PR).
4. Before context runs out: land what's landable, update the ledger with a
   one-line handoff note per in-flight item, stop cleanly. Never leave the
   ledger claiming more than the bytes show.

## Session 1 landing record (2026-08-05) — queue DRAINED

All session-1 PRs are merged: #155 (charter + C-1..C-4) · #156/#157/#158/#159
(Phase A briefs) · #160 (W0.1) · #161 (W0.3) · #162 (W0.2) · #163 (W0.4) ·
#164 (this record). Nothing from session 1 is left open.

Standing mechanics for future stacked landings (repo auto-merge is DISABLED):
merge-on-green is executed by hand — wait for "Build and Test" green, then
`gh pr merge <n> --squash`. Squash merges do not advance merge bases, so a
child PR stacked on a merged parent shows an add/add conflict on this file;
the fix is mechanical: `git rebase origin/master` (git skips already-applied
parent commits; ledger-table conflicts resolve by keeping every row's tick),
`git push --force-with-lease`, fresh CI, merge.
Next unchecked items: **W0.5 identity truth**, then **W0.6 backend enablers**
(W0.6 backend-route PRs serialize on `hypervisor-daemon.rs`), then the
per-surface build rows starting with work.

## Run State ledger

Per-surface rows cover that surface's full Phase B execution (its brief's §5
PR list, W1 read-first through its cutover). Surface rows are ordered by the
guide's Wave 1 launch order, then the remainder. A session takes the first
unchecked row, refreshes its brief at the bytes, and executes.

Sibling program (independent ledger, docs-first):
`2026-08-06-seed-mesh-and-odk-wiring-run.md` deepens each brief with a seed
mesh ledger, ontology wiring, and the ODK descriptor/extension lane, and
lands the ODK canon expansion (X-0). Before taking a surface build row below,
check that run's ledger: if the surface's mesh packet is unlanded, land it
first (or in the same session) so the build executes the enriched brief.

| Item | State | Handoff note |
|---|---|---|
| Phase A: per-surface briefs at `internal-docs/implementation/surfaces/` (20 files + `_index.md`) | ☑ 2026-08-05 | landed via PRs #155–#159; briefs pin canon cites to blob 21ae389fe (C-1..C-4 canon commit) |
| C-1..C-4 canon layering fixes | ☑ 2026-08-05 | landed in core-clients-surfaces.md (#155); surviving daemon/UI named-field sites recorded in briefs, migrate at the PR that touches them |
| W0.1 v2 route shell | ☑ 2026-08-05 | all 23 canonical routes + `/work/sessions` resolve from ONE table at `apps/hypervisor/scripts/v2-route-shell.mjs:29`; bare `/sessions` answers the daemon's typed 410; the home.md §3 `/automations` hijack retired (canonical route now renders the shell page, legacy readout linked) |
| W0.2 surface compiler | ☑ 2026-08-05 | ONE client-estate projection at `apps/hypervisor/scripts/surface-compiler.mjs` (`compileProductSurfaces()`) over POST `/v1/hypervisor/product-surface-projections` feeds v2 shell nav, `/__ioi/applications`, `/__ioi/api/applications`, launcher modal + Home grid; catalogs #1/#2 deleted, #3 demoted to evidence; daemon-off = named honest degraded state. Remaining daemon-side gaps (grouping, policy filtering, system-interface join) stay on the W3 build-list (applications.md §2) |
| W0.3 read + authority clients | ☑ 2026-08-05 | `apps/hypervisor/surfaces/read-client.mjs` (readProjection/readProjections/createReadClient) + `apps/hypervisor/surfaces/authority-client.mjs` (crossWithLease/createAuthorityClient); gateway order re-verified at lifecycle_routes.rs:11899-11942 (428 credential → 403 wallet → receipted); 13-check stub-gateway contract test at `test:hypervisor-app-clients` |
| W0.4 event client (M5 plane) | ☑ 2026-08-05 | `apps/hypervisor/surfaces/event-client.mjs` — durable `/v1/subscriptions` pull with typed live/resuming/daemon_unavailable/refused states, checkpoint-token resume, and `wrapLegacySse` presenting the same consumer interface (deprecated); 12-check stub-plane test at `test:hypervisor-app-events` |
| W0.5 identity truth | ☑ 2026-08-05 | removed: adapter constant identity + `IDENTITY_REWRITES` (captured demo-identity HTML residue now deleted, not substituted), ToS/org-policy/service-account/runner-manager/runner-logs/subscription constants, runner dressing, env logs-token + mark-active lies, mock fallthrough; daemon-backed: GetAuthenticatedUser+GetAccount (whoami), GetOrganization (W0.6 `GET /v1/hypervisor/organization`), ListSCMIntegrations (scm-connectors), GetEnvironmentClass (environment-classes); typed-unavailable: GetOrganizationPolicies, GetTermsOfService, ListServiceAccounts, InsightsService, runner-managers/logs-tokens, org update + all unmatched RPCs 501; named-gap banners on 5 settings panes (85-settings-gaps.js) |
| W0.6 backend enablers | ☑ 2026-08-05 | five routes live: `GET /v1/hypervisor/sessions/overview` (C-1: `subject_attachments` introduced on session records, the 3 named-field sites migrated) · `GET /v1/hypervisor/governance/approvals-inbox` (folds 4 decision planes + 2 named decision-shaped planes) · `GET /v1` (mechanically derived route-family index) · `GET /v1/hypervisor/scheduler/status` (liveness only; schedule posture stays on `/operations`) · `GET /v1/hypervisor/organization` (honest org-identity read) |
| Sibling run: seed-mesh + ODK wiring (`2026-08-06-seed-mesh-and-odk-wiring-run.md`) | ☑ 2026-08-06 | COMPLETE. All 20 briefs now carry §6 seed mesh ledger, §7 ontology wiring, §8 ODK descriptor/extension lane; `surfaces/_index.md` is the finished guide's table of contents; ODK canon expansion landed (DomainApp envelope family, composable-application journey, descriptor-expressibility rule = non-negotiables 22-23); `implementation/odk-extension-apps.md` written; all 39 harvest captures homed. **Read the surface's §6 before its §5 — the mesh ledger says what already exists and whether it rehomes, rebinds, or dies.** That run made NO frontend changes and does not make any canonical UX functional; every surface build below remains open. **Before starting any surface build, read `internal-docs/implementation/build-acceptance-gates.md`** — eight gates binding on every build (HEAD truth-refresh, identity propagation, mutation correctness, descriptor/Studio slice, Packages lifecycle, real generated runtime, routing/cutover, and the promoted C1-C30 Definition of Done), plus what green CI does and does not certify (standard CI builds neither `ioi-node` nor the web UI). Three findings that change build sequencing: the extension lane is gated on the Packages registry (stages 5-9 have no routes); Ontology + Governance hold 16 of the estate's 24 governed controls; `POST /odk/surface-descriptors` is live with no pane calling it |
| P0: SCM truthfulness defects (epic §1) | ☐ | five repair-or-disable defects, byte-verified — `internal-docs/implementation/scm-transition-chain-epic.md` §1; lands BEFORE any surface presents the Git workflow as governed |
| work build (owns `/work/sessions`; Cut #2 is its W4 leg) | ☐ | surfaces/work.md §5 |
| provenance build | ☐ | surfaces/provenance.md §5 |
| environments build | ☐ | surfaces/environments.md §5 |
| operations build | ☐ | surfaces/operations.md §5 |
| governance build | ☐ | surfaces/governance.md §5 (reviewer_ref defects; transition-receipt read route) |
| ontology build | ☐ | surfaces/ontology.md §5 (unreceipted deletes fix early) |
| data build | ☐ | surfaces/data.md §5 |
| automations build | ☐ | surfaces/automations.md §5 (receives machinery from Studio, paired PR) |
| foundry build | ☐ | surfaces/foundry.md §5 |
| developer-workspace build | ☐ | surfaces/developer-workspace.md §5 (three lanes, not one route) |
| studio build | ☐ | surfaces/studio.md §5 |
| evaluations build | ☐ | surfaces/evaluations.md §5 (live receiptless-mutation defect fixed first) |
| improvement build | ☐ | surfaces/improvement.md §5 (approve/reject receipts gate the W2 verb rehome) |
| packages build | ☐ | surfaces/packages.md §5 (biggest backend build; around existing install-admission planner) |
| developer-console build | ☐ | surfaces/developer-console.md §5 |
| home build | ☐ | surfaces/home.md §5 |
| systems build | ☐ | surfaces/systems.md §5 |
| projects build | ☐ | surfaces/projects.md §5 |
| applications build | ☐ | surfaces/applications.md §5 |
| settings build | ☐ | surfaces/settings.md §5 |
| SCM/Agentgres epic P1 contracts | ☐ | schemas/state vocabulary/threat model/admission + reconciliation contracts (epic §3 C1-C3/C5/C8/C12); interleaves with W1 per epic §4; contracts before wiring |
| SCM/Agentgres epic P2 ingestion + owner wiring | ☐ | signed webhook ingestion + Agentgres projections; wire Projects/Console/Workspace/Automations/Work (epic §2); interleaves with W2/W3 per epic §4 |
| SCM/Agentgres epic P3 proofs + parity + acceptance | ☐ | Governance/Provenance/Operations actions + proofs · CLI/TUI parity (C13) · a11y/security/observability/E2E acceptance; interleaves with W3/W4 per epic §4 |
| Wave 4 shared cutover | ☐ | server.cjs mocks · fixture API lane · duplicate static copy · canon 5-vs-6 nit (settings.md pins the 5 locations) |
| repo-wide UX disposition ledger — rule the UNDISPOSITIONED rows | ☐ | `internal-docs/implementation/repo-ux-disposition.md`; owner-scope pass over the estate surfaces the 2026-08-05 audit left undispositioned |
