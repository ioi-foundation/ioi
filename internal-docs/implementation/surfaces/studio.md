# Studio — implementation brief

Canonical route: `/studio` · Owner: Studio (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

All canon cites are `docs/architecture/components/hypervisor/core-clients-surfaces.md` unless
prefixed. Daemon cites are `crates/node/src/bin/hypervisor-daemon.rs` (router) or a
`hypervisor_daemon_routes/*.rs` module. UI cites are `apps/hypervisor/...`. Census cites
(`census:`) are `internal-docs/audits/2026-07-30-hypervisor-surface-end-state-audit/inventory.v1.json`
(2026-07-30; spot-verified against the live tree where load-bearing).

## 1. Canon digest

- Studio is the system/agent composition surface: a typed canvas over real substrate objects —
  agents (model + harness + tools + memory + policies), the connections between them, and the
  system boundary (authority scopes, tool allow-lists via capability leases, budgets); it saves
  draft blueprints and promotes them through governed gates; it absorbs the former Agent Studio
  as its agent-level lens (core-clients-surfaces.md:1300-1306).
- Tool placement: System Designer (legacy Solution Designer) → **Studio / System Design**
  (:1415). Process Graphs (legacy Machinery) → **Automations**, not Studio (:1416) — see
  Corrections; the machinery surface leaves Studio at rehome.
- Canonical route `/studio` (:892). Application surfaces are governed projections and control
  surfaces — never separate runtime truth (:1470-1473).
- The bounded-system builder journey runs through Studio: describe → **Studio compiles one
  inspectable package/genesis proposal** → validate with typed blockers → preview
  authority/policy/cost/topology/evidence/lifecycle → simulate → propose/approve through the
  existing owner paths → instantiate one System (:2062-2074). Visual Studio, declarative files,
  ADK/SDK/CLI are editors over ONE source-neutral build representation — same compiled
  contracts, no hidden defaults, no forked truth (:2076-2082). Fast composition is a product
  acceptance contract, not permission for Studio to absorb owner state or authority
  (:2090-2094). Templates prefill but never pre-authorize effects or create live state
  (:2086-2088).
- Surface modes classified under Studio: "blueprint / generated-surface builder (Studio;
  kit-scaffolded)" and "system designer / architecture planner (Studio)" (:2104, :2113, owner
  classification :2138-2141).
- **Surface Generate** (Studio, scaffolded by the developer kit) is the product path for
  object-aware application shells, widgets, forms, dashboards, operator consoles,
  autonomous-system blueprints, and generated domain apps (:2217-2221). Builder paths are
  proposal/packaging paths over Hypervisor Core — they own no runtime, authority, semantic, or
  storage truth; effectful actions ride Operator Plane + daemon admission + authority gates +
  receipts (:2223-2226).
- Studio authors interface descriptors; the kit may scaffold them; Packages admits and versions
  them; the product-surface compiler exposes eligible installed bindings (:1435-1441). ODK
  surface descriptors surface through Studio (:935-939, esp. :939).
- `GoalRunProfile`: Studio may author and compare profile revisions; Packages
  versions/distributes; none of the surfaces becomes a second runtime owner (:2645-2652).
- Embodied Systems: Studio authors graph source; Foundry produces candidates; Governance owns
  consequential admission; daemon + Agentgres own execution (:1374-1377).
- Canvas is a visual builder/editor **inside** Studio, Automations, Developer Workspace, or
  Foundry — never a separate product plane or runtime owner (:1399-1402); Canvas owns no
  execution, authority, state truth, receipts, or workflow semantics (:2443-2445). Canon nit:
  the `HypervisorCanvasView` minimal object's `owner_surface` enum is
  `automations | developer_workspace | foundry` (:3946-3947) and :2427 also omits Studio —
  internal drift vs :1399-1401; flag with the program's canon-nit PRs, do not re-decide here.
- May never: absorb owner state/authority (:2093-2094), own runtime truth (:1470-1473), let a
  reference capture determine taxonomy (:1296-1297).

## 2. Schema map

| Canon object / contract | Canon block (cite) | Daemon route today | Wave |
| --- | --- | --- | --- |
| Draft blueprint object ("saves draft blueprints and promotes them through governed gates") | :1304-1305; :2104; no minimal-object block, no `_meta/schemas` registry entry exists (registry grep clean) | **route-missing** — deliberate: router comments say "/blueprints stays 404" twice (hypervisor-daemon.rs:1624, :1639) | **W3** — new family `studio/blueprints`: draft CRUD + layout artifact + promote-through-gates |
| Blueprint promotion gate target | promote "through the existing owner paths" :2069, :2073-2074 | governance approval-requests exist: `/v1/hypervisor/governance/approval-requests[/:id]` (hypervisor-daemon.rs:1963-1970) | W3 (promotion endpoint composes existing governance/packages paths; no new authority kind) |
| Studio intent frame (compile-a-frame projection) | builder journey :2062-2066 | `POST /v1/studio/intent-frame` (hypervisor-daemon.rs:631-634) — pure kernel projection, no persistence (lifecycle_routes.rs:1511-1529). **No UI consumer** (grep clean in apps/hypervisor/scripts) | W1 (wire into the /studio composer read path) |
| Agent estate (agent-level lens, ex-Agent Studio) | :1305-1306; simple-label config Agent/Model/Reasoning :1443-1462 | `GET /v1/agents` (:775), `GET /v1/hypervisor/agent-runner-profiles` (:1237), model-routes registry + model-mount reads (aggregated by the T2 lens, serve-product-ui.mjs:9012-9035) | W1 |
| System-composition truth (typed canvas read view) | typed canvas over real substrate objects :1301-1304 | ODK reads complete: domain-ontologies (:1353-1371), connector-mappings (:1373-1396), policy-bound-data-views (:1398-1421), ontology-projections (:1452-1479), materialized-object-sets (:1580), domain-apps (:1854-1897) | W1 |
| OntologySurfaceDescriptor (interface descriptors Studio authors) | :1435-1441; :939 | `/v1/hypervisor/odk/surface-descriptors[/:id]` (:1613-1622) + list alias `/v1/hypervisor/surface-descriptors` (:1634) | W1 read; authoring W2 (CRUD exists on the ODK plane) |
| GoalRunProfile authoring/compare lens | :2645-2652 | launch-policies family incl. clone/promote/rollback (:1775-1795) | W1 read, W2 actions |
| Session launch from Studio previews | two-phase wallet relay | `/v1/goal-orchestration/ioi-agent/launch-preview` + `/launch` (:1643, :1647; "Two-phase launch relays the wallet challenge" router comment :1640-1641) | W2 |
| Process-graph / state-machine definitions | :1416 places them under Automations | `/v1/hypervisor/state-machines*` (:1939-1953) — definitions only by design (:1935-1938) | moves with machinery → see `automations.md` |
| Diagram/node layout persistence | `layout_ref: artifact://...` on CanvasView :3951 | route-missing (part of the blueprints family) | W3 |

`route-missing` rows feed Wave 3: the single Studio backend build is the **`studio/blueprints`
family** (draft blueprint CRUD, content-addressed revisions, canvas layout artifact,
promote-through-gates composing governance approval-requests / Packages admission, receipts on
every mutation).

## 3. UI seed map

**T1 shell:** no `/studio` route — census: `/studio` `resolves: false`
(census:canonical_target_routes). The vendored SPA has no Studio page; nothing to preserve.

**T2 native readouts (wired, the real Studio seed):**
- `/__ioi/agent-studio` (serve-product-ui.mjs:9007-9040) — the "Studio" landing (h1 "Studio",
  :2849): the agent estate lens, aggregating **22 daemon reads** in one Promise.all
  (:9012-9035): agents, runner profiles, model-mount routes/providers, agentops conversations,
  run transcripts, model-routes, launch-policies, memory/skill entries, automation-affinities,
  connectors, capability-leases, memory proposals/projections, intelligence
  review-queue/outcome-mining/improvement-proposals, release-controls, cohorts, ODK
  overview + surface-descriptors. Sub-readouts `/__ioi/agent-studio/intel/{graph,memory,skills}`
  and `/__ioi/agent-studio/launch-policies` (census:tier_t2_native_readouts). Home tile
  "Studio" → `/__ioi/agent-studio` (:1456). Classification: wired (read).
- `/__ioi/studio/designer` (serve:9593-9615) — reads 6 families (ODK domain-ontologies,
  connector-mappings, policy-bound-data-views, ontology-projections, materialized-object-sets,
  domain-apps — :9595-9602); renders the vendor landing splash + a below-fold **read-only
  composition map** (Concepts/Components/Resources columns of real ODK refs, ontology switcher
  :3858, :3890). Named gaps disabled in place, footer names them (:3910). Classification:
  partial (reads wired; all authoring dead).

**T3 registered surfaces:**
- `designer` — registry entry `scripts/surface-registry.mjs:59`: owner "Studio", title
  "Solution Designer", route `/__ioi/studio/designer`, capabilities `["browse"]`,
  operational_state `browse`, interaction_parity `none`; metadata-only (no extracted
  `surfaces/designer/` module — the handler lives in the serve file). Census control census:
  **51 controls / 7 implemented** (7 daemon_read, 17 local_view_interaction, 0
  governed_receipted_action, 20 disabled_missing_authority, 3 unsupported_reference_session,
  4 reference_data_only) — the worst implemented ratio in the estate
  (census:tier_t3_registered_applications.designer). The 20 disabled controls are the vendor
  authoring canvas: New Diagram / Open Diagram / Save / Group / Add Text / diagram title /
  drag-to-reference. Census missing-authority contracts: diagram-persistence plane (the core
  gap → W3 blueprints), AIP Architect/Critic NL-planning authority, favorites plane,
  principal/view-tracking, template library (vendor reference content only).
- `machinery` — registry `surface-registry.mjs:60` says owner "Studio", but its canonical
  target is **Automations / Process Graphs** (:1416; census `canon_target_name`). It leaves
  Studio at rehome; its seed map and bindings live in `automations.md`.

**T4 / vendor:** `/__apps/designer` capture is a documented-insufficient proxy lane
(cross-origin :9225 chunk fetches; serve:3910); workshop and module-builder captures are
reference-only sibling seeds (serve:3910). Template cards / reference diagrams are verbatim
vendor content (census: reference_data_only).

**Stale labels in bytes:** the designer/machinery footers name "Owner: Agent Studio"
(serve:3910, :4761) — a pre-canon label; canon retired Agent Studio into Studio's agent lens
(:1305-1306). Gap reasons are encoded in `title=` attributes, not the machine-readable
`data-ioi-disabled-reason` convention (0 present; census:atlas_blockers).

### Corrections vs v0

- v0 said: "Studio `/studio` — inherits `designer` + `machinery` surfaces (worst ratio: 7/51
  implemented)." — bytes show: 7/51 is **designer alone** (census designer control_census);
  machinery is 17/30 and its canonical target is **Automations / Process Graphs**
  (core-clients-surfaces.md:1416; census machinery `canon_target_name`) — only the code-side
  registry says Studio (surface-registry.mjs:60). Studio inherits `designer` plus the
  `/__ioi/agent-studio` T2 estate; machinery rehomes into Automations.
- v0 said: "Backend: `state-machines`, ODK reads exist" — bytes show: state-machines is a
  definitions-only plane that explicitly defers run/step/scheduling/binding
  (hypervisor-daemon.rs:1935-1938; state_machine_routes.rs:417) and belongs to Automations per
  canon :1416. Studio's wired backend is the ODK/domain-apps read estate **plus
  `POST /v1/studio/intent-frame`** (hypervisor-daemon.rs:631-634), which v0 omits and no UI
  calls today.
- v0 said: "no blueprint/canvas persistence plane" — confirmed at the bytes, and it is a
  deliberate refusal, not an accident: router comments "/blueprints stays 404"
  (hypervisor-daemon.rs:1624, :1639). Registry has no blueprint schema (grep clean).
- Canon-internal nit found while verifying: `HypervisorCanvasView.owner_surface` enum omits
  `studio` (:3946-3947) while :1399-1401 includes Studio in Canvas's host list — file with the
  program's canon-nit lane.

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Studio landing: agent-estate list + detail (model route, runtime posture, harness adapters, recent activity) | AgentRecord et al.; `/v1/agents`, `/v1/hypervisor/agent-runner-profiles`, model-routes/model-mount reads (serve:9012-9035) | wired at `/__ioi/agent-studio` | `wired-read` at `/studio` (read-projection client; rehome, don't rebuild) |
| Intel sub-views (memory/skills/graph, launch policies) | intelligence + launch-policies routes (:1775-1795) | wired T2 sub-readouts | `wired-read` as Studio panes; launch-policy clone/promote/rollback `wired-action-receipted` via lease client (403 wallet → 428 credential → receipt refs) |
| System Design composition map (Concepts/Components/Resources columns, refChips, ontology switcher) | ODK reads (:1353-1479, :1580) + domain-apps (:1854-1897) | wired reads at `/__ioi/studio/designer` (serve:9595-9602) | `wired-read` at `/studio` System Design view |
| Composer "describe → compile frame" entry | `POST /v1/studio/intent-frame` (:631-634) | route wired, UI-orphaned | `wired-read` (projection call from the Studio composer; no authority crossing) |
| Canvas authoring: New Diagram / Open / Save / title / Group / Add Text / node add (Concept/Component/Resource) | none — W3 `studio/blueprints` (draft CRUD + `layout_ref` artifact, CanvasView :3944-3953) | disabled_missing_authority ×20 (census) | `disabled-named-gap` until W3 lands; then `wired-action-receipted` (blueprint mutations receipted) |
| Promote blueprint through gates | W3 family composing governance approval-requests (:1963-1970) / Packages admission | absent | `wired-action-receipted` after W3 (lease flow; Governance decides, Studio proposes) |
| New Session / launch from a composed agent | ioi-agent launch-preview/launch (:1643, :1647) | absent in designer; "Use in Automation →" cross-link exists (serve:2909) | `wired-action-receipted` (two-phase wallet relay already daemon-side) |
| AIP Architect / AIP Critic / "Start planning" | no daemon contract (census missing-authority) | disabled in place | `disabled-named-gap` (no route → no target implying authority) |
| Favorites pill / per-row star; Creator / Last edited by / Last viewed | no favorites/principal/view plane (census) | honest em-dashes / disabled | `disabled-named-gap` |
| Template library / Reference Diagrams / Browse all | vendor reference content (census: reference_data_only) | decorative | `delete` at cutover (never estate data) |
| Machinery table + definition detail | state-machines (:1939-1953) | wired read under `/__ioi/studio/machinery` | `delete` from Studio — rehomes to `/automations` (see automations.md; paired PR) |
| Gap-reason encoding on disabled controls | `data-ioi-disabled-reason` convention | `title=` attrs only (census) | `disabled-named-gap` made machine-readable in the W1 rehome PR |

Session-serving elements: Studio has no session views of its own; any session ref it displays
(e.g. launch results) resolves through the session's `subject_attachments`
(core-clients-surfaces.md:3971-3984), never a named app field. No surviving named-field sites
exist in Studio UI bytes (grep clean).

## 5. Ordered PR list

1. **W1** — Register `/studio` in the v2 shell; rehome the `/__ioi/agent-studio` agent-estate
   lens as the `/studio` landing over the W0.3 read client (zero fixture data; honest-empty).
2. **W1** — Rehome the designer composition map as the `/studio` System Design view; keep every
   vendor-authoring control disabled with `data-ioi-disabled-reason`; retire the "Agent Studio"
   owner label in footers.
3. **W1** — Wire the composer to `POST /v1/studio/intent-frame` (projection only) as the
   describe→compile read path.
4. **W1** — Registry hygiene: transfer the `machinery` entry's owner family to Automations
   (surface-registry.mjs:60) — paired with automations.md PR 3; Studio's registration row keeps
   `designer` only.
5. **W2** — Authority actions via the CapabilityLease client: launch-policy clone/promote/
   rollback (:1786-1795), ioi-agent launch from Studio (:1643, :1647), ODK surface-descriptor
   authoring (:1613-1622). Everything else stays disabled-named-gap.
6. **W3** — Backend: `studio/blueprints` family (draft blueprint CRUD with content-addressed
   revisions, canvas `layout_ref` artifact, promote endpoint composing governance
   approval-requests, receipts on every mutation; router PR serialized on
   hypervisor-daemon.rs). Registry schema + fixtures land with it.
7. **W3** — UI: canvas authoring (New/Open/Save/node-add/layout) binds to the blueprints
   family; promote-through-gates flow surfaces typed blockers per :2066.
8. **W4** — Cutover per the 6-step rule: typed 410 for `/__ioi/agent-studio` +
   `/__ioi/studio/designer`; delete vendor template lanes and the `/__apps/designer` proxy
   note; shell/nav rows come from the product-surface compiler only.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none** — no vault names Studio as owner. Studio has the estate's largest
seed footprint by artifact count: 2 registered T3 surfaces, 8 T2 readouts, and 8 T5
captures (4 of them the Domain-Apps pattern evidence).

### 6.1 The Agent Studio split-rehome map

`/__ioi/agent-studio` (serve `:9043`) is **the estate's largest readout by a factor
of four** — T2 census `nat-agent-studio`: **1,050 controls, 0 disabled**, against
`/__ioi/workbench`'s 266 (`developer-workspace.md` §6). It accreted panes for five
different owners. This map is the authority for where each goes; every receiving
brief must carry the mirror row, and where one already does it is cited.

| Agent Studio lane (byte site) | T2 census | Canonical owner | Disposition | Mirror row |
|---|---|---|---|---|
| `#model-routes` tab — probe / enable / disable / select-default, planner-admitted + receipted (serve `:2983-2998`, table `:2488-2519`, proxy `:9446-9449`) | part of the 1,050 | **Foundry** (Deploy pane) | **rehome → Foundry** | `foundry.md` §7 already records this as its rehome source, with the stale-probe/412 gotcha preserved |
| `improvements/propose` POST (serve `:9192`) + embedded approve / request-approval forms (`:2704-2705`) | part of the 1,050 | **Improvement** (proposals); **Governance** (the approval form) | **rehome → Improvement** · the embedded approval form **retires** here and is reached through Governance | `governance.md` §6 records the embedded forms retiring with this split |
| `intel/memory` (serve `:9288`), `intel/skills`, `intel/graph` (`:9324`) | `nat-agent-studio-intel-memory` **5**, `-intel-skills` **5**, `-intel-graph` **0** | canon places personal memory/skill preferences in **Settings** (:981); the durable memory substrate is Agent Wiki / `ioi-memory` (:1044-1047) | **rehome → Settings** (preference panes) · Foundry consumes the same records **read-only** as training-evidence eligibility, and does **not** rehome the lifecycle verbs | `foundry.md` §3 Corrections already rules the lifecycle verbs out of Foundry |
| `vault/export` (serve `:9368`), `vault/import` (`:9379`) | part of the 1,050 | export/import of institutional state is **Governance**-gated, with the boundary owned by the institutional-learning canon | **rehome → Governance** — an import re-admits institutional state and must cross admission, not a Studio form | new row; `governance.md` §6 predates this map |
| `launch-policies` POST (serve `:9439`) | `nat-agent-studio-launch-policies` **5** | launch policy governs Session creation → **Work** (`/work/new-session`) with policy authored under **Governance** | **rehome → Work** (the launch affordance) · **Governance** (the policy object) | `work.md` §6 rehomes the New Session action; the policy object is new here |
| the remaining shell, agent lens, and composer panes | the bulk of the 1,050 | **Studio** | **rehome** — this is the part that stays | — |

**The map's one hard rule:** no lane may be rehomed to two owners, and no lane may
be dropped. Six lanes in, six destinations out, and every destination brief either
already carries the mirror row (four of six) or gains it in its own packet.

### 6.2 Ledger

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `designer` — Solution Designer** — `/__ioi/studio/designer` (serve `:9629`); protected seed, class `daemon_wired`; **the registry's lowest implementation ratio** | **51 controls, 0 governed**: 7 `daemon_read` · 17 `local_view_interaction` · 20 `disabled_missing_authority` · 3 `unsupported_reference_session` · 4 `reference_data_only` | Studio composes systems and agents; **Surface Generate** is the product path for object-aware shells (:2217-2226) | see cluster rows | — |
| ↳ real ontology-entry cluster | 7 `daemon_read` (open diagram, open in Data Lineage, design selector row, **Concepts → Ontology Manager**, **Components → Ontology Manager**, **Resources → object set / surface descriptor**, cross-app links to Pipeline/Machinery/Ontology Manager/Agent Studio) | the canvas's typed nodes resolve into real ontology and descriptor objects | **rehome** — these seven are the whole reason this surface matters: a design canvas whose Concept/Component/Resource nodes **enter the real ontology plane** is Surface Generate's authoring shape in embryo | W1 |
| ↳ canvas local-view cluster | 17 `local_view_interaction` (actions menu, save-as-JSON, copy-JSON, export PNG, clear, group, add text node, pan, move nodes, info tab, graph-settings tab, edge validity/labels/animation/minimap/icons, select node, wheel-zoom, control rail, node ⋯ menu, recents tab) | local canvas state is legitimately local | **rehome** | W1 |
| ↳ **authoring + persistence cluster — absent** | 20 `disabled_missing_authority` incl. New Diagram, Save, Share links, three Import lanes (JSON / picture BETA / Data Lineage), Concept/Component/Resource **placement**, click-to-add, drag-connect, select-implementation, custom metadata, diagram description | `studio/blueprints` draft CRUD + layout artifact + promote-through-gates is **route-missing** (§2, W3) | **blocked-missing-route** — a design canvas that cannot save is the honest state of a surface with no blueprint plane; enabling Save against local storage would make Studio a second truth store | W3 |
| ↳ **AIP faculty cluster** | 5 of the 20 disabled are vendor AIP lanes: AIP Critic, Enable AIP Critic (BETA), AIP Generate (BETA), AIP Architect panel, Ask AIP Assist, Start planning (AIP Architect) | vendor faculties ship in the estate — a **standing P2 gate** | **retire-at-cutover** — counted inside the 20 above and called out separately because they must not be mistaken for named gaps awaiting an IOI contract | W4 |
| ↳ reference gallery + chrome | 4 `reference_data_only` (title/unsaved chip, Help, Documentation/Tutorials cards, **Reference Diagrams gallery**) + 3 `unsupported_reference_session` (undo, redo, favorites tab) | no fixture data may be presented as truth | **retire-at-cutover** — the Reference Diagrams gallery is example content, and examples reach users through Packages/patterns, not a built-in gallery | W4 |
| **T3 `machinery` — Process Graphs** — `/__ioi/studio/machinery` (serve `:9652`), reads `/v1/hypervisor/state-machines`; renderer `renderMachineryPort` with a named-gap footer (`:4761` — run/step/execute, scheduling, binding, simulation, versioning all named); protected seed, class `daemon_wired` | **30 controls, 0 governed**: 5 `daemon_read` · 5 `local_view_interaction` · 12 `disabled_missing_authority` · 1 `unsupported_reference_session` · 7 `reference_data_only` | **contested**: `surface-registry.mjs:60` says owner Studio; the audit census `canon_target_name` says **"Automations / Process Graphs"** (:1416) | **meshed here, ownership deferred to X-2(a)** — the ledger rows below hold regardless of who wins, because the dispositions turn on what the controls do, not on whose route they end up under | — |
| ↳ definition read cluster | 5 `daemon_read` (Files, Ontology, file/definition row select, CREATOR column, Account) | state-machine definitions are real | **rehome** (to whichever owner X-2(a) rules) | W1 |
| ↳ **graph-authoring cluster — absent** | 12 `disabled_missing_authority` incl. New graph (primary create), New-graph caret, the **process graph-authoring canvas + build/mount lanes**, Favorites pill, per-row favorite star, LAST EDITED BY / LAST VIEWED columns, notifications, AIP Assist, help, installations dropdown, example install overlay | process-graph run/step/bind is **route-missing** (`automations.md` §2, W3) | **blocked-missing-route** for the authoring canvas and create lanes · **retire-at-cutover** for the per-user favorites/columns (no principal plane) and the AIP lane | W3 · W4 |
| ↳ reference marketing | 7 `reference_data_only` (omnibar, What's New, Recent, **Training pinned example app**, Support, hero band, **Cipher example cards ×2**) + 1 `unsupported_reference_session` (template picker) | fixture data must not render as truth; Cipher is a **vendor faculty** | **retire-at-cutover** | W4 |
| ↳ local view | 5 `local_view_interaction` (Home, Applications catalog, collapse sidebar, app icon link, Recents pill) | local | **rehome** | W1 |
| **T2 `/__ioi/domain-apps`** — list (serve `:9869`), new form (`:9876`), POST create (`:9881`), runtime view (`:9851`) | T2 census: `nat-domain-apps` **2 controls**, `nat-domain-apps-new` **14 controls**, both 0 disabled | **DomainApp draft creation is Studio's** — the extension lane's authoring stage (`odk-extension-apps.md` §2 stage 4); the object plane is canon as of X-0(a) | **rehome** — and this is the run's most consequential rehome: 16 controls are the entire product surface over a **fully implemented six-rung governed mount ladder** (`domain_apps_routes.rs`, 1,217 lines). The daemon plane is complete and the UI is 16 controls | W1 |
| ↳ the mount ladder is not surfaced | the 16 controls cover draft list + create only | mount / serve / stop / unmount / kill are all implemented daemon-side | **blocked-missing-route: no — build, not mesh.** The routes exist; no pane calls them. Governance owns the approval and release control that gate mount (`governance.md` §8), so the ladder's UI is a **joint build** across Studio (draft), Governance (controls), and Operations (runtime observation) | W2 · W3 |
| **T2 `/__ioi/agent-studio`** — serve `:9043` | **1,050 controls, 0 disabled** — the estate's largest readout | five owners' panes in one surface | **rehome (split)** — see §6.1 | W1 · W4 |
| **T5 `/__apps/designer`** — capture, owner Studio, `reference_capture`, capture state `boots_graph`, grammar `editor_canvas`, high_value, **`reboundLane: "odk composition patterns + surface descriptors"`** (`harvest-seed-inventory.mjs:26`) | not in the 563; §3 records the proxy as insufficient | Surface Generate | **rebind** — the **only capture in the estate whose declared rebound lane is the ODK descriptor plane itself.** Its named in-canvas gaps (open/save/reference/load-lineage) are exactly the blueprint plane W3 builds | W3 |
| **T5 `/__apps/machinery`** — capture, `reference_capture`, capture state `boots_graph`, grammar `graph`, high_value, `reboundLane: null`, "data lanes unbound" (`:27`) | not in the 563 | process graphs | **pattern-harvest** | — |
| **T5 `/__apps/workshop`** — capture, `reference_capture`, capture state `blocked_missing_capture`, grammar `editor_canvas`, high_value, `reboundLane: null`, "application/module builder; unbound" (`:28`) | not in the 563 | the application-builder grammar Surface Generate needs | **blocked-missing-capture** — the most unfortunate block in the run: the one capture whose grammar is literally "application builder" cannot be inspected | — |
| **T5 `/__apps/module`** — capture, `reference_capture`, capture state `shell_only`, grammar `editor_canvas`, aux, `reboundLane: null` (`:29`) | not in the 563 | compute-module authoring has no canon pane | **pattern-harvest** | — |
| **T5 `/__apps/{slate,logic,contour,fusion}`** — four captures under the **retired owner name "Domain Apps"** (`:79-82`); `slate` `blocked_missing_capture` high_value, the other three `shell_only` aux; all `editor_canvas`, all `reboundLane: null` | not in the 563 | generated domain apps (`odk-extension-apps.md` §6) | **pattern-harvest** — evidence of the *interaction grammar* a generated domain app should present (an editor canvas over domain objects, not a form stack), and nothing more. **`slate` is `blocked_missing_capture` and is therefore `blocked-missing-capture`, not pattern-harvest** (corrected 2026-08-06 post-close audit: a capture that does not boot has no observable grammar to harvest). Only `logic`/`contour`/`fusion` — all `shell_only`, all aux tier — carry harvestable grammar. **"Domain Apps" is a retired owner: these rehome under Studio and are never revived as a peer application** | — |

**Census reconciliation.** Studio's two T3 surfaces carry **81 of the 563** baseline
controls: `designer` 51 (7 + 17 + 20 + 3 + 4) and `machinery` 30 (5 + 5 + 12 + 1 + 7).
Both sums exact. **Neither has a single governed-receipted control** — Studio, the
surface canon names as the authoring owner of the whole extension lane, has **zero
governed controls today**, which is the finding, not an omission.

Its T2 readouts add **1,081 controls, 0 disabled** (1,050 + 2 + 14 + 5 + 5 + 5 + 0),
outside the baseline. `/__ioi/agent-studio` alone is 1,050.

**Disposition summary.** 8 rehome (one being the six-lane split map) · 1 **rebind** ·
4 pattern-harvest · 5 retire-at-cutover · **2 blocked-missing-route** ·
**1 blocked-missing-capture** · 1 recorded as build-not-mesh (the mount ladder's UI) ·
1 deferred to X-2(a) (`machinery` ownership).

## 7. Ontology wiring

Studio's wiring is unusual: it is the **authoring** surface for the semantic plane's
*surface* objects (descriptors, domain apps) while writing none of the semantic
plane's *content* objects.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Designer — Concept nodes | `DomainOntology` object types | `/odk/domain-ontologies` (via the Ontology Manager entry) | Read (deep link) | the canvas enters the ontology plane; it does not author it |
| Designer — Component nodes | `CanonicalObjectModel` entries | same | Read (deep link) | |
| Designer — Resource nodes | `MaterializedObjectSet` **and `OntologySurfaceDescriptor`** | `/odk/materialized-object-sets`, `/odk/surface-descriptors` | Read | the one census control that names the descriptor plane from a product surface |
| **Surface descriptor authoring** | `OntologySurfaceDescriptor` (`OntologySurfaceDescriptorEnvelope`) | `POST/PATCH /v1/hypervisor/odk/surface-descriptors` (`hypervisor-daemon.rs:1621-1631`) | **Write — wired in the legacy ODK lane, absent from Studio** | **Corrected 2026-08-06 (post-close audit).** This row first said "route exists, no pane". That is false: `renderOdkDescriptorForm` (serve `:3320`) renders a create/edit form and the `/__ioi/odk/*` family dispatch (serve `:9776`) POSTs create and PATCHes edit against the daemon. The real gap is narrower and different in kind: **the form lives in the legacy ODK substrate readout, not under Studio's canonical route, and it writes the thin descriptor record** — `composition_pattern`, singular `ontology_ref`, `recipe_refs`, opaque `view_config` — **so nothing it authors can satisfy invariant 11.** The work is a rehome plus a contract widening, not a build from zero |
| **DomainApp draft creation** | `DomainApp` (`DomainAppEnvelope`, canon as of X-0(a)) | `POST /v1/hypervisor/domain-apps` (`:1867`) | **Write (draft)** | wired at `/__ioi/domain-apps` (`serve:9881`); enforces the app-shape contract (descriptor must resolve and be `composition_pattern: domain_app`) |
| Machinery — state machines | **none — not object-bound** | `/v1/hypervisor/state-machines` | Read | process graphs are platform objects |
| System Design — the six ODK families | `DomainOntology`, `CanonicalObjectModel`, `DataRecipe`, `ConnectorMapping`, `PolicyBoundDataView`, `OntologyProjection` | the ODK routes | Read | the packet table's "reads all six ODK families into System Design" is the **target**, not today's state: today only Concepts/Components/Resources deep-link |
| **Write side** | descriptors (route exists, no pane) + DomainApp drafts (wired) | — | — | Studio writes the *shapes* of surfaces, never the *content* of the semantic plane. That boundary is what keeps a builder from becoming a truth store |

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md). **Studio is the
lane's authoring surface**, so this section is the run's longest exposer ledger and
its shortest consumer one.

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Designer canvas (read side: typed nodes resolving to ontology/descriptor objects) | `graph` | **descriptor-expressible** | binds ontology, object-model, object-set, and descriptor refs — the Resource-node row proves the refs are already reachable |
| Designer canvas (authoring: place Concept/Component/Resource, connect, save) | `graph` + write | **exempt — no write semantics in the descriptor** | sixth instance of the write-semantics finding, and the most pointed: **the surface that authors descriptors cannot itself be described by one** |
| Machinery definition list | `list_detail` | **exempt — no bindable primitive** | state machines are platform objects |
| Machinery graph canvas | `graph` | **exempt — no bindable primitive** | same |
| Domain-apps list + new form | `list_detail` / `wizard` | **descriptor-expressible (list side)** · **exempt (create)** | the list binds `DomainApp` + descriptor refs; create is an admission-adjacent write |

**Two expressible panes**, and one observation that belongs in the X-4 rollup: the
descriptor-authoring surface is itself the sharpest instance of the descriptor's
missing write semantics. A kit that cannot describe its own authoring tool is
incomplete in a way that the estate's own dogfooding rule (non-negotiable 23) is
designed to surface.

### (b) This surface as primitive exposer

**Studio owns journey stages 3 and 4** — the authoring half of the extension lane.

| Journey stage (`odk-extension-apps.md` §2) | What Studio contributes | State today |
|---|---|---|
| **3 — author or scaffold the descriptor** | Surface Generate: authors `OntologySurfaceDescriptor`s over ontology, object-model, recipe, view, and projection refs | **wired in the legacy ODK lane, not under Studio, and thin** (§7, corrected). A create/edit form and POST/PATCH dispatch exist at serve `:3320`/`:9776`; they write four fields, none of them the invariant-11 binding set. Stage 3 needs a rehome and a contract widening |
| **4 — shape it as an app** | `DomainApp` drafts over a `domain_app`-pattern descriptor, with the app-shape contract enforced at create | **wired** — 16 controls at `/__ioi/domain-apps` |

Three boundaries, all canon:

- **Surface Generate is a proposal path, not a runtime.** Builder paths never own
  runtime truth, authority, semantic truth, or storage truth (:2217-2226). A
  generated surface is a descriptor plus scaffolding until Packages admits it.
- **Kit-generated surfaces pass the same registration contract** as hand-authored
  ones (:1955-1963). Studio's output gets no shortcut into the catalog.
- **Studio authors; Packages admits; the compiler exposes.** Studio holds stages 3–4
  and hands off. It never admits a package, never registers a surface, and never
  mounts a Domain App — mount is Governance-gated (`governance.md` §8).

The state of the lane, from its authoring end (**corrected 2026-08-06**): stage 4
is wired; **stage 3 is wired in the wrong place against a contract too thin to
conform**; and stages 5–9 have no daemon routes at all (`odk-extension-apps.md`
§1). Studio can create a DomainApp draft today over a descriptor authored in a
substrate readout that cannot express invariant 11, for a package plane that does
not exist. That is the extension lane's actual shape, and Studio is where it is
most visible.
