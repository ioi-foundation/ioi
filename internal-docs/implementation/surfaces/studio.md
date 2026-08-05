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
