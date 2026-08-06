# Provenance — implementation brief

Canonical route: `/provenance` · Owner: Provenance (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 2 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended; §3 tier labels and
lineage/vertex cites corrected (2026-08-06 addendum under Corrections). Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Provenance is the proof plane: chronological receipt stream, lineage graph
  of runs/artifacts/authority where every edge is a receipt, state roots,
  replay entries, custody receipts; exposes editable domain object →
  immutable source snapshot → derived export including the exact
  tool/workflow revision, transformation run, and receipt per derived edge;
  evolves the former Work Ledger card (core-clients-surfaces.md:1333-1339;
  rail summary :842). Agentgres is the Provenance work-ledger substrate
  (:366). Canonical route `/provenance` (:897).
- Lifecycle "Observe" verb: receipts, replay, traces, logs, lineage, state
  roots (core-clients-surfaces.md:1133-1134). Provenance inspects evidence
  and owns transition trace, receipt, proof, settlement, and replay
  inspection; the dependency/provenance/impact graph is shared with Ontology
  (:1238-1239, :1235-1236, :1254).
- Receipts/replay must answer: what happened, why, under whose authority,
  against which policy, with which artifacts, whether it can be replayed,
  challenged, improved, packaged, or settled
  (core-clients-surfaces.md:2737-2749); surfaces expose the improvement loop
  without owning runtime truth (:2751-2767).
- **Work-first display rule** (the canon cite): the default UX stays
  work-first — show the event, authority, policy, receipt, replay, artifact,
  and proof state first; show raw transaction hashes, chain IDs, contract
  refs, bridge refs, or gas details only when the receipt is anchored/settled
  or the user opens proof, settlement, dispute, governance, developer, or
  evidence-export detail (core-clients-surfaces.md:2771-2776). A proof
  explorer for deep inspection across runs is allowed (:2771-2772).
- **Waterfall/detail-drawer contract**: one coherent trace/replay path — open
  a session, workrun, automation run, or workflow node; inspect grouped turns
  or run segments; scan a waterfall of agent/model/tool/connector/MCP/browser/
  terminal/environment/authority/eval/settlement spans; open a detail drawer
  for overview, event, request, response, graph, logs, authority, receipts,
  proof/settlement, artifacts. Proof/settlement is a drilldown from work
  inspection, never a chain-first default (core-clients-surfaces.md:2712-2718).
- Learning boundary: Provenance derives a metadata-safe learning-flow graph
  from source through eligibility, use, derivative, promotion, egress/export,
  and revocation (core-clients-surfaces.md:1089-1090).
- Every capability detail page's lifecycle strip deep-links receipts, replay,
  and proof refs back to Provenance (core-clients-surfaces.md:1170-1173,
  :1242-1247); Systems "Evidence" mode projects Provenance + Evaluations
  (:1651). `Receipts / Replay` as a family label is a facet alias, not a
  separate product surface (:2143-2146).
- May never: become runtime truth or a second truth store (application
  surfaces are governed projections — core-clients-surfaces.md:1470-1473);
  default to chain-first display (:2717-2718); own the room graph (Work / Room
  detail owns the graph-first shared view; a session is one
  participant drilldown — :2729-2733).

## 2. Schema map

The registry carries the envelope contracts (`receipt-envelope.v1`,
`receipt-proof-bundle.v1`, `receipt-checkpoint.v1`,
`authority-effect-admission-receipt.v1` in
`docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`);
no daemon receipt route returns these envelope shapes today — every family
returns its own ad-hoc record shape. Convergence is registry/program debt,
noted per row, not a separate route gap.

| Canon object / contract | Canon block / registry | Daemon route(s) today | Wave |
| --- | --- | --- | --- |
| Chronological receipt stream (Work Ledger aggregate) | core-clients-surfaces.md:1334, :366 | `GET /v1/hypervisor/work-ledger[?project]` hypervisor-daemon.rs:1307-1311; handler joins ~16 record families — automation runs (orchestration_routes.rs:583-622), provider crossings (:624-651), storage custody (:652-666), placement decisions (:667-681), failover runs (:682-700), webhook trigger receipts (:701-730), harness executions + goal-run invocations/reconciliations (:738-800), memory projections/lifecycle, simulation/rollout/policy/improvement receipts, goal runs, domain-app mounts, marketplace publishes, kill enforcements, ODK materializations (:806-951) | — |
| Receipt read family 1: authority receipts | :2771-2776 | `GET /v1/hypervisor/authority/receipts` hypervisor-daemon.rs:2752-2754 (authority_routes.rs:882-886) | — |
| Receipt read family 2: resource receipts | :1242-1247 | `GET /v1/hypervisor/resource/receipts` :2782-2785 (resource_routes.rs:504) | — |
| Receipt read family 3: provider receipts (+ spend backlink) | :1334 custody | `GET /v1/hypervisor/provider-receipts` :2821-2824 (provider_routes.rs:6436); `GET /v1/hypervisor/provider-spend/reconciliation` :2829-2832 | — |
| Receipt read family 4: storage/custody receipts | :1336 custody receipts | `GET /v1/hypervisor/storage-receipts` :2874-2877 (storage_backend_routes.rs:1430); archives :2866-2869; incidents :2870-2873 | — |
| Receipt read family 5: model-mount receipts (+ per-receipt replay) | :1334 | `GET /v1/model-mount/receipts` + `/:id` hypervisor-daemon.rs:738-739; `…/:id/replay` :740-742 | — |
| Governance approval-transition receipts | :2737-2749 | **route-missing** — write-only records (governance_routes.rs:372, :691-699); absent from the work-ledger join (grep verified over orchestration_routes.rs:532-951) | W3 |
| Unified receipt-stream projection with principal ownership coordinates | :1334; work-first :2771-2776 | **route-missing** — the aggregate exists but refuses everything except `local_development` (orchestration_routes.rs:537-566) and omits the authority/resource/model-mount/approval-transition families | W3 |
| State roots | :1334 | carried on transcripts + ledger rows: `GET /v1/hypervisor/agent-run-transcripts` + `/:id` hypervisor-daemon.rs:2952-2957 (comment :2950: Agentgres-backed Run Timeline truth) | — |
| Replay entries (run replay = one-shot event SSE) | :1334, :2712-2718 | `GET /v1/runs/:id/replay` hypervisor-daemon.rs:3299-3303 (alias of `/events` :3295-3298); run sub-projections usage/conversation/trace/inspect :3304-3320; `GET /v1/hypervisor/dev-replay/status` :613-616 | — |
| Outcome-room replay + graph projections (Work owns the room view; Provenance deep-links) | :2729-2733 | `GET /v1/goal-orchestration/outcome-rooms/:id/replay` hypervisor-daemon.rs:2413-2416; `…/collaborative-work-graph` :2417-2420; discussion/product projections :2421-2428 | — |
| GoalRun proof trail | :2751-2763 | `GET /v1/goal-orchestration/goal-runs` + `/:id` + `/:id/events` hypervisor-daemon.rs:1820-1851 | — |
| Lineage graph projection (one daemon-side graph over sources→recipes→sets→receipts) | :1334-1336, :1235-1236 | **route-missing** as a projection — today the serve composes 9 separate reads client-side (serve-product-ui.mjs:9645-9655); every constituent read exists | W3 (optional — composition via read client is a valid target) |
| Metadata-safe learning-flow graph | :1089-1090 | **route-missing** | W3 (named gap; build only if ruled in) |
| Event consumption for live stream updates | M5 plane | `/v1/event-streams/*` + `/v1/subscriptions/*` hypervisor-daemon.rs:2349-2382 (durable, checkpointed); legacy per-run SSE `/v1/runs/:id/events` wrapped, not extended | — |

## 3. UI seed map

All four inherited native readouts verified live in the tree (census seed
confirmed at the bytes):

- **`/__ioi/work-ledger`** — the owned proof stream
  (serve-product-ui.mjs:8748-8774): daemon work-ledger read + auth-posture
  read, honest typed unavailable/403 states, `renderWorkLedger`
  (serve-product-ui.mjs:1551) with `?receipt=`/`?objectSet=` selection context
  (:8771-8772) and per-kind deep links into ontology/pipeline/lineage/vertex
  surfaces (:1673-1686). Estate index tile "Provenance" points here
  (:1462); page header brands the surface Provenance and links the lineage
  canvas seed + graph lenses (:1578). Wired. census: 42 controls, 0 disabled.
- **`/__ioi/run-replay`** — replay index over three run sources (serve
  registry runs + daemon agent-run-transcripts + goal-runs), kind chips,
  state-root column, per-row replay link (serve-product-ui.mjs:7254-7310).
  Wired. census: 66 controls.
- **`/__ioi/run-timeline[/:runId|/goal-run/:id|/env/:id|/draft/:id]`** — the
  owned transcript primitive (serve-product-ui.mjs:7311-7460; goal-run proof
  page :7317-7360; env/draft branches :7381-7390): grouped turns, a
  **turn waterfall positioned from recorded timestamps only**, lineage row
  (env → session → run → turns → artifacts), receipts/artifact counts, deep
  links to the proof stream (:6535-6546). This is the estate's seed for the
  D6 waterfall/detail-drawer contract. Wired. census: 66 controls.
- **`/__ioi/lineage`** and **`/__ioi/vertex`** — graph lenses composing 9 and
  5 daemon reads respectively, work-ledger as `provenance_stream` input
  (serve-product-ui.mjs:9643-9671, :9623-9642; comment :9662: "the surface is
  Provenance"). Wired. census: 21 + 22 controls.
- **Serve-side allowlist**: work-ledger/run-timeline/run-replay are
  internally-owned managed GET routes (serve-product-ui.mjs:337-356) but each
  fails closed outside `local_development` posture (:7278-7283, :8764-8768) —
  matching the daemon-side refusal (orchestration_routes.rs:537-566).
- **T4 dormant seed**: `/__apps/lineage` — lineage canvas capture, explicitly
  "adopting" (serve-product-ui.mjs:1578); preserved under the seed invariant.
- **Shell SPA**: no provenance route; census `/provenance` `resolves: false`.
  The 97-RPC adapter maps only model-mount receipts
  (ioi-api-adapter.mjs:322); no other provenance RPCs.

### Corrections vs v0

- v0 said: "Backend: receipts read surfaces ×5 families" — bytes show the 5
  standalone GET families (authority :2752, resource :2782, provider :2821,
  storage :2874, model-mount :738) **plus** the work-ledger aggregate joining
  ~16 record families (orchestration_routes.rs:583-951), **plus** at least one
  receipt family with no read route at all (governance approval-transition
  receipts, governance_routes.rs:372) and one that is POST-admission only
  (service-composition-receipt-bundles, hypervisor-daemon.rs:1111-1113). The
  aggregate also OMITS the authority/resource/model-mount standalone families
  — "one receipt stream" does not exist yet at any route.
- v0 said: "inherits work-ledger/lineage/run-timeline/run-replay readouts (all
  wired T2)" — verified wired, but every core readout is a local-operator
  projection that fails closed outside `local_development` (daemon
  orchestration_routes.rs:537-566; serve :7278-7283, :8764-8768) because the
  joined families lack principal ownership coordinates. "Wired" ≠ deployable;
  the principal-coordinates gap is the W3 build, not more UI.
- v0 said: "outcome-room replay/graph projections" under Provenance backend —
  the routes exist (hypervisor-daemon.rs:2413-2428) but their consumer is the
  `/__ioi/goal-space` Work readout (serve-product-ui.mjs:8735-8746), and canon
  gives the room graph to Work / Room detail (:2729-2733). Provenance
  deep-links room replay; it does not rehome that pane.
- Layering note (C-1..C-4 record-the-site rule): ledger/timeline code still
  reads named app-family fields — `e.goal_run_ref` in ledger entry links
  (serve-product-ui.mjs:1673) and goal_run rows minted by the aggregate
  (orchestration_routes.rs:880-899 region); session identity on timeline rows
  is `sessionRef`/env lineage (serve-product-ui.mjs:6546). These are ledger
  ENTRY fields, not Session records, so they are legal evidence fields — but
  any new Provenance row that names what a SESSION serves must resolve via
  `subject_attachments` (core-clients-surfaces.md:3971-3990), and these sites
  migrate at the PR that touches them.

#### Addendum 2026-08-06 (mesh packet 2 — tier labels and cite refresh at `ba9e2ea0a`)

§3 labelled `/__apps/lineage` as the "**T4** dormant seed". That conflates two
distinct artifacts, and the mesh ledger below keeps them apart:

- **T4** is `apps/hypervisor/ux-seeds/lineage/surface.mjs` — the dormant seed
  vault from PR #95, `state: dormant_seed_evidence_only`
  (`ux-seeds/manifest.json:3`), owner Provenance, proposed route
  `/__ioi/provenance/lineage`, `active_registration: "none"`.
- **T5** is the `/__apps/lineage` harvest capture (parity matrix `lineage`,
  class `substrate_bound`, capture state `boots_graph`).

Two serve-lane cites drifted; the daemon and canon cites still resolve:

| §3 said | Bytes at `ba9e2ea0a` |
|---|---|
| `/__ioi/lineage` `serve:9643-9671` | `serve-product-ui.mjs:9679` |
| `/__ioi/vertex` `serve:9623-9642` | `serve-product-ui.mjs:9659` |

Re-verified unchanged: work-ledger `:8748-8774`, run-replay `:7254-7310`,
run-timeline `:7311-7460`, the managed-GET allowlist `:337-356`, and the
fail-closed posture checks `:7278-7283` / `:8764-8768`.

Also corrected: §3 said the lineage and vertex lenses compose "9 and 5 daemon
reads". Both counts are right, and the mesh ledger now names them — the reads are
almost entirely **ODK semantic-plane** routes, which is what makes Provenance the
one core proof surface with real ontology wiring (§7).

## 4. Schema→UI binding table

Reads use the uniform read-projection client (W0.3); live updates ride
`/v1/event-streams` + `/v1/subscriptions` (W0.4), wrapping the legacy per-run
SSE. Provenance is read-only — it has NO authority-crossing verbs; the only
"actions" are navigation, filters, and export drilldowns. Session-serving rows
bind through `subject_attachments` (core-clients-surfaces.md:3971-3990).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Receipt stream pane (chronological, kind/project filters) | work-ledger aggregate · hypervisor-daemon.rs:1307-1311 | wired at `/__ioi/work-ledger` (local-dev only) | wired-read |
| Stream facets: authority / resource / provider / storage / model-mount receipts | :2752-2754, :2782-2785, :2821-2824, :2874-2877, :738-742 | dead (no pane serves the standalone families) | wired-read |
| Approval-transition receipt rows | route-missing (write-only records) | absent (dangling refs in Governance banners) | disabled-named-gap → wired-read after W3 read route |
| Receipt detail drawer (overview/event/authority/receipts/proof/artifacts tabs per D6) | ledger entry + per-family `:id` reads · :2712-2718 | partial — `?receipt=` selection context exists (serve:8771-8772), no drawer tabs | wired-read |
| Proof drilldown (state roots, commitments, anchors) — hashes ONLY here | work-first rule :2771-2776; state roots on transcripts :2950-2957 | partial — roots truncated inline in rows (serve:2276, :7299) | wired-read (rows stay work-first; hashes move behind the drawer's Proof tab) |
| Run waterfall (turn spans from recorded timestamps) | run-timeline projection · serve:6535-6546; transcripts :2950-2957 | wired | wired-read |
| Replay index + per-run replay | `/v1/runs/:id/replay` :3299-3303; transcripts; goal-run events :1849-1851 | wired at `/__ioi/run-replay` | wired-read |
| Live stream tail (new receipts appear without reload) | M5 event plane :2349-2382 | absent (readouts are static renders) | wired-read (subscription client) |
| Lineage graph pane (sources → recipes → sets → receipts; every edge a receipt) | 9 composed reads · serve:9645-9655 | wired at `/__ioi/lineage` | wired-read (rehomed composition; daemon projection optional W3) |
| Vertex/object-neighborhood lens | 5 composed reads · serve:9625-9631 | wired at `/__ioi/vertex` | wired-read |
| Room replay / room graph deep links (Work owns the pane) | :2413-2428; canon :2729-2733 | wired via `/__ioi/goal-space` | wired-read deep link (never rehomed) |
| Session/work subject chips on stream rows | `subject_attachments` resolution · :3971-3990 | partial — legacy `goal_run_ref`/env refs (serve:1673, :6546) | wired-read (typed subject chips; legacy field sites migrate when touched) |
| Learning-flow graph | route-missing · :1089-1090 | absent | disabled-named-gap |
| Evidence-export / settlement detail | route-missing (no export route) | absent | disabled-named-gap |

## 5. Ordered PR list

Router-file PRs (#5, #6) are serial with all other backend-route PRs (central
router = merge hotspot; standing rule).

1. **W1** — `/provenance` canonical route in the v2 shell: receipt-stream pane
   rehomed from `/__ioi/work-ledger` via the read client; honest
   typed-unavailable states preserved; zero fixture data. Seeds keep serving
   until step 8.
2. **W1** — Waterfall + detail drawer: rehome run-timeline/run-replay under
   `/provenance` as the D6 contract (drawer tabs: overview, event, authority,
   receipts, proof, artifacts); hashes/state roots move behind the Proof tab
   per the work-first rule (core-clients-surfaces.md:2771-2776).
3. **W1** — Lineage graph pane: rehome the `/__ioi/lineage` + `/__ioi/vertex`
   composition; adopt the `/__apps/lineage` canvas seed for rendering
   (adopt→rebrand→rebind, never rebuild).
4. **W1** — Standalone receipt families as stream facets: authority, resource,
   provider (+spend backlinks), storage (+incidents/archives), model-mount
   (+per-receipt replay) over their existing GETs.
5. **W0.4/W1** — Live tail: subscription client on `/v1/event-streams` +
   `/v1/subscriptions`; legacy `/v1/runs/:id/events` SSE wrapped for the open
   drawer only.
6. **W3** — Unified receipt-stream projection with principal ownership
   coordinates: fold the standalone families + approval-transition receipts
   (read route lands here — joint with Governance brief step 8) into one
   daemon projection, retiring the `local_development`-only refusal
   (orchestration_routes.rs:537-566) by fixing its cause, not its gate.
7. **W3 (optional, only if ruled in)** — daemon lineage-graph projection and
   metadata-safe learning-flow graph; until then both stay
   composition/named-gap per section 4.
8. **W4** — Cutover: `/__ioi/work-ledger`, `/__ioi/run-timeline`,
   `/__ioi/run-replay`, `/__ioi/lineage`, `/__ioi/vertex` retired with typed
   410s per the 6-step rule; estate tiles/headers stop advertising the legacy
   paths.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Provenance gains transition-chain search/timeline, head/predecessor/gap/fork
verification, the integrity-vs-currentness distinction, checkpoint
verification, and proof export; it owns the receipt/checkpoint verification
+ export routes (epic §3 C9, a P3 leg) — these fold into the unified
receipt-stream projection this brief already plans.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 3 (registered surfaces): none.** Provenance has no row in
`scripts/surface-registry.mjs` — its whole estate is T2 native readouts plus one
dormant T4 vault and two T5 captures. It therefore contributes **0 of the 563
baseline controls**, and the census reconciliation below is over the T2 tier
instead. Recorded as an honest absence: the missing T3 registration is not a gap
to fill, because Provenance's readouts were built native rather than harvested.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T2 proof stream** — `/__ioi/work-ledger` (serve `:8748-8774`, renderer `renderWorkLedger` `:1551`) | T2 census `nat-work-ledger`: 42 controls, 0 disabled. Carries `?receipt=`/`?objectSet=` selection context (`:8771-8772`) and per-kind deep links (`:1673-1686`) | Provenance is the proof plane; chronological receipt stream evolving the former Work Ledger card (:1333-1339); Agentgres is the substrate (:366) | **rehome** — this IS the Provenance landing; the surface already brands itself Provenance (`:1578`) | W1 |
| **T2 replay index** — `/__ioi/run-replay` (serve `:7254-7310`) | T2 census `nat-run-replay`: 66 controls, 0 disabled. Three run sources, kind chips, state-root column, per-row replay link | Replay entries + "whether it can be replayed" (:2737-2749) | **rehome** | W1 |
| **T2 transcript primitive** — `/__ioi/run-timeline[/:runId\|/goal-run/:id\|/env/:id\|/draft/:id]` (serve `:7311-7460`) | T2 census `nat-run-timeline`: 66 controls, 0 disabled. **Waterfall positioned from recorded timestamps only** — no synthesized spacing | D6 waterfall + detail drawer, proof as drilldown never chain-first (:2712-2718, :2771-2776) | **rehome** — the estate's D6 seed; Work composes the same primitive for Session detail (see `work.md` §6) | W1 |
| **T2 lineage lens** — `/__ioi/lineage` (serve `:9679`) | T2 census `nat-lineage`: 21 controls, 0 disabled. Composes **9 daemon reads**, 7 of them ODK semantic-plane (§7) | Lineage graph of runs/artifacts/authority where **every edge is a receipt** (:1333-1339); dependency/provenance/impact graph is shared with Ontology (:1238-1239, :1254) | **rehome** — with the shared-graph boundary stated: Provenance owns the receipt-edge lens, Ontology owns the semantic dependency lens over the same primitives | W1 |
| **T2 vertex lens** — `/__ioi/vertex` (serve `:9659`) | T2 census `nat-vertex`: 22 controls, 0 disabled. Composes **5 daemon reads**, 4 ODK semantic-plane; the serve comment states "the surface is Provenance" | same graph contract (:1333-1339) | **rehome** — folds into the lineage lens as an object-set-first entry point rather than surviving as a second graph surface | W1 |
| **T2 fail-closed posture** — managed-GET allowlist (serve `:337-356`) + posture checks (`:7278-7283`, `:8764-8768`), matching the daemon refusal (`orchestration_routes.rs:537-566`) | not census controls | receipts must answer under whose authority (:2737-2749) | **rehome** — the refusal is correct and must survive the rehome verbatim: "wired" is not "deployable" until the joined families carry principal ownership coordinates (§3 correction) | W1 · W3 |
| **T4 dormant vault** — `apps/hypervisor/ux-seeds/lineage/surface.mjs` (PR #95; `manifest.json` `state: dormant_seed_evidence_only`; proposed route `/__ioi/provenance/lineage`; `active_registration: "none"`; `active_parity_class: substrate_bound`) | **No pixel certification** — and the seed says why: the pixel gate "REFUSES it by doctrine" because the monocle reference cannot render data on any local lane; the capture never recorded its graph queries, so every RID-seeded deep route bounces to the empty welcome graph (`surface.mjs:17-20`) | the graph contract above; a passing pixel certificate grants nothing in either direction | **pattern-harvest** — the seed's honest-gap discipline (every freeform editor tool, branch selector, Save-as, and dock lens **disabled in place, never hidden, never faked**, `surface.mjs:12-15`) is the pattern to carry into the functional lens; no code moves; the vault stays dormant until a current Provenance contract pulls it | — |
| **T5 `/__apps/lineage`** — harvest capture, class `substrate_bound`, capture state `boots_graph`, grammar `graph`, tier high_value; rebound lane recorded as "Work Ledger cross-object lineage edges" (`harvest-seed-inventory.mjs:36`) | protected seed, route `/__ioi/lineage`, class `substrate_bound` (`ported-seed-preservation.v1.json`) | same | **rebind** — the named rebound lane already exists; capture stays dormant per the seed-preservation invariant | W1 (reads) · W4 |
| **T5 `/__apps/vertex`** — harvest capture, class `substrate_bound`, capture state **`blocked_missing_capture`**, `reboundLane: null` (`harvest-seed-inventory.mjs:75`) | protected seed, route `/__ioi/vertex`, class `substrate_bound` | same | **blocked-missing-capture** — honest block: the capture cannot be inspected, so no claim about its interaction grammar is supportable. The `/__ioi/vertex` lens above is daemon-native and unaffected; only the capture is blocked | — |
| **Estate advertisement** — index tile "Provenance" → `/__ioi/work-ledger` (serve `:1462`); page header links the lineage canvas seed + graph lenses (`:1578`) | not census controls | canonical route is `/provenance` (:897) | **retire-at-cutover** — the tile retargets at cutover; the header's seed link retires with the T4 vault's dormancy | W4 |

**Census reconciliation.** Provenance holds **0 of the 563** T3 baseline controls
(no registered surface). Its five T2 readouts carry **217 controls, 0 disabled**
(42 + 66 + 66 + 21 + 22), all outside the 563 baseline, which covers only the
fourteen registered T3 surfaces. The zero-disabled figure across all five is worth
stating: Provenance's readouts do not carry a disabled-control backlog — their gap
is deployability (principal coordinates), not missing affordances.

**Disposition summary.** 6 rehome · 1 rebind · 1 pattern-harvest ·
1 retire-at-cutover · **1 blocked-missing-capture** (`/__apps/vertex`).

## 7. Ontology wiring

Provenance is the one proof-plane surface with **real** ontology wiring, and the
reason is structural: its two graph lenses read the semantic plane directly rather
than reading a platform projection over it. Eleven of the fourteen reads the two
lenses make are ODK routes.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Lineage lens — ontology spine | `DomainOntology` (`DomainOntologyEnvelope`) | `GET /v1/hypervisor/odk/domain-ontologies` | Read | also the vertex lens's entry selector (`?ontology=`) |
| Lineage + vertex — object sets | `MaterializedObjectSet` | `GET /v1/hypervisor/odk/materialized-object-sets` | Read | the `?objectSet=`/`?objectId=` selection context both lenses and the proof stream share |
| Lineage + vertex — projections | `OntologyProjection` (`OntologyProjectionEnvelope`) | `GET /v1/hypervisor/odk/ontology-projections` | Read | canon requires projections to expose freshness, recipe version, policy, and source watermark (non-negotiable 8) — the lens must render these, not just node counts |
| Lineage + vertex — materializing runs | materializing run records over `TransformationRun` semantics | `GET /v1/hypervisor/odk/materializing-runs` | Read | the run is the edge between a recipe and a set |
| Lineage — connector mappings | `ConnectorMapping` (`ConnectorMappingEnvelope`) | `GET /v1/hypervisor/odk/connector-mappings` | Read | source→object-model edge |
| Lineage — policy-bound views | `PolicyBoundDataView` | `GET /v1/hypervisor/odk/policy-bound-data-views` | Read | the governed-lens edge; canon gates read/train/export through these (non-negotiable 4) |
| Lineage — capability lease plans | ODK capability-lease plan records | `GET /v1/hypervisor/odk/capability-lease-plans` | Read | the authority edge of the graph |
| Lineage — sources | `DataSource` (Data-owned) | `GET /v1/hypervisor/data-sources` | Read | not a semantic-plane envelope; the graph's outermost input node |
| Lineage + vertex — proof stream | receipts / work-lifecycle records | `GET /v1/hypervisor/work-ledger` | Read | supplies the `provenance_stream` input both lenses join on |
| **`ProvenanceAssertion`** (`OntologyAssertionEnvelope` with `assertion_profile: provenance_assertion`) | **route-missing** | — | — | The canonically-named Provenance primitive **does not exist in code**. `canon-to-code-delta.md` records it as not started, with the receipt families as the evidence substrate an assertion will bind. Provenance today renders receipt edges, which prove their declared fact only — it does **not** render admitted assertions with valid time, confidence, contradiction, supersession, or dispute state (:2737-2749 vs `semantic-plane.md` `OntologyAssertionEnvelope`) — **W3** |
| **Write side — whole surface** | **none.** Provenance admits no semantic write | — | — | It reads receipts and renders edges. Every mutation deep-links to the owner; the surface has no admission path and must not gain one |

The one wiring ruling this surface needs, stated once: **Provenance owns the
receipt-edge lens over these primitives; Ontology owns the semantic
dependency/impact lens over the same primitives** (canon shares the graph,
:1238-1239, :1254). Two lenses, one primitive set, no duplicated ownership — and
neither may present mutation semantics over a projection.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

Provenance is the **first surface in this run where descriptor expressibility is
not blocked by the platform-object problem** (`work.md` §8): its graph panes bind
real ontology primitives, so the descriptor's required fields have something to
name.

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Lineage lens (`/__ioi/lineage` → `/provenance/lineage`) | `graph` | **descriptor-expressible** | binds `DomainOntology`, `MaterializedObjectSet`, `OntologyProjection`, `ConnectorMapping`, `PolicyBoundDataView` refs plus its daemon API deps and read-only action set — the invariant-11 fields all have real values |
| Vertex object-set lens | `graph` | **descriptor-expressible** | same primitive set, narrower entry point; folding it into the lineage descriptor is the cheaper end state than two descriptors |
| Proof stream (`/__ioi/work-ledger`) | `list_detail` | **exempt — no bindable primitive** | receipts are not ontology objects; the same blocking finding as `work.md` §8 (X-2 delta) |
| Replay index (`/__ioi/run-replay`) | `list_detail` | **exempt — no bindable primitive** | run records, not ontology objects |
| Run timeline / D6 waterfall | **no matching pattern** | **finding — already filed** | second surface to hit it; a span waterfall with a detail drawer is neither `graph` nor `monitoring_console` nor `dashboard`. Two independent surfaces needing it strengthens the X-2 case |
| Receipt detail drawer (overview/event/request/response/logs/authority/receipts/proof) | `object_view` | **exempt — no bindable primitive** | a receipt is evidence, not an ontology object |

**Caveat that keeps the two expressible rows honest.** Expressible means the
bindings are statable, not that a descriptor would pass admission today: the
implemented descriptor record carries none of the invariant-11 fields
(`odk_routes.rs:1501-1516`, filed in `canon-to-code-delta.md`). These two rows are
the first real candidates for descriptor-driven rendering **once the descriptor
record can hold its own contract** — which is exactly the dogfooding evidence
non-negotiable 23 was written to produce.

Zero panes are `descriptor-rendered` today.

### (b) This surface as primitive exposer

**n/a.** Provenance consumes semantic primitives and exposes none. It owns no
stage of the composable-application journey (`odk-extension-apps.md` §2), admits
nothing, versions nothing, and holds no descriptor.

One adjacency worth recording so a later packet does not mistake it for a stage:
when the extension lane finally runs end to end, **every rung of the Domain App
mount ladder emits a `DomainAppMountReceipt`** (`semantic-plane.md`), and those
receipts land in this surface's stream like any other. Provenance renders the
extension lane's evidence; it never admits any part of it.
