# Systems — implementation brief

Canonical route: `/systems` · Owner: core workspace (Systems)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 17 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Systems is the stable inventory and contextual workspace for live
  constitution-bound autonomous institutions; it projects one `system_id`
  across package revisions, membership changes, model-route changes, upgrades,
  recovery, migration, succession, and dissolution. It is NOT a truth store
  and never mints or mutates System identity by itself
  (core-clients-surfaces.md:1634-1640).
- Route rule: `/systems` — **"no fabricated System rows before honest read
  models"** (core-clients-surfaces.md:886).
- Seven contextual modes over existing owners: Overview / Design / Operate /
  Govern / Evidence / Improve / Interfaces — each a projection into owner
  applications, never a parallel surface (core-clients-surfaces.md:1643-1653).
- Division of labor: Operations performs admitted provider/placement/fencing/
  failover/member actions; Governance authorizes protected transitions;
  daemon/domain contracts execute; Agentgres records admitted truth
  (core-clients-surfaces.md:1655-1658).
- A direct Session, Project, AutomationSpec, or standalone GoalRun never
  requires System genesis. Upgrade proposals bind an owner-qualified
  `target_owner_ref`; a non-System target mints no System. Constitutional
  amendment, deployment, membership, lifecycle-transition, and
  network-enrollment changes are System-scoped (core-clients-surfaces.md:1658-1667).
  Field-level rules are owned by
  `docs/architecture/foundations/objects/interop-and-collaboration-terms.md`
  (core-clients-surfaces.md:1666-1669).
- A System-bound interface resolves under
  `/systems/{system_id}/interfaces/{system_binding_id}`; canonical routes
  preserve typed System context (core-clients-surfaces.md:908-913).
- System must not collapse into Package, node, process, GoalRun, Session, or
  UI; Project is not live System identity (core-clients-surfaces.md:3279-3281).
- Canon's own status stamp: "target contract … a complete policy-filtered
  Systems inventory, permanent shell destination, and blank-to-genesis product
  path are not shipped" (core-clients-surfaces.md:1671-1673).

## 2. Schema map

Registry = `docs/architecture/_meta/schemas/` (files listed by name; all have
entries in `architecture-contract-registry.v1.json`).

| Canon object / contract | Registry entry | Daemon route(s) today |
| --- | --- | --- |
| AutonomousSystemGenesis (+ Manifest, Constitution, InitialProfileBundle) | `autonomous-system-genesis.v1.schema.json` etc. | GET/POST `/v1/hypervisor/autonomous-systems` (hypervisor-daemon.rs:2173), GET `:id` (:2181) |
| System read projection (`ioi.hypervisor.autonomous-system-read-projection.v1`) | daemon literal only — NOT in registry (system_projection_routes.rs:132) | GET `/v1/hypervisor/autonomous-systems/projection?view=compact\|advanced` (hypervisor-daemon.rs:2177) |
| AutonomousSystemSequenceZeroMaterialization (+ receipts v1/v2) | `autonomous-system-sequence-zero-materialization.v1.schema.json` | GET/POST `:id/sequence-zero-materialization` (hypervisor-daemon.rs:2185) |
| AutonomousSystemActivationProposal/State/Receipt/AuthorityDecision | `autonomous-system-activation-*.v1.schema.json` | GET/POST `:id/initialize` (:2190), `:id/activate` (:2198) |
| AutonomousSystemProtectedTransitionProposal/Decision | `autonomous-system-protected-transition-*.v1.schema.json` | GET/POST `:id/transitions/:op` (hypervisor-daemon.rs:2206) |
| AutonomousSystemContinuityState, MigrationDestinationAcknowledgement, Dissolution* | `autonomous-system-continuity-state.v1.schema.json`, `autonomous-system-dissolution-*.v1.schema.json` | GET/POST `:id/continuity/:op` (:2221), POST `:id/continuity/migration-destination-acknowledgements` (:2214) |
| AutonomousSystemNodeMembership, MembershipTransition, DesiredTopology | `autonomous-system-node-membership.v1.schema.json` etc. | GET `:id/membership/projection` (:2267), GET `:id/topology/minimum` (:2271), POST `:id/membership/desired-topology` (:2275), GET/POST `:id/membership/:op` (:2282) |
| AutonomousSystemChain, ChainWriterReservation, ChainSuccessorClaim, WriterEpochTransition | `autonomous-system-chain*.v1.schema.json`, `autonomous-system-writer-epoch-transition.v1.schema.json` | GET `:id/writer/epoch` (:2290), POST `:id/writer/failover-profile` (:2294), GET `:id/writer/lost-suffixes` (:2301), POST `…/resolution` (:2305), GET/POST `:id/writer/transitions/:kind` (:2312) |
| AutonomousSystemConstitutionAmendment (+ approval decision, execution proposal/decision, receipt, transition) | `autonomous-system-constitution-amendment*.v1.schema.json`, `autonomous-system-amendment-*.v1.schema.json` | GET/POST `:id/amendments` (hypervisor-daemon.rs:2320) |
| AutonomousSystemActiveProfileSet (v1/v2), DeploymentProfileRevision, LifecycleState, OperationLog (v1/v2), HomeDomainBinding | schema files present (same dir) | surfaced inside the projection `advanced` view (system_projection_routes.rs:65-74) |
| HypervisorSystemInterfaceBinding | `hypervisor-system-interface-binding.v1.schema.json` | `route-missing` — record set carries ZERO `system_interface_bindings` rows (hypervisor_daemon_routes/hypervisor_surface_records.json) and the product-surface compiler never joins them (lifecycle_routes.rs:6058-6103). **W3** |
| SystemScopedObjectBinding | `system-scoped-object-binding.v1.schema.json` | `route-missing` — no read route projects System-scoped object bindings for the Interfaces mode. **W3** |

`route-missing` W3 build-list: (a) System interface-binding plane — durable
`HypervisorSystemInterfaceBinding` rows + compiler join + resolution of
`/systems/{system_id}/interfaces/{system_binding_id}`; (b) registry entry for
the read-projection response contract (registration-only, no daemon change).
Everything else this workspace needs already has a live daemon route — the
autonomous-systems family alone is 19 registrations (hypervisor-daemon.rs:2172-2326).

## 3. UI seed map

- **T1 shell**: no Systems rail item, tile, or SPA route; census:
  `canonical_target_routes` `/systems` `resolves: false`
  (census: inventory.v1.json). Still true at the live shell — the vendored SPA
  has no `/systems` path and the shell catalogs carry no Systems entry.
- **T2 native readouts**: the M1.6/M1.7 System-genesis surfaces are live and
  wired under `/__ioi/systems/*`, dispatched at serve-product-ui.mjs:9491-9493
  into `apps/hypervisor/scripts/system-genesis-surfaces.mjs` (777 lines):
  - `/__ioi/systems` → 302 to `packages` (system-genesis-surfaces.mjs:734-738)
  - `/compose` GET/POST — Studio-lane package/genesis composition, compact +
    advanced lanes (:739-746); POST is a verbatim proxy of the operator
    declaration to `POST /v1/hypervisor/autonomous-systems`
  - `/packages` — per-System instantiation census from the projection (:747-750)
  - `/governance` + `/governance/preview` — pending proposals/approvals,
    preview-not-authority (:751-758)
  - `/<asg_…64-hex>` detail (compact/advanced) + `/<asg>/<op>` POST actions —
    the genesis→sequence-zero→initialize→activate→transitions ladder (:760-773)
  - Doctrine in the module header: read truth per request, no UI-derived
    truth, wallet challenge/receipt relayed verbatim, deliberately NO
    permanent Systems navigation (not a rail item, not a suite card, not an
    app-catalog entry), honest `data-journey-state` states, and the
    projection's fail-closed `system_projection_source_incomplete` renders as
    a stale/conflict stop, never a partial list (system-genesis-surfaces.mjs:1-27).
  - census: `nat-systems` `/__ioi/systems` 200, 4 controls, 0 disabled
    (census: inventory.v1.json tier_t2).
- **Daemon honesty already satisfies the route rule**: the projection
  cross-checks the local record census against the Agentgres admission census
  and fails closed on divergence (`system_projection_source_incomplete`,
  system_projection_routes.rs:114-120); empty is reported as
  `state: "honest_empty"` with an explicit `nonclaims` block
  (system_projection_routes.rs:132-138). No fabrication exists to remove.
- **T3**: `designer` and `machinery` registered surfaces are Studio-owned
  seeds (surface-registry.mjs:59-60), not Systems assets; Systems only
  cross-links into Studio for the Design mode.
- Classification: genesis surfaces = wired (read + proxied governed actions);
  Systems inventory-as-workspace = absent (the root redirects to the packages
  census); membership/writer/amendment panes = absent despite live routes.

### Corrections vs v0

- v0 §3 has no Systems chapter (Systems appears only in the §1 workspace row
  and the 23-route ledger) — bytes show a substantial shipped seed: four
  wired genesis surfaces over 19 daemon routes
  (system-genesis-surfaces.mjs:4-27; hypervisor-daemon.rs:2172-2326). The
  brief's plan is therefore rehome-and-extend, not greenfield.
- v0 §1 "Actual" says "Sessions route absent" for the shell generally; for
  Systems specifically the census claim `/systems resolves:false` is
  confirmed at the shell, but the canon stamp "blank-to-genesis product path
  … not shipped" (core-clients-surfaces.md:1671-1673) is now PARTLY stale at
  the bytes: the blank-to-genesis path exists end-to-end at `/__ioi/systems/compose`
  — it is only unreachable from any permanent navigation, by M1.7 design
  (system-genesis-surfaces.mjs:16-19).
- census: `registration_contract_implementation_status` shows
  `HypervisorSystemInterfaceBinding` `contract_registry: 0` — stale; the
  registry now carries `hypervisor-system-interface-binding.v1.schema.json`
  plus a registry entry (architecture-contract-registry.v1.json). The gap that
  remains is rows + routes, not the schema.
- The daemon core taxonomy already registers the Systems workspace
  (`hypervisor-workspace://systems`, canonical_route `/systems`,
  hypervisor_daemon_routes/hypervisor_core_taxonomy.json `core_workspaces`),
  served through the product-surface projection (lifecycle_routes.rs:6042-6057)
  — the workspace row v0 promises from W0.2 is already in daemon truth.

## 4. Schema→UI binding table

Read client = W0.3 uniform read-projection fetch. Authority client = W0.3
CapabilityLease flow (403 wallet challenge → 428 credential → receipted); the
genesis surfaces' existing verbatim wallet-relay proxy migrates onto it, not
around it. Any Work/Session rows shown inside System modes bind through
`subject_attachments` (subject_kind + subject_ref), never a named app field.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Systems inventory (workspace root list) | read projection compact — GET `/v1/hypervisor/autonomous-systems/projection` (hypervisor-daemon.rs:2177) | absent (`/__ioi/systems` 302s to packages census) | `wired-read` — `honest_empty` and `system_projection_source_incomplete` pass through verbatim |
| System detail — Overview mode (identity, revision, lifecycle, profile refs) | projection `advanced` + GET `:id` (hypervisor-daemon.rs:2177, :2181) | wired at `/__ioi/systems/<asg>` | `wired-read` (rehomed to `/systems/{system_id}`) |
| Blank-to-genesis wizard (compose) | POST `/v1/hypervisor/autonomous-systems` (hypervisor-daemon.rs:2173) | wired at `/compose` (proxy relays wallet challenge) | `wired-action-receipted` via authority client |
| Sequence-zero materialization control | `:id/sequence-zero-materialization` (hypervisor-daemon.rs:2185) | wired (detail ladder) | `wired-action-receipted` |
| Initialize / Activate controls | `:id/initialize`, `:id/activate` (hypervisor-daemon.rs:2190, :2198) | wired (detail ladder) | `wired-action-receipted` |
| Protected transitions (deployment/lifecycle/enrollment ops) | `:id/transitions/:op` (hypervisor-daemon.rs:2206) | wired (detail actions) | `wired-action-receipted` — Governance authorizes; Systems only surfaces (canon :1655-1658) |
| Continuity actions (succession, migration, dissolution, local enrollment — 9 wire ops) | `:id/continuity/:op` + migration acks (hypervisor-daemon.rs:2221, :2214; op whitelist system-genesis-surfaces.mjs:36-46) | wired | `wired-action-receipted` |
| Govern mode — pending proposals/approvals preview | governance preview composition (system-genesis-surfaces.mjs:751-758) | wired, preview-only | `wired-read` (stays preview; approval verbs live in Governance) |
| Operate mode — desired-vs-observed topology pane | `:id/membership/projection`, `:id/topology/minimum` (hypervisor-daemon.rs:2267, :2271) | absent | `wired-read` (W1), then desired-topology declaration `wired-action-receipted` (:2275) |
| Operate mode — membership ops (join/fence/remove per contract) | `:id/membership/:op` (hypervisor-daemon.rs:2282) | absent | `wired-action-receipted` (W2) — executed by Operations semantics, surfaced here |
| Writer/failover pane (epoch, lost suffixes, failover profile) | writer routes (hypervisor-daemon.rs:2290-2312) | absent | `wired-read` first; transitions `wired-action-receipted` (W2) |
| Amendments pane (constitutional change) | `:id/amendments` (hypervisor-daemon.rs:2320) | absent | `wired-read` + `wired-action-receipted` (W2) |
| Interfaces mode — `/systems/{system_id}/interfaces/{system_binding_id}` | HypervisorSystemInterfaceBinding — no rows, no compiler join | absent | `disabled-named-gap` until W3 interface-binding plane lands |
| Design / Evidence / Improve mode tabs | deep links + embedded reads of Studio/Ontology/Data/Automations, Provenance/Evaluations, Improvement/Foundry (canon :1643-1653) | absent | `wired-read` (composition only; no new routes) |
| Operate mode — System-scoped Work rows | Work reads filtered by System scope; rows carry `subject_kind`/`subject_ref` (canon :1693-1702) | absent | `wired-read` via `subject_attachments` (never named app-family fields) |
| Legacy `/__ioi/systems/*` routes post-cutover | — | serving | `delete` (typed 410 per ADR 0022; daemon already 410s `/__ioi/*path` at its own level, hypervisor-daemon.rs:612) |

## 5. Ordered PR list

1. **W0** — `/systems` enters the v2 shell route table; rail/catalog entry
   comes from the compiler's `workspace_entries` (already emitted by
   POST `/v1/hypervisor/product-surface-projections`,
   lifecycle_routes.rs:6042-6057). No hand list.
2. **W1** — Systems inventory read view at `/systems` over the compact
   projection: honest_empty, fail-closed source-incomplete stop, per-System
   row → detail link. First screen honors the route-table rule by
   construction (the daemon read model is already honest).
3. **W1** — Rehome the four genesis surfaces under the canonical route
   (`/systems/new` ← compose, inventory facet ← packages census, Govern tab ←
   governance preview, `/systems/{system_id}` ← asg detail), preserving the
   seed module per the seed-preservation invariant; `/__ioi/systems/*` keeps
   serving until step 8.
4. **W1** — Detail gains read panes over already-live routes: membership
   projection + minimum topology, writer epoch/lost-suffixes, amendments
   history.
5. **W2** — Governed actions move onto the W0.3 authority client (genesis
   admit, sequence-zero, initialize/activate, transitions/:op,
   continuity/:op, membership/:op, desired-topology, writer transitions,
   amendments); every control receipted, everything else
   disabled-with-named-gap.
6. **W2** — Mode tabs (Design/Operate/Govern/Evidence/Improve) as
   compositions over owner reads; System-scoped Work rows via
   `subject_attachments`.
7. **W3** — Interface-binding plane: durable `HypervisorSystemInterfaceBinding`
   rows + compiler join + `/systems/{system_id}/interfaces/{system_binding_id}`
   resolution (backend first, UI same wave). Registry entry for the
   read-projection contract rides along.
8. **W4** — Cutover: shell stops linking `/__ioi/systems/*`; serve routes
   deleted with typed 410s per the 6-step per-app rule.
