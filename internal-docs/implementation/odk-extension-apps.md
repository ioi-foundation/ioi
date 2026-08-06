# ODK extension applications — the user-tailored application lane

Program doc for the composable-application journey: how a user goes from
"I can describe my domain" to a governed, launchable application built out of
the same primitives the first-party estate runs on.

Authored 2026-08-06 as packet X-1 of the seed-mesh + ODK wiring run
(`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`), from
bytes at master `44787da9e`. Canon counterpart: the composable-application
journey and the Domain App mount ladder in
`docs/architecture/foundations/domain-ontologies-and-data-recipes.md`, and the
DomainApp envelope family in
`docs/architecture/foundations/objects/semantic-plane.md` (both landed by
packet X-0).

Every per-surface brief's `## N+2. ODK descriptor and extension lane` section
points here. This doc owns the journey; the briefs own each surface's
participation in it.

## 1. The headline finding

**Both ends of the journey are built. The middle is not.**

Authoring (stages 1–4) is a real, working object plane: 56 ODK route
registrations across twelve families. Mounting and serving (stage 10) is a
fully implemented governed ladder with approval gating, live re-validation,
receipts, and kill-switch enforcement — 9 more registrations.

Between them, the stages that turn an authored candidate into durable product
inventory — package, admit, install, register, expose, bind to a System — are
where the estate has almost nothing:

- there is **no `/v1/hypervisor/packages/*` route family at all** (zero
  registrations in `crates/node/src/bin/hypervisor-daemon.rs`);
- there are **zero `extension_application` registrations** — all 15 surface
  registration records are first-party (13 `owner_application` + 2
  `substrate_application`), and they are `include_str!` static, not durable
  storage (`lifecycle_routes.rs:6085-6087`,
  `hypervisor_daemon_routes/hypervisor_surface_records.json`);
- `system_interface_bindings` is an **empty array** in that same file, and no
  `/systems/{id}/interfaces/*` route exists.

This explains a fact that otherwise looks like laziness: the implemented
`DomainApp.status` is pinned to `"draft"` and never advances
(`domain_apps_routes.rs:344`). There is nothing for it to advance *to*. The
status field is honest about the estate, not sloppy.

The build consequence: **the extension lane is gated on the Packages registry
family (W3), not on more ODK work.** Any plan that adds authoring capability
before the registry moves the estate further from a walkable journey, not
closer.

## 2. The journey, stage by stage, against the bytes

Canon owns the stage ladder and the owning surface per stage. This table adds
the current byte state. `route-missing` here means no daemon route exists, not
that the route is unwired in UI.

| # | Stage | Owning surface | Daemon state today |
|---|---|---|---|
| 1 | Describe the domain | Ontology | **exists** — `/v1/hypervisor/odk/domain-ontologies` (4 paths incl. health, history), `hypervisor-daemon.rs:1362-1380` |
| 2 | Bind the data | Data | **exists** — connector-mappings (5), policy-bound-data-views (5), data-recipes (2), transformation-runs (6), ontology-projections (6), materialized-object-sets (3), materializing-runs (8), connector-sessions (7), capability-lease-plans (5); `hypervisor-daemon.rs:1382-1611` |
| 3 | Author or scaffold the descriptor | Studio (Surface Generate); ODK scaffolds | **exists but thin** — `/v1/hypervisor/odk/surface-descriptors` (2 paths, `:1621-1631`); record carries only `composition_pattern`, singular `ontology_ref`, `recipe_refs`, opaque `view_config` (`odk_routes.rs:1501-1516`). See §4. |
| 4 | Shape it as an app | Studio | **exists** — `/v1/hypervisor/domain-apps` create/get/patch/delete with app-shape enforcement (`hypervisor-daemon.rs:1862-1877`) |
| 5 | Package it | Packages | **partial** — `/v1/hypervisor/odk/manifests` (2 paths, `:1612-1621`) is the only packaging object; no package candidate, no release |
| 6 | Admit and version | Packages | **route-missing** — zero `/v1/hypervisor/packages/*` routes exist |
| 7 | Install and register | Packages; Applications holds the contract | **route-missing** — registrations are static `include_str!`; zero `extension_application` rows; no create/install/enable verb |
| 8 | Expose at `/applications/{surface_key}` | product-surface compiler | **exists for first-party only** — `POST /v1/hypervisor/product-surface-projections` (`hypervisor-daemon.rs:1063`) joins registration → release → installation → serving binding over the static records; client compiler at `apps/hypervisor/scripts/surface-compiler.mjs` |
| 9 | Bind to a System for effectful launch | Systems | **route-missing** — `system_interface_bindings: []`; no `/systems/{id}/interfaces/*` route |
| 10 | Mount and serve (Domain Apps) | Governance admits; Operations observes | **exists, fully** — see §3 |

Route counts are from `hypervisor-daemon.rs` registrations on master
`44787da9e`; the 56 ODK + 9 domain-app paths reconcile against the 65 matching
`.route(` registrations in that file.

## 3. The Domain App mount ladder as implemented

`crates/node/src/bin/hypervisor_daemon_routes/domain_apps_routes.rs` (1,217
lines) implements the full governed ladder. This is the most complete part of
the lane and the part most at risk of being rebuilt by someone who does not
know it exists.

| Rung | Route | Enforcement (byte cite) |
|---|---|---|
| draft | `POST /v1/hypervisor/domain-apps` | `surface_descriptor_ref` required, must resolve, must be `composition_pattern == domain_app` (`:100-127`, `:294-311`); optional `odk_manifest_ref` must itself name that descriptor (`:129-163`, `:312-320`) |
| mount | `POST …/:id/mount` | ApprovalRequest must be `approved` **and** `subject_ref == domain_app_ref` (`:499-513`); ReleaseControl must be `open` **and** `release_target_ref == domain_app_ref` (`:515-529`); already-mounted refuses (`:586-596`) |
| serve | `POST …/:id/serve` | must be mounted and not serving (`:774-788`); **re-reads and re-checks both controls live** (`:824-847`); assigns internal route `/__ioi/domain-app-runtime/{rid}` only (`:860`) |
| stop | `POST …/:id/stop-serving` | must be serving; receipted; returns to `mounted` (`:892-964`) |
| unmount | `POST …/:id/unmount` | receipted state transition; runtime terminal (`:673-735`) |
| kill | governance enforce path | `kill_enforce_runtime` drives the same transitions under `domain_app.kill_stop_serving` / `domain_app.kill_unmount` action names, terminal state `killed` (`:992-1057`) |

Three properties worth preserving verbatim when this rehomes:

- **Serving re-validates rather than inherits.** A withdrawn approval or closed
  release control refuses the serve transition even though the mount already
  succeeded (`:842-847`). This is the single most valuable behavior in the file.
- **Enforcement is not a private path.** The kill path emits the same receipt
  family through the same writer (`write_mount_receipt`, `:545-570`), so an
  enforced stop leaves the same record a voluntary one does.
- **The plane refuses to overclaim.** The module header states plainly what it
  does not do — no process, no URL, no ingress, no publish, no connector action,
  no domain-action execution (`:1-13`, `:489-491`, `:651`). The
  `runtime_posture` note fields carry that honesty into the record itself.

### How it rehomes

The ladder is daemon-side and therefore survives the estate cutover unchanged.
What rehomes is its *surfacing*:

- **Studio** owns draft creation (stage 4) — it authors the descriptor and the
  DomainApp over it.
- **Governance** owns the approval and release control that gate mount, and the
  kill switch that enforces stop.
- **Operations** observes runtime state.
- **Applications** is where a mounted, admitted, registered app becomes
  launchable — never Studio, and never as a consequence of mounting.

There is no `/__ioi/domain-apps` UI card in the current cut (`:12-13`); the
`/__ioi/domain-apps` readout named in the Studio packet's inputs is the serve-lane
readout, not a daemon-owned surface. Verify at the bytes before meshing it.

## 4. The invariant-11 conformance bar

Non-negotiable 11 (`domain-ontologies-and-data-recipes.md`) is the bar every
generated surface must clear before it becomes durable product inventory. It
requires each ODK-generated surface to declare:

- [ ] owning ontology refs
- [ ] object-model refs
- [ ] data-recipe refs where applicable
- [ ] policy-bound data view refs
- [ ] authority requirements
- [ ] daemon/API dependencies
- [ ] receipt obligations
- [ ] conformance expectations

The canonical `OntologySurfaceDescriptorEnvelope`
(`objects/semantic-plane.md`) carries fields for all eight, plus projections,
allowed actions, operator/MCP contracts, and generated-artifact refs.

**The implemented descriptor record carries none of them.**
`handle_odk_descriptor_create` persists `composition_pattern`, a singular
`ontology_ref`, `recipe_refs`, and an opaque `view_config`
(`odk_routes.rs:1501-1516`). The consequence is precise and should not be
softened: **no stored descriptor can be checked against invariant 11 today** —
not because checking is unimplemented, but because the fields the check would
read do not exist. This is filed in `docs/architecture/_meta/canon-to-code-delta.md`.

What *is* complete is the pattern vocabulary: all eleven canonical
`composition_pattern` members are present and enforced at create and patch
(`odk_routes.rs:39-51`, `:1479-1483`, `:1540-1543`) —

```text
list_detail · object_view · object_editor · graph · wizard · review_inbox
monitoring_console · dashboard · data_recipe_builder
connector_mapping_editor · domain_app
```

So the shape vocabulary is trustworthy and the binding set is not. Surface
briefs may safely claim a pattern for a pane; they may not claim that a
descriptor for it would pass conformance.

## 5. Descriptor expressibility — what each surface brief records

Canon non-negotiable 23 (packet X-0c) requires every first-party owner-surface
pane whose shape matches a `composition_pattern` to carry a recorded
expressibility disposition. Each surface brief's `## N+2` section carries two
ledgers; this is their contract.

**(a) This surface as descriptor consumer.** One row per pane:

```text
| Pane | Matching composition_pattern | Disposition | Why |
```

Dispositions: `descriptor-expressible` (shape matches; bindings statable under
invariant 11), `descriptor-rendered` (actually rendered from a descriptor —
nothing qualifies today), or `exempt — <reason>`. Legitimate exemption reasons,
per canon: authority-crossing chrome, vendored shell internals owned verbatim,
dev/test-only lanes, and **no matching pattern** — which is a finding filed
against the pattern vocabulary, not a shrug.

**(b) This surface as primitive exposer.** What the surface contributes to the
user-tailored-application journey, keyed to the stage table in §2. Honest `n/a`
is expected for substrate surfaces and core workspaces that only consume — most
of the twenty surfaces will have a short or empty (b) ledger, and that is the
correct outcome, not a gap.

The expected stage owners, from §2: Ontology (1), Data (2), Studio (3, 4),
Packages (5, 6, 7), Applications (7 contract, 8 landing), Systems (9),
Governance (10 admission), Operations (10 observation). A surface claiming a
stage it does not own in that table is a defect in the brief.

## 6. Pattern evidence — what a generated domain app should feel like

Four harvest captures sit under the retired `Domain Apps` owner in
`apps/hypervisor/scripts/harvest-seed-inventory.mjs:79-82`. All four are
`reference_capture`, `grammar: editor_canvas`, `reboundLane: null`, and
explicitly noted `unbound`:

| slug | capture base | tier | capture state | note |
|---|---|---|---|---|
| `slate` | `/workspace/slate/` | high_value | `blocked_missing_capture` | app builder |
| `logic` | `/workspace/logic-app/` | aux | `shell_only` | logic builder |
| `contour` | `/workspace/contour-app/` | aux | `shell_only` | analysis |
| `fusion` | `/workspace/fusion/` | aux | `shell_only` | spreadsheet |

Their disposition is **`pattern-harvest`**, not rehome or rebind, and their
value is narrow and specific: they are evidence of the *interaction grammar* a
generated domain app should present — an editor canvas over domain objects
rather than a form stack — not evidence of any binding, route, or capability.
`slate` cannot even be inspected as a running capture today
(`blocked_missing_capture`), so claims about its behavior are unsupportable;
only its recorded grammar and tier are citable.

`Domain Apps` is a retired owner name. Per the retired-name rulings these four
rehome under **Studio** (the authoring surface, packet 11), never revived as a
peer application. Their mesh ledger rows live in the studio brief; this section
is their program-level context.

## 7. Build-list — what must exist before the journey is walkable

Ordered by dependency, not by effort. Every item is already filed in an owning
brief; this list exists so the extension lane's shape is visible in one place.

1. **Packages registry family (W3, packages brief).** Package, immutable
   release, install bindings, deprecation/disable/recall/revocation + receipts.
   This is stages 5–7 and it gates everything downstream. The extension lane
   does not move until this does.
2. **Durable surface registrations (W3, applications brief).** Replace the
   `include_str!` static records with storage; add the extension + tool
   registration CRUD and the install/enable/recall verbs. First
   `extension_application` row becomes possible here.
3. **Compiler recall hook (W3, applications + packages briefs).** Disable,
   recall, and revocation must remove launch eligibility immediately — the
   backwards direction of the ladder, which canon requires and no code
   implements.
4. **System interface-binding plane (W3, systems brief).** Stage 9. The schema
   slot exists with zero rows and zero routes; effectful extension launch is
   blocked until it lands.
5. **Descriptor binding set (W3, ontology brief).** Widen the descriptor record
   to carry the invariant-11 fields so conformance becomes checkable at
   admission rather than by inspection.
6. **DomainApp journey-stage refs (W3, studio brief).** Add
   `surface_registration_ref`, `package_release_ref`, `installation_ref`, and
   `system_binding_refs`; let `status` advance through admission instead of
   staying pinned to `draft`. Depends on 1, 2, and 4 — doing it earlier would
   add fields that nothing can populate.
7. **Mount receipt binds its runtime (W3, studio brief).** The receipt names the
   app but not the runtime it transitioned (`domain_apps_routes.rs:557-567`);
   an app with several runtimes over its life has an ambiguous receipt chain.

Items 5–7 are the canon-ahead-of-code deltas this run filed. Items 1–4 predate
it and are the real critical path.

## 8. What this doc is not

It is not a Domain Apps application brief — Domain Apps is a retired owner name
and gets no peer surface. It is not a schedule; wave assignments live in the
owning briefs. It is not permission to build the lane ahead of the Packages
registry. And it does not describe a working end-to-end journey: as of
2026-08-06, **no extension application has ever been registered, admitted,
installed, exposed, or System-bound in this estate**, and any document, demo, or
UI implying otherwise is describing fixtures.
