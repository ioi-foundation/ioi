# The Hypervisor wiring master guide — table of contents

This directory plus its two companion documents **is** the master guide for
wiring every Hypervisor surface from the UX states that exist today to its
canonical functional end state. A session that needs to build a surface should be
able to start here and never re-derive a seed disposition, a schema binding, or an
ontology/ODK lane.

**Status: research and planning complete as of 2026-08-06. No surface is built.**
All twenty briefs carry the full eight-section shape, and the seed-mesh + ODK
wiring run (`../../overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`) closed its
ledger on that date — that run changed documentation and one Rust file, and
**zero files under `apps/hypervisor/`**.

The build run (`../../overhaul/2026-08-05-hypervisor-bring-to-life-run.md`)
executes from here and **still has 26 unchecked rows**, including all twenty
surface builds, SCM P0–P3, shared cutover, and repository-wide disposition.
Nothing in this directory makes the canonical UX functional.

## What each brief contains

Sections 1–5 were authored 2026-08-05 (Phase A of the build run); sections 6–8
were appended per-surface 2026-08-06 by the mesh run. Numbering after §5 shifts by
one in `foundry.md`, which carries an earlier route-plane defect register at §6.

| § | Section | Answers |
|---|---|---|
| 1 | Canon digest | what canon says this surface is, cited to the line |
| 2 | Schema map | canon object → registry/canon block → daemon route today → gap wave |
| 3 | UI seed map (+ Corrections vs v0) | what exists and is traversable today, byte-verified |
| 4 | Schema→UI binding table | pane → backing schema + route → current state → target state |
| 5 | Ordered PR list | the wave-sequenced build |
| 6 | **Seed mesh ledger** | every seed artifact across five tiers, dispositioned with its census facts and canon end state |
| 7 | **Ontology wiring** | the exact semantic-plane primitives the surface reads or writes, with routes — `none` where honest |
| 8 | **ODK descriptor and extension lane** | which panes are descriptor-expressible and why the rest are not; what the surface exposes to the extension lane |

Disposition vocabulary in §6 is fixed: `rehome` · `rebind` · `pattern-harvest` ·
`retire-at-cutover` · `blocked-missing-capture` · `blocked-missing-route`. Two
briefs also record rows as **build, not mesh** (routes exist, no seed to
disposition) and one as **deferred to an owner ruling**.

## The twenty briefs

`Mesh` = §6 seed mesh ledger · `Ont` = §7 ontology wiring · `ODK` = §8 descriptor
and extension lane. `Expr` counts panes recorded **descriptor-expressible**.
`T3 controls` is the surface's share of the 563-control census baseline.

| Brief | Route | Kind | T3 controls | Mesh | Ont | ODK | Expr | Journey stage | Primary waves |
|---|---|---|---|---|---|---|---|---|---|
| [home.md](home.md) | `/home` | core workspace | 0 | ☑ | none | ☑ | 0 | — | W0.1 · W1 |
| [systems.md](systems.md) | `/systems` | core workspace | 0 | ☑ | none | ☑ | 0 | **9** bind for effect | W1 · W3 |
| [projects.md](projects.md) | `/projects` | core workspace | 0 | ☑ | none | ☑ | 0 | — | W1 |
| [applications.md](applications.md) | `/applications` | core workspace | 0 | ☑ | declared refs | ☑ | 0 | **7** register · **8** expose | W0.2 · W1 · W3 |
| [work.md](work.md) | `/work` (owns `/work/sessions`) | core workspace | 52 | ☑ | none | ☑ | 0 | — | W0.6 · W1 · W3 · W4 |
| [settings.md](settings.md) | `/settings` | core workspace | 0 | ☑ | none | ☑ | 0 | — | W0.5 · W1 · W4 |
| [studio.md](studio.md) | `/studio` | owner application | 81 | ☑ | descriptors + DomainApp | ☑ | 2 | **3** author · **4** shape | W1 · W3 |
| [automations.md](automations.md) | `/automations` | owner application | 29 | ☑ | object-set triggers (unbound) | ☑ | 0 | — | W0.6 · W1 · W2 · W3 |
| [ontology.md](ontology.md) | `/ontology` | owner application | 95 | ☑ | **owner** | ☑ | **4** | **1** describe | W1 · W2 · W3 |
| [data.md](data.md) | `/data` | owner application | 115 | ☑ | **supply side** | ☑ | **3** | **2** bind data | W1 · W2 · W3 |
| [governance.md](governance.md) | `/governance` | owner application | 40 | ☑ | mount gate + kill | ☑ | 0 | **10** admit | W0.6 · W1 · W2 · W3 |
| [provenance.md](provenance.md) | `/provenance` | owner application | 0 | ☑ | **11 ODK reads** | ☑ | **2** | — | W1 · W3 |
| [evaluations.md](evaluations.md) | `/evaluations` | owner application | 32 | ☑ | eval packs (unbound) | ☑ | 0 | — | W1 · W2 · W3 |
| [improvement.md](improvement.md) | `/improvement` | owner application | 47 | ☑ | none | ☑ | 0 | — | W1 · W2 · W3 |
| [foundry.md](foundry.md) | `/foundry` | owner application | 39 | ☑ | consumer-with-a-gate | ☑ | 0 | — | W1 · W2 · W3.0–W3.4 |
| [packages.md](packages.md) | `/packages` | owner application | 33 | ☑ | ontology packs (unbound) | ☑ | 0 | **5** package · **6** admit · **7** install | W3 (biggest build) |
| [developer-workspace.md](developer-workspace.md) | `/developer-workspace` | owner application | 0 | ☑ | none | ☑ | 0 | — | W1 · W2 · W4 |
| [developer-console.md](developer-console.md) | `/developer-console` | owner application | 0 | ☑ | none | ☑ | 0 | kit on-ramps (no pane) | W1 · W2 |
| [environments.md](environments.md) | `/environments` | substrate | 0 | ☑ | none | ☑ | 0 | — | W1 · W2 · W3 |
| [operations.md](operations.md) | `/operations` | substrate | 0 | ☑ | none | ☑ | 0 | **10** observe | W1 · W2 · W3 |

**Coverage: 20/20 meshed, 20/20 ontology-wired, 20/20 ODK-laned.** T3 controls sum
to **563**, the full census baseline, with every surface's share reconciled inside
its own §6.

Embodied Systems (`/embodied-systems`) is a reserved, nonlaunchable registration
row in the compiler (planned) — no brief, no UI work.

## Companion documents

- [`../odk-extension-apps.md`](../odk-extension-apps.md) — **the user-tailored
  application lane end to end.** The ten-stage composable-application journey
  against the bytes, the implemented Domain App mount ladder, the invariant-11
  conformance bar, and the two-ledger contract each brief's §8 fills in. Every
  brief's §8 points here.
- [`../scm-transition-chain-epic.md`](../scm-transition-chain-epic.md) — the
  Git/Agentgres transition-chain epic: five P0 truthfulness defects, the
  owner-by-owner missing-interface table, the missing-contracts build-list, and
  P0→P3 wave interleaving. Nine briefs carry a pointer to their §2 row.
- [`../build-acceptance-gates.md`](../build-acceptance-gates.md) — **the
  all-surface Definition of Done.** Eight gates binding on every surface build:
  HEAD truth-refresh, request-scoped identity propagation, mutation correctness,
  the descriptor/Studio vertical slice, the Packages/application lifecycle, a real
  generated runtime, canonical routing and cutover, and the promoted C1–C30
  operational criteria. **Read before starting any surface build**; it also
  records what green CI does and does not certify.
- [`../repo-ux-disposition.md`](../repo-ux-disposition.md) — repository-wide
  surface disposition ledger for estate surfaces outside these briefs, **plus the
  X-3 harvest-capture sweep**: all 39 `/__apps/*` captures, each with exactly one
  home. Zero undispositioned, zero multi-homed.

## What the mesh found across all twenty surfaces

Six findings recur widely enough that a build session should know them before
opening any single brief.

**1. Governed controls are concentrated in two surfaces.** Of the estate's 24
`governed_receipted_action` controls, **Ontology holds 13 (54%) and Governance
3** — 16 of 24 on two surfaces. Eleven of the twenty surfaces have zero, and for
most of those that is correct (read models, substrate, projection-only
workspaces) rather than a gap.

**2. The extension lane is built at both ends and empty in the middle.**
Authoring (stages 1–4) is 56 ODK route registrations; mounting and serving (stage
10) is a complete six-rung governed ladder. Between them, **stages 5–9 have
essentially no routes**: no `/v1/hypervisor/packages/*` family, zero
`extension_application` registrations, `system_interface_bindings: []`. The lane
is gated on the **Packages registry**, not on more ODK work.

**3. Descriptor authoring is wired in the wrong place, against a contract too thin
to conform.** *(Corrected 2026-08-06 — this finding first claimed no pane called
the route, which is false.)* A create/edit form and POST/PATCH dispatch exist in
the legacy ODK substrate readout (`serve-product-ui.mjs:3320`, `:9776`) — not
under Studio's canonical route — and they write four fields, none of them
invariant 11's binding set. Stage 3 needs a **rehome plus a contract widening**,
not a build from zero.

**4. Eleven panes across four surfaces are descriptor-expressible; none is
descriptor-rendered.** The four blocking limitations are now canon
(`domain-ontologies-and-data-recipes.md` → "Contract limitations found by
dogfooding"): the descriptor cannot bind a platform object family; it has no write
semantics; some canonical inboxes are cross-owner by construction; and three
first-party shapes have no matching pattern.

**5. A third of the harvest estate cannot be inspected.** **13** of 39 captures are
`blocked_missing_capture`. Where a brief says `pattern-harvest`, it is harvesting
a grammar that boots; where it says `blocked-missing-capture`, it is declining to
claim anything at all.

**6. Retired owner names still label ten captures and several routes.** Missions,
Marketplace, Workbench, and Domain Apps rehome into Work, Packages, Developer
Workspace, and Studio respectively. **None is revived as a peer application.**

## Using this guide to build a surface

1. Read the brief's §1 canon digest and §6 seed mesh ledger together — the ledger
   tells you what already exists and whether it moves, rebinds, or dies.
2. Take §5's ordered PR list. Cross-check each PR against §4's target-state column
   and §6's wave column; they are the same schedule seen three ways.
3. Before wiring any pane that touches semantics, read §7. If the row says
   `none — not object-bound`, that is a contract, not a gap: do not invent a
   binding to fill it.
4. Before building any authoring pane, read §8(a). If the pane is exempt, the
   reason is recorded; if it is expressible, it is a candidate for
   descriptor-driven rendering **once the descriptor record can hold its own
   contract**.
5. Honour the seed-preservation invariant: a protected seed retires only through
   its surface's six-step cutover, and a `pattern-harvest` row licenses no code
   movement.
