# Public Web Estate: Properties, Taxonomies, and Claim Rules

Status: canonical architecture authority.
Canonical owner: this file for public web-property boundaries, public taxonomy
axes, public status-claim rules, and estate messaging governance.
Supersedes: ad-hoc marketing-page taxonomy and unowned public claims when they
conflict.
Superseded by: none.
Last alignment pass: 2026-07-21.
Doctrine status: canonical
Implementation status: partial (hypervisor.com spine + status manifest + build
audit live; ioi-ai manifest mirror pending; ioi.ai property planned)
Last implementation audit: 2026-07-21

This file does not own product or application naming. App-suite naming is
owned by the vocabulary and suite canon; this file owns how that estate is
presented across the public web properties and which claims each property may
make.

## Property Contract

Three properties, three jobs. Each property links the others; none duplicates
another's job.

```text
internetofintelligence.com
  the thesis: long-form institutional and explanatory domain — canon,
  whitepaper v1.10.0, papers, roadmap, status truth. The honesty anchor.

hypervisor.com
  the product: what you install and operate. Standalone marketing surface
  today; its full rework is gated on the application suite being
  operationally complete and camera-ready (see Gates).

ioi.ai
  the front door: primary public umbrella and account/control-plane entry,
  activated when the Goal Space product is real (owner:
  domains/ioi-ai/control-plane.md). Vacant until then by decision, with
  internetofintelligence.com holding the umbrella job.
```

## Taxonomy Axes

The estate legitimately presents three different maps of one system. They are
axes, not competing taxonomies, and each surface must use the axis named for
it — mixing axes on one surface is drift.

```text
packaging axis (hypervisor.com "Platform")
  nine distributable products: clients (App · Web · CLI), builder kits
  (SDK · ADK · ODK), gateways & substrate (MCP · HypervisorOS · Embodied
  Runtime). This is what a customer downloads, opens, or provisions.

application axis (in-product; suite canon owns naming)
  the governed application suite rendered inside the product (Studio,
  Automations, Ontology, Data, Governance, Missions, Provenance,
  Evaluations, Improvement, Foundry, Marketplace, Workbench, Developer
  Console) plus the substrate lane. Public surfaces reference these only
  with real, current screens once camera-ready (see Gates).

narrative axis (internetofintelligence.com product-surface story)
  the protocol story chapters (Hypervisor → workers → outcome services →
  control plane → sovereign systems → optional settlement). This is a
  reading order, not a catalog.
```

## The Two Lanes

The product story is told in two lanes, and every product page belongs to
exactly one:

```text
run-on   Build and operate autonomous systems on the substrate. Effects only
         exist through capability exits, leases, and receipts.

attach   Attach the Authority Gateway to agents you already run. Audit, hold
         for exact-action approval, and receipt their consequential actions.
```

The attach lane must never claim total interception over opaque third-party
runtimes (owner: components/daemon-runtime/doctrine.md). Its public claims are
bounded by the enforcement-coverage vocabulary (discovered / observable /
attributable / mediated / preventable / receipted / uncovered).

## Hypervisor Type Lineage

The public master frame for hypervisor.com: Type 1 virtualized hardware,
Type 2 virtualized operating systems, Type 3 governs autonomous work and
includes the layers beneath. Definitions live in the estate messaging spine
(`apps/hypervisor-web/src/config/estateMessaging.js`, pending upstream to the
ioi-ai owner file). The lineage is a framing claim, not a shipping claim:
HypervisorOS remains design-stage and must be labeled as such wherever the
lineage is rendered.

## Status Axis and Claim Rules

```text
every public surface declares a stage from the estate status manifest
(private-preview · design-stage · single-node-proof · evidence-gated ·
planned); no copy may claim a stage ahead of the manifest
proof points must be architectural invariants or receipted facts — never
compliance badges, customer counts, or usage telemetry that does not exist
mockups presented where product screens will live must be visibly labeled
or replaced by generated captures of real receipted runs (see Gates)
```

The manifest is `apps/hypervisor-web/src/config/estateStatus.js` (single flip
point; ioi-ai mirrors it). Build-time audits enforce banned phrases and
required literals on hypervisor.com (`tools/audit-estate.mjs`) and parity on
internetofintelligence.com (`tools/audit-seo.mjs`).

## Naming and Domain Rulings

```text
product domain      hypervisor.com (app.hypervisor.com · get.hypervisor.com);
                    the .io fork is retired
RFA                 expands to "Request for Worker" everywhere; the acting
                    party in public copy is the Worker, not "agent"
legal entity        OPEN: "IOI, Inc." (hypervisor.com footer) vs
                    "IOI Foundation" (internetofintelligence.com) — needs an
                    owner decision before either is propagated further
```

## Gates

```text
hypervisor.com rework    gated on the application suite being operationally
                         complete and site-shot certified (per-app done bar);
                         executed against the rework spec and generated
                         captures, not staged screenshots
ioi.ai activation        gated on the Goal Space product being real (owner:
                         domains/ioi-ai/control-plane.md §Public Umbrella
                         Boundary)
```

Until those gates open, estate work is words, status truth, link topology,
and capture mechanics — nothing that the gated rework would redo.
