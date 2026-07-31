---
module_id: product-ux
module_class: method
title: Product compression and application depth
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M4, M5, M6, M7, M9]
legacy_id: WP-UX
canon_owners:
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
  - docs/architecture/components/hypervisor/identity-access-and-metering.md
  - docs/architecture/foundations/canonical-enums.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
  - docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md
  - docs/conformance/hypervisor-core/sovereign-local-completeness.md
---

# Product Compression And Application Depth

## What this module owns

This module owns the reusable method for compressing a governed runtime into one coherent operable product and
for proving honest depth behind each admitted surface: the zero-to-operable local journey, evidence-bearing
project discovery, non-fabricating operational readouts, one compact composition path beside one advanced
declaration, product-language leadership, the reference-evidence boundary, and seed reclassification. It owns a
method only — it never orders work, never carries status, and is never a sequencer; the pulling stage supplies
ordering and the owning work-item record supplies status.

## Pulled by

The stages named by `modules[].applies_to_stages` for `product-ux` in
[`sequence.v1.json`](../program/sequence.v1.json): **M4**, **M5**, **M6**, **M7**, **M9**. M6 pulls it beside
[`product-surface-ux-proof.md`](./product-surface-ux-proof.md), which owns the surface-compiler and
state/accessibility proof detail. The sequencer owns those bindings; this file adds none. Preparatory or shadow
application may precede the first pull, the terminal first-user product proof falls to the M9 pull, and later
deployment profiles add depth afterward; none of that reclassifies a stage, and none is presentable as product
truth outside the pulling stage's evidence.

## Canon owners

Owners for a pull are the Hypervisor core clients/surfaces owner plus each application-domain owner whose
objects the surface projects.

| Canon owner | What it governs here |
| --- | --- |
| [`hypervisor/core-clients-surfaces.md`](../../../docs/architecture/components/hypervisor/core-clients-surfaces.md) | Zero-to-operable local deployment journey, client/workspace/application-surface boundaries, `HypervisorProjectDiscoveryProposal` review semantics, compact-guided to complete-typed authoring, product-language and progressive-disclosure doctrine |
| [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md) | CLI/headless operator surface, shared lifecycle verbs, read-only status/doctor, uninstall-is-not-wipe, signed update/rollback trust transition |
| [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md) | Project-discovery proposal/accept, session and environment-ops, backup/archive/restore, route-binding, and cleanup-obligation APIs these surfaces read and call |
| [`daemon-runtime/platform-operability.md`](../../../docs/architecture/components/daemon-runtime/platform-operability.md) | Degraded, unavailable, stale, recovery, and forward-only-activation dispositions a surface may render, and the refusal boundary it must respect |
| [`hypervisor/identity-access-and-metering.md`](../../../docs/architecture/components/hypervisor/identity-access-and-metering.md) | Permissions, connected access and pairing lifecycle, principal-scoped leases, usage/budget projection, revoke |
| [`foundations/canonical-enums.md`](../../../docs/architecture/foundations/canonical-enums.md) | Surface class, publisher origin, creation method, distribution, capability depth, and operational-state member sets used by seed reclassification |
| [`foundations/common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md) | Envelope, ref, and hash shapes every composition path must compile to |
| [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md) | Payment, charging, and commercial-truth boundaries behind any payments surface |
| [`decisions/0016 application taxonomy`](../../../docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md) | Systems/Work product spine and application membership decisions this method renders |
| [`conformance/sovereign-local-completeness.md`](../../../docs/conformance/hypervisor-core/sovereign-local-completeness.md) | Conformance scenarios for the standalone local journey and managed optionality |

## Retained obligations

- **Zero-to-operable local journey.** Make it one coherent experience across signed release verification, install
  preview, explicit host authorization, deployment-local bootstrap, bounded readiness, shared status/doctor/logs,
  signed update/rollback, stop/uninstall, separate wipe, and verified recovery. App, Web, CLI/headless, SDK, and
  optional TUI projections resolve the same deployment state, never separate lifecycle truth.
- **Evidence-bearing discovery.** Render project-discovery candidates as proposals whose exact source snapshot,
  detector, confidence, conflicts, unknowns, selection, and admitted overrides remain reviewable before Project
  or recipe creation. Detection by itself creates nothing and runs nothing.
- **Operational truth without fabrication.** Expose route ownership, TLS, drift, backup completeness, staged
  restore gates, forward-only activation, and outstanding cleanup obligations without fabricating missing runtime
  truth; lost owner truth renders a typed unavailable or degraded state.
- **Composition parity.** Compose real objects through one compact path and one advanced declaration that compile
  to the same hashes, with movement in both directions losing no meaning and inventing no hidden defaults.
- **Leading surfaces.** Lead with Systems, goals, work, sessions, automations, applications, permissions,
  connected apps, evidence, payments, and revoke.
- **Compression without concealment.** Hide protocol vocabulary from routine work without hiding authority,
  uncertainty, denial, recovery, or provenance.
- **Reference-evidence boundary.** Use reference-product interaction evidence only for layout grammar,
  information density, editors, canvases, drawers, diff/review, lineage, and operational affordances. It is never
  a source for canonical application names or membership, target object ownership, runtime authority or truth,
  current route/file anchors, or a surface-by-surface implementation queue.
- **No membership by resemblance.** Never let a copied surface, name, screenshot, parity score, or harvest route
  grant product membership or operational maturity.
- **Journey before catalog.** Close one user journey before broad catalog expansion.

**Seed certification rule.** A certified seed or port means only that the captured interaction pattern, asset, or
local implementation passed its declared evidence test. It is reclassified against the current application
topology:

```text
seed evidence
  -> current canonical owner
  -> owning M-stage contract
  -> current product registration class
  -> daemon/Agentgres/authority data source
  -> honest capability depth and operational state
  -> focused product and adversarial verifier
```

Seeds with no current owner or contract remain evidence. They do not create another application.

## Applying it in a work item

- Name in scope which journey segments, discovery review, operational readouts, composition parity, leading
  surfaces, or seed inputs the cut touches, with the canon owner and application-domain owner for every
  projected object.
- Bind each rendered field to its owner API response or Agentgres-backed projection, and record the
  fixture-versus-real-source disposition plus the explicit reference profile for any remaining fixture data.
- Retain evidence for the honest empty, denied, revoked, unavailable, degraded, stale, recovery, and completed
  renderings of each admitted surface, plus denial evidence showing zero final-invoker calls on refusal.
- For discovery, retain the exact proposal ref/hash, selected candidate, and admitted override-set ref/hash, with
  proof that acceptance bound them into the created Project or recipe and executed no repository code.
- For composition parity, retain both authored forms, the compiled artifact identity or hash each produced, and
  the round-trip evidence.
- For any seed input, retain the completed reclassification chain rows and the focused product and adversarial
  verifier the seed answers to; record unowned seeds as evidence carrying no registration.

## Terminal evidence

The method's contribution to a stage exit closes when the pulled journey runs end to end against owner-supplied
truth on the stage's selected deployment profile, every consequential control in it revalidates authority at the
final invoker and produces a receipt, the adversarial and degraded renderings are retained under `evidence/`, no
admitted surface reports capability depth or operational state above what its owner data source supports, and the
nonclaims for uncovered surfaces are explicit in the owning record.

## Canon gaps

- Whether the compact guided form and the complete typed declaration must produce byte-identical canonical
  hashes, or only equivalent admitted contracts, is unsettled. Owners:
  `docs/architecture/components/hypervisor/core-clients-surfaces.md`,
  `docs/architecture/foundations/common-objects-and-envelopes.md`.
- Whether `HypervisorProjectDiscoveryProposal` must carry an exact scanned source-snapshot digest and a detector
  identity/version beside its candidates, confidence, conflicts, unknowns, and overrides is not stated. Owners:
  `docs/architecture/components/hypervisor/core-clients-surfaces.md`,
  `docs/architecture/components/daemon-runtime/api.md`.
- No canonical registration value distinguishes retained reference-capture or seed evidence from an admitted
  surface, leaving "remains evidence" without a typed form. Owners:
  `docs/architecture/foundations/canonical-enums.md`,
  `docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md`.
