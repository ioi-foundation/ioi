#!/usr/bin/env node
// ACC-10 · one operator workday across the estate — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. This is the coverage gate over the
// surfaces no other journey reaches, so clause 6 composes the product gates and the surface
// journeys how-to-check.md §4 lists (each boots its own daemon; this runner is long by nature).
// Clauses 4, 5, 7 and 9 name the units that still owe them as TYPED ABSENCES; clause 7 has no gate
// under any name and is recorded as M08.8's remainder (register R-138).
//
//   node scripts/check-acceptance-operator-workday.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, node, bounded } from "./lib/acceptance-journey.mjs";

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });
const SURFACE_JOURNEYS = [
  "check:ontology-journey",
  "check:governance-journey",
  "check:studio-journey",
  "check:automations-journey",
  "check:launch-chain",
  "check:session-authority",
  "check:projects-saga",
  "check:backup-restore",
  "check:environment-custody",
  "check:env-lease-authority",
  "check:model-route-authority",
  "check:model-router-decisions",
  "check:provider-transport",
  "check:ontology-backend-families",
].map((script) => bounded(app(script), 40));
const PRODUCT_GATES = ["check:ported-seed", "check:owned-product-ui", "check:shell-parity", "check:operational-depth"].map((script) => bounded(app(script), 30));

const CLAUSES = [
  { id: "1", clause: "One surface per click target: every launcher tile, canonical route, owner landing and certified deep route resolves to exactly one designated surface", unit: "M08.8", checks: [bounded(rootScript("check:product-surface-compiler"), 40), node("apps/hypervisor/scripts/check-landing-designations.mjs", ["--exit-gate"])] },
  { id: "2", clause: "Every surface is compiled, not hard-coded: shell, catalog, command palette, contextual and API projections come from one registration over the independent axes", unit: "M08.8", provenBy: "1" },
  { id: "3", clause: "Every lane is live or a typed absence: a named gap carries the disabled attribute, a human title, a machine reason and a citation to the adjudication", unit: "M08 · G-8", checks: [app("check:named-gap-truth")] },
  { id: "4", clause: "Systems and Work render truth they do not own: Work applies policy before search, counts, caching and recents and exposes typed subject refs", unit: "M08.9", absences: [absent("M08.9", "check:systems-work-projections", "the Systems projection's nonmutation and the typed Work subject contract")] },
  { id: "5", clause: "The package lifecycle is complete in both directions: intake, release, admission, install, registration, routing, then uninstall, recall, revocation and affected-System impact", unit: "M08.10", checks: [bounded(app("check:packages-journey"), 30)], absences: [absent("M08.10", "check:packages-product-lifecycle", "candidate/intake, dependency refs on the release, the extension_application registration the route's own nonclaim names, compiler/serving integration and affected-System impact on recall")] },
  { id: "6", clause: "Deep links and navigation converge, or carry a typed documented difference; every status is asserted at HTTP and body level (the product gates and the surface journeys, each end to end against its own daemon)", unit: "M08 · how-to-check §4", checks: [...PRODUCT_GATES, ...SURFACE_JOURNEYS] },
  { id: "7", clause: "Every primary journey is accessible: keyboard, focus, screen reader, contrast, both themes, reduced motion, 390-pixel viewport, embed and back-stack", unit: "M08.8 (remainder)", absences: [{ what: "no accessibility gate exists under any name (measured 2026-09-14: no check:* script asserts keyboard/focus/screen-reader/contrast/theme/reduced-motion/390px/embed/back-stack over the compiled catalog)", owner: "M08.8 remainder (register R-138)" }] },
  { id: "8", clause: "Zero fixture fallback, proven negatively against a real daemon", unit: "M08 · seed provenance", checks: [app("check:seed-provenance")], structural: () => ({ ok: process.env.IOI_ACCEPTANCE_FIXTURES !== "enabled", detail: "the harness clears IOI_HYPERVISOR_DAEMON_URL / IOI_PRODUCT_UI_REPLAY and sets IOI_ACCEPTANCE_FIXTURES=disabled for every child above" }) },
  { id: "9", clause: "Collective work is an artifact ecology, not agent theater: ioi.ai and Hypervisor show the same room, ancestry, definitions, installations, health, dependencies, caretaker coverage, leases, effects and receipts", unit: "M08.17", absences: [absent("M08.17", "check:collective-artifact-ecology-surface", "the Collective mode and Work/Rooms surfaces over the M04.12 composition, which is itself unbuilt")] },
  { id: "N1", negative: true, clause: "No capture link is offered as a product call to action", unit: "M08 · seed provenance", provenBy: "8" },
  { id: "N2", negative: true, clause: "No parity matrix, capture or pixel certificate registers a surface, assigns an owner or grants maturity", unit: "M08.8", provenBy: "1" },
  { id: "N3", negative: true, clause: "No surface is built ahead of the contract that pulls it (every named gap cites its adjudication)", unit: "M08 · G-8", provenBy: "3" },
  { id: "N4", negative: true, clause: "No chat, board or artifact-ecology projection becomes room, runtime, installation, authority, health or evaluation truth", unit: "M08.17", absences: [absent("M08.17", "check:collective-artifact-ecology-surface", "the projection-is-not-truth negatives")] },
  // check:verifier-floors is NOT composed here (R-145): its world is closed over every CI-gated
  // verifier and a single journey's census reads as `census_missing` for the rest; ACC-R checks the
  // floor over the union of the journeys' census directories.
  { id: "E", clause: "Journey evidence: the act tool's interactive and headless draw-down over the daemon's lease projection (the verifier-family floor is ACC-R's, over the union of the journeys' runs)", unit: "M08.13 · M08.14", checks: [app("check:standing-consumer-loop")] },
];

await runJourney({
  gate: "ACC-10",
  title: "one operator workday across the estate",
  doc: "internal-docs/implementation/acceptance/journey-10-operator-workday.md",
  clauses: CLAUSES,
});
