#!/usr/bin/env node
// ACC-10 · one operator workday across the estate — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. This is the coverage gate over the
// surfaces no other journey reaches, so clause 6 composes the product gates and the surface
// journeys how-to-check.md §4 lists (each boots its own daemon; this runner is long by nature).
// Clauses 7 and 9 name the units that still owe them as TYPED ABSENCES; clause 7 has no gate
// under any name and is recorded as M08.8's remainder (register R-138). Clause 5 executes M08.10's
// composed done-bar, check:packages-product-lifecycle (slices A–D landed 2026-09-14).
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
  // M08.9 landed 2026-09-14: canon's HypervisorSystemsProjection and HypervisorWorkSubjectProjection are registered and served, policy before search/counts/recents, owners never mutated, rebuild by re-derivation (check:systems-work-projections, floor-pinned).
  { id: "4", clause: "Systems and Work render truth they do not own: Work applies policy before search, counts, caching and recents and exposes typed subject refs", unit: "M08.9", checks: [bounded(app("check:systems-work-projections"), 20)] },
  // M08.10's composed done-bar (slices A–D landed 2026-09-14): it runs the packages journey, the
  // registry smoke, the compiler, the route tests and the contract bar on ONE basis.
  { id: "5", clause: "The package lifecycle is complete in both directions: intake, release, admission, install, registration, routing, then uninstall, recall, revocation and affected-System impact", unit: "M08.10", checks: [bounded(rootScript("check:packages-product-lifecycle"), 120)] },
  { id: "6", clause: "Deep links and navigation converge, or carry a typed documented difference; every status is asserted at HTTP and body level (the product gates and the surface journeys, each end to end against its own daemon)", unit: "M08 · how-to-check §4", checks: [...PRODUCT_GATES, ...SURFACE_JOURNEYS] },
  { id: "7", clause: "Every primary journey is accessible: keyboard, focus, screen reader, contrast, both themes, reduced motion, 390-pixel viewport, embed and back-stack", unit: "M08.8 (remainder)", absences: [{ what: "no accessibility gate exists under any name (measured 2026-09-14: no check:* script asserts keyboard/focus/screen-reader/contrast/theme/reduced-motion/390px/embed/back-stack over the compiled catalog)", owner: "M08.8 remainder (register R-138)" }] },
  { id: "8", clause: "Zero fixture fallback, proven negatively against a real daemon", unit: "M08 · seed provenance", checks: [app("check:seed-provenance")], structural: () => ({ ok: process.env.IOI_ACCEPTANCE_FIXTURES !== "enabled", detail: "the harness clears IOI_HYPERVISOR_DAEMON_URL / IOI_PRODUCT_UI_REPLAY and sets IOI_ACCEPTANCE_FIXTURES=disabled for every child above" }) },
  { id: "9", clause: "Collective work is an artifact ecology, not agent theater: ioi.ai and Hypervisor show the same room, ancestry, definitions, installations, health, dependencies, caretaker coverage, leases, effects and receipts", unit: "M08.17", absences: [absent("M08.17", "check:collective-artifact-ecology-surface", "the Collective mode and Work/Rooms surfaces over the M04.12 composition, which is itself unbuilt")] },
  // M08.11 landed 2026-09-20 (R-213): the App parks a refused provider operation as the byte-derived card,
  // the deployment-local tier mints one one-use grant for exactly the card's hashes, the App retries the
  // identical request and holds no grant — driven in-process over the daemon-minted challenge fixture with
  // the daemon transport and the custody tier injected; the real lane runs in the gate's full mode.
  { id: "10", clause: "A blocked spend is a card, and the App never signs it: a provider operation submitted through the App parks its challenge as the byte-derived card, the custody tier mints one one-use grant for exactly the card's hashes, the App retries the identical request and renders the daemon's receipt, operation and exposure", unit: "M08.11", checks: [{ ...bounded(rootScript("check:spend-approval-lane", ["--", "--drills"]), 15), allowsFixture: true }], battery: { ...rootScript("mutate:spend-approval-lane"), cost: "minutes" }, absences: [{ what: "the passkey step-up and the graduated wallet app as custody tiers, a signed denial receipt, the approvals-inbox row and the lane-issued C4 proposal", owner: "the passkey tier · the graduated wallet app · follow-on slices of M03.9 and M08.11 (owner questions, R-212/R-213)" }], scheduled: [{ what: "the live deployment_intent admission through the lane (a daemon-issued proposal, bid, lease, C6 readback, teardown, provider-confirmed settlement) and the session-execute card live (check:alpha-journey, deployment mode)", prerequisite: "an owner-authorized funded Akash account (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS); a local model and the deployment-local authority node", ruling: "R-139 (2026-09-14) and R-213 (2026-09-20): a missing credential, model or authority node blocks a live RUN, never the unit" }] },
  // M08.12 landed 2026-09-20 (R-214): the editor-side challenge relay — the attach authenticated by its
  // editor-open lease, the identical request under the user's own session through the M08.11 lane, a typed
  // notification with the decision links and nothing else, receipt parity read back from the daemon.
  { id: "11", clause: "An attached editor relays, it never signs: an editor-initiated effect reaches the daemon under the user's own session, its refusal parks as the same card, the editor receives a typed notification that deep-links the decision and carries no facet, grant or key, and the admitted operation's receipts are identical to the App path", unit: "M08.12", checks: [{ ...bounded(rootScript("check:editor-challenge-relay", ["--", "--drills"]), 15), allowsFixture: true }], battery: { ...rootScript("mutate:editor-challenge-relay"), cost: "minutes" }, absences: [{ what: "the rendering in a REAL VS Code and the packaged/JetBrains/SSH hosts, a daemon push channel for challenges, the Authority Gateway ide_extension crossing for provider operations, and Hypervisor Guard's sidecar packaging", owner: "the VS Code extension host · a daemon change · the Authority Gateway execute adapter · packaging (owner questions, R-214)" }], scheduled: [{ what: "the live deployment_intent admission relayed from an attached editor, and a hosted-editor leg on a host with the pinned openvscode-server runtime", prerequisite: "an owner-authorized funded Akash account (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS); IOI_EDITOR_RUNTIME_URL for the pinned editor runtime", ruling: "R-139 (2026-09-14) and R-214 (2026-09-20): a missing credential or editor runtime blocks a live RUN, never the unit" }] },
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
