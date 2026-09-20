#!/usr/bin/env node
// ACC-3 · authority is delegated, bounded, and revoked — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. Every ACC-3 clause names the existing
// done-bar that proves it, executed sequentially on ONE basis, or the unit that still owes it as a
// TYPED ABSENCE. Batteries that plant defects in daemon source (the standing-lease and trajectory
// drills) are multi-hour and run only with --mutation-batteries; population drills run always.
//
//   node scripts/check-acceptance-authority-and-leases.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, bounded } from "./lib/acceptance-journey.mjs";

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });
// The deployment-mode run that CARRIES the two approval-card rows (Work / Sessions and the SPA pane) is the
// 2026-09-08 release run; the 2026-09-10 file this cited until R-212 is a STANDING-lease run whose only card
// rows say the run never parked (measured 2026-09-20 by walking its steps).
const ALPHA_DEPLOYMENT_EVIDENCE = "docs/architecture/_meta/evidence/m12-alpha-journey-release-no-checkout-2026-09-08.v1.json";

const CLAUSES = [
  { id: "1", clause: "Ownership comes from the scope pin: an environment's owner resolves from the substrate binding made before its first durable byte; an authenticated non-owner is refused and the refusal is counted against zero durable effects", unit: "M03.1 · M03.2", checks: [app("check:env-lease-authority")] },
  { id: "2", clause: "The grant chain is portable and single-use: request → reviewed representation → single-use approval ceremony → typed authorization subject, bound into one grant; the pre-invocation decision is receipted; the gateway path resolves the same chain", unit: "M03.5 · M03.6", checks: [rootScript("check:portable-v3-grant-chain"), rootScript("check:authority-gateway-profile")], battery: [{ ...rootScript("mutate:portable-v3-grant-chain"), cost: "minutes" }, { ...rootScript("mutate:authority-gateway-profile"), cost: "minutes" }] },
  { id: "3", clause: "A lease is bounded on every axis — scope, TTL, heartbeat, policy, visibility, authority, resource and budget — and expiry ends the capability without a revocation call", unit: "M03.10 · M03.12", checks: [rootScript("check:standing-envelope-template"), rootScript("check:standing-lease-lifecycle")], battery: [{ ...rootScript("mutate:standing-envelope-template"), cost: "multi-hour" }, { ...rootScript("mutate:standing-lease-lifecycle"), cost: "multi-hour" }] },
  { id: "4", clause: "Revocation is immediate and legible: a revoked grant fails the next admission, and an in-flight effect enters its declared recovery posture rather than completing quietly", unit: "M03.12 · M06.2", provenBy: "3", checks: [rootScript("check:typed-effect-recovery")], battery: { ...rootScript("mutate:typed-effect-recovery"), cost: "multi-hour" } },
  { id: "5", clause: "Recovery never widens: a device transition or account recovery produces no grant the prior state did not already have", unit: "M03.5 · M03.8", provenBy: "2", checks: [rootScript("check:device-held-wallet-principal")], battery: { ...rootScript("mutate:device-held-wallet-principal"), cost: "multi-hour" } },
  { id: "6", clause: "A denial is method-precise: what a contract denies is recorded as route plus method; a prose mention with no typed sibling fact remains a citation", unit: "M03.3", checks: [app("check:named-gap-truth"), rootScript("check:architecture-contracts"), rootScript("check:architecture-docs")] },
  { id: "7", clause: "An externally owned account binds a session, not an effect: wallet linkage creates a product session and every consequential path still commits its own authority request", unit: "M03.7", checks: [rootScript("check:wallet-siwe-link-owner-v2")], battery: { ...rootScript("mutate:wallet-siwe-link-owner-v2"), cost: "minutes" } },
  { id: "8", clause: "Human authentication unlocks custody and does not travel with the worker: an enrolled passkey/device/guardian factor, no reusable operator password or plaintext recovery file in the daemon/model-readable data plane", unit: "M03.8", checks: [rootScript("check:device-custody-boundary")], battery: { ...rootScript("mutate:device-custody-boundary"), cost: "multi-hour" } },
  { id: "9", clause: "The worker demonstrably does not possess secrets: files, environment, process inspection and the broker API yield no vault storage, unlock material, recovery credentials, provider tokens or root sessions", unit: "M03.13", checks: [app("check:worker-secret-non-possession")] },
  // M03.9 landed 2026-09-20 (R-212): the daemon publishes the preimage bytes its commitment hashes cover, the
  // card grammar renders every hashed member from those bytes, and the diff harness refuses paraphrase,
  // truncation, re-statement and reconstruction — executed spend-free over a tracked daemon-minted fixture.
  { id: "10", clause: "The wallet renders the exact signed facets: amount/denomination, deposit, selector, artifact/config hash, teardown policy and stage derive from the canonical challenge bytes", unit: "M03.9", checks: [{ ...bounded(rootScript("check:approval-card-facets", ["--", "--drills"]), 15), allowsFixture: true }], battery: { ...rootScript("mutate:approval-card-facets"), cost: "minutes" }, cited: [{ label: "the alpha journey's approval card rendering the daemon's exact policy/request commitments for session execute and credential bind (deployment-local custody tier)", evidence: ALPHA_DEPLOYMENT_EVIDENCE }], absences: [{ what: "the App lane that PARKS a blocked provider operation as this card and hands it to the custody tier (the card grammar and its oracle are M03.9's; the routing is M08.11's), the graduated wallet app's handoff, and a signed denial receipt (no deny act exists on the authority node or the fixture)", owner: "M08.11 · the graduated wallet app · a follow-on slice of M03.9 (R-212)" }], scheduled: [{ what: "the session-execute and custody cards LIVE under the deployment-local tier — check:alpha-journey with IOI_ALPHA_JOURNEY_AUTHORITY=deployment", prerequisite: "a local model (Ollama) and the deployment-local authority node", ruling: "R-139 (2026-09-14) and R-212 (2026-09-20): a missing local model or authority node blocks that RUN, never the unit" }] },
  { id: "11", clause: "Standing authority is a bounded lease, not configuration: one ceremony signs a facet template, cumulative budget, expiry and use count; every unattended draw proves exact containment and currentness", unit: "M03.10", provenBy: "3", checks: [rootScript("check:standing-authority")], battery: { ...rootScript("mutate:standing-authority"), cost: "multi-hour" } },
  { id: "12", clause: "Draw-down and trajectory admission are atomic: usage, cumulative amount, C2 intent and AuthorityTrajectoryStateV1 advance at one admitted boundary; salami-slicing cannot exceed an ancestor's bound; denial consumes nothing", unit: "M03.11 · M03.14", checks: [rootScript("check:standing-drawdown-metering"), rootScript("check:authority-trajectory-admission")], battery: [{ ...rootScript("mutate:standing-drawdown-metering"), cost: "multi-hour" }, { ...rootScript("mutate:authority-trajectory-admission"), cost: "multi-hour" }] },
  { id: "13", clause: "Interactive and headless clients consume the same truth: an opaque capability handle produces the same receipt/state-root chain in both modes; restart preserves budget/uses, revoke fences the next use, no lease refuses rather than falling back", unit: "M08.13 · M08.14", checks: [app("check:standing-consumer-loop")] },
  // Since 2026-09-16 M03.16's own gate (check:provider-connection-lifecycle, ISOLATED, a stub OAuth
  // provider the daemon reaches over the wire) proves the clause: a registered single-use ceremony bound
  // to the resolved principal and the exact provider profile revision; every completion refusal admitted
  // as the ceremony's own successor; the binding's commitments re-derived from the records; the raw
  // tokens nowhere in plaintext; the fence at the single brokered-use gateway; verify observing
  // revocation; reauthorize and reconnect as successor versions that never revive a predecessor;
  // disconnect with durable obligations; the legacy connector oauth routes sharing the lineage.
  { id: "14", clause: "Connected is not authorized: a replay-safe provider ceremony creates a versioned ProviderConnectionBinding and brokered credential relationship, not a grant; disconnect, provider revocation, expiry and rotation fence the next use; reconnect creates successor lineage", unit: "M03.16", checks: [app("check:provider-connection-lifecycle"), app("mutate:provider-connection-lifecycle")] },
  { id: "N1", negative: true, clause: "A tenant check alone isolates nothing, and the journey asserts that directly", unit: "M03.1", provenBy: "1" },
  { id: "N2", negative: true, clause: "A preview or cross-consumer path cannot reach another environment's ports", unit: "M03.2", provenBy: "1" },
  { id: "N3", negative: true, clause: "No route mints ownership that cannot refuse", unit: "M03.1", provenBy: "1" },
  { id: "N4", negative: true, clause: "Sharing an OS principal, readable environment/process namespace or vault unlock material with the model worker cannot qualify as secret isolation", unit: "M03.13", provenBy: "9" },
  { id: "N5", negative: true, clause: "Host filters, remembered UI approval, a commercial entitlement or a successful prior draw cannot mint, widen or refresh standing authority", unit: "M08.13 · M03.10", provenBy: "13" },
  { id: "N6", negative: true, clause: "Provider-granted scopes, an active connection badge, an installed connector, credential presence or a prior provider success cannot mint action authority; asynchronous dependent cleanup cannot delay disconnect fencing", unit: "M03.16", absences: [absent("M03.16", "check:provider-connection-lifecycle", "the connected-is-not-authorized negatives")] },
  { id: "E", clause: "Journey evidence the document names beyond the clauses: session authority, model-route authority and admission evidence", unit: "M03", checks: [app("check:session-authority"), app("check:model-route-authority"), rootScript("check:admission-evidence")], absences: [absent("M08.16", "check:connected-access-cockpit", "the embedded / Hypervisor / advanced connected-access views over one daemon")] },
];

await runJourney({
  gate: "ACC-3",
  title: "authority is delegated, bounded, and revoked",
  doc: "internal-docs/implementation/acceptance/journey-03-authority-and-leases.md",
  clauses: CLAUSES,
});
