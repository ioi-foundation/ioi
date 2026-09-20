#!/usr/bin/env node
// ACC-11 · an environment composes, runs, restores, and closes its spend — the composed runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. The journey names live effects "only in
// a separately authorized exact-evidence lane": the spend-closure live leg is held the way M01.7
// holds it and R-139 records it (retained live evidence re-qualified by an applicability gate on
// every run; a fresh live transaction SCHEDULED-OUTSTANDING with its prerequisite named).
//
//   node scripts/check-acceptance-environment-lifecycle-spend.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, node, bounded } from "./lib/acceptance-journey.mjs";

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });
const LIVE_RULING = "R-139 (2026-09-14, MVP owner): the M01.7 precedent — retained live evidence re-qualified by check:t7-retained-capstone-applicability on every run";
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit, authorized leg by leg";

const CLAUSES = [
  { id: "1", clause: "Discovery proposes and stops: it does not execute source, grant authority, install dependencies or start anything, and an unaccepted proposal has no effect anywhere (measured across seven other families)", unit: "M09.1", checks: [app("check:project-discovery-proposal")], battery: { ...app("mutate:project-discovery-proposal"), cost: "minutes" } },
  { id: "2", clause: "Acceptance is explicit: candidates and overrides are accepted by a principal or a policy, exactly once, and the acceptance is receipted", unit: "M09.1", provenBy: "1" },
  { id: "3", clause: "The startup plan is inspectable before it runs — paths, endpoints, custody, supervision, egress and effects — and the lifecycle executes that plan", unit: "M09.2", checks: [rootScript("check:environment-startup-plan")], absences: [{ what: "the second half — that the lifecycle EXECUTES the admitted plan — belongs to the execution and readiness records canon names beside the plan (HypervisorEnvironmentStartupAdmission, …StartupExecution, …StartupRefusal), none of which exist (journey document, 2026-09-13)", owner: "M09.2 remainder (register R-138)" }] },
  { id: "4", clause: "Ports and route bindings are their own objects with their own authority and revocation, and a preview cannot reach another environment's ports", unit: "M09.3 · M03.2", checks: [rootScript("check:environment-route-binding"), app("check:env-lease-authority")] },
  { id: "5", clause: "Backup is admitted and restore is a ChangePlan; restore passes on semantic continuity, not blob presence, and never counts as reconciliation", unit: "M09.4", checks: [rootScript("check:canonical-environment-backup"), app("check:backup-restore")] },
  { id: "6", clause: "Every acquisition creates its cleanup obligation, which survives restart, owner change and partial failure — one registered object whose closure is the counterparty's fact", unit: "M09.5", checks: [rootScript("check:resource-cleanup-obligation")] },
  // verify-hypervisor-provider-spend-reconciliation.mjs targets the SHARED daemon at :8765 (ACC-4's first
  // composed run failed on ECONNREFUSED there); it is not isolated and is recorded as M07.3's absence (R-143).
  { id: "7", clause: "Zero-to-idle closes spend, verified against the provider's own billing readback rather than the estate's intention; deployment close with an escrow refund still pending is not zero-to-idle", unit: "M07.3 · M01.7 · M09.6 · M12.9", checks: [rootScript("check:provider-spend-reconciliation"), rootScript("check:t7-retained-capstone-applicability"), { ...bounded(rootScript("check:provider-neutral-live-transaction", ["--", "--drills"]), 15), allowsFixture: true }, { ...bounded(rootScript("check:c8-bounded-live-effect-certificate", ["--", "--drills"]), 15), allowsFixture: true }], battery: [{ ...rootScript("mutate:provider-spend-reconciliation"), cost: "minutes" }, { ...rootScript("mutate:t7-retained-capstone-applicability"), cost: "minutes" }, { ...rootScript("mutate:provider-neutral-live-transaction"), cost: "minutes" }, { ...rootScript("mutate:c8-bounded-live-effect-certificate"), cost: "minutes" }], absences: [{ what: "verify-hypervisor-provider-spend-reconciliation.mjs (M07.3's customer-borne spend-accounting done-bar) targets the shared daemon at 127.0.0.1:8765 and the ~/.ioi data dir; not isolated, not composed (R-143)", owner: "M07.3 (isolated form owed)" }], scheduled: [{ what: "the positive branch of M09.6's fresh live transaction closing to provider-confirmed final debit (check:provider-neutral-live-transaction), with its C8 v2 certificate GENERATED and replayed by M12.9's check:c8-bounded-live-effect-certificate from a second retained run; the no-qualified-bid branch and the retained 2026-08-21 positive certificate are GENERATED spend-free from the retained durable records by those gates' drills (R-210, R-211)", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING }] },
  { id: "8", clause: "Route eligibility precedes price: a cheaper route with unresolved rights is ineligible; comparison ranks eligible routes by cost per successful unit; switching passes improvement gates with hysteresis", unit: "M07.2 · M07.4", checks: [app("check:model-route-authority"), rootScript("check:route-rights-contracts"), rootScript("check:eligible-route-cost-shape")], battery: { ...rootScript("mutate:route-rights-contracts"), cost: "minutes" } },
  // M07.5 landed 2026-09-14: owner-derived metering dimensions, receipt dedup, foreign-tenant
  // refusal, plan-allowance consumption and the read-derived aggregate, pinned as a closed cargo
  // test population with source pins (check:substrate-metering-contract).
  { id: "9", clause: "Metering is invoice-grade: grant, burn, reservation, overage and top-up reproduce from receipts, and network/open work draws a separate budget", unit: "M07.1 · M07.5", checks: [rootScript("check:work-credit-budget-contract"), bounded(rootScript("check:substrate-metering-contract"), 40)] },
  { id: "N1", negative: true, clause: "No implicit conversion, spend, promotion, publication, external effect or production activation", unit: "M09.1 · M09.5", provenBy: "1" },
  { id: "N2", negative: true, clause: "A green candidate/quote lane is never cited as evidence for a live lane", unit: "ACC-11", structural: (clauses) => { const bad = clauses.filter((c) => (c.scheduled ?? []).length > 0).flatMap((c) => (c.checks ?? []).filter((k) => /(?::live\b|--live\b|\(live\))/iu.test(k.label)).map((k) => `${c.id}: ${k.label}`)); return { ok: bad.length === 0, detail: `every clause with a scheduled live leg executes only spend-free checks (a live-labelled check is one invoked as :live, --live or (live); a gate whose NAME carries the word, like check:provider-neutral-live-transaction, is judged by how it is invoked) and cites the retained live evidence through its applicability gate${bad.length ? `; violations: ${bad.join(", ")}` : ""}` }; } },
  { id: "N3", negative: true, clause: "A private-custody claim without a custody-proven route is typed as contractual privacy and says so", unit: "M09.7", checks: [app("check:custody-proven-private-routes"), app("mutate:custody-proven-private-routes")] },
  { id: "E", clause: "Journey evidence: environment custody, the projects saga and the provider transport boundary", unit: "M09", checks: [app("check:environment-custody"), bounded(app("check:projects-saga"), 30), app("check:provider-transport")] },
];

await runJourney({
  gate: "ACC-11",
  title: "an environment composes, runs, restores, and closes its spend",
  doc: "internal-docs/implementation/acceptance/journey-11-environment-lifecycle-and-spend.md",
  clauses: CLAUSES,
});
