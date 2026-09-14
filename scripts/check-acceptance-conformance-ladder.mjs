#!/usr/bin/env node
// ACC-14 · the conformance ladder — the composed journey runner, and its scheduled live lane.
//
// A clause table over scripts/lib/acceptance-journey.mjs. Rungs 1–6 are the deterministic ladder;
// rung 7's deterministic half (the three-institution matrix, the published offline-verifier
// package, two-substrate binding, same-owner refusal) is owed by M06.11 / M09.10 / M12.7 and is a
// TYPED ABSENCE per clause. Clause 2's zero-to-operable journey is the alpha journey in package +
// no-checkout mode: it needs Ollama, the deployment-local authority node and release packages
// OUTSIDE the repository, so it runs only with --with-alpha-journey and is otherwise CITED from
// its tracked evidence and recorded as a typed absence (a citation is never an execution).
//
// --live is the SCHEDULED lane (the manifest's scheduled_check): the separately authorized
// paid-stranger campaign with independently administered buyer, Worker and relying party. It is
// executable today in exactly one honest sense — it refuses, typed, until the campaign evidence
// M12.7 (product_track) produces is present at IOI_ACC14_LIVE_EVIDENCE, and it may reuse a prior
// live result only when commit, inputs and claim are identical. Exit 2, never 0, without it.
//
//   node scripts/check-acceptance-conformance-ladder.mjs [--with-alpha-journey] [--mutation-batteries] [--mutation] [--evidence <out.json>]
//   node scripts/check-acceptance-conformance-ladder.mjs --live

import fs from "node:fs";
import path from "node:path";
import { runJourney, app, rootScript, bounded, ROOT } from "./lib/acceptance-journey.mjs";

const argv = process.argv.slice(2);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

if (argv.includes("--live")) {
  const dir = process.env.IOI_ACC14_LIVE_EVIDENCE;
  const required = ["campaign-record.json", "independence-attestation.json", "settlement-readback.json", "post-exit-offline-verification.json"];
  const present = dir ? required.filter((f) => fs.existsSync(path.join(dir, f))) : [];
  console.log(`# ACC-14 scheduled live lane · paid-stranger campaign · evidence dir ${dir ?? "(IOI_ACC14_LIVE_EVIDENCE unset)"}`);
  console.log(`SCHEDULED-OUTSTANDING: the separately authorized paid-stranger campaign (independently administered buyer, Worker and relying party; real bounded funds; terminal settlement/dispute; endpoint shutdown; post-exit offline verification; no shared runtime/database/admin/key/wallet/provider account) has ${present.length}/${required.length} evidence members present.`);
  console.log("prerequisite: M12.7 (product_track) runs the campaign and hands this lane its evidence; this lane then consumes the exact passing rungs 1-6 basis and re-verifies the bundle offline. It may reuse a prior live result only when commit, inputs and claim are identical.");
  console.log("PARTIAL ACC-14 scheduled live lane: not a pass — the live campaign has not been run for this basis.");
  process.exit(2);
}

const withAlpha = argv.includes("--with-alpha-journey");
const ALPHA_ENV = { IOI_ALPHA_JOURNEY_AUTHORITY: "deployment", IOI_ALPHA_JOURNEY_PACKAGE: "1", IOI_ALPHA_JOURNEY_NO_CHECKOUT: "1" };
const ALPHA_EVIDENCE = "docs/architecture/_meta/evidence/m12-alpha-journey-release-no-checkout-2026-09-10.v1.json";
// M12.5's two cited verifiers default to the SHARED daemon at 127.0.0.1:8765 plus a served shell,
// need an operator session token and Playwright, and are registered by no npm script (R-137). Not
// isolated, therefore not composed: recorded as M12.5 / M10.1's absence, not run against nothing.
const NOT_ISOLATED = "targets the shared daemon at 127.0.0.1:8765 and a served shell at :4173 with an operator session token and Playwright; not isolated, not composed";

const CLAUSES = [
  { id: "1", clause: "Standalone operability: a local deployment bootstraps, governs, executes, preserves, replays, backs up, restores, exports and verifies with no ioi.ai account and no first-party managed dependency; every connected capability is typed unavailable", unit: "M12.1", absences: [absent("M12.1", "check:standalone-conformance", "the declared capability/durability/custody/assurance envelope as a pass-or-fail check whose negative half fails a deployment that quietly reaches a first-party dependency")] },
  { id: "2", clause: "Zero-to-operable, App and CLI/headless: verify → preview → install → bootstrap identity and authority → start → readiness → open → inspect → update or roll back through an admitted ChangePlan → stop or uninstall without implicit data wipe → export, back up, restore", unit: "M12.2", checks: withAlpha ? [{ ...bounded(app("check:alpha-journey"), 90), env: ALPHA_ENV, allowsFixture: true }] : [], cited: withAlpha ? [] : [{ label: "the alpha journey on the release-profile package with no checkout (deployment authority, package mode, no-checkout mode)", evidence: ALPHA_EVIDENCE }], absences: [...(withAlpha ? [] : [{ what: "NOT EXECUTED in this run (on demand: needs Ollama, the deployment-local authority node and release packages outside the repository) — pass --with-alpha-journey", owner: "this runner" }]), absent("M12.2", "check:zero-to-operable", "the pre-install preview of paths/endpoints/custody/supervision/egress/effects, a dedicated CLI client, the declared Agentgres posture at start and uninstall-without-data-wipe")] },
  { id: "3", clause: "The undeniable-product proof gate: canon's own gate over the selected minimum-L0 proof profile with its required sovereign-local fixture, passed or failed by name", unit: "M12.3", absences: [absent("M12.3", "check:undeniable-product-proof", "canon's proof gate run as a gate rather than as prose")] },
  { id: "4", clause: "Flagship, single node: package → genesis → constitution-bound room → room-child admission spine, end to end, through the selected bounded software-change profile", unit: "M12.4 (product_track)", checks: [{ ...bounded(app("check:m4-outcome-room-system-spine"), 60), allowsFixture: true }] },
  { id: "5", clause: "First bounded improvement campaign: frozen order-0 epoch, finite reservations, candidate/evaluator separation, exposure ledger, negative-result retention, reproduction and a target-owner UpgradeProposal handoff with no campaign-owned production mutation", unit: "M12.5", absences: [{ what: `the apply-time governance gates and what-if simulation replay (M12.5's partial evidence) — each ${NOT_ISOLATED}`, owner: "M12.5 / M10.1" }, absent("M12.5", "check:horizon-1b-improvement", "the frozen order-0 epoch, finite reservations, role separation, append-only exposure, negative retention, reproduction and the handoff (M10.1/M10.2 are unbuilt)")] },
  { id: "6", clause: "Distribution: one logical DAS across two failure domains with controlled continuity and useful distributed work under unchanged authority", unit: "M12.6", absences: [absent("M12.6", "check:horizon-2-distributed-work", "join/catch-up/root/fenced promotion/replay/drain plus typed assignments, leases, watermarks, coordination epochs and duplicate-effect reconciliation across two failure domains")] },
  { id: "7", clause: "The north-star network proof, deterministic half: the three-institution paid-hire/settlement/exit contract, the published offline-verifier package, two-substrate binding and same-owner/shared-control refusal, without claiming live organizational independence", unit: "M12.7 (product_track) · M06.11 · M09.10", absences: [absent("M12.7 (product_track)", "check:horizon-3-independent-worker", "the deterministic three-institution matrix"), absent("M06.11", "check:public-verifier-conformance", "the published package rebuilt and verified by canonical and clean-room verifiers with IOI offline"), absent("M09.10", "check:multi-substrate-portability", "two deterministic adapters running one workload/authority/receipt contract with the eight substitution mutations")] },
  { id: "N1", negative: true, clause: "Same-owner multiplicity never satisfies clause 7; a second first-party verifier, package, subsidiary, operator account or preselected trust policy is not an independently administered relying party", unit: "M12.7 (product_track)", absences: [absent("M12.7 (product_track)", "check:horizon-3-independent-worker", "the same-owner refusal matrix")] },
  { id: "N2", negative: true, clause: "Managed attachment never silently uploads, owns, meters, authorizes or completes a locally governed System", unit: "M12.1", absences: [absent("M12.1", "check:standalone-conformance", "the managed-attachment negative")] },
  { id: "N3", negative: true, clause: "No clause is satisfied by a green CI run: CI certifies no interactive behaviour, no live external effect and not the ioi.ai web UI", unit: "ACC-14", structural: () => ({ ok: process.env.CI === undefined || process.env.CI === "" || withAlpha, detail: process.env.CI ? "running under CI with the alpha journey executed" : "not a CI run" }) },
  { id: "E", clause: "Journey evidence named through the conformance ladder's own gates: architecture contracts, work items and the retained live capstone's applicability to this tree", unit: "M12 · M01.7", checks: [rootScript("check:architecture-contracts"), rootScript("check:work-items"), rootScript("check:t7-retained-capstone-applicability")] },
];

await runJourney({
  gate: "ACC-14",
  title: "the conformance ladder",
  doc: "internal-docs/implementation/acceptance/journey-14-conformance-ladder.md",
  clauses: CLAUSES,
  argv,
});

export const ROOT_FOR_TESTS = ROOT;
