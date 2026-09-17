#!/usr/bin/env node
// ACC-14 · the conformance ladder — the composed journey runner, and its scheduled live lane.
//
// A clause table over scripts/lib/acceptance-journey.mjs. Rungs 1–6 are the deterministic ladder;
// rung 7's deterministic half (the three-institution matrix, the published offline-verifier
// package, two-substrate binding, same-owner refusal) is owed by M06.11 / M09.10 / M12.7 and is a
// TYPED ABSENCE per clause. Clause 1 (M12.1, check:standalone-conformance) runs the alpha journey
// in package + no-checkout mode INSIDE the isolated-egress harness, plus the fault lane and
// portable replay: it needs Ollama, the deployment-local authority node and release packages
// OUTSIDE the repository, so the full check runs only with --with-alpha-journey — and clause 2's
// zero-to-operable journey is then PROVEN BY that run rather than executed a second time. Without
// the flag clause 1 runs the check's CI-bound drills (the profile, the harness oracles, the
// daemon's typed availability and the undeclared-reach negative) and records the full run as a
// typed absence naming this runner; clause 2 is CITED from its tracked evidence (a citation is
// never an execution).
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
// R-179/R-180 (2026-09-16): the OutcomeRoom/System spine verifier this clause once drove is DELETED —
// outcome rooms and goal runs are ioi.ai compositions over thread orchestration primitives, not
// hypervisor planes — so clause 4 now executes the platform half the flagship path is built from
// (release-bound genesis → constitution-bound System activation → the record seam) and the
// application composition over it (coordinating thread, delegations, reservations, seam-admitted
// records), both on the real wallet fixture. The bounded software-change profile the old clause
// claimed is owed by M12.4 (product_track) as a typed absence, never inferred from these two.
const ALPHA_EVIDENCE = "docs/architecture/_meta/evidence/m12-alpha-journey-release-no-checkout-2026-09-10.v1.json";
// M12.5's two cited verifiers default to the SHARED daemon at 127.0.0.1:8765 plus a served shell,
// need an operator session token and Playwright, and are registered by no npm script (R-137). Not
// isolated, therefore not composed: recorded as M12.5 / M10.1's absence, not run against nothing.
const NOT_ISOLATED = "targets the shared daemon at 127.0.0.1:8765 and a served shell at :4173 with an operator session token and Playwright; not isolated, not composed";

const CLAUSES = [
  { id: "1", clause: "Standalone operability: a local deployment bootstraps, governs, executes, preserves, replays, backs up, restores, exports and verifies with no ioi.ai account and no first-party managed dependency; every connected capability is typed unavailable", unit: "M12.1", checks: withAlpha ? [{ ...bounded(rootScript("check:standalone-conformance"), 150), allowsFixture: true }] : [{ ...bounded(rootScript("check:standalone-conformance", ["--", "--drills"]), 20), allowsFixture: true }, rootScript("mutate:standalone-conformance")], absences: [...(withAlpha ? [] : [{ what: "the FULL standalone check NOT EXECUTED in this run (the alpha journey under the isolated-egress harness, the mid-run fault lane, portable replay — on demand: needs Ollama, the deployment-local authority node and release packages outside the repository) — pass --with-alpha-journey", owner: "this runner" }]), { what: "System genesis + governance under the sovereign-local fixture — the bounded alpha (ADR 0052) contains no System; the profile declares the genesis interfaces and M12.3's gate composes genesis, constitution and the room under the same fixture", owner: "M12.3" }] },
  { id: "2", clause: "Zero-to-operable, App and CLI/headless: verify → preview → install → bootstrap identity and authority → start → readiness → open → inspect → update or roll back through an admitted ChangePlan → stop or uninstall without implicit data wipe → export, back up, restore", unit: "M12.2", ...(withAlpha ? { provenBy: "1" } : { cited: [{ label: "the alpha journey on the release-profile package with no checkout (deployment authority, package mode, no-checkout mode)", evidence: ALPHA_EVIDENCE }] }), absences: [...(withAlpha ? [] : [{ what: "NOT EXECUTED in this run (on demand: the alpha journey runs inside clause 1's standalone check with --with-alpha-journey)", owner: "this runner" }]), absent("M12.2", "check:zero-to-operable", "the pre-install preview of paths/endpoints/custody/supervision/egress/effects, a dedicated CLI client, the declared Agentgres posture at start and uninstall-without-data-wipe")] },
  { id: "3", clause: "The undeniable-product proof gate: canon's own gate over the selected minimum-L0 proof profile with its required sovereign-local fixture, passed or failed by name", unit: "M12.3", absences: [absent("M12.3", "check:undeniable-product-proof", "canon's proof gate run as a gate rather than as prose")] },
  { id: "4", clause: "Flagship, single node: release-bound genesis → constitution-bound System activation → records admitted through the System-record seam → the ioi.ai orchestration composed over that System (coordinating thread, delegations, reservations, seam-admitted records), end to end on one node; a proof that only works for one composition has proved that composition", unit: "M12.4 (product_track)", checks: [{ ...bounded(app("check:system-record-seam"), 60), allowsFixture: true }, { ...bounded(app("check:orchestration-composition"), 60), allowsFixture: true }], absences: [{ what: "the selected bounded software-change profile driven end to end through the composed flagship path — the room-hosted spine gate that carried this claim retired on 2026-09-16 (R-179), and the two executed gates prove the platform seam and the composition, not a software-change profile", owner: "M12.4 (product_track)" }] },
  { id: "5", clause: "First bounded improvement campaign: frozen order-0 epoch, finite reservations, candidate/evaluator separation, exposure ledger, negative-result retention, reproduction and a target-owner UpgradeProposal handoff with no campaign-owned production mutation", unit: "M12.5", absences: [{ what: `the apply-time governance gates and what-if simulation replay (M12.5's partial evidence) — each ${NOT_ISOLATED}`, owner: "M12.5 / M10.1" }, absent("M12.5", "check:horizon-1b-improvement", "the frozen order-0 epoch, finite reservations, role separation, append-only exposure, negative retention, reproduction and the handoff (M10.1/M10.2 are unbuilt)")] },
  { id: "6", clause: "Distribution: one logical DAS across two failure domains with controlled continuity and useful distributed work under unchanged authority", unit: "M12.6", absences: [absent("M12.6", "check:horizon-2-distributed-work", "join/catch-up/root/fenced promotion/replay/drain plus typed assignments, leases, watermarks, coordination epochs and duplicate-effect reconciliation across two failure domains")] },
  { id: "7", clause: "The north-star network proof, deterministic half: the three-institution paid-hire/settlement/exit contract, the published offline-verifier package, two-substrate binding and same-owner/shared-control refusal, without claiming live organizational independence", unit: "M12.7 (product_track) · M06.11 · M09.10", absences: [absent("M12.7 (product_track)", "check:horizon-3-independent-worker", "the deterministic three-institution matrix"), absent("M06.11", "check:public-verifier-conformance", "the published package rebuilt and verified by canonical and clean-room verifiers with IOI offline"), absent("M09.10", "check:multi-substrate-portability", "two deterministic adapters running one workload/authority/receipt contract with the eight substitution mutations")] },
  { id: "N1", negative: true, clause: "Same-owner multiplicity never satisfies clause 7; a second first-party verifier, package, subsidiary, operator account or preselected trust policy is not an independently administered relying party", unit: "M12.7 (product_track)", absences: [absent("M12.7 (product_track)", "check:horizon-3-independent-worker", "the same-owner refusal matrix")] },
  { id: "N2", negative: true, clause: "Managed attachment never silently uploads, owns, meters, authorizes or completes a locally governed System", unit: "M12.1", ...(withAlpha ? { provenBy: "1" } : { absences: [{ what: "proven by clause 1's FULL run (zero reach beyond loopback across the whole journey while every managed family stayed typed unavailable and the local System bootstrapped, governed, executed, preserved and restored) — not executed in this run; pass --with-alpha-journey", owner: "this runner" }] }) },
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
