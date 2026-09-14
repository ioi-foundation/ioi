#!/usr/bin/env node
// ACC-20 · one governed machine, integrated and standalone — the composed journey runner, and its
// scheduled soak lane.
//
// A clause table over scripts/lib/acceptance-journey.mjs. What exists today is M09.11: eleven
// machine-control contracts registered before any surface, the sixteen-verb vocabulary closed and
// agreeing between contract and kernel, two deliberately asymmetric reference backends driven over
// the real route with stale-head, replayed-key, drifted-declaration and ambiguous-completion
// refusals. The integrated / focused-standalone / ODK-extension clients (M08.15) and the two
// profile certificates (M12.15) are TYPED ABSENCES per clause.
//
// --soak is the SCHEDULED lane (the manifest's scheduled_check): fresh hosted and attached
// subjects through the phase-by-phase crash/restart/recovery matrix with current backend/host
// evidence for each named certificate. It refuses, typed, until IOI_ACC20_SOAK_EVIDENCE names a
// directory holding fresh hosted and attached backend evidence; a stale, drifted, simulated-only
// or unsupported cell withdraws rather than promotes. Exit 2, never 0, without it.
//
//   node scripts/check-governed-machine-product.mjs [--mutation] [--evidence <out.json>]
//   node scripts/check-governed-machine-product.mjs --soak

import fs from "node:fs";
import path from "node:path";
import { runJourney, rootScript } from "./lib/acceptance-journey.mjs";

const argv = process.argv.slice(2);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

if (argv.includes("--soak")) {
  const dir = process.env.IOI_ACC20_SOAK_EVIDENCE;
  const required = ["hosted-backend-evidence.json", "attached-backend-evidence.json", "crash-restart-matrix.json"];
  const present = dir ? required.filter((f) => fs.existsSync(path.join(dir, f))) : [];
  console.log(`# ACC-20 scheduled soak lane · evidence dir ${dir ?? "(IOI_ACC20_SOAK_EVIDENCE unset)"}`);
  console.log(`SCHEDULED-OUTSTANDING: fresh hosted (ordinary-OS backend on this host's KVM) and attached (an independently implemented attached-estate backend) subjects through the full phase-by-phase crash/restart/recovery and lifecycle matrix — ${present.length}/${required.length} evidence members present.`);
  console.log("prerequisite: a real attached-estate backend (the reference backends are deterministic and simulated-only, which the journey says may validate the contract but cannot qualify a public host or attached-estate matrix) and M08.15's clients to drive it cross-client.");
  console.log("PARTIAL ACC-20 scheduled soak lane: not a pass — no fresh backend/host evidence for this basis.");
  process.exit(2);
}

const CONFORMANCE = rootScript("check:machine-lifecycle-backend-conformance");

const CLAUSES = [
  { id: "1", clause: "Contracts precede surfaces: host, image, volume/network/device attachments, console, snapshot, migration/maintenance, operation and receipt contracts are registered before any client claims them (all eleven, asserted by the gate)", unit: "M09.11", checks: [CONFORMANCE] },
  { id: "2", clause: "One desired/observed spine: every delivery form renders the same VirtualMachineWorkload, exact target hash, desired generation, expected head, observed generation/phase, boot epoch, backend evidence, receipts and cleanup obligations", unit: "M09.11 · M08.15", provenBy: "1", absences: [absent("M08.15", "check:machine-product-composition", "that integrated and standalone forms RENDER the same spine — the daemon half is proven, the client half does not exist")] },
  { id: "3", clause: "One operation vocabulary: the sixteen verbs resolve to the same versioned daemon operations; backend aliases never become canonical verbs", unit: "M09.11", provenBy: "1" },
  { id: "4", clause: "Capability truth is current and explicit: the selected backend's exact declaration (bound by ref AND hash) decides eligible operations; unsupported, stale, unknown or drifted cells refuse before effect with a typed reason", unit: "M09.11", provenBy: "1" },
  { id: "5", clause: "Authority and effects do not move into clients: integrated, standalone and generated clients submit proposals and display challenges; the daemon and wallet-owned authority path admit", unit: "M08.15", absences: [absent("M08.15", "check:machine-product-composition", "the clients")] },
  { id: "6", clause: "Console and devices stay bounded: a console session and every attachment are machine-, principal-, environment-, scope- and epoch-bound and grant no ambient access", unit: "M09.11 · M08.15", absences: [absent("M08.15", "check:machine-product-composition", "console sessions and attachments exercised through existing owner surfaces")] },
  { id: "7", clause: "Lifecycle survives failure: duplicate, reordered and replayed requests, stale generation and uncertain external completion converge without double effect or invented rollback (the gate's stale-head, replayed-key and ambiguous-completion proofs); daemon/client/backend loss and crash-before/after-durable-steps are the soak's", unit: "M09.11", provenBy: "1", scheduled: [{ what: "the phase-by-phase crash/restart/recovery matrix on fresh hosted and attached subjects (this runner's --soak lane)", prerequisite: "a real attached-estate backend and M08.15's clients", ruling: "the journey's own matrix text: the merge lane uses deterministic reference backends; a release claim additionally carries fresh scheduled backend/host evidence" }] },
  { id: "8", clause: "Integrated and standalone are the same product truth: create through one, operate through the other, restart both, remove either client, observe the same machine, operation ids, receipts and history", unit: "M08.15", absences: [absent("M08.15", "check:machine-product-composition", "cross-client driving")] },
  { id: "9", clause: "The extension seam is real: an ODK-scaffolded, Packages-admitted extension_application renders inventory and invokes allowed public operations but cannot access private projections, bypass admission, invent a capability or receive first-party privilege", unit: "M08.15 · M08.10", absences: [absent("M08.15", "check:machine-product-composition", "the ODK-scaffolded extension console, which also needs M08.10's extension_application registration")] },
  { id: "10", clause: "Claims are scoped: separate offline certificates bind the exact hosted Workstation and attached-Infrastructure release/profile/backend matrices, unsupported cells, freshness and limitations", unit: "M12.15", absences: [absent("M12.15", "check:machine-product-profile-qualification", "workstation_hosted_v1 and infrastructure_attached_v1 certificates")] },
  { id: "N1", negative: true, clause: "A VM boot, hostile-guest test, downloadable binary, bootable image, generated dashboard, backend declaration or autonomy proof is not profile qualification", unit: "M12.15", absences: [absent("M12.15", "check:machine-product-profile-qualification", "the evidence-lending refusals")] },
  { id: "N2", negative: true, clause: "A focused standalone client is not a second runtime, database, machine owner, provider owner, authority path or receipt writer", unit: "M08.15", absences: [absent("M08.15", "check:machine-product-composition", "client-private-truth mutations")] },
  { id: "N3", negative: true, clause: "The portable subset does not erase backend-specific extensions or turn an unsupported operation into simulated success (an extension cell runs only where declared; the other backend refuses with the declaration's own reason)", unit: "M09.11", provenBy: "1" },
  { id: "N4", negative: true, clause: "A non-simulated backend is admitted but NOT executed by the reference executor (the fence that keeps it out of a real deployment)", unit: "M09.11", provenBy: "1" },
];

await runJourney({
  gate: "ACC-20",
  title: "one governed machine, integrated and standalone",
  doc: "internal-docs/implementation/acceptance/journey-20-governed-machine-product.md",
  clauses: CLAUSES,
  argv,
});
