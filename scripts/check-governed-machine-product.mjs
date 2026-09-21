#!/usr/bin/env node
// ACC-20 · one governed machine, integrated and standalone — the composed journey runner, and its
// scheduled soak lane.
//
// A clause table over scripts/lib/acceptance-journey.mjs. M09.11: eleven machine-control contracts
// registered before any surface, the sixteen-verb vocabulary closed and agreeing between contract
// and kernel, two deliberately asymmetric reference backends driven over the real route with
// stale-head, replayed-key, drifted-declaration and ambiguous-completion refusals. M08.15 (R-215,
// 2026-09-20): check:machine-product-composition — the daemon's machine READ MODEL projected through
// the App as the integrated form and driven by a thin client as the standalone form against ONE
// isolated daemon (cross-client, restart, removal, deletion survival), and one ODK-authored extension
// admitted through Packages whose view renders only the public read model; CI-bound at its drills
// here, its full mode on demand. What stays a TYPED ABSENCE is named per clause with its owner: the
// distributed standalone client, the wallet-owned authority challenge on machine operations, the
// extension's invocation crossing, the unserved machine-control members' surfaces (M09.11), and the
// two profile certificates (M12.15).
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
import { bounded, runJourney, rootScript } from "./lib/acceptance-journey.mjs";

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
const COMPOSITION = { ...bounded(rootScript("check:machine-product-composition", ["--", "--drills"]), 15), allowsFixture: true };
const COMPOSITION_BATTERY = { ...rootScript("mutate:machine-product-composition"), cost: "minutes" };
const OWNER_Q = "owner question, R-215";

const CLAUSES = [
  { id: "1", clause: "Contracts precede surfaces: host, image, volume/network/device attachments, console, snapshot, migration/maintenance, operation and receipt contracts are registered before any client claims them (all eleven, asserted by the gate)", unit: "M09.11", checks: [CONFORMANCE] },
  { id: "2", clause: "One desired/observed spine: every delivery form renders the same VirtualMachineWorkload, exact target hash, desired generation, expected head, observed generation/phase, boot epoch, backend evidence, receipts and cleanup obligations (the daemon's read model — head, generations, phases, the bound declaration, operations in chain order, receipts, cleanup obligations — rendered by the App member for member and read by the thin client from the same route, the gate's drills over the tracked read-model fixture and its source pins; the full mode's cross-client SPINE leg on demand)", unit: "M09.11 · M08.15", checks: [COMPOSITION], battery: COMPOSITION_BATTERY, absences: [{ what: "a boot epoch and backend evidence on the spine: the read model carries the four generations, the phases and the bound declaration's evidence mode; the boot epoch is a member of the unserved VirtualMachineWorkload state payload, not of any record the daemon writes", owner: "M09.11 (the VM state payload's serving)" }] },
  { id: "3", clause: "One operation vocabulary: the sixteen verbs resolve to the same versioned daemon operations; backend aliases never become canonical verbs", unit: "M09.11", provenBy: "1" },
  { id: "4", clause: "Capability truth is current and explicit: the selected backend's exact declaration (bound by ref AND hash) decides eligible operations; unsupported, stale, unknown or drifted cells refuse before effect with a typed reason", unit: "M09.11", provenBy: "1" },
  { id: "5", clause: "Authority and effects do not move into clients: integrated, standalone and generated clients submit proposals and display challenges; the daemon and wallet-owned authority path admit (both clients submit PROPOSALS under the operator's own session, an anonymous proposal is refused 401 through either, the daemon mints the identity and records the submitter as it resolved it, the App's lane relays verbatim)", unit: "M08.15", provenBy: "2", absences: [{ what: "the wallet-owned authority CHALLENGE on a machine operation: a proposal's authority_refs are schema strings the kernel does not adjudicate, and no machine verb parks a byte-derived card the way a provider operation does (M08.11) — the daemon binds identity and admits through its kernel, it does not yet ask the custody tier", owner: `M09.11's authority seam with the M03 approval card (${OWNER_Q})` }] },
  { id: "6", clause: "Console and devices stay bounded: a console session and every attachment are machine-, principal-, environment-, scope- and epoch-bound and grant no ambient access", unit: "M09.11 · M08.15", absences: [{ what: "the daemon serves the operation and receipt members of the machine-control family on one route; the console-session, attachment, snapshot-lineage and the other unserved members are registered contracts with no record behind them, so no surface can exercise a binding that does not exist (the open_console/close_console and snapshot VERBS are admitted and receipted; a session or a lineage is not a record)", owner: "M09.11 (its own OUTSTANDING: attachments, console scope, snapshot lineage)" }] },
  { id: "7", clause: "Lifecycle survives failure: duplicate, reordered and replayed requests, stale generation and uncertain external completion converge without double effect or invented rollback (the gate's stale-head, replayed-key and ambiguous-completion proofs); daemon/client/backend loss and crash-before/after-durable-steps are the soak's", unit: "M09.11", provenBy: "1", scheduled: [{ what: "the phase-by-phase crash/restart/recovery matrix on fresh hosted and attached subjects (this runner's --soak lane)", prerequisite: "a real attached-estate backend and M08.15's clients", ruling: "the journey's own matrix text: the merge lane uses deterministic reference backends; a release claim additionally carries fresh scheduled backend/host evidence" }] },
  { id: "8", clause: "Integrated and standalone are the same product truth: create through one, operate through the other, restart both, remove either client, observe the same machine, operation ids, receipts and history (the full mode's SPINE leg: create through the App, start through the thin client, refusals through both, the daemon restarted on its records, the App restarted, removed and doubled, the workload deleted with its history intact; the drills pin the App against deriving any of it)", unit: "M08.15", provenBy: "2", absences: [{ what: "a separately DISTRIBUTED focused client on an ADR 0032 axis: the standalone FORM the gate drives is the daemon's HTTP API as a thin client (M12.2's precedent), labelled exactly that", owner: `the standalone client's packaging (${OWNER_Q}; the taxonomy's cli_headless first-class client)` }] },
  { id: "9", clause: "The extension seam is real: an ODK-scaffolded, Packages-admitted extension_application renders inventory and invokes allowed public operations but cannot access private projections, bypass admission, invent a capability or receive first-party privilege (the full mode's EXT leg: an ODK-authored mesh admitted through Packages, served through the compiled join, its view rendering the public read model in parity with the daemon, listing a non-public daemon_api_ref unrendered, offering its action disabled with a typed reason, carrying no lane, unreachable anonymously, its class/origin/effect boundary/route derived by the registration; the drills pin the view's single guarded read and disabled offers)", unit: "M08.15 · M08.10", provenBy: "2", absences: [{ what: "the extension's INVOCATION crossing: an offered action is rendered disabled because no gateway path exists for an extension to submit a machine proposal under its own admitted contracts; and an ODK SCAFFOLDING command — the mesh is authored through the ODK routes, no `scaffold` verb produces a skeleton", owner: `the DomainApp runtime plane and the Hypervisor MCP Gateway · M05's developer kit (${OWNER_Q})` }] },
  { id: "10", clause: "Claims are scoped: separate offline certificates bind the exact hosted Workstation and attached-Infrastructure release/profile/backend matrices, unsupported cells, freshness and limitations", unit: "M12.15", absences: [absent("M12.15", "check:machine-product-profile-qualification", "workstation_hosted_v1 and infrastructure_attached_v1 certificates")] },
  { id: "N1", negative: true, clause: "A VM boot, hostile-guest test, downloadable binary, bootable image, generated dashboard, backend declaration or autonomy proof is not profile qualification", unit: "M12.15", absences: [absent("M12.15", "check:machine-product-profile-qualification", "the evidence-lending refusals")] },
  { id: "N2", negative: true, clause: "A focused standalone client is not a second runtime, database, machine owner, provider owner, authority path or receipt writer (the App keeps no machine cache and derives no head or phase — pinned and mutation-drilled; every client read leaves the daemon's record families byte-identical; the thin client holds nothing between requests)", unit: "M08.15", provenBy: "2" },
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
