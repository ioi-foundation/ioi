#!/usr/bin/env node
// check:machine-product-composition — M08.15: the Workstation / Infrastructure product composition, as a gate
// (docs/architecture/components/hypervisor/core-clients-surfaces.md § Workstation and Infrastructure delivery
// forms; providers-and-environments.md § Machine-control contract family; register R-215, executing R-124,
// R-128..R-130, R-133, R-139 and R-143).
//
// CANON. One governed machine lifecycle is a public composable primitive. The integrated Hypervisor profile
// and a focused standalone client open the SAME registered projections and invoke the SAME daemon operations,
// authority checks, receipts and readbacks; neither stores a parallel inventory, desired/observed state,
// operation journal or receipt; removing either delivery form leaves the governed machine and its history
// unchanged. An organization may package a specialized console through the `extension_application` path
// and it cannot bypass the daemon's operation and owner boundaries.
//
// WHAT THIS RUNNER IS. The acceptance's demands are CLAUSES, each EXECUTED by one of this runner's own legs,
// by a floored gate that already proves it, or NAMED (a typed failure with an owner, or a SCHEDULED leg with
// its exact prerequisite and ruling). The runner's own legs:
//   PURE     — the App's projection, renderers and readers over the TRACKED read-model fixture (minted from a
//              real run): the readout carries every member of the daemon's spine and derives none; a page
//              renders and reads back member for member; a fork reads back as no head; parity detects a
//              changed head, receipt, phase or operation; the extension view renders only the public read
//              model, lists a non-public ref unrendered and offers actions without invoking.
//   SOURCE   — the serve's three routes and verbatim relay, no head derivation and no machine cache in the
//              App, the pure library, the runtime view's guarded reads, the daemon's identity-first submit
//              and read model, the M09.11 gate asking the daemon for the head, canon's binding (pins).
//   SPINE    — full mode, one isolated daemon with the two simulated reference backends planted, the runner's
//              OWN serve as the INTEGRATED form and the daemon's HTTP API driven by this runner as the
//              STANDALONE form (M12.2's thin-client precedent — the distributed client is NAMED): anonymous
//              proposals refused 401 through both; create through the App, operate through the thin client
//              and back; the App's rendered spine equals the daemon's member for member; refusals (stale head,
//              drifted and unknown declarations) receipted and rendered verbatim; the record families'
//              digests unchanged by any read; the daemon restarted on the same records and the App restarted,
//              removed and doubled with identical readback; the workload deleted through the thin client with
//              its history intact.
//   EXT      — full mode, on the same plane: an ODK-authored mesh (ontology → revision → v2 descriptor naming
//              the public machine read model AND a non-public ref → manifest → DomainApp) admitted through
//              Packages (candidate → release → install → registration → governed mount → serving → serving
//              binding) reaches its runtime view through the compiled join: the view renders the machine
//              inventory in parity with the daemon, lists the non-public ref unrendered, offers the declared
//              action disabled with a typed reason, carries no lane, form or script call; anonymous cannot
//              reach the route; the registration's class, origin, effect boundary and route are derived.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills           CI-bound, seconds: the binding, PURE, SOURCE, the verdict rules. No daemon.
//   --mutation         planted defects against the drills' oracles — each must go red.
//   --mint-fixture <p> full-mode SPINE only, writing the daemon's read model to <p> as the drills' fixture.
//   (default)          the full gate: the drills, SPINE, EXT, then every composed gate inside the
//                      isolated-egress harness. Exit 0 pass, 2 named failure, 1 fail. Spend-free by
//                      construction: both reference backends are simulated and the executor refuses any other.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/machine-product-composition.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const FIXTURE = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m08-15-machine-read-model-fixture-2026-09-20.v1.json");
const CANON_SURFACES = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
const CANON_PE = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "providers-and-environments.md");
const SERVE = path.join(APP_DIR, "scripts", "serve-product-ui.mjs");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "machine-product-composition.mjs");
const MACHINE_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "machine_routes.rs");
const DAEMON_MAIN = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const CONFORMANCE_GATE = path.join(ROOT, "scripts", "check-machine-lifecycle-backend-conformance.mjs");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : flag("--mint-fixture") ? "mint" : "full";
const GENESIS = `sha256:${"0".repeat(64)}`;
const HASH = /^sha256:[0-9a-f]{64}$/u;
const SOAK_PREREQ = "IOI_ACC20_SOAK_EVIDENCE naming fresh hosted (this host's KVM, an ordinary-OS backend) and attached (an independently implemented attached-estate backend) subjects driven through the phase-by-phase crash/restart/recovery matrix (check:governed-machine-product --soak)";
const SOAK_RULING = "the journey's own matrix text (the merge lane uses deterministic reference backends; a release claim additionally carries fresh scheduled backend/host evidence), R-139 (2026-09-14) and R-215 (2026-09-20): a missing backend or host blocks a RUN, never the unit";
const OWNER_Q = "owner question, R-215";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const rootGate = (script, minutes, undrilled) => ({ kind: "root", script, minutes, undrilled });
const CONFORMANCE = rootGate("check:machine-lifecycle-backend-conformance", 15, "M09.11's own gate; its drill battery is M09.11's to author (named in its module record)");
// The packages journey runs a 3-posture BROWSER matrix; Chromium probes Google Public DNS over HTTPS
// (2001:4860:4860::8888:443) on start-up, and the host refuses it (ENETUNREACH). Declared here, by
// name, as the browser's probe and not the journey's subject — the classifier still counts it and
// the evidence records it; an UNDECLARED destination stays a failure.
const PACKAGES = { ...gate("check:packages-journey", "packages-journey", 30), declaredHosts: ["2001:4860:4860::8888"], declaredNames: ["dns.google"], declared_note: "Chromium's DNS-over-HTTPS probe from the journey's browser matrix; refused by the host (ENETUNREACH); not the journey's subject" };
const ODK = gate("check:odk-contract-and-domainapp", "odk-contract-and-domainapp", 30);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const SPINE = self("spine");
const EXT = self("ext");

export const CLAUSES = [
  { n: 1, demand: "contracts precede surfaces, the sixteen-verb vocabulary is one and closed, and capability truth is the backend's current declaration bound by ref and hash (unsupported, drifted, stale and replayed cells refuse before effect; a non-simulated backend is admitted and never executed by the reference executor)", executed_by: [CONFORMANCE] },
  { n: 2, demand: "one desired/observed spine: the App renders the daemon's read model — head, generations, phases, the bound declaration, operations in chain order, receipts, cleanup obligations — member for member and derives none of it; the standalone client reads the same spine from the same route", executed_by: [PURE, SOURCE, SPINE] },
  { n: 3, demand: "authority and effects do not move into clients: both clients submit PROPOSALS under the operator's own session, an anonymous proposal is refused 401 through either, the daemon mints the identity and records the submitter as it resolved it, the App's lane relays the daemon's answer verbatim", executed_by: [SPINE, SOURCE], absence: { what: "the wallet-owned authority challenge on a machine operation — a proposal's authority_refs are schema strings the kernel does not adjudicate, and no machine verb parks a byte-derived card the way a provider operation does (M08.11); the daemon binds identity and admits through its kernel, it does not yet ask the custody tier", owner: `M09.11's authority seam with the M03 approval card (${OWNER_Q})` } },
  { n: 4, demand: "capability truth through the clients: a drifted declaration hash and a declaration the daemon does not hold refuse with a receipt through the App's lane, and the refusal is rendered verbatim on the machine's page beside its receipt ref", executed_by: [SPINE, CONFORMANCE] },
  { n: 5, demand: "integrated and standalone are the same product truth: create through the App, operate through the standalone client and back, and both read the same workload, operation ids, receipts, history and inventory", executed_by: [SPINE], absence: { what: "a separately DISTRIBUTED focused client on an ADR 0032 axis (a packaged cli_headless or TUI presentation over the same routes): the standalone FORM here is the daemon's HTTP API driven as a thin client, M12.2's precedent, labelled exactly that", owner: `the standalone client's packaging (${OWNER_Q}; the taxonomy's cli_headless first-class client)` } },
  { n: 6, demand: "restart both, remove either: the daemon restarted on the same records and the App restarted read back the identical spine; the App removed leaves the standalone readback unchanged; a second App instance reads the same and its removal changes nothing; no client read changes any record family", executed_by: [SPINE], scheduled: { what: "daemon, client and backend LOSS mid-operation and crash before/after durable steps on fresh hosted and attached subjects — the phase-by-phase crash/restart/recovery matrix", prerequisite: SOAK_PREREQ, ruling: SOAK_RULING } },
  { n: 7, demand: "deletion survival: the workload deleted through the standalone client keeps its whole history readable from both clients, its observed phase reads deleted, and the inventory keeps the row rather than forgetting the machine", executed_by: [SPINE] },
  { n: 8, demand: "console sessions, device/volume/network attachments, snapshot/restore lineage, capacity and health, image posture and host inventory through the existing owner surfaces", executed_by: [], absence: { what: "the daemon serves the operation and receipt members of the machine-control family on one route; the nine host/image/attachment/console/snapshot/migration/maintenance members are registered and unserved, so no surface can render them without inventing them — the snapshot VERB is admitted and receipted here, its lineage is not a record", owner: "M09.11 (its own OUTSTANDING: attachments, console scope, snapshot lineage — ACC-20 clause 6)" } },
  { n: 9, demand: "the extension seam is real: an ODK-authored, Packages-admitted extension_application reaches its runtime view through the compiled join and renders the machine inventory from the PUBLIC read model in parity with the daemon, offers its declared actions, and cannot render a ref outside the public list", executed_by: [EXT, PURE, PACKAGES, ODK], absence: { what: "the extension's INVOCATION crossing: an offered action is rendered disabled with a typed reason because no gateway path exists for an extension to submit a machine proposal under its own admitted contracts (canon routes UI-initiated extension actions through the MCP Gateway / RuntimeToolContract, which has no machine binding)", owner: `the DomainApp runtime plane and the Hypervisor MCP Gateway (${OWNER_Q})` } },
  { n: 10, demand: "the four mutations refuse: private projection (anonymous cannot reach the extension's route, the compiled join answers only under the caller's org, a non-public daemon_api_ref is listed and never fetched, an environment's identity never appears on the extension's page), authority bypass (anonymous 401 at the daemon and through the App's lane, no lane, form or script call on the extension's page), capability forgery (a forged hash and an unknown declaration refuse with receipts), first-party privilege (class, origin, effect boundary and route are derived by the registration, never claimed)", executed_by: [EXT, SPINE, SOURCE] },
  { n: 11, demand: "neither delivery form is a second runtime, database, machine owner, authority path or receipt writer: the App keeps no machine cache and derives no head, the library is pure, the daemon's record families are unchanged by every client read, and the standalone client holds nothing between requests", executed_by: [SOURCE, SPINE], absence: { what: "an ODK SCAFFOLDING command: the extension's mesh is authored through the ODK routes (the dev kit's four draft objects); no `scaffold` verb produces a package skeleton, fixtures or conformance checks from a template", owner: `M05's developer kit (${OWNER_Q})` } },
  { n: 12, demand: "backend registration through a route, Agentgres-backed machine truth, and the two profile certificates", executed_by: [], absence: { what: "declarations are planted as files under machine-capability-declarations (no registration route); the machine families are durable_fs records, not Agentgres streams; workstation_hosted_v1 and infrastructure_attached_v1 are M12.15's certificates", owner: "M09.11 (registration route, Agentgres migration) · M12.15 (check:machine-product-profile-qualification)" } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.machine-product-composition-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, spine: null, ext: null, clauses: [], verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function blocked(reason) { console.error(`BLOCKED: ${reason}`); writeEvidence(); process.exit(2); }
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `machine-product-composition-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
const sha256File = (f) => (fs.existsSync(f) ? sha256(fs.readFileSync(f)) : null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));

// The runner's OWN copy of the spine's member names — the oracle the projection is measured against, so a
// library that quietly dropped a member cannot also drop it from the expectation.
const EXPECTED_SPINE_MEMBERS = ["workload_ref", "workload_id", "head", "head_error", "desired_generation", "observed_generation", "desired_phase", "observed_phase", "backend_registration_ref", "capability_declaration_ref", "capability_declaration_hash", "capability_declaration_resolves", "evidence_mode", "operation_count", "admitted_count", "refused_count", "receipt_count", "cleanup_obligation_refs"];
const EXPECTED_OPERATION_MEMBERS = ["operation_ref", "operation", "state", "admitted", "refusal_dimension", "refusal_reason", "previous_head", "admitted_request_hash", "receipt_ref", "result", "submitted_by", "capability_declaration_ref", "capability_declaration_hash"];
const EXPECTED_RECEIPT_MEMBERS = ["receipt_ref", "operation_ref", "result", "result_reason", "backend_native_operation_id", "desired_generation_before", "desired_generation_after", "observed_generation_before", "observed_generation_after"];

// ---- PURE: the projection, renderers and readers over the fixture ----------------------------------------
export function pureFindings(lib, fixture) {
  const f = [];
  const machines = Array.isArray(fixture?.machines) ? fixture.machines : [];
  const real = machines.find((m) => Array.isArray(m.operations) && m.operations.length >= 3 && m.receipts?.length >= 2) ?? machines[0];
  if (!real) return ["fixture_has_no_machine"];
  const esc = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  // 1. the readout carries every member and derives none: each scalar equals the daemon's, as a string
  const p = lib.projectMachineSpine(real);
  for (const k of EXPECTED_SPINE_MEMBERS) {
    if (!(k in p)) { f.push(`projection_drops_member:${k}`); continue; }
    const expected = Array.isArray(real[k]) ? real[k].join(" ") : real[k] == null ? "" : String(real[k]);
    if (p[k] !== expected) f.push(`projection_alters_member:${k}:${String(p[k]).slice(0, 30)}≠${expected.slice(0, 30)}`);
  }
  if (!Array.isArray(p.operations) || p.operations.length !== real.operations.length) f.push("projection_operations_count");
  else for (const k of EXPECTED_OPERATION_MEMBERS) if (!(k in (p.operations[0] ?? {}))) f.push(`projection_drops_operation_member:${k}`);
  if (!Array.isArray(p.receipts) || p.receipts.length !== real.receipts.length) f.push("projection_receipts_count");
  else for (const k of EXPECTED_RECEIPT_MEMBERS) if (!(k in (p.receipts[0] ?? {}))) f.push(`projection_drops_receipt_member:${k}`);
  // 2. a fork reads back as NO head (the daemon said null; a projection that computed one from the last
  //    operation would be the client-side derivation the unit forbids)
  const forked = { ...real, head: null, head_error: "2 uncited heads for this workload — a fork, not a history", admitted_count: 0 };
  const pf = lib.projectMachineSpine(forked);
  if (pf.head !== "" || pf.head_error !== forked.head_error) f.push(`projection_derives_head_on_fork:${String(pf.head).slice(0, 20)}`);
  // 3. render → read back → parity, member for member
  const html = lib.renderMachineDetail(real, { esc });
  const back = lib.spineFromRenderedDetail(html);
  const parity = lib.spineParity(back, real);
  if (parity.length) f.push(`rendered_detail_parity:${parity.slice(0, 3).join("|")}`);
  for (const k of EXPECTED_SPINE_MEMBERS) if (!(k in back)) f.push(`rendered_detail_drops_member:${k}`);
  if (!html.includes(`data-ioi-machine-lane="${lib.MACHINE_LANE_PATH}"`)) f.push("rendered_detail_lane_form_missing");
  if (!/data-ioi-refusal="expected_head_stale"|data-ioi-refusal="capability_declaration_drifted"|data-ioi-refusal="capability_declaration_not_resolved"/u.test(html) && real.operations.some((o) => o.refusal_dimension)) f.push("rendered_detail_refusal_not_verbatim");
  // 4. parity DETECTS a changed head, a changed receipt result, a changed phase, a dropped operation
  const clone = () => JSON.parse(JSON.stringify(real));
  const h2 = clone(); h2.head = `sha256:${"f".repeat(64)}`;
  if (!lib.spineParity(real, h2).some((x) => x.startsWith("head:"))) f.push("parity_blind_to_head");
  const r2 = clone(); r2.receipts[0].result = "ambiguous";
  if (!lib.spineParity(real, r2).some((x) => /receipts\[0\]\.result/u.test(x))) f.push("parity_blind_to_receipt");
  const ph = clone(); ph.observed_phase = "somewhere-else";
  if (!lib.spineParity(real, ph).some((x) => x.startsWith("observed_phase:"))) f.push("parity_blind_to_phase");
  const o2 = clone(); o2.operations.pop();
  if (!lib.spineParity(real, o2).some((x) => x.startsWith("operations:"))) f.push("parity_blind_to_operations");
  // 5. the inventory renders every machine and reads back
  const inv = lib.renderMachineInventory(machines, { esc });
  const invBack = lib.inventoryFromRendered(inv);
  const invParity = lib.inventoryParity(invBack, machines);
  if (invParity.length) f.push(`rendered_inventory_parity:${invParity.slice(0, 3).join("|")}`);
  if (invBack.length !== machines.length) f.push(`rendered_inventory_count:${invBack.length}≠${machines.length}`);
  const emptyInv = lib.renderMachineInventory([], { esc });
  if (!emptyInv.includes('data-ioi-machines-empty="true"') || lib.inventoryFromRendered(emptyInv).length !== 0) f.push("rendered_inventory_invents_rows");
  // 6. the extension view: the public read model rendered in parity, a non-public ref listed and never
  //    rendered, the declared action offered DISABLED with the typed reason, no form and no lane
  const descriptor = { daemon_api_refs: ["api://v1/hypervisor/machines", "api://v1/hypervisor/environments-summary"], allowed_action_refs: ["action://machine-console/start"] };
  const ext = lib.renderExtensionMachineReads({ descriptor, machines, esc });
  const reads = lib.extensionReadsFromRendered(ext);
  if (reads.machines.length !== machines.length) f.push(`ext_render_count:${reads.machines.length}≠${machines.length}`);
  else machines.forEach((m, i) => { if (!(reads.machines[i].workload_id === String(m.workload_id) && reads.machines[i].head === String(m.head ?? "") && reads.machines[i].observed_phase === String(m.observed_phase))) f.push(`ext_render_parity:${i}`); });
  if (!reads.not_public.includes("api://v1/hypervisor/environments-summary")) f.push("ext_render_non_public_not_listed");
  if (ext.includes("environments-summary\" data-ioi-ext-read") || /data-ioi-ext-read="api:\/\/v1\/hypervisor\/environments-summary"/u.test(ext)) f.push("ext_render_non_public_rendered");
  if (!(reads.actions.length === 1 && reads.actions[0].ref === "action://machine-console/start" && reads.actions[0].disabled === true && reads.actions[0].reason === lib.EXTENSION_ACTION_REASON)) f.push(`ext_render_action:${JSON.stringify(reads.actions).slice(0, 100)}`);
  if (reads.has_form || reads.has_script_fetch || reads.names_lane) f.push("ext_render_carries_a_lane");
  if (lib.renderExtensionMachineReads({ descriptor: { daemon_api_refs: [], allowed_action_refs: [] }, machines, esc }) !== "") f.push("ext_render_invents_reads");
  const closed = Object.keys(lib.PUBLIC_EXTENSION_READS);
  if (!(closed.length === 1 && closed[0] === "api://v1/hypervisor/machines" && lib.PUBLIC_EXTENSION_READS[closed[0]] === "/v1/hypervisor/machines")) f.push(`ext_public_list_not_closed:${closed.join(",")}`);
  return f;
}

// ---- SOURCE: pins ----------------------------------------------------------------------------------------
export function sourceFindings({ serve, lib, routes, daemonMain, conformance }) {
  const f = [];
  if (!serve.includes("pathname === MACHINES_ROUTE && req.method === \"GET\"")) f.push("pin_serve_inventory_route_missing");
  if (!serve.includes("pathname.startsWith(`${MACHINES_ROUTE}/`) && req.method === \"GET\"")) f.push("pin_serve_detail_route_missing");
  if (!serve.includes("pathname === MACHINE_LANE_PATH && req.method === \"POST\"")) f.push("pin_serve_lane_route_missing");
  if (!serve.includes("res.end(relayed.text);")) f.push("pin_serve_lane_not_verbatim");
  if (!/daemonFetch\(`\$\{MACHINES_API\}\/\$\{encodeURIComponent\(workload\)\}\/operations`, \{ method: "POST"/u.test(serve)) f.push("pin_serve_lane_not_the_daemon_route");
  if (/admitted_request_hash|previous_head|MACHINE_GENESIS|"0"\.repeat\(64\)/u.test(serve)) f.push("pin_serve_derives_head");
  if (/machineCache|machine_cache|machinesCache/u.test(serve)) f.push("pin_serve_keeps_machine_cache");
  const laneStart = serve.indexOf("pathname === MACHINE_LANE_PATH && req.method === \"POST\"");
  const laneBody = laneStart >= 0 ? serve.slice(laneStart, serve.indexOf("pathname === \"/__ioi/provider-ops\"", laneStart)) : "";
  if (laneBody && /mintLocalApproverGrant|wallet_approval_grant|approver/u.test(laneBody)) f.push("pin_serve_lane_touches_authority");
  if (!(serve.includes("renderExtensionMachineReads({ descriptor: desc") && serve.includes("head + banner + model + reads + footer"))) f.push("pin_runtime_view_reads_missing");
  const viewStart = serve.indexOf("const publicReads = {};");
  const viewBody = viewStart >= 0 ? serve.slice(viewStart, serve.indexOf("renderDomainAppRuntimeView(rt, dapp, descriptor, ontRes.ontology || {}, publicReads)", viewStart)) : "";
  const fetches = (viewBody.match(/daemonFetch\(/gu) ?? []).length;
  if (!(viewBody && fetches === 1 && viewBody.includes("if (ref === \"api://v1/hypervisor/machines\" && PUBLIC_EXTENSION_READS[ref])"))) f.push(`pin_runtime_view_reads_unguarded:${fetches}`);
  if (/\bfetch\(|from "node:fs"|process\.env/u.test(lib)) f.push("pin_lib_not_pure");
  if (/new Set\(|\bcited\b|"running"|"stopped"|"deleted"/u.test(lib)) f.push("pin_lib_derives_head_or_phase");
  if (!lib.includes("disabled aria-disabled=\"true\"") || !lib.includes("EXTENSION_ACTION_REASON")) f.push("pin_lib_extension_actions_enabled");
  const extFn = lib.slice(lib.indexOf("export function renderExtensionMachineReads"), lib.indexOf("// ---- readers"));
  if (/<form\b/u.test(extFn)) f.push("pin_lib_extension_view_has_form");
  if (!(routes.includes("request_principal_required") && routes.includes("StatusCode::UNAUTHORIZED") && routes.includes("resolve_principal(&st.data_dir, &headers)"))) f.push("pin_daemon_submit_not_identity_first");
  if (!(routes.includes("pub(crate) fn machine_spine(") && routes.includes("pub(crate) async fn handle_machine_get(") && routes.includes("pub(crate) async fn handle_machines_list("))) f.push("pin_daemon_read_model_missing");
  if (!(routes.includes("\"submitted_by\": submitted_by") && routes.includes("observed_head_for(data_dir, workload_ref)"))) f.push("pin_daemon_record_or_head_rule");
  if (!(daemonMain.includes("machine_routes::handle_machines_list") && daemonMain.includes("machine_routes::handle_machine_get"))) f.push("pin_daemon_routes_unwired");
  const head = conformance.slice(conformance.indexOf("async function currentHead()"), conformance.indexOf("async function submit("));
  if (!head.includes("/v1/hypervisor/machines/vm_conformance`") || /\bcited\b|new Set\(/u.test(head)) f.push("pin_conformance_gate_derives_head");
  if (!conformance.includes("auth/bootstrap")) f.push("pin_conformance_gate_anonymous");
  return f;
}
export function canonFindings(surfaces, pe) {
  const f = [];
  const s = surfaces.replace(/\s+/gu, " ");
  const p = pe.replace(/\s+/gu, " ");
  const need = [["surfaces_gate", s, /`check:machine-product-composition`/u], ["surfaces_never_standalone_in_truth", s, /never standalone in truth/u], ["surfaces_no_bypass", s, /No generated or hand-authored console may bypass the same daemon operation and owner boundaries/u], ["pe_gate", p, /`check:machine-product-composition`/u], ["pe_read_model", p, /GET \/v1\/hypervisor\/machines/u]];
  for (const [name, text, re] of need) if (!re.test(text)) f.push(`canon_${name}_missing`);
  return f;
}
export function bindingFindings(clauses, { rootPkg, appPkg, floors }) {
  const f = [];
  const seen = new Set();
  for (const c of clauses) {
    if (!Number.isInteger(c.n) || c.n < 1 || c.n > 12) f.push(`clause_out_of_range: ${c.n}`);
    if (seen.has(c.n)) f.push(`clause_duplicated: ${c.n}`);
    seen.add(c.n);
    if ((c.executed_by ?? []).length === 0 && !c.absence && !c.scheduled) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
        if (!row) f.push(`clause_${c.n}_floor_missing: ${g.floor}`);
        else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) f.push(`clause_${c.n}_floor_mismatch: ${g.floor}`);
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")] && !(typeof g.undrilled === "string" && g.undrilled.length > 20)) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}
export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 12) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.scheduled) { if (!(r.scheduled.prerequisite && r.scheduled.ruling)) failures.push(`clause_${r.n}_scheduled_without_prerequisite_or_ruling`); else absences.push({ n: r.n, what: `SCHEDULED-OUTSTANDING: ${r.scheduled.what}`, owner: `prerequisite: ${r.scheduled.prerequisite} · ${r.scheduled.ruling}` }); }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ------------------------------------------------------------------------------------------------
function sources() {
  return { serve: fs.readFileSync(SERVE, "utf8"), lib: fs.readFileSync(LIB_PATH, "utf8"), routes: fs.readFileSync(MACHINE_ROUTES, "utf8"), daemonMain: fs.readFileSync(DAEMON_MAIN, "utf8"), conformance: fs.readFileSync(CONFORMANCE_GATE, "utf8") };
}
async function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  const b = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("BINDING — the acceptance's demands are twelve clauses, each executed by a floored gate, M09.11's own gate or this runner's legs, or named with an owner or scheduled with its prerequisite and ruling", b.length === 0, b.join("; ") || `${CLAUSES.length} clauses`);
  const fixture = fs.existsSync(FIXTURE) ? readJson(FIXTURE) : null;
  const pf = fixture ? pureFindings(LIB, fixture) : ["fixture_missing"];
  evidence.pure = { findings: pf, fixture: fixture ? { sha256: sha256File(FIXTURE), machines: fixture.machines?.length, minted_at: fixture.minted_at } : null };
  ok("PURE — over the tracked read-model fixture: the App's readout carries every member of the daemon's spine and derives none (a fork reads back as no head); a page renders and reads back member for member with the lane form and the refusals verbatim; parity detects a changed head, receipt, phase and operation; the inventory renders every machine and invents none; the extension view renders only the public read model, lists the non-public ref unrendered, offers the action disabled with the typed reason and carries no lane", pf.length === 0, pf.join("; ") || `${fixture?.machines?.length} machine(s) in the fixture`);
  const sf = sourceFindings(sources());
  evidence.source = sf;
  ok("SOURCE — the serve's inventory, detail and lane routes, the lane relaying the daemon's answer verbatim to the daemon's own route and touching no authority, no head derivation and no machine cache in the App, the runtime view's single guarded public read, the pure library with disabled offers and no form, the daemon's identity-first submit, its read model, its recorded submitter and its head rule, the routes wired, the M09.11 gate asking the daemon for the head under a bootstrapped session", sf.length === 0, sf.join("; ") || "pins hold");
  const c = canonFindings(fs.readFileSync(CANON_SURFACES, "utf8"), fs.readFileSync(CANON_PE, "utf8"));
  ok("CANON — core-clients-surfaces.md binds the gate to the two delivery forms and the extension path; providers-and-environments.md names the read model and the gate", c.length === 0, c.join("; ") || "bound");
  const rows = CLAUSES.map((x) => ({ n: x.n, executed: (x.executed_by ?? []).map((g) => ({ script: g.script, status: 0, evidence: "x", evidence_sha256: "sha256:x", ledger: { reach: 0 } })), absence: x.absence || null, scheduled: x.scheduled || null }));
  const v = verdict(rows);
  const v2 = verdict(rows.map((r) => (r.n === 2 ? { ...r, executed: [{ ...r.executed[0], status: 1 }] } : r)));
  const v3 = verdict(rows.map((r) => (r.n === 2 ? { ...r, executed: [{ ...r.executed[0], evidence: null }] } : r)));
  const v4 = verdict(rows.map((r) => (r.n === 2 ? { ...r, executed: [{ ...r.executed[0], ledger: { reach: 1 } }] } : r)));
  const v5 = verdict(rows.filter((r) => r.n !== 7));
  ok("VERDICT — pass only when every clause is executed green with evidence and no absence is named; a named absence or scheduled leg is a NAMED FAILURE (exit 2); a red, an evidence-less green, an undeclared egress or a missing row is a FAIL", v.kind === "named_failure" && v2.kind === "fail" && v3.kind === "fail" && v4.kind === "fail" && v5.kind === "fail", `${v.kind}/${v2.kind}/${v3.kind}/${v4.kind}/${v5.kind}`);
}

// ---- mutation: planted defects, each must go red ----------------------------------------------------------
async function mutantLib(transform) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpc-mutant-"));
  const file = path.join(dir, `lib-${crypto.randomBytes(4).toString("hex")}.mjs`);
  fs.writeFileSync(file, transform(fs.readFileSync(LIB_PATH, "utf8")));
  const mod = await import(pathToFileURL(file).href);
  return { mod, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
async function mutation() {
  const rows = [];
  sink = [];
  const plant = (name, detected, detail) => { rows.push({ name, detected: !!detected, detail: String(detail ?? "").slice(0, 160) }); console.log(`${detected ? "RED " : "MISS"}  ${name}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const fixture = readJson(FIXTURE);
  const s = sources();
  const mutate = async (name, transform, predicate) => {
    let m = null;
    try { m = await mutantLib(transform); const f = pureFindings(m.mod, fixture); plant(name, predicate(f), f[0]); } catch (error) { plant(name, true, `mutant does not load: ${String(error?.message || error).slice(0, 80)}`); } finally { m?.cleanup(); }
  };
  await mutate("a projection that drops the head from the readout", (t) => t.replace('"workload_ref", "workload_id", "head", "head_error",', '"workload_ref", "workload_id", "head_error",'), (f) => f.some((x) => x === "projection_drops_member:head" || x.startsWith("rendered_detail_drops_member:head")));
  await mutate("a projection that DERIVES the head from the last operation (the client-side rule)", (t) => t.replace("  return {\n    ...pick(m, SPINE_MEMBERS),", "  const derived = (Array.isArray(m.operations) ? m.operations : []).filter((o) => o.admitted === true).map((o) => o.admitted_request_hash).at(-1);\n  return {\n    ...pick(m, SPINE_MEMBERS),\n    head: m.head == null ? String(derived ?? \"\") : String(m.head),"), (f) => f.some((x) => x.startsWith("projection_derives_head_on_fork")));
  await mutate("a renderer that drops a receipt member from the page", (t) => t.replace('"data-ioi-generations": `${r.desired_generation_before}/${r.desired_generation_after}/${r.observed_generation_before}/${r.observed_generation_after}`', '"data-ioi-generations": `${r.desired_generation_before}/${r.desired_generation_after}/${r.observed_generation_before}/0`'), (f) => f.some((x) => x.startsWith("rendered_detail_parity")));
  await mutate("a parity that ignores receipts", (t) => t.replace("  if (a.receipts.length !== b.receipts.length) f.push(`receipts:${a.receipts.length}≠${b.receipts.length}`);\n  else a.receipts.forEach", "  if (false) f.push(\"\");\n  else if (false) a.receipts.forEach"), (f) => f.includes("parity_blind_to_receipt"));
  await mutate("an inventory that renders only the first machine", (t) => t.replace("const rows = projectMachineInventory(machines);\n  const body = rows.length", "const rows = projectMachineInventory(machines).slice(0, 1);\n  const body = rows.length"), (f) => f.some((x) => x.startsWith("rendered_inventory_count") || x.startsWith("rendered_inventory_parity")));
  await mutate("an extension view that ENABLES the offered action", (t) => t.replace('<button class="act ghost" disabled aria-disabled="true"', '<button class="act ghost"'), (f) => f.some((x) => x.startsWith("ext_render_action")));
  await mutate("an extension view that treats a first-party projection as public", (t) => t.replace('Object.freeze({ "api://v1/hypervisor/machines": MACHINES_API })', 'Object.freeze({ "api://v1/hypervisor/machines": MACHINES_API, "api://v1/hypervisor/environments-summary": "/v1/hypervisor/environments-summary" })'), (f) => f.some((x) => x === "ext_render_non_public_not_listed" || x.startsWith("ext_public_list_not_closed")));
  await mutate("an extension view that carries a form", (t) => t.replace("return `<section data-ioi-ext-reads=\"${refs.length}\">${parts.join(\"\")}</section>`;", "return `<section data-ioi-ext-reads=\"${refs.length}\">${parts.join(\"\")}<form method=\"post\" action=\"/__ioi/machine-ops\"></form></section>`;"), (f) => f.includes("ext_render_carries_a_lane"));
  let f = sourceFindings({ ...s, serve: s.serve.replace("pathname === MACHINE_LANE_PATH && req.method === \"POST\"", "pathname === \"/__ioi/machine-ops-x\" && req.method === \"POST\"") });
  plant("a serve without the lane route", f.includes("pin_serve_lane_route_missing"), f[0]);
  f = sourceFindings({ ...s, serve: s.serve.replace("res.end(relayed.text);", "res.end(JSON.stringify({ ok: true }));") });
  plant("a lane that answers for the daemon instead of relaying it", f.includes("pin_serve_lane_not_verbatim"), f[0]);
  f = sourceFindings({ ...s, serve: `${s.serve}\nfunction shadowHead(ops) { const cited = new Set(ops.map((o) => o.previous_head)); return ops.map((o) => o.admitted_request_hash).find((h) => !cited.has(h)); }\n` });
  plant("a serve that derives the head", f.includes("pin_serve_derives_head"), f[0]);
  f = sourceFindings({ ...s, serve: s.serve.replace("if (ref === \"api://v1/hypervisor/machines\" && PUBLIC_EXTENSION_READS[ref]) {\n          publicReads.machines = await daemonFetch(PUBLIC_EXTENSION_READS[ref])", "if (true) {\n          publicReads.machines = await daemonFetch(ref.replace(\"api://\", \"/\"))") });
  plant("a runtime view that fetches whatever the descriptor names", f.some((x) => x.startsWith("pin_runtime_view_reads_unguarded")), f[0]);
  f = sourceFindings({ ...s, lib: s.lib.replace("disabled aria-disabled=\"true\"", "") });
  plant("a library whose offered actions are enabled", f.includes("pin_lib_extension_actions_enabled"), f[0]);
  f = sourceFindings({ ...s, routes: s.routes.replace(/request_principal_required/gu, "anyone_welcome") });
  plant("a daemon that admits an anonymous proposal", f.includes("pin_daemon_submit_not_identity_first"), f[0]);
  f = sourceFindings({ ...s, routes: s.routes.replace("\"submitted_by\": submitted_by", "\"submitted_by\": operation[\"owner_ref\"]") });
  plant("a daemon that records the caller's claimed owner as the submitter", f.includes("pin_daemon_record_or_head_rule"), f[0]);
  f = sourceFindings({ ...s, conformance: s.conformance.replace("async function currentHead() {", "async function currentHead() {\n  const cited = new Set();") });
  plant("the M09.11 gate deriving the head on its own again", f.includes("pin_conformance_gate_derives_head"), f[0]);
  const c = canonFindings(fs.readFileSync(CANON_SURFACES, "utf8").replace(/`check:machine-product-composition`/gu, "`check:something-else`"), fs.readFileSync(CANON_PE, "utf8"));
  plant("canon that no longer names the gate", c.includes("canon_surfaces_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const unbound = bindingFindings(CLAUSES.map((x) => (x.n === 8 ? { n: 8, demand: x.demand, executed_by: [] } : x)), { rootPkg: readJson(path.join(ROOT, "package.json")), appPkg: readJson(path.join(APP_DIR, "package.json")), floors: readJson(FLOORS) });
  plant("a clause that is neither executed nor named", unbound.includes("clause_8_neither_executed_nor_named"), unbound[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate: the REAL plane -----------------------------------------------------------------------
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
const PORTABLE = ["discover", "define", "import", "create", "start", "stop", "pause", "resume", "reboot", "open_console", "close_console", "snapshot", "delete"];
function declaration(reference, hash, supported, unsupported) {
  return { schema_version: "ioi.components.hypervisor.backend-capability-declaration.v1", declaration_ref: `capability://backend/${reference}/1`, declaration_hash: hash, producer_ref: "runtime://daemon/node-1", producer_release_ref: "release://hypervisor/0.1.0", backend_registration_ref: `backend://reference/${reference}`, adapter_release_ref: `release://adapter/${reference}/0.1.0`, scope_ref: "runtime-node://local/node-1", observed_backend_version: "1.0.0", evidence_mode: "simulated", discovery_method_ref: "evaluator://backend-preflight/v1", supported_machine_architectures: ["x86_64"], supported_operations: supported, unsupported_operations: unsupported, limitations: [], evaluator_ref: "evaluator://backend-capability/v1", signature_or_attestation_ref: "evidence://signature/backend-capability-1", temporal_verification_evidence_ref: "evidence://temporal/backend-capability-1", currentness_evaluation_ref: "evaluation://currentness/backend-capability-1", provenance_evidence_refs: ["evidence://preflight/backend-capability-1"] };
}
const HOSTED = declaration("workstation-hosted", `sha256:${"a".repeat(64)}`, [...PORTABLE, "clone", "restore"], [{ operation: "migrate", reason_code: "backend_is_single_host" }]);
const ATTACHED = declaration("infrastructure-attached", `sha256:${"b".repeat(64)}`, [...PORTABLE.filter((v) => !v.endsWith("_console")), "migrate"], [{ operation: "open_console", reason_code: "attached_estate_withholds_console" }, { operation: "close_console", reason_code: "attached_estate_withholds_console" }]);
let nonce = 0;
function proposal(workload, verb, decl, { head = GENESIS, generation = 1, hash = null, declarationRef = null } = {}) {
  nonce += 1;
  return { schema_version: "ioi.hypervisor.machine-operation.v1", operation_ref: "machine-operation://caller-chose-this", operation: verb, workload_ref: `virtual-machine-workload://${workload}`, desired_generation: generation, expected_head: head, owner_ref: "principal://owner_01", environment_ref: "environment://env_01", backend_registration_ref: decl.backend_registration_ref, capability_declaration_ref: declarationRef ?? decl.declaration_ref, capability_declaration_hash: hash ?? decl.declaration_hash, affected_image_bindings: [], affected_volume_bindings: [], affected_network_bindings: [], affected_device_bindings: [], authority_refs: ["authority://wallet_network_01"], policy_refs: [], idempotency_key_hash: `sha256:${String(nonce).padStart(64, "d")}`, cleanup_obligation_ref: null, durability_boundary_ref: "durability-boundary://declared_01", observation_boundary_ref: "observation-boundary://declared_01" };
}
function familyDigest(dataDir) {
  const h = crypto.createHash("sha256");
  for (const family of ["machine-operations", "machine-operation-receipts", "machine-capability-declarations"]) {
    const dir = path.join(dataDir, family);
    const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort() : [];
    for (const f of files) { h.update(`${family}/${f}\n`); h.update(fs.readFileSync(path.join(dir, f))); h.update("\n"); }
  }
  return `sha256:${h.digest("hex")}`;
}
function bootstrapTokenIn(dataDir) {
  const logs = fs.readdirSync(dataDir).filter((f) => /^isolated-daemon.*\.log$/u.test(f)).sort();
  for (const f of logs.reverse()) { const t = fs.readFileSync(path.join(dataDir, f), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1); if (t) return t; }
  return null;
}
async function startServe({ daemonUrl }) {
  const servePort = await freePort(); const productUiPort = await freePort();
  const url = `http://127.0.0.1:${servePort}`;
  let log = "";
  const child = spawn(process.execPath, [SERVE], { cwd: APP_DIR, env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP_DIR, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: daemonUrl }, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (c) => { log = `${log}${c}`.slice(-32000); });
  child.stderr.on("data", (c) => { log = `${log}${c}`.slice(-32000); });
  const up = await waitFor(`${url}/__ioi/login`, 90000);
  return { child, url, up, log: () => log, stop: () => { try { child.kill("SIGTERM"); } catch { /* gone */ } } };
}

async function fullLegs({ mintFixture = null } = {}) {
  const fs_ = []; const fe = [];
  const out = { spine: {}, ext: {} };
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpc-plane-"));
  let plane = null; let serve = null; let serve2 = null;
  const planeEnv = { IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_HYPERVISOR_DAEMON_BINARY: binary };
  try {
    fs.mkdirSync(path.join(dataDir, "machine-capability-declarations"), { recursive: true });
    fs.writeFileSync(path.join(dataDir, "machine-capability-declarations", "hosted.json"), JSON.stringify(HOSTED));
    fs.writeFileSync(path.join(dataDir, "machine-capability-declarations", "attached.json"), JSON.stringify(ATTACHED));
    plane = await startIsolatedPlane({ baseEnv: process.env, env: planeEnv, dataDir });
    if (!plane) { fs_.push("isolated_plane_did_not_start"); return { spine: { findings: fs_ }, ext: { findings: ["not_reached"] } }; }
    let DAEMON = plane.daemonUrl;
    const token = bootstrapTokenIn(dataDir);
    const boot = await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "machine-product-composition-pass-1", email: "machine-product-composition@ioi.local" }) });
    const bootBody = await boot.json().catch(() => ({}));
    const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
    if (!cookie) fs_.push(`bootstrap:${boot.status}`);
    const jd = (base, p, init = {}) => fetch(`${base}${p}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...(init.anonymous ? {} : { cookie }), ...(init.headers || {}) } }).then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = {}; } return { status: r.status, body, text, headers: r.headers }; });
    const who = (await jd(DAEMON, "/v1/hypervisor/auth/whoami")).body;
    const PRINCIPAL_ID = who.principal?.principal_id ?? who.principal?.id ?? "";
    const OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
    if (!(PRINCIPAL_ID && OWNER)) fs_.push(`whoami:${JSON.stringify(who).slice(0, 120)}`);
    serve = await startServe({ daemonUrl: DAEMON });
    if (!serve.up) fs_.push("serve_did_not_start");
    let SERVE_URL = serve.url;
    const W = "vm_composed"; const W2 = "vm_attached";
    const thinSpine = async (w) => jd(DAEMON, `/v1/hypervisor/machines/${w}`);
    const thinList = async () => (await jd(DAEMON, "/v1/hypervisor/machines")).body?.machines ?? [];
    const appSubmit = (w, p, init = {}) => jd(SERVE_URL, LIB.MACHINE_LANE_PATH, { method: "POST", body: JSON.stringify({ workload: w, proposal: p }), ...init });
    const thinSubmit = (w, p, init = {}) => jd(DAEMON, `/v1/hypervisor/machines/${w}/operations`, { method: "POST", body: JSON.stringify(p), ...init });
    const appDetail = async (w) => { const r = await jd(SERVE_URL, `${LIB.MACHINES_ROUTE}/${w}`); return { status: r.status, spine: LIB.spineFromRenderedDetail(r.text), text: r.text }; };
    const appInventory = async () => { const r = await jd(SERVE_URL, LIB.MACHINES_ROUTE); return { status: r.status, rows: LIB.inventoryFromRendered(r.text), text: r.text }; };
    const parityNow = async (w, label) => { const t = await thinSpine(w); const a = await appDetail(w); const f = a.status === 200 && t.status === 200 ? LIB.spineParity(a.spine, t.body.machine) : [`status:${a.status}/${t.status}`]; if (f.length) fs_.push(`${label}:parity:${f.slice(0, 3).join("|")}`); return { thin: t.body.machine, app: a.spine }; };
    const digest0 = familyDigest(dataDir);
    // ---- SPINE 1: identity first, through both clients --------------------------------------------------
    const anonThin = await thinSubmit(W, proposal(W, "create", HOSTED), { anonymous: true });
    const anonApp = await appSubmit(W, proposal(W, "create", HOSTED), { anonymous: true });
    if (!(anonThin.status === 401 && anonThin.body?.reason === "request_principal_required")) fs_.push(`anonymous_thin:${anonThin.status}:${anonThin.body?.reason}`);
    if (!(anonApp.status === 401 && anonApp.body?.reason === "request_principal_required")) fs_.push(`anonymous_app:${anonApp.status}:${anonApp.body?.reason}`);
    const unknownBefore = await thinSpine(W);
    if (!(unknownBefore.status === 404 && unknownBefore.body?.code === "machine_workload_unknown")) fs_.push(`unknown_before_first_operation:${unknownBefore.status}`);
    const unknownPage = await appDetail(W);
    if (!(unknownPage.status === 404 && unknownPage.text.includes(`data-ioi-machine-unknown="${W}"`))) fs_.push(`unknown_page:${unknownPage.status}`);
    if (familyDigest(dataDir) !== digest0) fs_.push("refused_anonymous_wrote_a_record");
    // ---- SPINE 2: create through the App, start through the thin client, both read the same ------------
    const created = await appSubmit(W, proposal(W, "create", HOSTED, { generation: 1 }));
    if (!(created.status === 200 && created.body?.ok === true && created.body?.state === "succeeded" && String(created.body?.operation_ref).startsWith(`machine-operation://hypervisor/${W}/create/`))) fs_.push(`create_via_app:${created.status}:${JSON.stringify(created.body).slice(0, 120)}`);
    let t = await thinSpine(W);
    if (!(t.status === 200 && HASH.test(t.body.machine?.head) && t.body.machine.head !== GENESIS && t.body.machine.desired_phase === "defined" && t.body.machine.observed_phase === "defined" && t.body.machine.operations?.[0]?.submitted_by === `user://${PRINCIPAL_ID}`)) fs_.push(`spine_after_create:${JSON.stringify(t.body).slice(0, 160)}`);
    const started = await thinSubmit(W, proposal(W, "start", HOSTED, { head: t.body.machine?.head, generation: 2 }));
    if (!(started.status === 200 && started.body?.ok === true && started.body?.state === "succeeded")) fs_.push(`start_via_thin:${started.status}:${JSON.stringify(started.body).slice(0, 120)}`);
    let both = await parityNow(W, "after_start");
    if (!(both.thin?.observed_phase === "running" && both.thin?.observed_generation === 2 && both.app?.observed_phase === "running")) fs_.push(`phase_after_start:${both.thin?.observed_phase}/${both.app?.observed_phase}`);
    // ---- SPINE 3: refusals through the App, receipted and rendered verbatim -----------------------------
    const stale = await appSubmit(W, proposal(W, "stop", HOSTED, { head: GENESIS, generation: 3 }));
    if (!(stale.status === 200 && stale.body?.ok === false && stale.body?.reason === "expected_head_stale" && typeof stale.body?.receipt_ref === "string")) fs_.push(`stale_via_app:${JSON.stringify(stale.body).slice(0, 120)}`);
    const drifted = await appSubmit(W, proposal(W, "stop", HOSTED, { head: both.thin?.head, generation: 3, hash: `sha256:${"e".repeat(64)}` }));
    if (!(drifted.body?.reason === "capability_declaration_drifted" && typeof drifted.body?.receipt_ref === "string")) fs_.push(`drifted_via_app:${JSON.stringify(drifted.body).slice(0, 120)}`);
    const unknownDecl = await thinSubmit(W, proposal(W, "stop", HOSTED, { head: both.thin?.head, generation: 3, declarationRef: "capability://backend/invented-by-a-client/1" }));
    if (!(unknownDecl.body?.reason === "capability_declaration_not_resolved" && typeof unknownDecl.body?.receipt_ref === "string")) fs_.push(`unknown_declaration_via_thin:${JSON.stringify(unknownDecl.body).slice(0, 120)}`);
    const page = await appDetail(W);
    for (const [dim, ref] of [["expected_head_stale", stale.body?.receipt_ref], ["capability_declaration_drifted", drifted.body?.receipt_ref], ["capability_declaration_not_resolved", unknownDecl.body?.receipt_ref]]) {
      const row = page.spine.operations.find((o) => o.refusal_dimension === dim);
      if (!(row && row.receipt_ref === ref && row.state === "refused" && row.result === "refused")) fs_.push(`refusal_not_rendered_verbatim:${dim}`);
    }
    const snap = await appSubmit(W, proposal(W, "snapshot", HOSTED, { head: (await thinSpine(W)).body.machine?.head, generation: 3 }));
    if (!(snap.body?.ok === true && snap.body?.state === "succeeded")) fs_.push(`snapshot_via_app:${JSON.stringify(snap.body).slice(0, 120)}`);
    both = await parityNow(W, "after_snapshot");
    if (both.thin?.observed_phase !== "running") fs_.push(`snapshot_moved_phase:${both.thin?.observed_phase}`);
    // a second workload on the attached backend, through the thin client: an ambiguous migration
    const created2 = await thinSubmit(W2, proposal(W2, "create", ATTACHED, { generation: 1 }));
    const h2 = (await thinSpine(W2)).body.machine?.head;
    const migrated = await thinSubmit(W2, proposal(W2, "migrate", ATTACHED, { head: h2, generation: 2 }));
    if (!(created2.body?.ok === true && migrated.body?.ok === true && migrated.body?.state === "ambiguous")) fs_.push(`attached_workload:${created2.body?.state}/${migrated.body?.state}`);
    const t2 = (await thinSpine(W2)).body.machine;
    if (!(t2?.observed_generation === 1 && t2?.desired_generation === 1 && t2?.receipts?.some((r) => r.result === "ambiguous"))) fs_.push(`ambiguous_advanced_a_generation:${t2?.desired_generation}/${t2?.observed_generation}`);
    await parityNow(W2, "attached");
    // ---- SPINE 4: the inventory agrees, and reads write nothing ------------------------------------------
    const inv = await appInventory(); const list = await thinList();
    const invParity = LIB.inventoryParity(inv.rows, list);
    if (!(inv.status === 200 && list.length === 2 && invParity.length === 0)) fs_.push(`inventory:${inv.status}:${list.length}:${invParity.slice(0, 2).join("|")}`);
    if (!(list[0].workload_ref < list[1].workload_ref)) fs_.push("inventory_not_ordered");
    const digest1 = familyDigest(dataDir);
    for (let i = 0; i < 3; i += 1) { await appInventory(); await appDetail(W); await thinList(); await thinSpine(W2); }
    if (familyDigest(dataDir) !== digest1) fs_.push("reads_changed_a_record_family");
    const before = stable([(await thinSpine(W)).body.machine, (await thinSpine(W2)).body.machine]);
    if (mintFixture) {
      const fixture = { schema: "ioi.m08-15-machine-read-model-fixture.v1", minted_at: new Date().toISOString(), minted_by: "scripts/check-machine-product-composition.mjs --mint-fixture", source: "an isolated daemon with the two simulated reference declarations planted; create/start/snapshot on the hosted workload through the App lane and the thin client with three receipted refusals, and create/migrate (ambiguous) on the attached workload — the daemon's own read model, verbatim", machines: list };
      fs.mkdirSync(path.dirname(mintFixture), { recursive: true });
      fs.writeFileSync(mintFixture, `${JSON.stringify(fixture, null, 2)}\n`);
      out.spine.fixture_minted = path.relative(ROOT, mintFixture);
    }
    // ---- SPINE 5: restart both, remove either --------------------------------------------------------------
    serve.stop(); serve = null;
    await plane.stop();
    plane = await startIsolatedPlane({ baseEnv: process.env, env: planeEnv, dataDir });
    if (!plane) { fs_.push("isolated_plane_did_not_restart"); return { spine: { findings: fs_, ...out.spine }, ext: { findings: ["not_reached"] } }; }
    DAEMON = plane.daemonUrl;
    const afterDaemonRestart = stable([(await thinSpine(W)).body.machine, (await thinSpine(W2)).body.machine]);
    if (afterDaemonRestart !== before) fs_.push("daemon_restart_readback_differs");
    serve = await startServe({ daemonUrl: DAEMON }); SERVE_URL = serve.url;
    if (!serve.up) fs_.push("serve_did_not_restart");
    await parityNow(W, "after_restart_both");
    serve.stop(); serve = null;
    const withoutApp = stable([(await thinSpine(W)).body.machine, (await thinSpine(W2)).body.machine]);
    if (withoutApp !== before) fs_.push("app_removed_changed_readback");
    serve2 = await startServe({ daemonUrl: DAEMON }); SERVE_URL = serve2.url;
    if (!serve2.up) fs_.push("second_serve_did_not_start");
    await parityNow(W, "second_app");
    const invSecond = await appInventory();
    if (LIB.inventoryParity(invSecond.rows, await thinList()).length) fs_.push("second_app_inventory_differs");
    serve2.stop(); serve2 = null;
    if (stable([(await thinSpine(W)).body.machine, (await thinSpine(W2)).body.machine]) !== before) fs_.push("second_app_removed_changed_readback");
    if (familyDigest(dataDir) !== digest1) fs_.push("restart_or_removal_changed_a_record_family");
    serve = await startServe({ daemonUrl: DAEMON }); SERVE_URL = serve.url;
    // ---- SPINE 6: deletion survival --------------------------------------------------------------------------
    const head3 = (await thinSpine(W)).body.machine?.head;
    const opsBefore = (await thinSpine(W)).body.machine?.operations?.length ?? 0;
    const deleted = await thinSubmit(W, proposal(W, "delete", HOSTED, { head: head3, generation: 4 }));
    if (!(deleted.body?.ok === true && deleted.body?.state === "succeeded")) fs_.push(`delete_via_thin:${JSON.stringify(deleted.body).slice(0, 120)}`);
    const afterDelete = await parityNow(W, "after_delete");
    if (!(afterDelete.thin?.observed_phase === "deleted" && afterDelete.thin?.desired_phase === "deleted" && afterDelete.thin?.operations?.length === opsBefore + 1 && afterDelete.thin?.receipts?.length >= 5)) fs_.push(`history_after_delete:${afterDelete.thin?.observed_phase}:${afterDelete.thin?.operations?.length}/${opsBefore + 1}:${afterDelete.thin?.receipts?.length}`);
    const invAfter = await appInventory();
    if (!(invAfter.rows.some((r) => r.workload_id === W && r.observed_phase === "deleted") && (await thinList()).length === 2)) fs_.push("inventory_forgot_the_deleted_machine");
    out.spine = { ...out.spine, principal: PRINCIPAL_ID, owner: OWNER, workloads: [W, W2], head_after_create: t.body.machine?.head, refusal_receipts: [stale.body?.receipt_ref, drifted.body?.receipt_ref, unknownDecl.body?.receipt_ref], operations_after_delete: afterDelete.thin?.operations?.length, receipts_after_delete: afterDelete.thin?.receipts?.length, family_digest: familyDigest(dataDir) };
    if (mintFixture) return { spine: { findings: fs_, ...out.spine }, ext: { findings: [], not_run: "mint mode" } };
    // ---- EXT: the ODK-authored, Packages-admitted extension console ---------------------------------------
    const NS = "machine-console"; const ONT = "console"; const PKG = "machine-console-ext"; const INST = "primary"; const LANE = "/__ioi/packages/registry"; const SURFACE_REF = `surface://extensions/${PKG}`;
    const act = async (tail, fields, init = {}) => { const r = await fetch(`${SERVE_URL}${LANE}${tail}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(init.anonymous ? {} : { cookie }) }, body: new URLSearchParams(fields).toString(), redirect: "manual" }).catch(() => null); const location = r?.headers?.get("location") || ""; const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? ""); return { status: r?.status ?? 0, location, q }; };
    // an environment exists, so "no private projection" is measured against a real identity
    const env = await jd(DAEMON, "/v1/hypervisor/environments", { method: "POST", body: JSON.stringify({ spec: {} }) });
    const ENV_ID = env.body?.environment?.id ?? env.body?.id ?? env.body?.environment_id ?? "";
    if (!ENV_ID) fe.push(`environment:${env.status}:${JSON.stringify(env.body).slice(0, 100)}`);
    const ont = await jd(DAEMON, "/v1/hypervisor/odk/domain-ontologies", { method: "POST", body: JSON.stringify({ domain: NS, owner_ref: OWNER, idempotency_key: "mpc-ont-1" }) });
    const ontRef = ont.body?.ontology?.ref || "";
    const version = await jd(DAEMON, "/v1/hypervisor/ontology-versions", { method: "POST", body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "mpc-ontology-version-1", namespace: NS, name: ONT, governing_scope_ref: `domain://${NS}/registry`, policy_hash: `sha256:${"1a".repeat(32)}`, entity_types: [{ term_id: `ontology://${NS}/${ONT}/term/machine`, label: "machine" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } }) });
    const revisionRef = version.body?.ontology_version?.ontology_id || "";
    const sd = await jd(DAEMON, "/v1/hypervisor/odk/surface-descriptors", { method: "POST", body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "mpc-sd-1", schema_version: "ioi.ontology-surface-descriptor.v2", display_name: "Machine console (extension)", surface_ref: SURFACE_REF, composition_pattern: "domain_app", ontology_refs: [revisionRef], canonical_object_model_refs: [`object-model://${NS}/${ONT}/machine`], data_recipe_refs: [], policy_bound_data_view_refs: [`view://${NS}/inventory`], authority_requirement_refs: ["scope:machines.propose"], daemon_api_refs: ["api://v1/hypervisor/machines", "api://v1/hypervisor/environments-summary"], receipt_obligations: [`receipt://${NS}/proposal`], conformance_profile_refs: [`profile://${NS}/v1`], connector_mapping_refs: [], ontology_projection_refs: [], allowed_action_refs: [`action://${NS}/start`], operator_contract_refs: [], mcp_contract_refs: [], generated_artifact_refs: [], does_not_assert: ["authority", "capability_lease_crossing", "runtime_truth", "semantic_truth", "permission_truth", "marketplace_truth"] }) });
    const sdRef = sd.body?.surface_descriptor?.surface_descriptor_id || "";
    const man = await jd(DAEMON, "/v1/hypervisor/odk/manifests", { method: "POST", body: JSON.stringify({ name: "Machine console manifest", version: "1.0.0", ontology_refs: [ontRef], data_recipe_refs: [], surface_descriptor_refs: [sdRef], evaluation_dataset_refs: [], benchmark_profile_refs: [], operator_contract_refs: [], mcp_contract_refs: [], owner_ref: OWNER, idempotency_key: "mpc-man-1" }) });
    const manRef = man.body?.manifest?.odk_manifest_id || man.body?.manifest?.ref || "";
    const dapp = await jd(DAEMON, "/v1/hypervisor/domain-apps", { method: "POST", body: JSON.stringify({ name: "Machine console", surface_descriptor_ref: sdRef, odk_manifest_ref: manRef, owner_ref: OWNER, idempotency_key: "mpc-dapp-1" }) });
    const dappRef = dapp.body?.domain_app?.domain_app_id || "";
    if (!(ont.status === 201 && version.status === 201 && sd.status === 201 && man.status === 201 && dapp.status === 201 && dappRef)) fe.push(`odk_mesh:${ont.status}/${version.status}/${sd.status}/${man.status}/${dapp.status}:${JSON.stringify(sd.status === 201 ? (man.status === 201 ? dapp.body : man.body) : sd.body).slice(0, 600)}`);
    const admitted = await act("/actions/admit-candidate", { owner_ref: OWNER, package_id: PKG, domain_app_ref: dappRef, idempotency_key: "mpc-candidate-1", return: LANE });
    const pkgGet = async () => (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}`)).body;
    const candidateHead = (await pkgGet()).package?.agentgres?.head || "";
    if (!(admitted.status === 303 && admitted.q.get("acted") === "admit-candidate" && candidateHead)) fe.push(`candidate:${admitted.status}:${admitted.q.get("refused") ?? ""}`);
    const releaseCut = await act(`/${PKG}/cut-release`, { idempotency_key: "mpc-release-1", expected_package_head: candidateHead, surface_distribution: "private_registry", surface_capability_depth: "propose", object_contract_refs: `object-model://${NS}`, action_contract_refs: `action://${NS}/start`, evidence_refs: `artifact://${NS}/conformance`, return: `${LANE}?pkg=${PKG}` });
    const releaseDigest = releaseCut.q.get("record") || "";
    const releaseHead = (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}`)).body?.release?.agentgres?.head || "";
    if (!(releaseCut.status === 303 && HASH.test(releaseDigest) && releaseHead)) fe.push(`release:${releaseCut.status}:${releaseCut.q.get("refused") ?? ""}`);
    const installed = await act(`/${PKG}/install`, { idempotency_key: "mpc-install-1", release_digest: releaseDigest, expected_release_head: releaseHead, installation_id: INST, visibility: "organization", allowed_object_contract_refs: `object-model://${NS}`, allowed_action_refs: `action://${NS}/start`, return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}` });
    const instGet = async () => (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/installations/${INST}`)).body;
    const installationHead = (await instGet()).installation?.agentgres?.head || "";
    if (!(installed.status === 303 && installed.q.get("acted") === "install-release" && installationHead)) fe.push(`install:${installed.status}:${installed.q.get("refused") ?? ""}`);
    const registered = await act(`/${PKG}/register`, { idempotency_key: "mpc-register-1", release_digest: releaseDigest, installation_id: INST, expected_installation_head: installationHead, display_name: "Machine console", supported_placements: "applications_catalog open_application", launch_modes: "direct open_application", supported_context_kinds: "project", return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}` });
    if (!(registered.status === 303 && registered.q.get("record") === SURFACE_REF)) fe.push(`register:${registered.status}:${registered.q.get("refused") ?? ""}`);
    const regRead = (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/installations/${INST}/registration`)).body?.registration?.record ?? {};
    if (!(regRead.surface_class === "extension_application" && regRead.surface_origin === "organization" && regRead.effect_boundary === "propose_only" && regRead.canonical_route === `/__ioi/extensions/${PKG}` && regRead.surface_creation_method === "developer_kit_generated")) fe.push(`registration_derived:${JSON.stringify(regRead).slice(0, 160)}`);
    const enabledHead = (await instGet()).installation?.agentgres?.head || "";
    const dappId = dappRef.replace(/^domain-app:\/\//u, "");
    const approval = await jd(DAEMON, "/v1/hypervisor/governance/approval-requests", { method: "POST", body: JSON.stringify({ subject_ref: dappRef, request_kind: "mount" }) });
    const approvalRef = approval.body?.approval_request?.ref || "";
    await jd(DAEMON, `/v1/hypervisor/governance/approval-requests/${encodeURIComponent(approvalRef.replace(/^approval-request:\/\//u, ""))}`, { method: "PATCH", body: JSON.stringify({ transition: "approve" }) });
    const control = await jd(DAEMON, "/v1/hypervisor/governance/release-controls", { method: "POST", body: JSON.stringify({ release_target_ref: dappRef }) });
    const controlRef = control.body?.release_control?.ref || "";
    await jd(DAEMON, `/v1/hypervisor/governance/release-controls/${encodeURIComponent(controlRef.replace(/^release-control:\/\//u, ""))}`, { method: "PATCH", body: JSON.stringify({ transition: "open" }) });
    const mounted = await jd(DAEMON, `/v1/hypervisor/domain-apps/${encodeURIComponent(dappId)}/mount`, { method: "POST", body: JSON.stringify({ approval_request_ref: approvalRef, release_control_ref: controlRef, owner_ref: OWNER, idempotency_key: "mpc-mount-1" }) });
    const runtimeRef = mounted.body?.runtime?.domain_app_runtime_id || "";
    const served = await jd(DAEMON, `/v1/hypervisor/domain-apps/${encodeURIComponent(dappId)}/serve`, { method: "POST", body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "mpc-serve-1" }) });
    const runtimeRoute = served.body?.runtime?.internal_route_ref || "";
    if (!(mounted.status === 201 && served.status === 201 && runtimeRoute.startsWith("/__ioi/domain-app-runtime/"))) fe.push(`mount_serve:${mounted.status}/${served.status}:${JSON.stringify(served.body).slice(0, 120)}`);
    const bound = await act(`/${PKG}/bind-serving`, { idempotency_key: "mpc-serving-1", release_digest: releaseDigest, installation_id: INST, expected_installation_head: enabledHead, domain_app_runtime_ref: runtimeRef, return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}` });
    if (!(bound.status === 303 && bound.q.get("result") === "serving")) fe.push(`bind_serving:${bound.status}:${bound.q.get("refused") ?? ""}`);
    // the compiled join answers under the caller's org only
    const feed = (await jd(DAEMON, "/v1/hypervisor/product-surface-projections", { method: "POST", body: JSON.stringify({}) })).body;
    const entry = (feed.application_entries || []).find((e) => e.identity_ref === SURFACE_REF);
    if (!(feed.org_ref === OWNER && entry?.launchable === true && entry?.resolved_launch_route === runtimeRoute && entry?.surface_class === "extension_application" && entry?.surface_origin === "organization")) fe.push(`join:${JSON.stringify(entry ?? feed).slice(0, 160)}`);
    const hop = await jd(SERVE_URL, `/__ioi/extensions/${PKG}`);
    if (!(hop.status === 302 && hop.headers.get("location") === runtimeRoute)) fe.push(`canonical_route:${hop.status}:${hop.headers.get("location")}`);
    // PRIVATE PROJECTION, measured in the posture where it is a question. On loopback in the
    // local_development posture an anonymous READ resolves the daemon's documented local-operator
    // convenience (the second full run measured 302 here, and that is the fence working as
    // written, not a leak; recorded, not asserted). The posture that matters is the EXPOSED one,
    // which the daemon detects from the forwarded-host lane the serve forwards verbatim, and there
    // the deployment fails CLOSED (the auth-gated rollout posture): the anonymous exposed request
    // is refused 401 before any projection is compiled, and the operator's loopback-minted session
    // is refused 403 too — outside local development nothing is served until the deployment is
    // authenticated-managed. The third full run measured exactly these two codes.
    const hopAnonymous = await jd(SERVE_URL, `/__ioi/extensions/${PKG}`, { anonymous: true });
    const hopExposedAnonymous = await jd(SERVE_URL, `/__ioi/extensions/${PKG}`, { anonymous: true, headers: { "x-forwarded-host": "hv.example.com" } });
    const hopExposedOperator = await jd(SERVE_URL, `/__ioi/extensions/${PKG}`, { headers: { "x-forwarded-host": "hv.example.com" } });
    if (hopExposedAnonymous.status !== 401) fe.push(`exposed_anonymous_not_refused_401:${hopExposedAnonymous.status}`);
    if (hopExposedOperator.status !== 403) fe.push(`exposed_operator_not_fail_closed_403:${hopExposedOperator.status}`);
    if (hopExposedAnonymous.text.includes(runtimeRoute) || hopExposedOperator.text.includes(runtimeRoute)) fe.push("exposed_refusal_leaks_the_launch_route");
    // the runtime view: the public read model in parity with the daemon, the non-public ref unrendered
    const view = await jd(SERVE_URL, runtimeRoute);
    const reads = LIB.extensionReadsFromRendered(view.text);
    const listNow = await thinList();
    if (!(view.status === 200 && reads.machines.length === listNow.length && listNow.every((m, i) => reads.machines[i].workload_id === String(m.workload_id) && reads.machines[i].head === String(m.head) && reads.machines[i].observed_phase === String(m.observed_phase) && reads.machines[i].desired_generation === String(m.desired_generation)))) fe.push(`ext_view_parity:${view.status}:${JSON.stringify(reads.machines).slice(0, 160)}`);
    if (!reads.not_public.includes("api://v1/hypervisor/environments-summary")) fe.push("ext_view_non_public_not_listed");
    if (ENV_ID && view.text.includes(ENV_ID)) fe.push("ext_view_shows_an_environment");
    const appEnvironments = await jd(SERVE_URL, "/__ioi/environments");
    if (ENV_ID && !appEnvironments.text.includes(ENV_ID)) fe.push("app_environments_page_lacks_the_environment_control");
    if (!(reads.actions.length === 1 && reads.actions[0].ref === `action://${NS}/start` && reads.actions[0].disabled && reads.actions[0].reason === LIB.EXTENSION_ACTION_REASON)) fe.push(`ext_view_action:${JSON.stringify(reads.actions).slice(0, 120)}`);
    if (reads.has_form || reads.has_script_fetch || reads.names_lane) fe.push(`ext_view_carries_a_lane:${reads.has_form}/${reads.has_script_fetch}/${reads.names_lane}`);
    if (!view.text.includes("read-only")) fe.push("ext_view_not_labelled_read_only");
    // a live read, not a copy: an operation on the attached workload moves the extension's readout
    const h4 = (await thinSpine(W2)).body.machine?.head;
    const stopped2 = await appSubmit(W2, proposal(W2, "start", ATTACHED, { head: h4, generation: 2 }));
    if (!(stopped2.body?.ok === true)) fe.push(`attached_start:${JSON.stringify(stopped2.body).slice(0, 100)}`);
    const view2 = LIB.extensionReadsFromRendered((await jd(SERVE_URL, runtimeRoute)).text);
    const w2Now = (await thinSpine(W2)).body.machine;
    const row2 = view2.machines.find((m) => m.workload_id === W2);
    if (!(row2 && row2.head === w2Now?.head && row2.observed_phase === "running")) fe.push(`ext_view_stale:${JSON.stringify(row2 ?? null).slice(0, 100)}`);
    if (familyDigest(dataDir) === digest1) fe.push("attached_start_wrote_nothing");
    out.ext = { package: PKG, surface_ref: SURFACE_REF, runtime_route: runtimeRoute, registration: { surface_class: regRead.surface_class, surface_origin: regRead.surface_origin, effect_boundary: regRead.effect_boundary, canonical_route: regRead.canonical_route }, reads: { machines: reads.machines.length, not_public: reads.not_public, actions: reads.actions }, environment_probe: ENV_ID, route_statuses: { loopback_anonymous: hopAnonymous.status, exposed_anonymous: hopExposedAnonymous.status, exposed_operator: hopExposedOperator.status } };
    out.spine.serve_log_tail = serve?.log().slice(-400) ?? null;
  } catch (error) {
    (fe.length || fs_.length ? fe : fs_).push(`leg_crashed:${String(error?.stack || error).slice(0, 300)}`);
  } finally {
    serve?.stop(); serve2?.stop();
    if (plane) { try { await plane.stop(); } catch { /* gone */ } }
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
  return { spine: { findings: fs_, ...out.spine }, ext: { findings: fe, ...out.ext } };
}

async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const argvRun = ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv: argvRun, cwd: ROOT, env, workDir, bridges: [], timeoutMs: g.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: g.declaredHosts ?? [], declaredNames: g.declaredNames ?? [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  const logAssertions = !censusJson && fs.existsSync(logFile) ? Number((fs.readFileSync(logFile, "utf8").match(/(\d+)\/(\d+) assertion/u) ?? [])[1] ?? NaN) : NaN;
  return { script: g.script, kind: g.kind, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0), declared: (classified.declared?.length ?? 0), declared_hosts: g.declaredHosts ?? [], declared_note: g.declared_note ?? null }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256File(evidenceFile) : null, executed_assertions: censusJson?.executed_assertions ?? (Number.isFinite(logAssertions) ? logAssertions : null), floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpc-gate-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# SPINE and EXT: one isolated daemon with the two simulated reference backends, this runner's own serve as the integrated form, the daemon's API as the standalone form, the admitted extension's runtime view");
  const legs = await fullLegs();
  evidence.spine = legs.spine; evidence.ext = legs.ext;
  console.log(`  → SPINE ${legs.spine.findings.length === 0 ? "created, operated cross-client, refused verbatim, restarted, removed, doubled, deleted with history intact" : legs.spine.findings.join("; ")}`);
  console.log(`  → EXT ${legs.ext.findings.length === 0 ? "admitted through Packages, served through the compiled join, rendered the public read model in parity, offered without invoking, refused the non-public ref and the anonymous route" : legs.ext.findings.join("; ")}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ pure: evidence.pure, source: evidence.source, spine: evidence.spine, ext: evidence.ext }, null, 2)}\n`);
  const legGreen = { "pure (this runner)": (evidence.pure?.findings?.length ?? 1) === 0, "source (this runner)": (evidence.source?.length ?? 1) === 0, "spine (this runner)": legs.spine.findings.length === 0, "ext (this runner)": legs.ext.findings.length === 0 };
  const selfRun = (name) => ({ script: name, status: legGreen[name] ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null });
  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null, scheduled: c.scheduled || null };
    for (const g of c.executed_by ?? []) {
      if (g.kind === "self") { row.executed.push(selfRun(g.script)); continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (clause ${c.n})`);
        done.set(g.script, await runGate(g, workDir, floors, c.n));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}${r.floor_expected != null ? `/${r.floor_expected}` : ""} · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  evidence.clauses = rows;
  evidence.verdict = v;
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else if (MODE === "mint") {
    const target = path.resolve(ROOT, flagValue("--mint-fixture"));
    const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
    if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary}`);
    process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
    const legs = await fullLegs({ mintFixture: target });
    evidence.spine = legs.spine;
    console.log(`SPINE ${legs.spine.findings.length === 0 ? "green" : legs.spine.findings.join("; ")} · fixture ${legs.spine.fixture_minted ?? "not written"}`);
    exit = legs.spine.findings.length === 0 ? 0 : 1;
  } else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "machine-product-composition", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
