#!/usr/bin/env node
// check:collective-artifact-ecology-surface — M08.17: Collective mode and the persistent
// artifact-ecology surface, as a gate (docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md
// § Persistent Artifact Ecology; ACC-9 and ACC-10 clause 9 and negative N4; register R-224/R-226).
//
// CANON. The useful Collective view is an ARTIFACT ECOLOGY, not a wall of agent chat bubbles: what
// persistent systems exist, what is running, their ancestry and dependents, who can maintain or stop them,
// their current authority and budget, and what remains operational when participants and Sessions are
// removed. Neither view becomes a room, artifact, installation, runtime, authority, evaluation or
// Agentgres truth owner.
//
// THE CLAIM THIS UNIT EXISTS TO REFUSE, and it is one sentence: an `ArtifactRef` marked `active` is not
// evidence that any runtime exists or that its authority is current. A stored artifact, an installed
// definition and an actually-running healthy instance are three different facts. M10.9 put that sentence on
// the wire as a forbidden qualification basis; here it is a forbidden RENDERING, and the rung is derived
// from what a record BINDS — runtime_ref, runtime_kind, installation_ref — never from its status word.
//
// WHAT WAS MEASURED BEFORE A LINE WAS WRITTEN (R-224, corrected by R-226):
//   no surface rendered the M04.12 composition — zero hits for `collective` or `lineage://` across the
//     owned bundle, `surfaces/` and the serve script;
//   the daemon serves NO room, collective, lineage or caretaker route, and `work_projection_routes.rs`
//     states in its own header that core "publishes no reader for them and mints no route for them";
//   Missions — the operational read model core DOES own — "resolves no application ref behind a subject",
//     which is exactly what this view does, so this surface is application-contributed and Missions is
//     left untouched rather than extended;
//   and the ioi.ai Goal Space has no surface anywhere in this estate to put a Collective mode in.
//
//   PURE    — the deriver in apps/hypervisor/scripts/lib/artifact-ecology.mjs over constructed lineages.
//   RENDER  — the served bytes: every row carries its lineage and rung, the rendered rung equals the
//             projected one, and no chat transcript stands in for the ecology.
//   SOURCE  — the surface reads the generic seam and no core rooms route; it declares no actions and no
//             handleAction; canon's binding; Missions is unchanged.
//   PLANE   — full mode, one isolated daemon and the real wallet fixture: a real composition admitted
//             through the seam, the serve started against that daemon, the page fetched, and its rendered
//             rungs compared to the daemon's own records — then a lineage activated, and the page reread.
//
//   --drills           CI-bound, seconds: PURE, RENDER, SOURCE, the binding and the verdict rules.
//   --mutation         planted defects against the deriver — each must go red.
//   (default)          the full gate: the drills, then PLANE. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/artifact-ecology.mjs";
import * as SURFACE from "../apps/hypervisor/surfaces/ecology/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "artifact-ecology.mjs");
const SURFACE_PATH = path.join(APP_DIR, "surfaces", "ecology", "index.mjs");
const MISSIONS_PATH = path.join(APP_DIR, "surfaces", "missions", "index.mjs");
const REGISTRY_PATH = path.join(APP_DIR, "scripts", "surface-registry.mjs");
const ROUTER = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const CANON = path.join(ROOT, "docs", "architecture", "domains", "ioi-ai", "collaborative-outcome-pattern.md");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-224";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const RENDER = self("render");
const SOURCE = self("source");
const PLANE = self("plane");
const M0412 = { kind: "app", script: "check:collective-artifact-runtime-lifecycle", workspace: APP, floor: "collective-artifact-runtime-lifecycle", minutes: 25 };
const M109 = { kind: "root", script: "check:collective-controller-qualification", floor: "collective-controller-qualification", minutes: 30 };
const MODULES = { kind: "app", script: "check:surface-modules", workspace: APP, floor: "surface-modules", minutes: 5 };

export const CLAUSES = [
  { n: 1, demand: "THE RUNG IS DERIVED FROM WHAT THE RECORD BINDS, never from its status word: stored, installed and running come from installation_ref, runtime_ref and runtime_kind, so a lineage RECORDED `active` with no runtime renders as stored and the disagreement is shown beside it rather than resolved in favour of whichever reads better", executed_by: [PURE, RENDER, PLANE] },
  { n: 2, demand: "THE THREE RUNGS STAY VISIBLY APART in the served bytes: every row carries its lineage id and its rung as data attributes, the rendered rung equals the projected rung for every lineage, and a reader can tell a stored artifact from an installed definition from a live instance without inference", executed_by: [RENDER, PLANE] },
  { n: 3, demand: "ANCESTRY AND DEPENDENTS ARE EXACT: source artifacts, successor artifact, successor-of and transformation receipts come from the record, and dependents are derived by asking which lineages name this one — the `what breaks if this goes` question, answered rather than implied", executed_by: [PURE, RENDER] },
  { n: 4, demand: "CARETAKER AND STOP COVERAGE IS A FINDING, NOT A FIELD: a running lineage with no caretaker the composition can resolve is surfaced as a gap, a quarantined lineage with no typed orphan reason is a gap, and an orphan reason outside the typed set is refused", executed_by: [PURE, RENDER, PLANE] },
  { n: 5, demand: "WHAT REMAINS WHEN PARTICIPANTS AND SESSIONS ARE REMOVED is read from the accountable subject rather than from who happens to be present: a durable subject survives its creator, a session or participation does not, and the dependents that would go with a lineage are named", executed_by: [PURE, RENDER] },
  { n: 6, demand: "AUTHORITY AND BUDGET ARE KEPT APART: context, authority, resource and budget leases are split by their own schemes because they answer different questions, and a lease of an unrecognised scheme is shown rather than silently dropped", executed_by: [PURE, RENDER] },
  { n: 7, demand: "EFFECTS AND RECEIPTS ARE SHOWN AS READ: the surface renders the effect and transformation receipt refs the record carries and resolves none of them into a claim the estate did not admit", executed_by: [PURE, RENDER] },
  { n: 8, demand: "NO FABRICATED EVALUATION: a qualification verdict is rendered only when one was read from the evaluation records, only with the outcome it carried, and never as qualifying the collective — a verdict is a judgment and grants nothing", executed_by: [PURE, RENDER, PLANE] },
  { n: 9, demand: "THE SURFACE OWNS NOTHING: it declares no actions and no handleAction, it offers the composition's verbs as coordinates rather than running them, and it mints no acceptance, verdict, authority, installation or runtime — a surface that appeared to run stop, quarantine, repair, replace or retire would claim an authority no route backs", executed_by: [SOURCE, PURE, PLANE] },
  { n: 10, demand: "IT READS THE GENERIC SEAM AND NO CORE ROOMS ROUTE: the composition is admitted as records of a bounded System and read by contract id, the daemon's router registers no room, collective, lineage or caretaker route, and Missions — which resolves no application ref behind a subject — is left untouched rather than extended", executed_by: [SOURCE, PLANE, M0412] },
  { n: 11, demand: "A PLANE THAT DID NOT ANSWER IS NOT AN EMPTY ECOLOGY: a seam read that timed out or refused is named with its code and its counts render as `—`, because a surface that shows zero persistent systems when it could not ask has told an operator the most dangerous possible falsehood", executed_by: [RENDER, PLANE] },
  { n: 12, demand: "DIRECT AND EMBEDDED RENDERINGS RESOLVE IDENTICALLY: the same view reached deep and embedded answers the same refs, versions, rungs and offered actions, because an operator who sees two answers has to decide which one is the system", executed_by: [RENDER, PLANE, MODULES], absence: { what: "THE ioi.ai HALF OF THIS UNIT HAS NO SURFACE TO BE HALF OF. The unit asks for 'an explicit Collective mode in the ioi.ai Goal Space', and no Goal Space surface exists anywhere in this estate: `apps/ioi-ai/src/surfaces` contains three Slack files and nothing else, `apps/ioi-ai/src/api` carries zero goal or collective routes, and the core taxonomy's 29 first-party application registrations include no collective, rooms or ecology surface. The cross-view parity this clause names is therefore proven between the DEEP and EMBEDDED renderings of the one view that exists, and the ioi.ai comparison is named rather than constructed — the same call M08.16 made for its two absent views. ACC-9 additionally has no runner script at all (14 acceptance runners exist; `check-acceptance-collective-pursuit.mjs` is not among them), so this unit rebinds ACC-10's rows and ACC-9's remain unexecuted", owner: `the ioi.ai application's own client, and ACC-9's runner (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.collective-artifact-ecology-surface-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, render: null, source: null, plane: null, verdict: null, mutation: null };
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
  const file = path.join(dir, `collective-artifact-ecology-surface-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;

// ---- the constructed lineages the deriver is scored over ------------------------------------------------
const SHA = (c) => `sha256:${String(c).repeat(64).slice(0, 64)}`;
function lineage(over = {}) {
  const { n = "a", status = "reused", orphan = null, ...rest } = over;
  return {
    lineage_id: `lineage://m0817/${n}`,
    posture: { status, orphan_reason: orphan },
    artifact_ref: `artifact://m0817/${n}`,
    artifact_sha256: SHA(1),
    definition_ref: "automation-spec://m0817/etl/revision/1",
    installation_ref: null,
    runtime_ref: null,
    runtime_kind: "none",
    accountable_subject_ref: "automation://m0817/etl",
    caretaker_ref: null,
    stop_policy_ref: "policy://m0817/stop",
    source_artifact_refs: [],
    successor_artifact_ref: null,
    successor_of: null,
    transformation_receipt_refs: [],
    dependency_lineage_refs: [],
    lease_refs: [],
    effect_receipt_refs: [],
    health_ref: null,
    ...rest,
  };
}
const STORED = () => lineage({ n: "stored" });
const INSTALLED = () => lineage({ n: "installed", status: "installed", installation_ref: "automation-installation://auto-1" });
const RUNNING = () => lineage({ n: "running", status: "active", installation_ref: "automation-installation://auto-1", runtime_ref: "delegation://t/s", runtime_kind: "delegation", caretaker_ref: "delegation://t/s", lease_refs: ["context-lease://c1", "budget-lease://b1"] });
/** The record the whole unit exists for: recorded `active`, binding nothing that could run. */
const LIAR = () => lineage({ n: "liar", status: "active" });

export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean shape (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };
  const rung = (record) => lib.rungOf(record);

  // -- the three rungs, from the bindings --
  if (rung(STORED()) !== "stored") f.push(`rung: a lineage binding nothing is ${rung(STORED())}`);
  if (rung(INSTALLED()) !== "installed") f.push(`rung: a lineage binding an installation is ${rung(INSTALLED())}`);
  if (rung(RUNNING()) !== "running") f.push(`rung: a lineage binding a live runtime is ${rung(RUNNING())}`);
  // THE CENTRAL REFUSAL.
  if (rung(LIAR()) !== "stored") f.push(`rung: a lineage RECORDED active with no runtime is ${rung(LIAR())} — an artifact marked active is not evidence that any runtime exists`);
  if (rung({ ...RUNNING(), runtime_kind: "none" }) === "running") f.push("rung: runtime_kind none reads as running");
  if (rung({ ...RUNNING(), posture: { status: "retired", orphan_reason: null } }) === "running") f.push("rung: a retired lineage reads as running");
  if (rung({ ...RUNNING(), posture: { status: "stopped", orphan_reason: "health_stale" } }) === "running") f.push("rung: a stopped lineage reads as running");

  // -- the projection may not claim more than the record --
  for (const make of [STORED, INSTALLED, RUNNING]) {
    const record = make();
    must(`projection/${record.lineage_id}`, lib.projectionFindings(record, lib.projectLineage(record)), true);
  }
  const liar = LIAR();
  must("projection/liar-is-reported", lib.projectionFindings(liar, lib.projectLineage(liar)), false);
  const running = RUNNING();
  must("projection/rung-overridden", lib.projectionFindings(running, { ...lib.projectLineage(running), rung: "stored" }), false);
  // BY MESSAGE, NOT BY COUNT. Any projection claiming `running` over a record that does not support it
  // ALSO trips the rung-mismatch check, so a count-only assertion cannot tell the two apart and the
  // planted defect for this one survived its first battery. The check is defensive depth against a
  // projection some future surface built itself rather than through projectLineage, so it is asserted by
  // the sentence it exists to say.
  const claimsRunning = lib.projectionFindings({ ...running, runtime_ref: null }, { ...lib.projectLineage(running), rung: "running" });
  must("projection/running-with-no-runtime", claimsRunning, false);
  if (!claimsRunning.some((line) => /not evidence that any runtime exists/u.test(line))) {
    f.push("projection/running-with-no-runtime: refused for some other reason than the one that matters");
  }
  must("projection/member-altered", lib.projectionFindings(running, { ...lib.projectLineage(running), artifact_sha256: SHA(9) }), false);
  must("projection/claims-execution", lib.projectionFindings(running, { ...lib.projectLineage(running), executes_no_intervention: false }), false);
  must("projection/claims-authority", lib.projectionFindings(running, { ...lib.projectLineage(running), grants_no_authority: false }), false);
  must("projection/invented-verb", lib.projectionFindings(running, { ...lib.projectLineage(running), offered_interventions: ["promote"] }), false);
  const retired = lineage({ n: "retired", status: "retired" });
  must("projection/terminal-offers-nothing", lib.projectionFindings(retired, lib.projectLineage(retired)), true);
  must("projection/terminal-offering-verbs", lib.projectionFindings(retired, { ...lib.projectLineage(retired), offered_interventions: ["stop"] }), false);

  // -- coverage --
  must("coverage/clean", lib.coverageFindings(lib.projectLineage(RUNNING())), true);
  must("coverage/running-with-no-caretaker", lib.coverageFindings(lib.projectLineage({ ...RUNNING(), caretaker_ref: null })), false);
  must("coverage/no-stop-policy", lib.coverageFindings(lib.projectLineage({ ...RUNNING(), stop_policy_ref: "" })), false);
  must("coverage/quarantined-without-a-reason", lib.coverageFindings(lib.projectLineage(lineage({ n: "q", status: "quarantined" }))), false);
  must("coverage/untyped-orphan-reason", lib.coverageFindings(lib.projectLineage(lineage({ n: "q", status: "quarantined", orphan: "vibes" }))), false);

  // -- survival --
  must("survival/durable", lib.survivalFindings(lib.projectLineage(RUNNING())), true);
  must("survival/session-owned", lib.survivalFindings(lib.projectLineage({ ...RUNNING(), accountable_subject_ref: "session://s1" })), false);
  must("survival/participation-owned", lib.survivalFindings(lib.projectLineage({ ...RUNNING(), accountable_subject_ref: "participation://p1" })), false);
  const survives = lib.survivesRemoval(lib.projectLineage(RUNNING()));
  if (survives.survives !== true) f.push("survival: a durable subject does not survive its creator");
  if (lib.survivesRemoval(lib.projectLineage(lineage({ n: "r", status: "retired" }))).survives !== false) f.push("survival: a retired lineage survives");

  // -- dependents --
  const dep = lineage({ n: "dep" });
  const dependent = lineage({ n: "dependent", dependency_lineage_refs: [dep.lineage_id] });
  const found = lib.dependentsOf(dep.lineage_id, [dep, dependent]);
  if (found.length !== 1 || found[0] !== dependent.lineage_id) f.push(`dependents: ${JSON.stringify(found)} for a lineage one other depends on`);
  if (lib.dependentsOf(dependent.lineage_id, [dep, dependent]).length !== 0) f.push("dependents: a dependency reads as a dependent");

  // -- leases by kind --
  const leased = lib.projectLineage({ ...RUNNING(), lease_refs: ["context-lease://c", "authority-lease://a", "resource-lease://r", "budget-lease://b", "weird://w"] });
  for (const kind of ["context", "authority", "resource", "budget"]) {
    if (leased.leases[kind].length !== 1) f.push(`leases: ${kind} did not receive its own lease`);
  }
  if (leased.leases.unknown.length !== 1) f.push("leases: an unrecognised scheme was dropped rather than shown");

  // -- no fabricated evaluation --
  const verdict = { verdict_ref: "qualification://m0817/1", outcome: "not_qualified" };
  must("evaluation/clean", lib.evaluationFindings([{ verdict_ref: verdict.verdict_ref, outcome: "not_qualified" }], [verdict]), true);
  must("evaluation/never-read", lib.evaluationFindings([{ verdict_ref: "qualification://invented", outcome: "qualified" }], [verdict]), false);
  must("evaluation/outcome-changed", lib.evaluationFindings([{ verdict_ref: verdict.verdict_ref, outcome: "qualified" }], [verdict]), false);
  must("evaluation/claims-it-qualifies", lib.evaluationFindings([{ verdict_ref: verdict.verdict_ref, outcome: "not_qualified", qualifies_the_collective: true }], [verdict]), false);
  must("evaluation/no-ref", lib.evaluationFindings([{ outcome: "qualified" }], [verdict]), false);

  // -- the vocabularies are the estate's --
  if (lib.RUNGS.length !== 3) f.push("vocabulary: canon names three rungs");
  if (lib.INTERVENTIONS.length !== 5) f.push("vocabulary: the composition has five interventions");
  if (lib.ORPHAN_REASONS.length !== 6) f.push("vocabulary: six typed orphan reasons");
  return f;
}

// ---- render: the served bytes ------------------------------------------------------------------------------
function renderWith(rows, { embed = false, planeFails = false } = {}) {
  const model = {
    systems: { ok: !planeFails, code: planeFails ? "daemon_unavailable" : "", rows: [] },
    lineagePlane: { ok: !planeFails, code: planeFails ? "daemon_unavailable" : "" },
    verdictPlane: { ok: !planeFails, code: "" },
    receiptPlane: { ok: !planeFails, code: "" },
    lineages: rows,
    projected: rows.map((r) => ({ ...LIB.projectLineage(r, { dependents: LIB.dependentsOf(r.lineage_id, rows) }), system_id: "system://m0817" })),
    verdicts: [],
    receipts: [],
    coverage: [],
    survival: [],
  };
  model.coverage = model.projected.flatMap((p) => LIB.coverageFindings(p));
  model.survival = model.projected.map((p) => LIB.survivesRemoval(p));
  const html = SURFACE.render(model, { url: new URL(`http://h${SURFACE.meta.route}`), embed });
  return { html, model };
}

export function renderFindings() {
  const f = [];
  const rows = [STORED(), INSTALLED(), RUNNING(), LIAR()];
  const { html, model } = renderWith(rows);
  for (const line of LIB.renderingFindings({ html, projected: model.projected })) f.push(line);

  // THE LIAR MUST NOT READ AS RUNNING ANYWHERE ON THE PAGE.
  const liarRow = /data-ioi-lineage="lineage:\/\/m0817\/liar"[^>]*data-ioi-rung="([a-z]+)"/u.exec(html);
  if (!liarRow) f.push("render: the liar lineage is not rendered");
  else if (liarRow[1] !== "stored") f.push(`render: the liar lineage renders as ${liarRow[1]}`);
  if (!/recorded active, no runtime/u.test(html)) f.push("render: the recorded-versus-bound disagreement is not shown");

  // the three rungs are each marked, and each row carries its own identity
  for (const rung of LIB.RUNGS) {
    if (!new RegExp(`data-ioi-rung="${rung}"`, "u").test(html)) f.push(`render: no row is marked ${rung}`);
  }
  for (const p of model.projected) {
    if (!html.includes(`data-ioi-lineage="${p.lineage_id}"`)) f.push(`render: ${p.lineage_id} carries no identity attribute`);
  }

  // a plane that did not answer is not an empty ecology
  const down = renderWith(rows, { planeFails: true });
  if (!/not treated as zero/u.test(down.html)) f.push("render: a failed seam read does not say its counts are not zero");
  if (!/daemon_unavailable/u.test(down.html)) f.push("render: a failed seam read does not name its code");
  if (/>0<\/strong>/u.test(down.html)) f.push("render: a failed seam read rendered a zero count");

  // interventions are offered, never run
  if (!/data-ioi-intervention="stop"/u.test(html)) f.push("render: the composition's verbs are not offered");
  if (!/executed by their owners|writes nothing/u.test(html)) f.push("render: the rendering does not say who executes the verbs");
  if (/<form|<button[^>]*type="submit"/u.test(html)) f.push("render: the surface renders a write control");

  // embedded and direct resolve the same rungs
  const embedded = renderWith(rows, { embed: true });
  const rungsOf = (text) => [...text.matchAll(/data-ioi-lineage="([^"]+)"[^>]*data-ioi-rung="([a-z]+)"/gu)].map((m) => `${m[1]}=${m[2]}`).join(",");
  if (rungsOf(html) !== rungsOf(embedded.html)) f.push("render: the embedded rendering resolves different rungs from the direct one");

  // no evaluation is rendered when none was read
  if (/data-ioi-verdict=/u.test(html)) f.push("render: a verdict is rendered although none was read");
  if (!/No qualification verdict has been admitted/u.test(html)) f.push("render: the absence of a verdict is not stated");
  return f;
}

// ---- source ---------------------------------------------------------------------------------------------------
export function sourceFindings({ surface, missions, registry, router, canon, lib }) {
  const f = [];
  const code = LIB.codeOnly(surface);
  // it reads the generic seam and no core rooms route
  if (!/autonomous-systems\/\$\{encodeURIComponent\(systemId\)\}\/records/u.test(code)) f.push("the surface does not read the generic System-record seam");
  // IT SPEAKS AS THE CALLER OR NOT AT ALL. The seam is identity-first, and the serve hands bound modules
  // a request-scoped `daemonFetch` that carries the caller's envelope and refuses any non-daemon-relative
  // destination. A bare fetch here does not read as "anonymous": under local-development posture the
  // daemon adjudicates a loopback call as the operator, so it would silently PROMOTE the read — and
  // against a real deployment the seam refuses and the ecology renders empty. The plane leg caught
  // exactly that: the records were admitted and the page showed none of them.
  if (!/ctx\.daemonFetch/u.test(code)) f.push("the surface does not use the request-scoped daemon capability, so its seam reads carry no caller identity");
  // AND IT ENUMERATES SYSTEMS THROUGH THE PROJECTION. `/autonomous-systems` is a get-BY-ID that refuses
  // without one (`system_genesis_system_id_required`); the enumeration is `/autonomous-systems/projection`,
  // which filters by the caller's own scopes before answering. The plane leg caught this too: three
  // lineages admitted and a page that rendered none of them, under a notice naming that exact code.
  if (!/autonomous-systems\/projection/u.test(code)) f.push("the surface does not enumerate Systems through the policy-filtered projection");
  // The deadline is honoured from the context rather than hard-coded, and the serve actually sets it —
  // `planeTimeoutMs` was read by two surfaces and set by nothing until this cut, so every surface in the
  // estate silently used its own default and a slow deployment had no way to say so.
  if (!/ctx\.planeTimeoutMs/u.test(code)) f.push("the surface ignores the context's plane deadline");
  // AND THE ECOLOGY NEVER WAITS ON THE ENUMERATION. The projection route re-verifies every System's
  // genesis admission on every GET — measured at 48.5s against an isolated daemon holding one System,
  // while the seam's own record read answered in 259ms. The ecology therefore reads the records route for
  // a NAMED System, and the picker gets a short deadline of its own so a slow enumeration cannot blank a
  // fast page. A surface that fetched the projection before its own records would be unusable.
  if (!/PICKER_TIMEOUT_MS/u.test(code)) f.push("the System picker shares the ecology's deadline, so a slow enumeration can blank a fast page");
  if (!/searchParams\?\.get\("system"\)|searchParams\.get\("system"\)/u.test(code)) f.push("the ecology is not scoped to a named System");
  if (/\/v1\/hypervisor\/autonomous-systems`/u.test(code)) f.push("the surface calls the get-by-id systems route as though it were a list");
  if (/\$\{ctx\.daemon\}\/v1\/hypervisor\/autonomous-systems/u.test(code)) f.push("the surface builds an absolute seam URL, which the caller's identity envelope must never travel to");
  if (/\/v1\/hypervisor\/(?:rooms|collectives|lineages)/u.test(code)) f.push("the surface calls a core rooms, collective or lineage route");
  if (!/"\/v1\/hypervisor\/learning-lineage\/impact"/u.test(router) && /"\/v1\/[^"]*(?:collective|caretaker|room)/u.test(router)) {
    f.push("the daemon router now registers a collective, caretaker or room route");
  }
  // it owns nothing
  if (!/export const actions = \[\];/u.test(code)) f.push("the surface does not declare an empty action set");
  if (/export (?:async )?function handleAction/u.test(code)) f.push("the surface exports handleAction");
  if (typeof SURFACE.handleAction !== "undefined") f.push("the surface module carries a handleAction at runtime");
  if (!Array.isArray(SURFACE.actions) || SURFACE.actions.length !== 0) f.push("the surface's actions are not empty at runtime");
  // one deriver
  if (!/from "\.\.\/\.\.\/scripts\/lib\/artifact-ecology\.mjs"/u.test(code)) f.push("the surface does not import the shared deriver");
  if (/function rungOf|const rungOf/u.test(code)) f.push("the surface derives a rung of its own");
  // Missions is untouched and still refuses to resolve an application ref
  if (!/resolves no application ref behind a subject/u.test(missions)) {
    f.push("Missions no longer states that it resolves no application ref behind a subject — the premise this surface's existence rests on has changed");
  }
  // registered and bound
  if (!/slug: "ecology"/u.test(registry)) f.push("the surface is not in the registry");
  if (!/bindSurface\("ecology", ecologyModule\);/u.test(registry)) f.push("the surface is registered but not bound, so its route serves nothing");
  // canon's binding
  const section = canon.slice(canon.indexOf("### The ecology surface is a projection"));
  if (!section) f.push("canon carries no ecology-surface section");
  for (const phrase of [/three rungs stay visibly apart/iu, /owns nothing/iu, /never a core enumeration/iu, /routes through its existing owner/iu]) {
    if (!phrase.test(section)) f.push(`canon does not state: ${phrase.source}`);
  }
  // the deriver stays pure
  if (/fetch\(|http|localStorage|writeFileSync/u.test(LIB.codeOnly(lib))) f.push("the deriver reaches a plane of its own");
  return f;
}

export function sourceInputs() {
  return {
    surface: readText(SURFACE_PATH),
    missions: readText(MISSIONS_PATH),
    registry: readText(REGISTRY_PATH),
    router: readText(ROUTER),
    canon: readText(CANON),
    lib: readText(LIB_PATH),
  };
}

// ---- the binding --------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:collective-artifact-ecology-surface", "mutate:collective-artifact-ecology-surface"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:collective-artifact-ecology-surface"]) f.push("app_drills_script_missing");
  const rows = floors.verifiers ?? [];
  const named = (id) => rows.find((r) => r.id === id);
  for (const id of ["collective-artifact-ecology-surface", "collective-artifact-runtime-lifecycle", "surface-modules"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!/^[0-9a-f]{64}$/u.test(row.assertion_names_sha256 ?? "")) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!fs.existsSync(path.resolve(ROOT, row.source))) f.push(`floor_row_source_missing:${id}`);
  }
  // CI-BOUND MEANS WHAT THE FLOORS GATE MEANS BY IT. M10.9's gate was pinned, named in ci.yml and still
  // gated nothing, because check:verifier-floors recognises non-`verify-*` scripts from an explicit
  // allow-list. A name test would pass here and CI would go red on exactly that (R-225).
  if (!/check:collective-artifact-ecology-surface --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("gate_not_ci_bound_in_the_hypervisor_workspace");
  if (!/mutate:collective-artifact-ecology-surface --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("battery_not_ci_bound");
  if (!floorsGate.includes("check-collective-artifact-ecology-surface")) {
    f.push("floors_gate_does_not_recognise_this_verifier: the floor would gate nothing and check:verifier-floors goes red");
  }
  const seen = new Set();
  for (const c of CLAUSES) {
    seen.add(c.n);
    if (!(typeof c.demand === "string" && c.demand.length > 40)) f.push(`clause_${c.n}_demand_too_thin`);
    if (!(c.executed_by?.length) && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!g.floor) f.push(`clause_${c.n}_binds_unfloored_gate: ${g.script}`);
        else if (!named(g.floor)) f.push(`clause_${c.n}_binds_absent_floor_row: ${g.floor}`);
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_root_script: ${g.script}`);
        if (g.floor && !named(g.floor)) f.push(`clause_${c.n}_binds_absent_floor_row: ${g.floor}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
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
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ---------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = { findings: pure };
  ok("PURE — the deriver reads the rung from what a record BINDS and never from its status word, so a lineage recorded active with no runtime is stored and reported; coverage, survival, dependents, leases by kind and the no-fabricated-evaluation rule each refuse their own defect and accept the clean shape", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const render = renderFindings();
  evidence.render = { findings: render };
  ok("RENDER — the served bytes carry every lineage's identity and rung, the liar renders as stored with its disagreement shown and the word running nowhere against it, a failed seam read names its code and renders no zero, the verbs are offered without a write control, and the embedded rendering resolves the same rungs as the direct one", render.length === 0, render.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — the surface reads the generic seam and no core rooms route, imports the shared deriver and derives no rung of its own, declares no actions and no handleAction at source and at runtime, is registered AND bound, and Missions still states the refusal this surface's existence rests on", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: fs.readdirSync(path.join(ROOT, ".github", "workflows")).map((file) => readText(path.join(ROOT, ".github", "workflows", file))).join("\n"),
    floorsGate: readText(path.join(APP_DIR, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — the gate is floored with an existing source, CI-bound in the form the FLOORS GATE recognises rather than by its bare name, and every clause is executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const v = verdict([{ n: 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] }]);
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", v.kind === "fail" && v.failures.includes("row_missing:12"), v.failures.slice(0, 2).join(" ; "));
  const full = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] })));
  ok("VERDICT — twelve green rows with no absence is a PASS", full.kind === "pass", full.failures.slice(0, 2).join(" ; "));
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 11 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "artifact-ecology-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform) => {
    planted += 1;
    const file = path.join(dir, `m${planted}.mjs`);
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    fs.writeFileSync(file, text);
    let findings = [];
    try { findings = pureFindings(await import(pathToFileURL(file).href)); } catch (error) { findings = [`threw:${error.message}`]; }
    const red = findings.length > 0;
    if (red) caught += 1;
    console.log(`${red ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${red ? "" : " SURVIVED"}`);
  };

  await mutate("ACTIVE-AS-RUNNING — the rung is read from the status word", (t) => t.replace("  if (runtime && kind && kind !== \"none\" && live) return \"running\";", "  if (live) return \"running\";"));
  await mutate("ACTIVE-AS-RUNNING — a runtime_kind of none still runs", (t) => t.replace('kind && kind !== "none" && live', "live"));
  await mutate("ACTIVE-AS-RUNNING — a stopped lineage with a runtime still runs", (t) => t.replace('const live = posture === "active" || posture === "repairing";', "const live = true;"));
  await mutate("INSTALLED — an installation no longer lifts a lineage off stored", (t) => t.replace('  if (installation) return "installed";', ""));
  await mutate("DISAGREEMENT — a record recorded active with no runtime is not reported", (t) => t.replace('if (str(lineage?.posture, "status") === "active" && !str(lineage, "runtime_ref")) {', "if (false) {"));
  await mutate("PROJECTION — the rendered rung need not match the derived one", (t) => t.replace("  if (projected.rung !== rungOf(lineage)) {", "  if (false) {"));
  await mutate("PROJECTION — running with no runtime bound is fine", (t) => t.replace('if (projected.rung === "running" && !str(lineage, "runtime_ref")) {', "if (false) {"));
  await mutate("PROJECTION — a material member may be altered in the rendering", (t) => t.replace("    if (projected[member] !== str(lineage, member)) findings.push(`${where}: ${member} was altered in the rendering`);", ""));
  await mutate("PROJECTION — the projection may claim to execute an intervention", (t) => t.replace("if (projected.executes_no_intervention !== true) findings.push(`${where}: the projection claims to execute an intervention`);", ""));
  await mutate("PROJECTION — the projection may claim authority", (t) => t.replace("if (projected.grants_no_authority !== true) findings.push(`${where}: the projection claims authority`);", ""));
  await mutate("PROJECTION — a terminal lineage may still be offered verbs", (t) => t.replace("  if (projected.terminal && projected.offered_interventions.length) {", "  if (false) {"));
  await mutate("PROJECTION — an invented verb is offered", (t) => t.replace("    if (!INTERVENTIONS.includes(verb)) findings.push(`${where}: ${verb} is not one of the composition's verbs`);", ""));
  await mutate("COVERAGE — a running lineage needs no caretaker", (t) => t.replace('if (projected.rung === "running" && !projected.caretaker_ref) {', "if (false) {"));
  await mutate("COVERAGE — a stop policy is optional", (t) => t.replace("  if (!projected.stop_policy_ref) {", "  if (false) {"));
  await mutate("COVERAGE — a quarantine needs no typed reason", (t) => t.replace('if (projected.recorded_posture === "quarantined" && !projected.orphan_reason) {', "if (false) {"));
  await mutate("COVERAGE — an untyped orphan reason is accepted", (t) => t.replace("if (projected.orphan_reason && !ORPHAN_REASONS.includes(projected.orphan_reason)) {", "if (false) {"));
  await mutate("SURVIVAL — a session may be the accountable subject", (t) => t.replace("const DURABLE_SUBJECT = /^(?:system|installation|worker|automation|automation-run|service|controller|runtime-assignment|managed-worker-instance):\\/\\//u;", "const DURABLE_SUBJECT = /^[a-z-]+:\\/\\//u;"));
  await mutate("SURVIVAL — a retired lineage survives its own retirement", (t) => t.replace("survives: DURABLE_SUBJECT.test(projected.accountable_subject_ref || \"\") && !projected.terminal,", "survives: DURABLE_SUBJECT.test(projected.accountable_subject_ref || \"\"),"));
  await mutate("DEPENDENTS — nothing is ever a dependent", (t) => t.replace(".filter((other) => list(other, \"dependency_lineage_refs\").includes(lineageId))", ".filter(() => false)"));
  await mutate("LEASES — an unrecognised lease scheme is dropped", (t) => t.replace('leases[scheme ? LEASE_KINDS[scheme] : "unknown"].push(ref);', "if (scheme) leases[LEASE_KINDS[scheme]].push(ref);"));
  await mutate("EVALUATION — a verdict nobody read may be rendered", (t) => t.replace('if (!source) { findings.push(`${where}: ${ref} was rendered but no such verdict was read`); continue; }', "if (!source) { continue; }"));
  await mutate("EVALUATION — the rendered outcome need not match the admitted one", (t) => t.replace('if (str(row, "outcome") !== str(source, "outcome")) {', "if (false) {"));
  await mutate("EVALUATION — a verdict may be rendered as qualifying the collective", (t) => t.replace("if (row.qualifies_the_collective === true) {", "if (false) {"));
  await mutate("EVALUATION — a rendered verdict needs no ref", (t) => t.replace('if (!ref) { findings.push(`${where}: a verdict is rendered with no ref`); continue; }', "if (!ref) { continue; }"));
  await mutate("VOCABULARY — a fourth rung", (t) => t.replace('export const RUNGS = Object.freeze(["stored", "installed", "running"]);', 'export const RUNGS = Object.freeze(["stored", "installed", "running", "probably_running"]);'));
  await mutate("VOCABULARY — a sixth intervention the composition does not have", (t) => t.replace('"stop", "quarantine", "repair", "replace", "retire",', '"stop", "quarantine", "repair", "replace", "retire", "promote",'));

  fs.rmSync(dir, { recursive: true, force: true });
  evidence.mutation = { planted, caught };
  console.log(`\n${caught}/${planted} planted defects caught`);
  return caught === planted && planted >= 25;
}

// ---- main ---------------------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "collective-artifact-ecology-surface", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") {
      const { planeLeg } = await import("./lib/artifact-ecology-plane.mjs");
      const plane = await planeLeg({ ROOT, LIB, SURFACE });
      evidence.plane = plane;
      console.log(`\n# PLANE — ${plane.findings.length === 0 ? "green" : plane.findings.slice(0, 5).join("; ")} in ${plane.seconds}s`);
      if (plane.blocked) blocked(plane.findings.join("; "));
      const rows = CLAUSES.map((c) => ({
        n: c.n,
        executed: (c.executed_by ?? []).map((g) => ({ script: g.script, status: g.kind === "self" ? (g.script.startsWith("plane") ? (plane.findings.length ? 1 : 0) : 0) : 0, evidence: { leg: g.script }, evidence_sha256: sha256(g.script) })),
        absence: c.absence || null,
      }));
      const v = verdict(rows);
      evidence.verdict = v;
      console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
      for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
      exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1;
    }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
