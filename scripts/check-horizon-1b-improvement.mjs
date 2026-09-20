#!/usr/bin/env node
// check:horizon-1b-improvement — M12.5: Horizon 1B, the first bounded improvement campaign, as a gate
// (docs/architecture/_meta/execution-horizons.md § Horizon 1B; register R-208).
//
// CANON. Prove the optional campaign path on one low-risk, target-order-0 target inside one System:
// one immutable governance profile, one agenda, one finite campaign, one exact target base and one
// coordinating-work declaration; Search, Judgment and Authority identified separately; one frozen
// EvaluationEpoch with visible and sealed suites and fixed ceilings; immutable candidate attempts with
// positive, negative, exploit, invalid and inconclusive findings retained and every protected access
// appended to the exposure ledger; the selected result reproduced against the unchanged epoch and
// target base; only a target-owner UpgradeProposal emitted; and the falsifier — the Campaign cannot
// alter its selecting evaluator, reset budgets by branching, promote itself, or mutate production: a
// campaign that changed production has falsified itself. ACC-14 clause 5 names seven demands plus the
// falsifier. This closes only the bounded-campaign vertical slice.
//
// WHAT THIS RUNNER IS. The demands are CLAUSES. Each is EXECUTED by the isolated, floored gate that
// already proves it — check:improvement-governance-spine (M10.1: the frozen order-0 epoch, finite
// exposure reservations, the append-only ledger, the handoff as exactly one pending UpgradeProposal,
// the falsifier as byte-identity of every other observable family at every campaign operation),
// check:improvement-role-separation (M10.2: three real principals; Search cannot freeze, activate,
// challenge or submit evidence; negative results retained in the archive), check:governed-evaluation-
// plane (M10.4 + M12.5: negative results retained, immutable, reproduced across a restart; the
// reproduction leg [P14]: a run admitted under the independent_reproduction lane by an
// independent_reproducer, bound to the unchanged epoch, suite and evaluator revisions, re-invoking the
// same routes and required to carry the same verdict and answers as the selected result) — or it is a
// NAMED, TYPED failure with its owner. Nothing is read back and called verified: a clause counts as
// executed only from its gate's own exit status AND the evidence that gate wrote; an absence counts
// only with an owner; the verdict is a pure function of the clause rows and is drilled with planted
// rows (the falsifier's own failure conditions as the runner's rules).
//
//   --drills      CI-bound: the binding of every clause to a real npm script and a pinned floor; the
//                 structural claims each executed gate's source must carry (the spine freezes an
//                 order-0 campaign and measures every other family byte-identical; the role gate binds
//                 three principals; the evaluation gate carries the reproduction leg); the verdict
//                 rules; canon's binding. Seconds, no daemon.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, then the three gates run INSIDE the isolated-egress
//                 harness (their stub model routes and principals are loopback), each ledger
//                 classified here; then the verdict. Exit 0 = pass, 2 = named failure, 1 = fail.
//   --only <a,b>  (full) run only these clause numbers of the executed set.
//   --evidence <path>  also write the evidence there (default .artifacts/mvp-finish-line/).
//
//   IOI_HYPERVISOR_DAEMON_BINARY   the prebuilt daemon the gates run (default target/debug/hypervisor-
//                                  daemon; the harness must not build)

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const APP_SCRIPTS = path.join(ROOT, "apps", "hypervisor", "scripts");
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");
const CANON = path.join(ROOT, "docs", "architecture", "_meta", "execution-horizons.md");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const ONLY = flagValue("--only") ? new Set(flagValue("--only").split(",").map((n) => Number(n))) : null;

const SPINE = { script: "check:improvement-governance-spine", workspace: APP, floor: "improvement-governance-spine", source: "verify-hypervisor-improvement-governance-spine.mjs", minutes: 45 };
const ROLES = { script: "check:improvement-role-separation", workspace: APP, floor: "improvement-role-separation", source: "verify-hypervisor-improvement-role-separation.mjs", minutes: 45 };
const EVAL = { script: "check:governed-evaluation-plane", workspace: APP, floor: "governed-evaluation-plane", source: "verify-hypervisor-governed-evaluation-plane.mjs", minutes: 45 };
const M10_8 = "M10.8 (the ancestor resource and statistical-risk ledgers; the assurance tiers above independent_review)";

// ---- clause 5's seven demands and the falsifier, bound to what executes them ------------------------------
export const CLAUSES = [
  { n: 1, demand: "frozen order-0 epoch", executed_by: [SPINE, EVAL], absence: { what: "the epoch is frozen over a core-owned target (automation-affinity, skill-entry), not over the selected bounded software-change target base; order 0 is asserted from the spine's own campaign, not contrasted with a higher order", owner: "M12.4 (product_track)" } },
  { n: 2, demand: "finite reservations", executed_by: [SPINE, EVAL], absence: { what: "finite reservations close on the evaluation-exposure ledger (budget, reserve, spend, return, exhaustion); the ancestor resource and statistical-risk ledgers, wall-clock and false-promotion ceilings and disjoint reservations for concurrent descendants are not driven", owner: M10_8 } },
  { n: 3, demand: "candidate/evaluator separation", executed_by: [ROLES, EVAL], absence: { what: "separation is proven over three real principals at independent_review and over the evaluator lifecycle; no candidate/attempt/finding object exists (candidates are a derived projection over nominations) and the tiers above independent_review fail closed assurance_profile_not_evidenced", owner: `${M10_8} · the ioi.ai application (attempt and finding objects, R-155)` } },
  { n: 4, demand: "exposure ledger (append-only)", executed_by: [SPINE, EVAL], absence: { what: "ancestor-inherited spend across a child campaign (a child cannot reset spent exposure by changing identity or order) is not driven", owner: M10_8 } },
  { n: 5, demand: "negative-result retention", executed_by: [EVAL, ROLES], absence: { what: "exploit findings and attempt ancestry have no object; negative, invalid, blocked and rejected results are retained, immutable and reproduced across a restart", owner: "the ioi.ai application (attempt and finding objects, R-155)" } },
  { n: 6, demand: "reproduction", executed_by: [EVAL], absence: { what: "the reproducer is the same operator under local_lightweight; a fourth principal bound to neither search nor authority at independent_review is not driven", owner: "M10.8 · a credentialed run" } },
  { n: 7, demand: "target-owner UpgradeProposal handoff with no campaign-owned production mutation", executed_by: [SPINE], absence: { what: "the handoff carries no evidence/recovery bundle: ImprovementEvidenceClaim is unregistered (recursive_claim_unsupported); shadow, canary and activation crossings are the target owner's ordinary release path and are not driven here", owner: "M10.8 · a follow-on slice of M12.5 (the evidence claim)" } },
  { n: 8, demand: "the falsifier: a campaign that changed production has falsified itself", executed_by: [SPINE], absence: { what: "byte-identity is measured over the isolated verifier's own observable families at every campaign operation; the same measurement over the flagship System's records (the M12.4 path) is not driven", owner: "M12.4 (product_track)" } },
];
export const DROPPED_CITATIONS = ["verify-hypervisor-improvement-governance-gates.mjs", "verify-hypervisor-improvement-simulation-replay.mjs"];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.horizon-1b-improvement-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `horizon-1b-improvement-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

// ---- the oracles (pure) -----------------------------------------------------------------------------------
export function bindingFindings(clauses, { appPkg, floors }) {
  const findings = [];
  const seen = new Set();
  for (const c of clauses) {
    if (!Number.isInteger(c.n) || c.n < 1 || c.n > 8) findings.push(`clause_out_of_range: ${c.n}`);
    if (seen.has(c.n)) findings.push(`clause_duplicated: ${c.n}`);
    seen.add(c.n);
    const gates = c.executed_by ?? [];
    if (gates.length === 0 && !c.absence) findings.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of gates) {
      if (!appPkg.scripts?.[g.script]) findings.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
      const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
      if (!row) findings.push(`clause_${c.n}_floor_missing: ${g.floor}`);
      else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) findings.push(`clause_${c.n}_floor_mismatch: ${g.floor} pins ${row.npm_script} at ${row.runtime_assertions}`);
      if (!fs.existsSync(path.join(APP_SCRIPTS, g.source))) findings.push(`clause_${c.n}_source_missing: ${g.source}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) findings.push(`clause_${c.n}_absence_without_owner`);
  }
  for (let n = 1; n <= 8; n += 1) if (!seen.has(n)) findings.push(`clause_missing: ${n}`);
  return findings;
}
/** What each executed gate's SOURCE must carry for the clause it is bound to — read, never inferred from a green run. */
export function structuralFindings(sources) {
  const f = [];
  const spine = sources[SPINE.source] ?? "";
  const roles = sources[ROLES.source] ?? "";
  const ev = sources[EVAL.source] ?? "";
  if (!/target_improvement_order:\s*0\b/u.test(spine) || !/requested_target_improvement_order:\s*0\b/u.test(spine)) f.push("spine_does_not_freeze_an_order_0_campaign");
  if (!/evaluation_exposure_exhausted/u.test(spine)) f.push("spine_does_not_drive_exposure_exhaustion");
  if (!/byte-identical/u.test(spine) || !/improvement_not_approved/u.test(spine)) f.push("spine_does_not_measure_the_falsifier_and_the_handoff");
  if (!/role_separation_violated/u.test(roles) || (roles.match(/principal/giu) || []).length < 3) f.push("role_gate_does_not_bind_three_principals_with_refusals");
  if (!/\[P14 reproduction\]/u.test(ev) || !/independent_reproduction/u.test(ev) || !/independent_reproducer/u.test(ev)) f.push("evaluation_gate_lacks_the_reproduction_leg");
  if (!/RETAINED/u.test(ev) || !/\[P12 state restore\/replay\]/u.test(ev)) f.push("evaluation_gate_lacks_negative_retention_or_restart_reproduction");
  return f;
}
/** PASS only with every clause executed green and no absence; NAMED FAILURE with typed absences; FAIL otherwise. */
export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 8) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 8; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- the drills -------------------------------------------------------------------------------------------
function drills() {
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { appPkg, floors });
  const gates = [...new Set(CLAUSES.flatMap((c) => (c.executed_by ?? []).map((g) => g.floor)))];
  const total = gates.reduce((n, id) => n + ((floors.verifiers ?? []).find((r) => r.id === id)?.runtime_assertions ?? 0), 0);
  ok(`clause 5's seven demands and the falsifier are bound: every executed clause names a real hypervisor-workspace script with a pinned floor (${gates.join(", ")} = ${total} assertions, all isolated), every named failure carries its owner, clauses cover 1–8 exactly once`, binding.length === 0 && total >= 300, binding.join("; ") || `${total} assertions`);
  const sources = Object.fromEntries([SPINE, ROLES, EVAL].map((g) => [g.source, fs.existsSync(path.join(APP_SCRIPTS, g.source)) ? fs.readFileSync(path.join(APP_SCRIPTS, g.source), "utf8") : ""]));
  const structural = structuralFindings(sources);
  ok("each executed gate's SOURCE carries what its clause claims: the spine freezes an order-0 campaign, drives exposure exhaustion and measures the falsifier and the handoff (every other family byte-identical, apply refused before approval); the role gate binds three principals and refuses crossings by name; the evaluation gate carries the reproduction leg ([P14], independent_reproduction lane, independent_reproducer) and retains negative results across a restart", structural.length === 0, structural.join("; ") || "read from the three sources");
  const cited = DROPPED_CITATIONS.map((s) => [s, fs.existsSync(path.join(APP_SCRIPTS, s)), Object.values(appPkg.scripts ?? {}).some((cmd) => cmd.includes(s))]);
  ok("the two verifiers the unit's check text once cited (apply-time governance gates, what-if simulation replay) are NOT composed: they target the shared daemon with Playwright and are registered by no npm script, so this gate names them dropped rather than reading them as evidence", cited.every(([, , registered]) => !registered), cited.map(([s, exists, registered]) => `${s}: ${exists ? "present" : "absent"}, ${registered ? "registered" : "unregistered"}`).join(" · "));
  const green = (n, script) => ({ n, executed: [{ script, status: 0, evidence: "x.json", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 10, floor_expected: 10 }] });
  const base = []; for (let n = 1; n <= 8; n += 1) base.push(green(n, `check:${n}`));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 6 ? { ...r, absence: { what: "the reproducer is the same operator", owner: "M10.8" } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 7 ? { n: 7, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 8 ? { n: 8, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const shrunk = verdict(base.map((r) => (r.n === 1 ? { n: 1, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", executed_assertions: 9, floor_expected: 10 }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 2 ? { n: 2, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const noOwner = verdict(base.map((r) => (r.n === 3 ? { n: 3, absence: { what: "x", owner: "" } } : r)));
  const missing = verdict(base.filter((r) => r.n !== 8));
  ok("the verdict is a pure function of the clause rows and carries the falsifier's own conditions as its rules: all executed green with no absence → PASS; a typed absence → NAMED FAILURE; a fabricated success row, a red gate, a census below its floor, a reach beyond loopback, an unowned absence or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && fabricated.kind === "fail" && red.kind === "fail" && shrunk.kind === "fail" && /below_floor/u.test(shrunk.failures[0]) && reach.kind === "fail" && noOwner.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${fabricated.kind}/${red.kind}/${shrunk.kind}/${reach.kind}/${noOwner.kind}/${missing.kind}`);
  const canon = fs.readFileSync(CANON, "utf8");
  const h1b = canon.slice(canon.indexOf("### Horizon 1B"), canon.indexOf("## Horizon 2"));
  ok("canon binds the gate: execution-horizons.md § Horizon 1B names check:horizon-1b-improvement, reads the coordinating work as the ioi.ai orchestration composed over the System (R-192), lists the reproduction leg and the named failures, and claims no Horizon 1B pass", h1b.includes("`check:horizon-1b-improvement`") && h1b.includes("composed\n  over the System") && /independent_reproduction/u.test(h1b) && /no Horizon 1B pass is claimed/u.test(h1b) && !/coordinating `GoalRunProfile` resolution/u.test(h1b), "read from execution-horizons.md");
}

// ---- mutation ---------------------------------------------------------------------------------------------
function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 6 ? { ...c, executed_by: [{ ...EVAL, script: "check:a-script-that-does-not-exist" }] } : c)), { appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 7 ? { ...c, executed_by: [{ ...SPINE, floor: "a-floor-nobody-pinned" }] } : c)), { appPkg, floors });
  plant("an executed clause whose floor row does not exist", f.some((x) => /floor_missing/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 8 ? { ...c, absence: { what: c.absence.what, owner: "" } } : c)), { appPkg, floors });
  plant("a named failure without an owner", f.some((x) => /absence_without_owner/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 6), { appPkg, floors });
  plant("the reproduction clause silently dropped", f.some((x) => /clause_missing: 6/u.test(x)), f[0]);
  const real = Object.fromEntries([SPINE, ROLES, EVAL].map((g) => [g.source, fs.readFileSync(path.join(APP_SCRIPTS, g.source), "utf8")]));
  f = structuralFindings({ ...real, [SPINE.source]: real[SPINE.source].replace(/target_improvement_order:\s*0\b/gu, "target_improvement_order: 1") });
  plant("a spine that freezes an order-1 campaign instead of order 0", f.includes("spine_does_not_freeze_an_order_0_campaign"), f[0]);
  f = structuralFindings({ ...real, [EVAL.source]: real[EVAL.source].replace(/\[P14 reproduction\]/gu, "[P14 replay]") });
  plant("an evaluation gate whose reproduction leg is gone", f.includes("evaluation_gate_lacks_the_reproduction_leg"), f[0]);
  f = structuralFindings({ ...real, [SPINE.source]: real[SPINE.source].replace(/byte-identical/gu, "byte-similar") });
  plant("a spine that no longer measures byte-identity (the falsifier)", f.includes("spine_does_not_measure_the_falsifier_and_the_handoff"), f[0]);
  const fake = verdict(CLAUSES.map((c) => ({ n: c.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const shrunk = verdict(CLAUSES.map((c) => ({ n: c.n, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", executed_assertions: 1, floor_expected: 100 }] })));
  plant("a run whose gate census fell below its pinned floor", shrunk.kind === "fail" && /below_floor/u.test(shrunk.failures[0]), shrunk.failures[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate ----------------------------------------------------------------------------------------
async function runGate(gate, workDir, floors) {
  const argvNpm = ["npm", "run", "-s", gate.script, `--workspace=${gate.workspace}`];
  const censusDir = path.join(workDir, "census", gate.floor);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const iso = await runIsolated({ label: gate.floor, argv: argvNpm, cwd: ROOT, env, workDir, bridges: [], timeoutMs: gate.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: [], declaredNames: [] });
  const census = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = census[0] || null;
  const floorRow = (floors.verifiers ?? []).find((r) => r.id === gate.floor);
  return { script: gate.script, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0) }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256(fs.readFileSync(evidenceFile)) : null, executed_assertions: evidenceFile ? readJson(evidenceFile).executed_assertions ?? null : null, floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-horizon-1b-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null };
    for (const g of c.executed_by ?? []) {
      if (ONLY && !ONLY.has(c.n)) { row.not_executed = `${g.script} (--only)`; continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (proves clause ${c.n}${CLAUSES.filter((x) => x.n !== c.n && (x.executed_by ?? []).some((y) => y.script === g.script)).map((x) => `, ${x.n}`).join("")})`);
        done.set(g.script, await runGate(g, workDir, floors));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}/${r.floor_expected ?? "?"} assertions · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  evidence.clauses = rows;
  evidence.verdict = v;
  const seen = new Set();
  const runs = rows.flatMap((r) => r.executed).filter((g) => !seen.has(g.script) && seen.add(g.script));
  evidence.network_blocked_completion = { runs: runs.length, attempts: runs.reduce((a, g) => a + g.ledger.attempts, 0), reach: runs.reduce((a, g) => a + g.ledger.reach, 0) };
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 160)} → owner ${a.owner}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = mutation() ? 0 : 1;
  else {
    drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "horizon-1b-improvement", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
