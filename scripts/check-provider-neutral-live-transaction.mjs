#!/usr/bin/env node
// check:provider-neutral-live-transaction — M09.6: one provider-neutral live transaction lane, as a gate
// (docs/architecture/components/hypervisor/byo-provider-plane.md § The Provider-Neutral Live Transaction Lane;
// register R-210, executing R-140 and R-139).
//
// CANON. One lane, provider-neutral in shape, proven on one provider: typed admissible-provider selection,
// a verbatim-or-skipped quote, the committed intent root, execution, the outcome root, reconciliation on
// ambiguity, teardown, provider-native billing readback — authorized leg by leg; a plan document is never
// authorization to spend. Two terminal branches, never conflated: no qualified bid → close → provider-
// confirmed refund; qualified bid → lease → live readback → endpoint → teardown → zero open exposure. Safe
// refusal is not successful deployment; close acceptance is not refund settlement. A missing credential
// blocks a live RUN, never the unit (R-139).
//
// WHAT THIS RUNNER IS. The lane's legs and its two branches are CLAUSES. Each is EXECUTED by the floored
// gate that already proves it, or by one of this runner's own legs, or it is NAMED (a typed failure with an
// owner, or a SCHEDULED live leg with its exact prerequisite and ruling). The runner's own legs:
//   GENERATION — the no-qualified-bid branch as a typed terminal certificate GENERATED at run time from the
//   retained durable records of the nine owner-authorized live closes (a tracked, redacted, hash-committed
//   set; every row's sha256 re-derived here before it is read), sealed, verified by the certificate library's
//   no-bid branch, and mutation-drilled on the GENERATED output: a lease smuggled in, a relabel to success, a
//   pending refund, a refund short of the deposit, an open exposure, a hidden unrecorded member, a simulated
//   run — each must go red by its own code.
//   NEUTRALITY — the lane's provider-neutral SHAPE read from the daemon's own dispatch: one operation
//   vocabulary over the adapters behind one trait, the quote posture, the reconciliation_required posture —
//   and the certificate library's refusal to certify neutrality kept as the boundary it is.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding, the generation leg, the neutrality leg, the verdict rules,
//                 canon's binding. No daemon, no network, no credential.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, then every executed gate inside the isolated-egress harness;
//                 the positive live branch stays scheduled unless IOI_C7_EMAIL / IOI_C7_PASSWORD_FILE /
//                 IOI_WALLET_SECRET_PASS are present (then it is still NOT run here: a live spend needs its
//                 own leg-by-leg owner authorization, and this runner never spends). Exit 0 pass, 2 named
//                 failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import { NO_BID_RESULT, NO_BID_UNRECORDED_VOCABULARY, assembleNoQualifiedBidClose, sealCertificate, validateCertificate, validateNoQualifiedBidCertificate } from "../apps/hypervisor/scripts/lib/c7-c8-certificate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const APP_SCRIPTS = path.join(ROOT, "apps", "hypervisor", "scripts");
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");
const RETAINED = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m09-6-akash-retained-no-qualified-bid-closes-2026-09-20.v1.json");
const CANON = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const PROVIDER_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "provider_routes.rs");
const CERT_LIB = path.join(APP_SCRIPTS, "lib", "c7-c8-certificate.mjs");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS), authorized leg by leg";
const LIVE_RULING = "R-139 (2026-09-14) and R-210 (2026-09-20): a missing credential blocks a live RUN, never the unit; the positive branch is the unit's scheduled check";

const gate = (script, floor, minutes, source = null) => ({ kind: "app", script, workspace: APP, floor, minutes, source });
const root = (script, minutes) => ({ kind: "root", script, workspace: null, minutes });
const GOVERNED = gate("check:governed-effect-assurance-floor", "governed-effect-assurance", 30);
const PROVENANCE = gate("check:provider-proposal-provenance", "provider-proposal-provenance", 30);
const TRANSPORT = gate("check:provider-transport", "provider-transport", 30);
const AKASH = gate("check:akash-live-lifecycle", "akash-live-lifecycle", 40, "verify-akash-live-lifecycle.mjs");
const RECONCILE = root("check:provider-spend-reconciliation", 30);
const T7 = root("check:t7-retained-capstone-applicability", 20);
const GENERATION = { kind: "self", script: "generation (this runner)" };
const NEUTRALITY = { kind: "self", script: "neutrality (this runner)" };
const ADAPTERS_OWED = "M09.10 · a follow-on slice (the eight adapter done-bars target the shared daemon without a session and are registered by no npm script — un-composable, R-143 class; their isolated form is owed)";

export const CLAUSES = [
  { n: 1, demand: "typed admissible-provider selection", executed_by: [NEUTRALITY, PROVENANCE], absence: { what: "selection refusing an unverified account is driven only inside the shared-daemon adapter done-bars", owner: ADAPTERS_OWED } },
  { n: 2, demand: "a verbatim-or-skipped quote, never estimated", executed_by: [NEUTRALITY], absence: { what: "quote gating is driven only inside the shared-daemon adapter done-bars (vast, runpod, lambda, akash)", owner: ADAPTERS_OWED } },
  { n: 3, demand: "the committed intent root before the provider call", executed_by: [GOVERNED, PROVENANCE] },
  { n: 4, demand: "execution through the daemon's dispatch, never the guest", executed_by: [GOVERNED, TRANSPORT] },
  { n: 5, demand: "the outcome root after the call", executed_by: [GOVERNED] },
  { n: 6, demand: "reconciliation on ambiguity: reconciliation_required, never a second invocation", executed_by: [NEUTRALITY], absence: { what: "an ambiguous provider call driven to reconciliation_required on the provider lane exists only in the shared-daemon adapter done-bars; the posture is read from the dispatch", owner: ADAPTERS_OWED } },
  { n: 7, demand: "teardown to zero open and unknown exposure", executed_by: [GENERATION], absence: { what: "live teardown is driven only by the retained runs (nine no-bid closes, one positive capstone); the resource-cleanup obligation's provider-native evidence ref stays null (M09.5)", owner: "M09.5 · the scheduled live branch" } },
  { n: 8, demand: "provider-native billing readback, never the estate's intention", executed_by: [RECONCILE, GENERATION] },
  { n: 9, demand: "leg-by-leg authorization; a changed ceiling or selector needs a fresh challenge", executed_by: [PROVENANCE, AKASH], absence: { what: "no gate asserts that a CHANGED ceiling or selector forces a new challenge; the certificate refuses changed facets after the fact", owner: "a follow-on slice of M09.6" } },
  { n: 10, demand: "branch (a): no qualified bid → close → provider-confirmed refund, certified as a terminal non-success", executed_by: [GENERATION, AKASH] },
  { n: 11, demand: "branch (b): qualified bid → lease → live provider readback → endpoint → teardown → provider-confirmed zero open exposure", executed_by: [T7], scheduled: { what: "a FRESH positive live transaction (bid, lease, C6 retrieved_live, endpoint, teardown, zero open exposure) assembled and verified independently — the retained 2026-08-24 capstone is re-qualified on every run by its applicability gate; a fresh run is owed", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } },
  { n: 12, demand: "the lane's shape is provider-neutral", executed_by: [NEUTRALITY], absence: { what: "neutrality is asserted over the daemon's dispatch (one operation vocabulary over the adapters behind one trait); a second substrate executing the same workload, authority, effect and receipt contract is M09.10's own proof, and the C7/C8 certificate refuses to certify neutrality by contract", owner: "M09.10" } },
];
export const DROPPED_CITATIONS = ["verify-hypervisor-vast-lifecycle.mjs", "verify-hypervisor-runpod-adapter.mjs", "verify-hypervisor-lambda-gpu-vm-adapter.mjs", "verify-hypervisor-akash-depin-adapter.mjs", "verify-hypervisor-aws-enterprise-vm-adapter.mjs", "verify-hypervisor-gcp-enterprise-vm-adapter.mjs", "verify-hypervisor-azure-enterprise-vm-adapter.mjs", "verify-hypervisor-k8s-kubevirt-cluster-adapter.mjs", "verify-hypervisor-cross-provider-failover.mjs"];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.provider-neutral-live-transaction-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], generation: null, neutrality: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `provider-neutral-live-transaction-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const sha = (v) => `sha256:${crypto.createHash("sha256").update(stable(v)).digest("hex")}`;
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);

// ---- oracles (pure) ---------------------------------------------------------------------------------------
export function retainedSetFindings(set) {
  const f = [];
  if (set?.schema_version !== "ioi.evidence.retained-akash-no-qualified-bid-closes.v1") f.push("retained_schema_invalid");
  const rows = Array.isArray(set?.rows) ? set.rows : [];
  if (rows.length < 1) f.push("retained_rows_empty");
  for (const r of rows) {
    const recomputed = sha({ dseq: r.dseq, deployment: r.deployment, operations: r.operations, unrecorded_members: r.unrecorded_members });
    if (recomputed !== r.row_sha256) f.push(`row_sha256_mismatch:${r.dseq}`);
    if (r.deployment?.execution_mode !== "live_console_api") f.push(`row_not_live:${r.dseq}`);
    if (r.deployment?.bid_ref != null || r.deployment?.lease_ref != null) f.push(`row_has_lease_evidence:${r.dseq}`);
  }
  if (rows.length && sha(rows.map((r) => r.row_sha256)) !== set?.set_sha256) f.push("set_sha256_mismatch");
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
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")]) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}
export function neutralityFindings(routes, certLib) {
  const f = [];
  const vocab = ["preflight", "create", "start", "workrun", "stop", "snapshot", "restore", "inject_outage", "recover", "delete", "observe"];
  for (const op of vocab) if (!new RegExp(`"${op}"`, "u").test(routes)) f.push(`op_vocabulary_missing:${op}`);
  const adapters = (routes.match(/impl EnvironmentProvider for /gu) || []).length;
  if (adapters < 8) f.push(`adapters_behind_one_trait:${adapters}`);
  if (!/reconciliation_required/u.test(routes) || !/NOT a refusal/u.test(routes)) f.push("reconciliation_required_posture_missing");
  if (!/never estimated|skipped/u.test(routes)) f.push("quote_posture_missing");
  if (!/provider_neutrality_claimed !== false/u.test(certLib)) f.push("certificate_neutrality_refusal_missing");
  if (!/no_qualified_bid_closed/u.test(certLib) || !/validateNoQualifiedBidCertificate/u.test(certLib)) f.push("certificate_lacks_no_bid_branch");
  return { findings: f, adapters };
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

// ---- the runner's own legs ---------------------------------------------------------------------------------
export function generationLeg(set, { mutate = true } = {}) {
  const certificates = [];
  const failures = [];
  for (const row of set.rows) {
    const cert = sealCertificate(assembleNoQualifiedBidClose(row, { retainedSetRef: path.relative(ROOT, RETAINED) }));
    const v = validateCertificate(cert);
    if (!v.ok) failures.push({ dseq: row.dseq, codes: v.failures.map((x) => x.code) });
    certificates.push({ dseq: row.dseq, certificate_hash: cert.certificate_hash, result: cert.result, refund_usd: cert.settlement.refund_usd, unrecorded: cert.unrecorded_members });
  }
  const plants = [];
  if (mutate && set.rows.length) {
    const base = assembleNoQualifiedBidClose(set.rows[0], { retainedSetRef: "x" });
    const cases = [
      ["lease_evidence_in_no_bid_certificate", (c) => { c.provider.lease_ref = "akash-lease://smuggled"; }],
      ["no_bid_result_invalid", (c) => { c.result = "success"; c.terminal_branch = "no_qualified_bid"; }],
      ["settlement_not_refund_settled", (c) => { c.settlement.state = "refund_pending"; }],
      ["refund_short_of_deposit", (c) => { c.settlement.refund_usd = 0.5; }],
      ["open_or_unknown_exposure", (c) => { c.settlement.open_exposure_count = 1; }],
      ["deployment_not_closed", (c) => { c.provider.active_lease_count = 1; }],
      ["unrecorded_member_present", (c) => { c.source.commit = "deadbeef123"; }],
      ["no_bid_not_live", (c) => { c.refusal.execution_mode = "simulated_control_plane"; }],
      ["no_bid_claims_inflated", (c) => { c.claims.deployment_claimed = true; }],
      ["certificate_hash_mismatch", (c) => { c.certificate_hash = `sha256:${"0".repeat(64)}`; }],
      ["secret_bearing_artifact", (c) => { c.operator = { session_token: "ioi_sess_forbidden" }; }],
    ];
    for (const [expected, mutateFn] of cases) {
      const c = structuredClone(base);
      const sealed = sealCertificate(c);
      mutateFn(sealed);
      const resealed = expected === "certificate_hash_mismatch" ? sealed : sealCertificate(sealed);
      const v = validateNoQualifiedBidCertificate(resealed);
      plants.push({ expected, detected: !v.ok && v.failures.some((x) => x.code === expected), codes: v.failures.map((x) => x.code).slice(0, 4) });
    }
  }
  return { certificates, failures, plants, ok: failures.length === 0 && plants.every((p) => p.detected) };
}

// ---- drills ------------------------------------------------------------------------------------------------
function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("the lane's legs and its two branches are bound: every executed clause names a real script with a pinned floor (app) or a drilled root script, every named failure carries its owner, the live branch is SCHEDULED with its exact prerequisite and ruling, clauses cover 1–12 exactly once", binding.length === 0, binding.join("; ") || "bound");
  if (!fs.existsSync(RETAINED)) blocked(`retained record set absent at ${RETAINED}`);
  const set = readJson(RETAINED);
  const setFindings = retainedSetFindings(set);
  ok(`the retained durable-record set is intact before it is read: ${set.rows?.length ?? 0} live no-qualified-bid closes, every row's sha256 re-derived here, the set's sha256 over the rows, no row carrying lease evidence, every row a live console-API run`, setFindings.length === 0, setFindings.join("; ") || `${set.set_sha256?.slice(0, 19)}`);
  const gen = generationLeg(set);
  evidence.generation = { certificates: gen.certificates, failures: gen.failures, plants: gen.plants };
  ok(`GENERATION: a typed no-qualified-bid terminal certificate is generated, sealed and verified for each of the ${set.rows.length} retained closes — result no_qualified_bid_closed, no lease evidence, deployment and escrow closed, provider-confirmed refund of the whole deposit at a settled height, zero open exposure, every unrecorded member named (${[...new Set(gen.certificates.flatMap((c) => c.unrecorded))].join(", ")}), never publication-eligible, no secret`, gen.failures.length === 0 && gen.certificates.length === set.rows.length, gen.failures.length ? JSON.stringify(gen.failures).slice(0, 200) : gen.certificates.map((c) => c.certificate_hash.slice(7, 15)).join(","));
  ok(`GENERATION drill: ${gen.plants.length} planted defects on the GENERATED certificate each go red by their own code — a lease smuggled in, a relabel to success, a pending refund, a refund short of the deposit, an open exposure, an active lease, a hidden unrecorded member, a simulated run, an inflated claim, a wrong hash, a bearer token`, gen.plants.length >= 11 && gen.plants.every((p) => p.detected), gen.plants.filter((p) => !p.detected).map((p) => `${p.expected} → ${p.codes.join("/")}`).join("; ") || `${gen.plants.length}/${gen.plants.length}`);
  const routes = fs.readFileSync(PROVIDER_ROUTES, "utf8");
  const certLib = fs.readFileSync(CERT_LIB, "utf8");
  const neutrality = neutralityFindings(routes, certLib);
  evidence.neutrality = neutrality;
  ok(`NEUTRALITY: the lane's provider-neutral SHAPE is read from the daemon's own dispatch — one operation vocabulary (preflight, create, start, workrun, stop, snapshot, restore, inject_outage, recover, delete, observe) over ${neutrality.adapters} adapters behind one trait, quotes verbatim or skipped, ambiguity a reconciliation_required that is NOT a refusal — and the certificate library refuses to certify neutrality and carries the no-bid branch`, neutrality.findings.length === 0, neutrality.findings.join("; ") || `${neutrality.adapters} adapters`);
  const cited = DROPPED_CITATIONS.map((s) => [s, Object.values(appPkg.scripts ?? {}).some((cmd) => cmd.includes(s))]);
  ok("the nine provider adapter done-bars (vast, runpod, lambda, akash, aws, gcp, azure, k8s, cross-provider failover) are NOT composed: they target the shared daemon without a session and are registered by no npm script — named as owed in their isolated form, never read as evidence", cited.every(([, r]) => !r), cited.filter(([, r]) => r).map(([s]) => s).join(",") || "none registered");
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 12; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 12 ? { n: 12, absence: { what: "a second substrate", owner: "M09.10" } } : r)));
  const withScheduled = verdict(base.map((r) => (r.n === 11 ? { n: 11, scheduled: { what: "x", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } } : r)));
  const scheduledNoRuling = verdict(base.map((r) => (r.n === 11 ? { n: 11, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 8 ? { n: 8, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 3 ? { n: 3, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 4 ? { n: 4, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 10));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence or a scheduled live leg → NAMED FAILURE; a scheduled leg without a ruling, a fabricated success row, a red gate, a reach beyond loopback or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withScheduled.kind === "named_failure" && scheduledNoRuling.kind === "fail" && fabricated.kind === "fail" && red.kind === "fail" && reach.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${withScheduled.kind}/${scheduledNoRuling.kind}/${fabricated.kind}/${red.kind}/${reach.kind}/${missing.kind}`);
  const canon = fs.readFileSync(CANON, "utf8");
  const section = canon.slice(canon.indexOf("## The Provider-Neutral Live Transaction Lane"));
  ok("canon binds the gate: byo-provider-plane.md § The Provider-Neutral Live Transaction Lane names check:provider-neutral-live-transaction, says safe refusal is not successful deployment and close acceptance is not refund settlement, names the generated no-qualified-bid certificate and the scheduled positive branch, and claims no provider-neutral live pass", section.includes("`check:provider-neutral-live-transaction`") && /Safe\s+refusal is not successful deployment/u.test(section) && /close acceptance is not refund\s+settlement/u.test(section) && /GENERATED at run time/u.test(section) && /scheduled check/u.test(section) && /no provider-neutral live pass is claimed/u.test(section), "read from byo-provider-plane.md");
}

// ---- mutation ---------------------------------------------------------------------------------------------
function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 3 ? { ...c, executed_by: [{ ...GOVERNED, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 11 ? { ...c, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : c)), { rootPkg, appPkg, floors });
  plant("a scheduled live leg without a ruling", f.some((x) => /scheduled_without_prerequisite_or_ruling/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 10), { rootPkg, appPkg, floors });
  plant("the no-qualified-bid branch clause silently dropped", f.some((x) => /clause_missing: 10/u.test(x)), f[0]);
  const set = readJson(RETAINED);
  const tampered = structuredClone(set); tampered.rows[0].deployment.provider_native_settlement.refund_usd = 0.25;
  f = retainedSetFindings(tampered);
  plant("a retained row whose bytes were changed after it was committed (refund altered)", f.some((x) => /row_sha256_mismatch/u.test(x)), f[0]);
  const smuggled = structuredClone(set); smuggled.rows[1].deployment.lease_ref = "akash-lease://smuggled"; smuggled.rows[1].row_sha256 = sha({ dseq: smuggled.rows[1].dseq, deployment: smuggled.rows[1].deployment, operations: smuggled.rows[1].operations, unrecorded_members: smuggled.rows[1].unrecorded_members });
  f = retainedSetFindings(smuggled);
  plant("a retained row re-committed WITH lease evidence (the set's own hash then disagrees, and the row is refused as a no-bid close)", f.some((x) => /row_has_lease_evidence|set_sha256_mismatch/u.test(x)), f[0]);
  const gen = generationLeg(set, { mutate: true });
  plant("the generation drill's own eleven planted defects on a generated certificate", gen.plants.length >= 11 && gen.plants.every((p) => p.detected), gen.plants.filter((p) => !p.detected).map((p) => p.expected).join(",") || `${gen.plants.length}/${gen.plants.length}`);
  const routes = fs.readFileSync(PROVIDER_ROUTES, "utf8"); const certLib = fs.readFileSync(CERT_LIB, "utf8");
  let n = neutralityFindings(routes.replace(/impl EnvironmentProvider for /gu, "impl SomethingElse for "), certLib);
  plant("a dispatch with no adapters behind the one trait", n.findings.some((x) => /adapters_behind_one_trait/u.test(x)), n.findings[0]);
  n = neutralityFindings(routes, certLib.replace(/provider_neutrality_claimed !== false/gu, "provider_neutrality_claimed !== true"));
  plant("a certificate library that would certify provider neutrality", n.findings.includes("certificate_neutrality_refusal_missing"), n.findings[0]);
  n = neutralityFindings(routes, certLib.replace(/validateNoQualifiedBidCertificate/gu, "validateSomethingElse"));
  plant("a certificate library without the no-bid branch", n.findings.includes("certificate_lacks_no_bid_branch"), n.findings[0]);
  const fake = verdict(CLAUSES.map((c) => ({ n: c.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate ----------------------------------------------------------------------------------------
async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const argvRun = ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv: argvRun, cwd: ROOT, env, workDir, bridges: [], timeoutMs: g.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: [], declaredNames: [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  return { script: g.script, kind: g.kind, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0) }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256File(evidenceFile) : null, executed_assertions: censusJson?.executed_assertions ?? null, floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-pnlt-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir, live_credentials_present: !!(process.env.IOI_C7_EMAIL && process.env.IOI_C7_PASSWORD_FILE) };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ generation: evidence.generation, neutrality: evidence.neutrality }, null, 2)}\n`);
  const selfRun = { script: "self", status: evidence.generation?.failures?.length === 0 && (evidence.neutrality?.findings?.length ?? 1) === 0 ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null };
  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null, scheduled: c.scheduled || null };
    for (const g of c.executed_by ?? []) {
      if (g.kind === "self") { row.executed.push({ ...selfRun, script: g.script }); continue; }
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
  if (MODE === "mutation") exit = mutation() ? 0 : 1;
  else {
    drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "provider-neutral-live-transaction", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
