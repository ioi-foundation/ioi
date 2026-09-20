#!/usr/bin/env node
// check:c8-bounded-live-effect-certificate — M12.9: the C8 v2 bounded provider-lifecycle certificate, GENERATED
// (docs/architecture/components/hypervisor/byo-provider-plane.md § The C8 v2 Bounded Provider-Lifecycle
// Certificate; register R-211, executing R-140 and finishing the positive half of R-210(1)).
//
// CANON. The certificate binds the exact authority, the proposal provenance, the two-phase roots, the
// provider-native live state, the C6 proof, teardown and the final billing/refund readback of ONE bounded
// live effect; every incomplete or unsafe condition yields a typed non-success report, never a success
// label. It is generated from durable records, never read pre-sealed. Under the kernel's C8 clause a
// certificate regenerated from retained records is evidence about the retained crossing and never a new
// one; a fresh crossing is a separately authorized live run (R-139).
//
// WHAT THIS RUNNER IS. The certificate's binding demands are CLAUSES. Each is EXECUTED by the floored gate
// that already proves it, or by one of this runner's own legs, or it is NAMED (a typed failure with an
// owner, or a SCHEDULED live leg with its exact prerequisite and ruling). The runner's own legs:
//   GENERATION — the run evidence ASSEMBLED at run time from the tracked, redacted, hash-committed record
//   set of one retained owner-authorized positive live run (every hash re-derived before the set is read;
//   the set states in its own words that it is NOT the T7 capstone), sealed, verified, and required to
//   regenerate EXACTLY the hash sealed on the day the records were written — the certificate bytes are
//   never tracked, only their hash.
//   REPLAY — the capstone verifier's 22 structural and 22 durable mutation cases replayed on the GENERATED
//   certificate: the structural ones against the validator, the durable ones against the retained records
//   materialized as a data dir with the retained receipts served from a loopback stub this runner owns —
//   each case classified fired / not_applicable (typed) / masked_by_moved_tree, the counts pinned exactly,
//   and the moved-tree baseline asserted to be EXACTLY the three host-bound checks and nothing else.
//   NON-SUCCESS — every fired case yields a typed non-success report that certifies nothing; the generated
//   certificate yields none; the lane's no-qualified-bid terminal certificate (M09.6's retained set) is
//   validated as the other typed non-success and refused when relabelled.
//   BASIS — the run's source commit resolves and is an ancestor of HEAD; its declared-dirty basis makes the
//   certificate never publication-eligible, and the certificate says so.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding, the four legs, the verdict rules, canon's binding. No
//                 daemon, no network beyond a loopback stub this runner starts, no credential.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: the drills, then every executed gate inside the isolated-egress harness;
//                 the fresh crossing stays scheduled (this runner never spends). Exit 0 pass, 2 named
//                 failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import { NON_SUCCESS_REPORT_SCHEMA, NO_BID_RESULT, assembleNoQualifiedBidClose, judgeCertificate, nonSuccessReport, sealCertificate, validateCertificate } from "../apps/hypervisor/scripts/lib/c7-c8-certificate.mjs";
import { assembleRunEvidence } from "../apps/hypervisor/scripts/lib/c7-c8-evidence.mjs";
import { DURABLE_CASES, SELF_TEST_CASES, verifyDurable } from "../apps/hypervisor/scripts/verify-c7-c8-capstone.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");
const RETAINED = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m12-9-c7-retained-bounded-live-effect-run-2026-09-20.v1.json");
const NO_BID_SET = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m09-6-akash-retained-no-qualified-bid-closes-2026-09-20.v1.json");
const CANON = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const CANON_SECTION = "## The C8 v2 Bounded Provider-Lifecycle Certificate";
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS), authorized leg by leg";
const LIVE_RULING = "R-139 (2026-09-14) and R-211 (2026-09-20): a missing credential blocks a live RUN, never the unit; a certificate regenerated from retained records is evidence about the retained crossing, never a new one — the fresh crossing is the unit's scheduled check";
const MOVED_TREE_OWNER = "the scheduled fresh crossing (clause 12): the substrate log prefix, the certified daemon binary and the equality of HEAD with the run's commit can be answered only on the run's own host";

// THE PINS. The replay's populations and classifications, exact. A deleted case, a case that stops
// firing, or a case that starts firing for the wrong reason moves one of these and goes red.
export const PINS = {
  structural_cases: 22,
  durable_cases: 22,
  structural: { fired: 21, not_applicable: 1, masked_by_moved_tree: 0, false_green: 0 },
  durable: { fired: 20, not_applicable: 1, masked_by_moved_tree: 1, false_green: 0 },
  // exactly these three, with the binary either absent (a tree that never built it) or different.
  moved_tree: { always: ["substrate_log_missing", "source_commit_mismatch"], one_of: ["daemon_binary_mismatch", "daemon_binary_missing"] },
};
export const ARTIFACT_MEMBERS = ["challenge", "proposal_admission", "cast", "start", "logs", "delete", "reconcile", "whoami", "receipts", "reconciliation", "operations"];
export const SECRET_PATTERNS = [/"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key)"\s*:/iu, /ioi_sess_[A-Za-z0-9_-]+/u, /ioi_bootstrap_[A-Za-z0-9_-]+/u, /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u, /"email"\s*:/u];

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const root = (script, minutes) => ({ kind: "root", script, workspace: null, minutes });
const GOVERNED = gate("check:governed-effect-assurance-floor", "governed-effect-assurance", 30);
const PROVENANCE = gate("check:provider-proposal-provenance", "provider-proposal-provenance", 30);
const LANE = gate("check:provider-neutral-live-transaction", "provider-neutral-live-transaction", 20);
const T7 = root("check:t7-retained-capstone-applicability", 20);
const GENERATION = { kind: "self", script: "generation (this runner)" };
const REPLAY = { kind: "self", script: "replay (this runner)" };
const NON_SUCCESS = { kind: "self", script: "non-success (this runner)" };
const BASIS = { kind: "self", script: "basis (this runner)" };

export const CLAUSES = [
  { n: 1, demand: "the certificate is GENERATED from durable records at run time, never read pre-sealed, and regenerates exactly the hash sealed when the records were written", executed_by: [GENERATION] },
  { n: 2, demand: "the source commit and daemon binary of the run are bound and the publication posture is declared", executed_by: [GENERATION, BASIS, T7], absence: { what: "the equality of HEAD and of the built daemon binary with the run's basis, and the substrate log prefix, are the moved-tree remainder: asserted here as EXACTLY those three and nothing else, answerable only on the run's own host", owner: MOVED_TREE_OWNER } },
  { n: 3, demand: "an authenticated operator principal; no secret value, password path, bearer session or credential material anywhere", executed_by: [GENERATION, REPLAY] },
  { n: 4, demand: "the challenge policy and request hashes and the exact reviewed facets: deposit, ceiling, selector, SDL hash, teardown policy, retry count", executed_by: [GENERATION, REPLAY, GOVERNED] },
  { n: 5, demand: "the wallet grant and the consumed one-shot capability lease, terminal, with its expiry and revocation", executed_by: [GENERATION, REPLAY] },
  { n: 6, demand: "daemon-issued C4 proposal admission and consumption, never inline caller-authored provenance", executed_by: [REPLAY, PROVENANCE] },
  { n: 7, demand: "the C2 intent and outcome roots, the outcome a distinct successor of the exact intent", executed_by: [GENERATION, REPLAY, GOVERNED] },
  { n: 8, demand: "provider-native deployment, bid, provider and lease identifiers; C6 state fetched live; endpoint evidence", executed_by: [GENERATION, REPLAY] },
  { n: 9, demand: "teardown, the provider-native final billing/refund readback, the final net cost, zero open and unknown exposure", executed_by: [GENERATION, REPLAY, LANE] },
  { n: 10, demand: "the negative refusal receipts, durable and promoted", executed_by: [REPLAY], absence: { what: "the promoted receipts are served from the retained set by a loopback stub this runner owns; the live daemon's promoted family is read only by a run on the run's own host", owner: MOVED_TREE_OWNER } },
  { n: 11, demand: "every incomplete or unsafe condition yields a typed non-success report, never a success label; the no-qualified-bid close is the lane's typed terminal non-success; no ACC-14 rung is claimed", executed_by: [NON_SUCCESS, REPLAY, LANE] },
  { n: 12, demand: "a fresh certificate from a fresh live crossing", executed_by: [T7], scheduled: { what: "a NEW live crossing (bid → lease → C6 retrieved_live → endpoint → teardown → provider-confirmed final debit) driven leg by leg, its artifacts extracted into a second retained run, and a NEW certificate generated and replayed by this same gate — the certificate generated today is evidence about the retained 2026-08-21 crossing", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.c8-bounded-live-effect-certificate-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], generation: null, replay: null, non_success: null, basis: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `c8-bounded-live-effect-certificate-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const sha = (v) => `sha256:${crypto.createHash("sha256").update(stable(v)).digest("hex")}`;
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);
const HASH = /^sha256:[0-9a-f]{64}$/u;

// ---- oracles (pure) ---------------------------------------------------------------------------------------
export function runHash(run) { return sha({ dseq: run.dseq, environment_ref: run.environment_ref, subject: run.subject, source_basis: run.source_basis, substrate_anchor: run.substrate_anchor, artifacts: run.artifacts, records: run.records }); }
export function retainedSetFindings(set) {
  const f = [];
  if (set?.schema_version !== "ioi.evidence.retained-c7-bounded-live-effect-run.v1") f.push("retained_schema_invalid");
  const runs = Array.isArray(set?.runs) ? set.runs : [];
  if (runs.length < 1) f.push("retained_runs_empty");
  if (!HASH.test(String(set?.attested_certificate_sha256 ?? ""))) f.push("attested_certificate_hash_malformed");
  for (const r of runs) {
    const id = r?.dseq ?? "?";
    if (runHash(r) !== r?.run_sha256) f.push(`run_sha256_mismatch:${id}`);
    if (r?.subject?.is_t7_capstone !== false) f.push(`run_not_declared_non_t7:${id}`);
    if (!(typeof r?.subject?.statement === "string" && /\bNOT the T7\b/u.test(r.subject.statement) && r.subject.statement.includes(String(r?.subject?.t7_capstone_dseq ?? "\u0000")) && r.subject.t7_capstone_dseq !== r.dseq)) f.push(`run_statement_missing:${id}`);
    if (r?.source_basis?.publication_eligible !== false) f.push(`run_publication_posture_invalid:${id}`);
    if (!/^[0-9a-f]{40}$/u.test(String(r?.source_basis?.commit ?? "")) || !HASH.test(String(r?.source_basis?.daemon_binary_sha256 ?? ""))) f.push(`run_source_basis_malformed:${id}`);
    if (!(Number.isSafeInteger(r?.substrate_anchor?.bytes) && r.substrate_anchor.bytes > 0 && HASH.test(String(r?.substrate_anchor?.prefix_sha256 ?? "")))) f.push(`run_substrate_anchor_malformed:${id}`);
    const d = r?.records?.deployment;
    if (d?.execution_mode !== "live_console_api") f.push(`run_not_live:${id}`);
    if (!d?.lease_ref || !d?.bid_ref || d?.state !== "final_debit_settled") f.push(`run_not_a_settled_positive:${id}`);
    for (const m of ARTIFACT_MEMBERS) if (r?.artifacts?.[m] === undefined) f.push(`artifact_member_missing:${id}:${m}`);
    for (const m of ["deployment", "provider_lease", "endpoint", "capability_lease", "provider_operations"]) if (!r?.records?.[m]) f.push(`record_member_missing:${id}:${m}`);
    const serialized = JSON.stringify(r);
    if (SECRET_PATTERNS.some((p) => p.test(serialized))) f.push(`secret_bearing_row:${id}`);
  }
  if (runs.length && sha(runs.map((r) => r.run_sha256)) !== set?.set_sha256) f.push("set_sha256_mismatch");
  return f;
}
export function generateFromRun(run) {
  const a = run.artifacts;
  const r = run.records;
  const evidenceObject = assembleRunEvidence({
    artifacts: { challenge: a.challenge, proposalAdmission: a.proposal_admission, cast: a.cast, start: a.start, logs: a.logs, deleted: a.delete, reconcile: a.reconcile ?? null, whoami: a.whoami, receipts: a.receipts?.receipts ?? [], reconciliation: a.reconciliation ?? {}, operations: a.operations?.operations ?? [] },
    records: { deployments: [r.deployment], leases: [r.provider_lease], endpoints: [r.endpoint], capabilityLeases: [r.capability_lease] },
    environment: run.environment_ref,
    source: run.source_basis,
    substrateAnchor: run.substrate_anchor,
  });
  return sealCertificate(evidenceObject);
}
export function generationFindings(set) {
  const f = [];
  const out = { certificates: [] };
  for (const run of set.runs ?? []) {
    let cert = null;
    try { cert = generateFromRun(run); } catch (error) { f.push(`assembly_refused:${run.dseq}:${String(error.message).slice(0, 80)}`); out.certificates.push({ dseq: run.dseq, refused: String(error.message) }); continue; }
    const v = validateCertificate(cert);
    if (!v.ok) f.push(`generated_certificate_invalid:${run.dseq}:${v.failures.map((x) => x.code).join("/")}`);
    if (cert.certificate_hash !== set.attested_certificate_sha256) f.push(`regenerated_hash_differs:${run.dseq}:${cert.certificate_hash.slice(7, 19)}!=${String(set.attested_certificate_sha256).slice(7, 19)}`);
    if (cert.result !== "success" || cert.ok !== true) f.push(`generated_not_success:${run.dseq}`);
    if (cert.source?.publication_eligible !== false) f.push(`generated_publication_posture_invalid:${run.dseq}`);
    if (cert.claims?.certified_scope !== "governed_infrastructure_lifecycle" || cert.claims?.bare_metal_claimed !== false || cert.claims?.provider_neutrality_claimed !== false) f.push(`generated_claims_inflated:${run.dseq}`);
    if (String(cert.provider?.dseq) !== String(run.dseq)) f.push(`generated_dseq_differs:${run.dseq}`);
    out.certificates.push({ dseq: run.dseq, certificate_hash: cert.certificate_hash, result: cert.result, final_net_cost_usd: cert.settlement?.final_net_cost_usd, settlement_state: cert.settlement?.state, publication_eligible: cert.source?.publication_eligible, nonclaims: cert.nonclaims?.length ?? 0, certificate: cert });
  }
  return { findings: f, ...out };
}
export function classifyCase(expected, observedCodes, { baseline, selectorMode }) {
  // Masking is judged BEFORE firing: a code the UNMUTATED certificate already carries on this tree
  // is observed whether or not the mutation did anything, so observing it proves nothing.
  if (baseline.includes(expected)) return { outcome: "masked_by_moved_tree", reason: `${expected} is already carried by the UNMUTATED certificate on this tree (moved-tree baseline), so the planted defect cannot be told from the host` };
  if (expected === "daemon_binary_mismatch" && baseline.includes("daemon_binary_missing")) return { outcome: "masked_by_moved_tree", reason: "the certified binary is absent on this tree, so its mismatch cannot be exercised (daemon_binary_missing in the baseline)" };
  if (observedCodes.includes(expected)) return { outcome: "fired" };
  if (expected === "exact_provider_mismatch" && selectorMode !== "exact") return { outcome: "not_applicable", reason: `the retained run reviewed a ${selectorMode} selector; exact_provider_mismatch fires only for an exact-provider selector` };
  return { outcome: "false_green" };
}
export function movedTreeFindings(baseline) {
  const f = [];
  for (const code of PINS.moved_tree.always) if (!baseline.includes(code)) f.push(`baseline_missing:${code}`);
  const binary = baseline.filter((c) => PINS.moved_tree.one_of.includes(c));
  if (binary.length !== 1) f.push(`baseline_binary_codes:${binary.join("/") || "none"}`);
  const allowed = new Set([...PINS.moved_tree.always, ...PINS.moved_tree.one_of]);
  for (const code of baseline) if (!allowed.has(code)) f.push(`baseline_extra:${code}`);
  return f;
}
export function tally(rows) {
  const t = { fired: 0, not_applicable: 0, masked_by_moved_tree: 0, false_green: 0 };
  for (const r of rows) t[r.outcome] = (t[r.outcome] ?? 0) + 1;
  return t;
}
export function replayFindings(replay, { structuralCases = PINS.structural_cases, durableCases = PINS.durable_cases } = {}) {
  const f = [];
  if (replay.structural.rows.length !== structuralCases) f.push(`structural_population:${replay.structural.rows.length}!=${structuralCases}`);
  if (replay.durable.rows.length !== durableCases) f.push(`durable_population:${replay.durable.rows.length}!=${durableCases}`);
  for (const [name, expected] of [["structural", PINS.structural], ["durable", PINS.durable]]) {
    const got = tally(replay[name].rows);
    for (const k of Object.keys(expected)) if (got[k] !== expected[k]) f.push(`${name}_${k}:${got[k]}!=${expected[k]}`);
    for (const r of replay[name].rows) if (r.outcome === "false_green") f.push(`${name}_false_green:${r.expected}`);
    for (const r of replay[name].rows) if (r.outcome !== "fired" && !(typeof r.reason === "string" && r.reason.length > 20)) f.push(`${name}_untyped_skip:${r.expected}`);
  }
  f.push(...movedTreeFindings(replay.baseline));
  return f;
}
export function nonSuccessFindings(replay, generated, noBidSet) {
  const f = [];
  const reports = [...replay.structural.rows, ...replay.durable.rows].filter((r) => r.outcome === "fired");
  for (const r of reports) {
    const rep = r.report;
    if (rep?.schema_version !== NON_SUCCESS_REPORT_SCHEMA || rep?.result !== "not_certified" || rep?.claims !== null) f.push(`report_untyped:${r.expected}`);
    if (!Array.isArray(rep?.codes) || !rep.codes.includes(r.expected)) f.push(`report_lacks_code:${r.expected}`);
    if (rep?.subject_certificate_hash !== r.mutated_hash) f.push(`report_subject_mismatch:${r.expected}`);
    if (rep?.result === "success" || rep?.ok === true) f.push(`report_is_success:${r.expected}`);
  }
  if (reports.length === 0) f.push("no_reports");
  const judged = judgeCertificate(generated);
  if (judged.kind !== "certificate") f.push("generated_certificate_reported_non_success");
  const rows = Array.isArray(noBidSet?.rows) ? noBidSet.rows : [];
  if (rows.length === 0) f.push("no_bid_set_empty");
  else {
    const noBid = sealCertificate(assembleNoQualifiedBidClose(rows[0], { retainedSetRef: path.relative(ROOT, NO_BID_SET) }));
    const v = validateCertificate(noBid);
    if (!v.ok || noBid.result !== NO_BID_RESULT || noBid.result === "success") f.push(`no_bid_terminal_invalid:${v.failures.map((x) => x.code).join("/")}`);
    const relabelled = sealCertificate({ ...structuredClone(noBid), result: "success", terminal_branch: undefined });
    if (validateCertificate(relabelled).ok) f.push("no_bid_relabelled_success_accepted");
    const positiveAsNoBid = sealCertificate({ ...structuredClone(generated), result: NO_BID_RESULT, terminal_branch: "no_qualified_bid" });
    const pv = validateCertificate(positiveAsNoBid);
    if (pv.ok || !pv.failures.some((x) => x.code === "lease_evidence_in_no_bid_certificate")) f.push("positive_relabelled_no_bid_accepted");
  }
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
export function canonFindings(text) {
  const f = [];
  const at = text.indexOf(CANON_SECTION);
  if (at < 0) return ["canon_section_missing"];
  const s = text.slice(at).replace(/\s+/gu, " ");
  const need = [["names_gate", /`check:c8-bounded-live-effect-certificate`/u], ["gloss", /"bounded-live-effect certificate"/u], ["generated_not_read", /generated, not read/u], ["typed_non_success", /typed non-success report, never a success label/u], ["not_t7", /NOT the T7 integrated capstone/u], ["hash_equality", /regenerated hash to equal the hash sealed/u], ["kernel_c8", /evidence about the retained crossing and never a new one/u], ["scheduled", /scheduled check/u], ["no_pass", /no fresh bounded-live-effect pass is claimed/u], ["disambiguation", /neither the kernel's C8 clause/u]];
  for (const [name, re] of need) if (!re.test(s)) f.push(`canon_${name}_missing`);
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

// ---- the runner's own legs ---------------------------------------------------------------------------------
function materializeRecords(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-c8-records-"));
  const put = (family, id, record) => { fs.mkdirSync(path.join(dir, family), { recursive: true }); fs.writeFileSync(path.join(dir, family, `${id}.json`), JSON.stringify(record)); };
  const r = run.records;
  put("akash-deployments", r.deployment.record_id, r.deployment);
  put("akash-leases", r.provider_lease.record_id, r.provider_lease);
  put("akash-endpoints", r.endpoint.record_id, r.endpoint);
  put("capability-leases", r.capability_lease.lease_id, r.capability_lease);
  for (const op of r.provider_operations ?? []) put("provider-operations", op.operation_id, op);
  return dir;
}
function serveRetainedReceipts(receipts) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ receipts })); });
    server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(() => r())) }));
  });
}
export async function replayLeg(generated, run, { structuralCases = SELF_TEST_CASES, durableCases = DURABLE_CASES, repo = ROOT } = {}) {
  const dataDir = materializeRecords(run);
  const stub = await serveRetainedReceipts(run.artifacts.receipts?.receipts ?? []);
  try {
    const baseline = [...new Set((await verifyDurable(structuredClone(generated), dataDir, repo, stub.url)).map((x) => x.code))];
    const selectorMode = generated.authority?.reviewed_facets?.provider_selector?.mode ?? "unknown";
    const play = async (cases, durable) => {
      const rows = [];
      for (const [expected, mutate, needsDurable] of cases) {
        const c = structuredClone(generated);
        mutate(c);
        c.certificate_hash = sealCertificate(c).certificate_hash;
        const structural = validateCertificate(c).failures;
        const durableFailures = durable && needsDurable ? await verifyDurable(c, dataDir, repo, stub.url) : [];
        const observed = [...structural, ...durableFailures];
        const codes = [...new Set(observed.map((x) => x.code))];
        const cls = classifyCase(expected, codes, { baseline, selectorMode });
        rows.push({ expected, needs_durable: !!(durable && needsDurable), outcome: cls.outcome, reason: cls.reason ?? null, codes: codes.slice(0, 6), mutated_hash: c.certificate_hash, report: cls.outcome === "fired" ? nonSuccessReport(c, observed, { condition: expected, subject: `retained run dseq ${run.dseq}, planted ${expected}` }) : null });
      }
      return rows;
    };
    const structural = { rows: await play(structuralCases, false) };
    const durable = { rows: await play(durableCases, true) };
    return { baseline, selector_mode: selectorMode, structural, durable, stub: stub.url, data_dir: dataDir };
  } finally {
    await stub.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}
export function basisLeg(run, generated, repo = ROOT) {
  const f = [];
  const commit = String(run.source_basis?.commit ?? "");
  const git = (args) => spawnSync("git", args, { cwd: repo, encoding: "utf8" });
  const have = () => git(["cat-file", "-e", `${commit}^{commit}`]).status === 0;
  const isAncestor = () => git(["merge-base", "--is-ancestor", commit, "HEAD"]).status === 0;
  let resolves = have();
  let ancestor = resolves && isAncestor();
  if ((!resolves || !ancestor) && git(["rev-parse", "--is-shallow-repository"]).stdout?.trim() === "true") {
    spawnSync("git", ["fetch", "--unshallow"], { cwd: repo, encoding: "utf8", timeout: 600000 });
    resolves = have();
    ancestor = resolves && isAncestor();
  }
  if (!resolves) f.push("source_commit_unresolvable");
  else if (!ancestor) f.push("source_commit_not_an_ancestor");
  if (run.source_basis?.dirty_state_declaration === "clean") f.push("basis_declares_clean_but_ruled_dirty");
  if (generated?.source?.commit !== commit || generated?.source?.daemon_binary_sha256 !== run.source_basis?.daemon_binary_sha256) f.push("generated_source_differs_from_basis");
  if (generated?.source?.publication_eligible !== false) f.push("generated_publication_eligible");
  const head = git(["rev-parse", "HEAD"]).stdout?.trim() ?? "";
  return { findings: f, commit, head, resolves, ancestor };
}

// ---- drills ------------------------------------------------------------------------------------------------
async function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("the certificate's binding demands are bound: every executed clause names a real script with a pinned floor (app) or a drilled root script, every named failure carries its owner, the fresh crossing is SCHEDULED with its exact prerequisite and ruling, clauses cover 1–12 exactly once", binding.length === 0, binding.join("; ") || "bound");
  if (!fs.existsSync(RETAINED)) blocked(`retained record set absent at ${RETAINED}`);
  if (!fs.existsSync(NO_BID_SET)) blocked(`no-qualified-bid record set absent at ${NO_BID_SET}`);
  const set = readJson(RETAINED);
  const setFindings = retainedSetFindings(set);
  ok(`the retained record set is intact before it is read: ${set.runs?.length ?? 0} owner-authorized positive live run, its sha256 re-derived here over the eleven artifact projections, the five record members, the source basis and the substrate anchor, the set's sha256 over the runs, the run declared in its own words NOT the T7 capstone, never publication-eligible, no secret or identity member`, setFindings.length === 0, setFindings.join("; ") || `${set.set_sha256?.slice(0, 19)}`);
  const gen = generationFindings(set);
  const generated = gen.certificates[0]?.certificate ?? null;
  evidence.generation = { findings: gen.findings, certificates: gen.certificates.map(({ certificate, ...rest }) => rest), attested_certificate_sha256: set.attested_certificate_sha256 };
  ok(`GENERATION: the run evidence is ASSEMBLED at run time from the retained records (never read pre-sealed), sealed as a C8 v2 certificate, verified with zero failures, and regenerates EXACTLY the hash sealed on 2026-08-21 — ${String(set.attested_certificate_sha256).slice(0, 19)} — with result success, scope governed_infrastructure_lifecycle, no bare-metal or neutrality claim, never publication-eligible`, gen.findings.length === 0 && !!generated, gen.findings.join("; ") || `${gen.certificates.map((c) => `${c.dseq} → ${String(c.certificate_hash).slice(7, 19)} · ${c.settlement_state} · $${c.final_net_cost_usd}`).join(", ")}`);
  if (!generated) blocked("no certificate was generated; the replay has no subject");
  const replay = await replayLeg(generated, set.runs[0]);
  const rf = replayFindings(replay);
  evidence.replay = { baseline: replay.baseline, selector_mode: replay.selector_mode, structural: { tally: tally(replay.structural.rows), rows: replay.structural.rows.map(({ report, ...r }) => r) }, durable: { tally: tally(replay.durable.rows), rows: replay.durable.rows.map(({ report, ...r }) => r) }, findings: rf };
  const st = tally(replay.structural.rows);
  const du = tally(replay.durable.rows);
  ok(`REPLAY (structural): the verifier's ${PINS.structural_cases} structural mutation cases are REPLAYED on the GENERATED certificate — ${PINS.structural.fired} fire by their own code, ${PINS.structural.not_applicable} is not applicable by a typed reason (the exact-provider case on a ${replay.selector_mode}-selector run), none is a false green`, replay.structural.rows.length === PINS.structural_cases && st.fired === PINS.structural.fired && st.not_applicable === PINS.structural.not_applicable && st.masked_by_moved_tree === 0 && st.false_green === 0, rf.filter((x) => /^structural/u.test(x)).join("; ") || `${st.fired}/${st.not_applicable}/${st.masked_by_moved_tree}/${st.false_green}`);
  ok(`REPLAY (durable): the verifier's ${PINS.durable_cases} durable mutation cases are REPLAYED on the GENERATED certificate against the RETAINED records materialized as a data dir, the retained receipts served from a loopback stub this runner owns — the unmutated certificate's moved-tree baseline is EXACTLY the three host-bound checks (substrate log, daemon binary, HEAD equality) and nothing else; ${PINS.durable.fired} cases fire, ${PINS.durable.not_applicable} is typed not applicable, ${PINS.durable.masked_by_moved_tree} is masked by the moved tree, none is a false green`, replay.durable.rows.length === PINS.durable_cases && du.fired === PINS.durable.fired && du.not_applicable === PINS.durable.not_applicable && du.masked_by_moved_tree === PINS.durable.masked_by_moved_tree && du.false_green === 0 && movedTreeFindings(replay.baseline).length === 0, rf.filter((x) => /^(durable|baseline)/u.test(x)).join("; ") || `baseline ${replay.baseline.join(",")} · ${du.fired}/${du.not_applicable}/${du.masked_by_moved_tree}/${du.false_green}`);
  const noBidSet = readJson(NO_BID_SET);
  const ns = nonSuccessFindings(replay, generated, noBidSet);
  evidence.non_success = { findings: ns, reports: [...replay.structural.rows, ...replay.durable.rows].filter((r) => r.outcome === "fired").length };
  ok(`NON-SUCCESS: every fired case yields a TYPED non-success report (${NON_SUCCESS_REPORT_SCHEMA}: result not_certified, the planted condition, the subject hash, the codes; it claims nothing), the generated certificate itself is judged a certificate and not a report, the lane's no-qualified-bid terminal certificate assembles from M09.6's retained set as a validated NON-success, a no-bid certificate relabelled success is refused, and the positive certificate relabelled no-bid is refused for the lease evidence it carries`, ns.length === 0, ns.join("; ") || `${evidence.non_success.reports} reports`);
  const basis = basisLeg(set.runs[0], generated);
  evidence.basis = basis;
  ok("BASIS: the run's source commit resolves in this repository and is an ANCESTOR of HEAD (the applicability question, asked of this run too), its basis is declared dirty and so never publication-eligible, and the generated certificate carries exactly that commit, binary hash and posture", basis.findings.length === 0, basis.findings.join("; ") || `${basis.commit.slice(0, 12)} ancestor of ${basis.head.slice(0, 12)}`);
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 12; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 2 ? { n: 2, absence: { what: "the moved-tree remainder, three checks", owner: "the scheduled crossing" } } : r)));
  const withScheduled = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING } } : r)));
  const scheduledNoRuling = verdict(base.map((r) => (r.n === 12 ? { n: 12, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 1 ? { n: 1, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 4 ? { n: 4, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 9 ? { n: 9, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 11));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence or a scheduled live leg → NAMED FAILURE; a scheduled leg without a ruling, a fabricated success row, a red gate, a reach beyond loopback or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withScheduled.kind === "named_failure" && scheduledNoRuling.kind === "fail" && fabricated.kind === "fail" && red.kind === "fail" && reach.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${withScheduled.kind}/${scheduledNoRuling.kind}/${fabricated.kind}/${red.kind}/${reach.kind}/${missing.kind}`);
  const cf = canonFindings(fs.readFileSync(CANON, "utf8"));
  ok("canon binds the gate: byo-provider-plane.md § The C8 v2 Bounded Provider-Lifecycle Certificate names check:c8-bounded-live-effect-certificate, records \"bounded-live-effect certificate\" as this program's gloss for canon's own name, disambiguates it from the kernel's C8 clause and the v3 envelope, states the typed non-success rule, says the certificate is generated not read and regenerates the sealed hash from records that are NOT the T7 capstone, says a regenerated certificate is evidence about the retained crossing and never a new one, names the scheduled crossing, and claims no fresh pass", cf.length === 0, cf.join("; ") || "read from byo-provider-plane.md");
  return { set, generated };
}

// ---- mutation ---------------------------------------------------------------------------------------------
async function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 4 ? { ...c, executed_by: [{ ...GOVERNED, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 12 ? { ...c, scheduled: { what: "x", prerequisite: LIVE_PREREQ } } : c)), { rootPkg, appPkg, floors });
  plant("the fresh crossing scheduled without a ruling", f.some((x) => /scheduled_without_prerequisite_or_ruling/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 11), { rootPkg, appPkg, floors });
  plant("the typed non-success clause silently dropped", f.some((x) => /clause_missing: 11/u.test(x)), f[0]);
  const set = readJson(RETAINED);
  const tampered = structuredClone(set); tampered.runs[0].records.deployment.provider_native_settlement.final_debit_usd = 0.5;
  f = retainedSetFindings(tampered);
  plant("a retained record whose bytes were changed after commit (the final debit altered)", f.some((x) => /run_sha256_mismatch/u.test(x)), f[0]);
  const relabelled = structuredClone(set); relabelled.runs[0].subject.is_t7_capstone = true; relabelled.runs[0].run_sha256 = runHash(relabelled.runs[0]); relabelled.set_sha256 = sha([relabelled.runs[0].run_sha256]);
  f = retainedSetFindings(relabelled);
  plant("the run re-committed as the T7 capstone it is not", f.some((x) => /run_not_declared_non_t7/u.test(x)), f[0]);
  const leaky = structuredClone(set); leaky.runs[0].artifacts.cast.session_token = "ioi_sess_forbidden"; leaky.runs[0].run_sha256 = runHash(leaky.runs[0]); leaky.set_sha256 = sha([leaky.runs[0].run_sha256]);
  f = retainedSetFindings(leaky);
  plant("a bearer session re-committed into the set", f.some((x) => /secret_bearing_row/u.test(x)), f[0]);
  const wrongHash = structuredClone(set); wrongHash.attested_certificate_sha256 = `sha256:${"0".repeat(64)}`;
  let g = generationFindings(wrongHash);
  plant("an attested hash the regenerated certificate does not equal", g.findings.some((x) => /regenerated_hash_differs/u.test(x)), g.findings[0]);
  const pending = structuredClone(set); pending.runs[0].records.deployment.provider_native_settlement.settlement_state = "refund_pending";
  g = generationFindings(pending);
  plant("a retained deployment record whose settlement is refund_pending: the generated certificate is refused, never a success", g.findings.some((x) => /generated_certificate_invalid:.*settlement_not_terminal/u.test(x)), g.findings.find((x) => /generated_certificate_invalid/u.test(x)));
  const generated = generateFromRun(set.runs[0]);
  const replay = await replayLeg(generated, set.runs[0]);
  const clean = replayFindings(replay);
  plant("the positive control: the full replay on the generated certificate has no finding", clean.length === 0, clean.join("; ") || "clean");
  const shortened = { ...replay, structural: { rows: replay.structural.rows.slice(1) } };
  f = replayFindings(shortened);
  plant("a deleted structural mutation case (the replay's population pin)", f.some((x) => /structural_population:21!=22/u.test(x)), f.find((x) => /structural_population/u.test(x)));
  const noFire = { ...replay, structural: { rows: replay.structural.rows.map((r, i) => (i === 0 ? { ...r, outcome: "false_green", report: null } : r)) } };
  f = replayFindings(noFire);
  plant("a structural case that no longer fires on the generated certificate (a false green)", f.some((x) => /structural_false_green/u.test(x)), f.find((x) => /structural_false_green/u.test(x)));
  const extraBaseline = { ...replay, baseline: [...replay.baseline, "durable_settlement_mismatch"] };
  f = replayFindings(extraBaseline);
  plant("a moved-tree baseline carrying a fourth code (a real durable mismatch hidden as host state)", f.some((x) => /baseline_extra:durable_settlement_mismatch/u.test(x)), f.find((x) => /baseline_extra/u.test(x)));
  const untyped = { ...replay, structural: { rows: replay.structural.rows.map((r) => (r.outcome === "not_applicable" ? { ...r, reason: null } : r)) } };
  f = replayFindings(untyped);
  plant("a skipped case without a typed reason", f.some((x) => /structural_untyped_skip/u.test(x)), f.find((x) => /structural_untyped_skip/u.test(x)));
  const masked = { ...replay, durable: { rows: replay.durable.rows.map((r) => (r.outcome === "masked_by_moved_tree" ? { ...r, outcome: "fired" } : r)) } };
  f = replayFindings(masked);
  plant("a case masked by the moved tree counted as fired (the host's own mismatch passed off as the mutation's)", f.some((x) => /durable_masked_by_moved_tree:0!=1/u.test(x)), f.find((x) => /durable_masked/u.test(x)));
  const untypedReport = { ...replay, structural: { rows: replay.structural.rows.map((r, i) => (i === 0 ? { ...r, report: { ...r.report, result: "success" } } : r)) } };
  const ns = nonSuccessFindings(untypedReport, generated, readJson(NO_BID_SET));
  plant("a non-success report relabelled success", ns.some((x) => /report_is_success|report_untyped/u.test(x)), ns[0]);
  const c = canonFindings(fs.readFileSync(CANON, "utf8").replace(/`check:c8-bounded-live-effect-certificate`/gu, "`check:something-else`"));
  plant("canon that no longer names the gate", c.includes("canon_names_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
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
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-c8blec-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir, live_credentials_present: !!(process.env.IOI_C7_EMAIL && process.env.IOI_C7_PASSWORD_FILE) };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ generation: evidence.generation, replay: evidence.replay, non_success: evidence.non_success, basis: evidence.basis }, null, 2)}\n`);
  const selfGreen = (evidence.generation?.findings?.length ?? 1) === 0 && (evidence.replay?.findings?.length ?? 1) === 0 && (evidence.non_success?.findings?.length ?? 1) === 0 && (evidence.basis?.findings?.length ?? 1) === 0;
  const selfRun = { script: "self", status: selfGreen ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null };
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
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "c8-bounded-live-effect-certificate", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
