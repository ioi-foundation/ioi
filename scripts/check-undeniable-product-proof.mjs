#!/usr/bin/env node
// check:undeniable-product-proof — M12.3: canon's undeniable-product proof gate, run as a gate
// (docs/architecture/_meta/execution-horizons.md § Undeniable-product proof gate; register R-207).
//
// CANON. The selected minimum-L0 profile is the bounded software-change institution the ioi.ai
// orchestration application composes over the substrate (R-192: a composition, not a plane). The first
// profile crosses from architecture demonstration to product proof only when one operator completes
// the twenty-two-step journey through supported surfaces and public contracts, with every IOI-managed
// endpoint blocked (the `embedded_single_operator_offline` fixture). The gate fails if any step requires
// a hidden database edit, a privileged one-off script, copied bearer authority, an uninspectable
// prompt-only transition, a fabricated success row, or manual reconstruction of the evidence chain. The
// result is a PASS or a NAMED, TYPED failure — never a weaker pass. The proof records its measurements;
// thresholds are the release program's, omitting the measurements is not.
//
// WHAT THIS RUNNER IS. The twenty-two steps are CLAUSES. Each is EXECUTED by the gate that already
// proves it under the fixture — the standalone-conformance and zero-to-operable runners (1–6, 18–20,
// 22), the System-record seam gate (10–11: the compiled genesis it proposes and the System it
// activates), the goal-run, orchestration and context-family composition gates (12–13), the collective
// artifact runtime-lifecycle gate (17) — or it is a NAMED failure with an owner: 7 (no template-choice
// surface), 8–9 (goal description and discovery proposal not driven), 14–16 (the exact-effect review
// chain, the next kernel program), 21's System retirement, and profile 2 (managed optionality, which
// needs an account; the minimum-L0 claim requires profile 1 only). Nothing is read back and called
// verified: a clause counts as executed only from its gate's own exit status AND the evidence that
// gate wrote; an absence counts only with an owner; the verdict is a pure function of the clause rows
// and is drilled with planted rows (the failure taxonomy above as the runner's own rules).
//
//   --drills      CI-bound: the registered profile instance loaded, validated and pinned; the
//                 step→gate binding resolved against real npm scripts and pinned floors; the verdict
//                 rules; the measurement set; canon's binding. Minutes, no daemon.
//   --mutation    planted defects against the drills' oracles (a re-fixtured profile, a profile
//                 without negative tests, a binding onto a script that does not exist, a fabricated
//                 success row, an absence without an owner, a duplicated step) — each must go red.
//   (default)     the full gate: the drills, then every executed clause run INSIDE the isolated-egress
//                 harness (scripts/lib/egress-harness.mjs) with the wallet fixture as the declared
//                 loopback dependency, its ledger classified here; then the verdict. Exit 0 = pass,
//                 2 = named failure (every executed clause green, typed absences remain), 1 = fail.
//   --with-packaged   (full) also EXECUTE the packaged clauses (the standalone check's positive and
//                 replay legs and the zero-to-operable full check) instead of naming them not executed;
//                 needs two release packages whose daemon bytes differ.
//   --only <n,m>  (full) run only these clause numbers of the executed set (the rest named not executed).
//   --evidence <path>  also write the evidence there (default .artifacts/mvp-finish-line/).
//
//   IOI_HYPERVISOR_DAEMON_BINARY   the prebuilt daemon the composition gates run (default
//                                  target/debug/hypervisor-daemon; the harness must not build: a cargo
//                                  reach inside the namespace would be a finding, not a build)

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const PROFILE_SCHEMA = path.join(SCHEMAS, "conformance-profile.v1.schema.json");
const PROFILE_INVARIANTS = path.join(SCHEMAS, "invariants", "conformance-profile.v1.invariants.json");
const PROFILE_PATH = path.join(SCHEMAS, "fixtures", "conformance-profile-v1", "positive-flagship-minimum-l0-software-change.json");
const PROFILE_ID = "conformance_profile://ioi/flagship/minimum-l0-software-change/v1";
const ENVELOPE_REF = "canon://docs/architecture/_meta/execution-horizons.md#selected-minimum-l0-proof-profile";
const FIXTURE_ID = "embedded_single_operator_offline";
const FAMILIES = ["ioi_ai_account", "hosted_wallet_network_login", "marketplace", "ioi_network_enrollment", "ioi_l1", "license_heartbeat", "telemetry", "update_service", "external_model_provider"];
const CANON = path.join(ROOT, "docs", "architecture", "_meta", "execution-horizons.md");
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const WITH_PACKAGED = flag("--with-packaged");
const ONLY = flagValue("--only") ? new Set(flagValue("--only").split(",").map((n) => Number(n))) : null;

// ---- the twenty-two steps, as canon numbers them, bound to what executes them ---------------------------
// `executed_by` names an npm script (root or the hypervisor workspace) whose exit status and evidence
// decide the clause; `floor` is the pinned floor row its census must satisfy; `absence` names what is
// missing and who owes it. A step may carry both an executed gate and a residual absence (partial).
const KERNEL_CHAIN = "the exact-effect review chain, M03.15 → M01.9 → M13.6 (execution-horizons.md § The first proof: the next kernel program)";
export const STEPS = [
  { n: 1, step: "verify the selected release, signer, integrity, and supply-chain evidence", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 2, step: "preview install paths, endpoints, custody, supervision, egress, and effects", executed_by: { script: "check:zero-to-operable", workspace: null, extra: [], packaged: true, minutes: 150 } },
  { n: 3, step: "install and bootstrap deployment-local identity and authority posture", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 4, step: "start the client, daemon, and declared Agentgres posture", executed_by: { script: "check:zero-to-operable", workspace: null, extra: [], packaged: true, minutes: 150 } },
  { n: 5, step: "pass bounded readiness and inspect status, doctor findings, and logs", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 6, step: "authenticate through the deployment-local or connected identity lane", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 }, absence: { what: "the connected identity lane (provider-neutral account authentication, passkey step-up, the portable AuthorityGrantEnvelope v3 successor) is not exercised; the deployment-local lane is", owner: "M03.9 · M10.2" } },
  { n: 7, step: "choose the bounded software-change template", absence: { what: "no template-choice surface exists: the composition gates instantiate the package's genesis directly (exactGenesisBody), never through a chosen template", owner: "M12.4 (product_track) · Studio" } },
  { n: 8, step: "describe the goal, repository, constraints, authority, and acceptance", absence: { what: "the goal description is not driven as an operator input: the goal-run composition gate admits a GoalRun over a committed profile-resolution closure it authors itself", owner: "M12.4 (product_track)" } },
  { n: 9, step: "inspect and explicitly accept any discovery candidate and overrides", absence: { what: "HypervisorProjectDiscoveryProposal is not driven by any M12 gate; blank/template construction must record that no discovery proposal was used", owner: "M08.15" } },
  { n: 10, step: "validate, preview, and simulate one compiled package/genesis proposal", executed_by: { script: "check:system-record-seam", workspace: APP, extra: [], floor: "system-record-seam", minutes: 60 }, absence: { what: "preview and simulation of the compiled proposal before admission are not separate operator states; the seam gate proposes the exact genesis body and the daemon admits it", owner: "M12.4 (product_track)" } },
  { n: 11, step: "approve genesis and inspect the stable System", executed_by: { script: "check:system-record-seam", workspace: APP, extra: [], floor: "system-record-seam", minutes: 60 } },
  { n: 12, step: "start or admit the GoalRun in its composed work context (the ioi.ai orchestration over the System)", executed_by: [{ script: "check:orchestration-composition", workspace: APP, extra: [], floor: "orchestration-composition", minutes: 60 }, { script: "check:goal-run-composition", workspace: APP, extra: [], floor: "goal-run-composition", minutes: 60 }], absence: { what: "the GoalRun is ADMITTED over a committed closure; execution is not started and no invocation is minted (the goal-run gate's own non-claim)", owner: "M12.4 (product_track)" } },
  { n: 13, step: "observe planning, claimed work, attempts, verification, and blockers", executed_by: { script: "check:context-family-composition", workspace: APP, extra: [], floor: "context-family-composition", minutes: 60 }, absence: { what: "attempts, verification findings and blockers as observed operator states are not driven; the context family (cells, leases, handoffs) and the orchestration's claims are", owner: "M12.4 (product_track)" } },
  { n: 14, step: "review the exact proposed repository effect", absence: { what: "no gate drives an exact proposed repository effect under the fixture", owner: KERNEL_CHAIN } },
  { n: 15, step: "satisfy the lane's exact scoped authority ceremony", absence: { what: "no gate drives the exact scoped authority ceremony for a repository effect under the fixture", owner: KERNEL_CHAIN } },
  { n: 16, step: "let the daemon revalidate and execute or refuse the effect", absence: { what: "no gate drives daemon-boundary revalidation and execute-or-refuse of a repository effect under the fixture", owner: KERNEL_CHAIN } },
  { n: 17, step: "inspect the diff, tests, evidence admission, receipt chain, state root, costs, provider route, and learning eligibility", executed_by: { script: "check:collective-artifact-runtime-lifecycle", workspace: APP, extra: [], floor: "collective-artifact-runtime-lifecycle", minutes: 60 }, absence: { what: "diff, tests, costs, provider route and learning eligibility of a repository effect are not inspected because no effect is produced (14–16); the artifact lineage, receipts and re-derived roots are. ArtifactRef production has no producer (R-205, open owner question)", owner: `${KERNEL_CHAIN} · R-205` } },
  { n: 18, step: "replay the decision and effect from exported evidence", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 19, step: "create and verify a manifest-complete backup", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 20, step: "prepare a restore without mutation, then apply or refuse it through a fenced change plan and verify the resulting root/readiness", executed_by: { script: "check:standalone-conformance", workspace: null, extra: ["--", "--legs", "positive,replay"], packaged: true, minutes: 150 } },
  { n: 21, step: "propose an upgrade, exercise rollback or recall, and retire the System", executed_by: { script: "check:zero-to-operable", workspace: null, extra: [], packaged: true, minutes: 150 }, absence: { what: "System retirement (dissolution) is not exercised; release update and rollback through admitted change plans are", owner: "M12.4 (product_track)" } },
  { n: 22, step: "stop and uninstall without implicit data wipe", executed_by: { script: "check:zero-to-operable", workspace: null, extra: [], packaged: true, minutes: 150 } },
];
export const PROFILE_2 = { what: "profile 2, managed optionality (link an account, enable one managed service, execute one managed operation, inspect binding/custody/usage/charge/receipts, revoke) needs an ioi.ai account; the minimum-L0 claim requires profile 1 only (execution-horizons.md: 'The minimum-L0 claim requires the first profile')", owner: "M12.4 (product_track) · a credentialed run" };

// ---- canon's measurement set: recorded by the run, or typed not_measured with an owner ------------------
export const MEASUREMENTS = {
  "time to verified release": { source: "clause 1 (seconds of the standalone check's positive leg to its 1-install step)", from: "clause:1" },
  "time to operable": { source: "clause 4 (the zero-to-operable check's journey to 3-readiness)", from: "clause:4" },
  "diagnostic detection and recovery": { source: "clause 5 (11-diagnostics, 9-recover inside the standalone check)", from: "clause:5" },
  "time to first valid preview": { source: "clause 2 (0-preview inside the zero-to-operable check)", from: "clause:2" },
  "time to genesis": { source: "clause 11 (seconds of the seam gate to its activated System)", from: "clause:11" },
  "typed-blocker resolution rate": { not_measured: "no blockers are raised as operator states (step 13's absence)", owner: "M12.4 (product_track)" },
  "authorized completion rate": { not_measured: "no repository effect is authorized or completed (steps 14–16)", owner: KERNEL_CHAIN },
  "verifier reproducibility": { source: "clause 18 (portable replay: a bundle reproduces its decision on the standalone relying party)", from: "clause:18" },
  "effect-recovery success": { not_measured: "no effect is produced (steps 14–16)", owner: KERNEL_CHAIN },
  "receipt/replay completeness": { source: "clause 18 (every missing or substituted member refused)", from: "clause:18" },
  "provider-swap continuity": { not_measured: "the fixture runs one declared model route; the swap continuity report is M10.4's evaluation plane, not this journey", owner: "M10.4 (closed) · a two-route run" },
  "recovery/revocation behavior": { source: "clause 6 (2c-rotation, 2c-revocation inside the standalone check)", from: "clause:6" },
  "time to a locally valid System": { source: "clause 11 (seconds of the seam gate)", from: "clause:11" },
  "network-blocked completion": { source: "every executed clause (the harness ledger: zero reach beyond loopback)", from: "ledger" },
  "managed-link scope accuracy": { not_measured: "profile 2 is not run", owner: PROFILE_2.owner },
  "disconnect continuity": { not_measured: "profile 2 is not run", owner: PROFILE_2.owner },
  "backup-byte/manifest verification": { source: "clause 19 (10-backup inside the standalone check)", from: "clause:19" },
  "restore-preparation non-mutation": { source: "clause 20 (the two-daemon backup/restore verifier's prepare leg)", from: "clause:20" },
  "active-head preservation under failed/late execution": { not_measured: "no effect fails late (steps 14–16)", owner: KERNEL_CHAIN },
  "uninstall-without-wipe": { source: "clause 22 (14-uninstall: the data dir digested before and after)", from: "clause:22" },
  "export/import portability": { source: "clause 18 (backup export → import across daemons, portable replay)", from: "clause:18" },
  "the amount of architecture vocabulary exposed to a first-time operator": { not_measured: "no first-time-operator cohort has run the journey; a count of vocabulary terms on the surfaces is a release-program measurement", owner: "the release program" },
};

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.undeniable-product-proof-evidence.v1", mode: MODE, started_at: new Date().toISOString(), profile: null, drills: [], clauses: [], measurements: null, verdict: null, mutation: null };
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
  const file = path.join(dir, `undeniable-product-proof-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
const validators = new Map();
function validateAgainst(schemaPath, doc) {
  if (!validators.has(schemaPath)) validators.set(schemaPath, ajv.compile(readJson(schemaPath)));
  const v = validators.get(schemaPath);
  const valid = v(doc);
  return { valid, errors: valid ? [] : (v.errors || []).map((e) => `${e.instancePath || "/"} ${e.message}`) };
}

// ---- the oracles (pure, so the mutation mode can feed them planted inputs) ------------------------------
export function loadProfile(profilePath = PROFILE_PATH) {
  const bytes = fs.readFileSync(profilePath);
  const profile = JSON.parse(bytes.toString("utf8"));
  return { profile, digest: sha256(bytes), schema: validateAgainst(PROFILE_SCHEMA, profile), path: path.relative(ROOT, profilePath) };
}
/** The profile's preconditions for THIS gate, beyond its registered schema. */
export function profileFindings({ profile, schema }) {
  const findings = [];
  if (!schema.valid) findings.push(`profile_schema_invalid: ${schema.errors.join("; ")}`);
  if (profile?.profile_id !== PROFILE_ID) findings.push(`profile_id_mismatch: ${profile?.profile_id}`);
  if (profile?.family !== "runtime_node") findings.push(`family_not_runtime_node: ${profile?.family}`);
  if (profile?.declared_envelope_ref !== ENVELOPE_REF) findings.push(`envelope_not_the_selected_profile: ${profile?.declared_envelope_ref}`);
  if (profile?.fixture?.fixture_id !== FIXTURE_ID) findings.push(`fixture_mismatch: ${profile?.fixture?.fixture_id}`);
  const denied = profile?.fixture?.denied_endpoint_families ?? [];
  if (denied.length !== FAMILIES.length || FAMILIES.some((f) => !denied.includes(f))) findings.push(`denied_families_incomplete: ${JSON.stringify(denied)}`);
  const negatives = profile?.negative_tests ?? [];
  if (negatives.length < 3) findings.push(`negative_tests_incomplete: ${negatives.length} (the fixture's two plus the gate's failure taxonomy)`);
  if (!negatives.some((t) => /fabricated success row/u.test(t.condition || "") && t.expected === "reject")) findings.push("negative_tests_lack_the_failure_taxonomy");
  const refs = (profile?.required_interfaces ?? []).map((r) => r.interface_ref);
  for (const must of ["api://hypervisor-daemon/v1/hypervisor/autonomous-systems", "api://hypervisor-daemon/v1/hypervisor/autonomous-systems/{system_id}/activate", "api://hypervisor-daemon/v1/hypervisor/autonomous-systems/{system_id}/records"]) {
    if (!refs.includes(must)) findings.push(`required_interface_missing: ${must}`);
  }
  // the registered invariant, evaluated here too: a runtime_node profile declares negative tests
  const inv = readJson(PROFILE_INVARIANTS);
  const rule = inv.rules.find((r) => r.expression?.operator === "non_empty_when_in");
  if (rule && rule.expression.values.includes(profile?.family) && !(Array.isArray(negatives) && negatives.length > 0)) findings.push(`invariant:${rule.rule_id}`);
  return findings;
}
/** The binding: every executed gate is a real npm script; every app verifier carries a pinned floor; every absence has an owner; steps cover 1..22 once. */
export function bindingFindings(steps, { rootPkg, appPkg, floors }) {
  const findings = [];
  const seen = new Set();
  for (const s of steps) {
    if (!Number.isInteger(s.n) || s.n < 1 || s.n > 22) findings.push(`step_out_of_range: ${s.n}`);
    if (seen.has(s.n)) findings.push(`step_duplicated: ${s.n}`);
    seen.add(s.n);
    const gates = Array.isArray(s.executed_by) ? s.executed_by : s.executed_by ? [s.executed_by] : [];
    if (gates.length === 0 && !s.absence) findings.push(`step_${s.n}_neither_executed_nor_named`);
    for (const g of gates) {
      const pkg = g.workspace === APP ? appPkg : rootPkg;
      if (!pkg.scripts?.[g.script]) findings.push(`step_${s.n}_binds_missing_script: ${g.script}${g.workspace ? ` (${g.workspace})` : ""}`);
      if (g.floor) {
        const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
        if (!row) findings.push(`step_${s.n}_floor_missing: ${g.floor}`);
        else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) findings.push(`step_${s.n}_floor_mismatch: ${g.floor} pins ${row.npm_script} at ${row.runtime_assertions}`);
      }
    }
    if (s.absence && !(typeof s.absence.owner === "string" && s.absence.owner.trim().length > 0 && typeof s.absence.what === "string" && s.absence.what.length > 20)) findings.push(`step_${s.n}_absence_without_owner`);
  }
  for (let n = 1; n <= 22; n += 1) if (!seen.has(n)) findings.push(`step_missing: ${n}`);
  return findings;
}
/** The verdict over clause rows: PASS only with every clause executed green and no absence; NAMED FAILURE when every executed clause is green and typed absences remain; FAIL otherwise. A fabricated row — pass without evidence — is a FAIL, never a pass. */
export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 22) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
    }
    if (r.absence) {
      if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`);
      else absences.push({ n: r.n, ...r.absence });
    }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 22; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  const kind = failures.length ? "fail" : absences.length ? "named_failure" : "pass";
  return { kind, failures, absences };
}
export function measurementFindings(measurements) {
  const findings = [];
  const CANON_SET = ["time to verified release", "time to operable", "diagnostic detection and recovery", "time to first valid preview", "time to genesis", "typed-blocker resolution rate", "authorized completion rate", "verifier reproducibility", "effect-recovery success", "receipt/replay completeness", "provider-swap continuity", "recovery/revocation behavior", "time to a locally valid System", "network-blocked completion", "managed-link scope accuracy", "disconnect continuity", "backup-byte/manifest verification", "restore-preparation non-mutation", "active-head preservation under failed/late execution", "uninstall-without-wipe", "export/import portability", "the amount of architecture vocabulary exposed to a first-time operator"];
  for (const name of CANON_SET) {
    const m = measurements[name];
    if (!m) { findings.push(`measurement_missing: ${name}`); continue; }
    if (!(m.source || (m.not_measured && m.owner))) findings.push(`measurement_untyped: ${name}`);
  }
  for (const name of Object.keys(measurements)) if (!CANON_SET.includes(name)) findings.push(`measurement_not_canon: ${name}`);
  return findings;
}

// ---- the drills -------------------------------------------------------------------------------------------
function drills() {
  const loaded = loadProfile();
  const findings = profileFindings(loaded);
  evidence.profile = { id: loaded.profile.profile_id, path: loaded.path, digest: `sha256:${loaded.digest}`, interfaces: loaded.profile.required_interfaces?.length, receipts: loaded.profile.required_receipts?.length, negative_tests: loaded.profile.negative_tests?.length, findings };
  ok("the selected minimum-L0 profile is a registered ConformanceProfile instance: valid against schema://ioi/foundations/conformance-profile/v1, family runtime_node, envelope = execution-horizons.md § Selected minimum-L0 proof profile, fixture embedded_single_operator_offline with the nine denied families, the seam and activation interfaces required, and the gate's failure taxonomy among its negative tests — loaded and pinned by digest", findings.length === 0, findings.join("; ") || `${loaded.profile.profile_id} · sha256:${loaded.digest.slice(0, 16)}`);
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(STEPS, { rootPkg, appPkg, floors });
  const executed = STEPS.filter((s) => s.executed_by).map((s) => s.n);
  const named = STEPS.filter((s) => s.absence).map((s) => s.n);
  ok(`the twenty-two steps are bound: every executed clause names a real npm script (${executed.length} steps: ${executed.join(",")}) and every app verifier a pinned floor; every named failure carries its owner (${named.length} steps: ${named.join(",")}); steps cover 1–22 exactly once`, binding.length === 0, binding.join("; ") || "bound");
  const composed = STEPS.flatMap((s) => (Array.isArray(s.executed_by) ? s.executed_by : s.executed_by ? [s.executed_by] : [])).filter((g) => g.floor).map((g) => g.floor);
  const floorTotal = [...new Set(composed)].reduce((n, id) => n + ((floors.verifiers ?? []).find((r) => r.id === id)?.runtime_assertions ?? 0), 0);
  ok(`the composed half stands on pinned floors: ${[...new Set(composed)].join(", ")} = ${floorTotal} assertions against an isolated daemon and the real wallet fixture; the packaged half stands on the standalone-conformance and zero-to-operable runners' own floors`, floorTotal >= 90 && ["standalone-conformance", "zero-to-operable"].every((id) => (floors.verifiers ?? []).some((r) => r.id === id)), `${floorTotal}`);
  // the failure taxonomy as the verdict's own rules, drilled with planted rows
  const green = (n, script) => ({ n, executed: [{ script, status: 0, evidence: "x.json", evidence_sha256: "ab", ledger: { reach: 0 } }] });
  const base = [];
  for (let n = 1; n <= 22; n += 1) base.push(green(n, `check:${n}`));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 14 ? { n: 14, absence: { what: "no gate drives the effect", owner: "M03.15" } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 11 ? { n: 11, executed: [{ script: "check:x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 11 ? { n: 11, executed: [{ script: "check:x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const noOwner = verdict(base.map((r) => (r.n === 14 ? { n: 14, absence: { what: "x", owner: "" } } : r)));
  const dup = verdict([...base, green(11, "check:again")]);
  const reach = verdict(base.map((r) => (r.n === 12 ? { n: 12, executed: [{ script: "check:x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 2 } }] } : r)));
  const missing = verdict(base.filter((r) => r.n !== 22));
  ok("the verdict is a pure function of the clause rows and carries canon's failure conditions as its own rules: all clauses executed green with no absence → PASS; a typed absence with an owner → NAMED FAILURE; a fabricated success row (success without evidence), a red clause, an absence without an owner, a duplicated step, a missing step, or a reach beyond loopback → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && withAbsence.absences.length === 1 && fabricated.kind === "fail" && /fabricated/u.test(fabricated.failures[0]) && red.kind === "fail" && noOwner.kind === "fail" && dup.kind === "fail" && reach.kind === "fail" && /undeclared_egress/u.test(reach.failures[0]) && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${fabricated.kind}/${red.kind}/${noOwner.kind}/${dup.kind}/${reach.kind}/${missing.kind}`);
  const mf = measurementFindings(MEASUREMENTS);
  const measured = Object.values(MEASUREMENTS).filter((m) => m.source).length;
  ok(`canon's twenty-two measurements are each recorded by a named clause or typed not_measured with an owner (${measured} recorded, ${22 - measured} typed not_measured); none is omitted`, mf.length === 0, mf.join("; ") || `${measured}/22 recorded`);
  const canon = fs.readFileSync(CANON, "utf8");
  const gateSection = canon.slice(canon.indexOf("## Undeniable-product proof gate"), canon.indexOf("## The Hypervisor base-platform alpha"));
  ok("canon binds the gate: execution-horizons.md § Undeniable-product proof gate names check:undeniable-product-proof, says the result is a pass or a named typed failure, and types the selected profile as the ioi.ai composition over the substrate (R-192); the stale OutcomeRoom-backed reading is gone from the profile, the fixture paragraph, the ruling and the build sequence", gateSection.includes("`check:undeniable-product-proof`") && /named, typed failure|NAMED, TYPED failure/u.test(gateSection) && canon.includes("composed\nby the ioi.ai orchestration application over the substrate") && (canon.split("OutcomeRoom-backed").length - 1) === (canon.match(/not an OutcomeRoom-backed|"OutcomeRoom-backed"/gu) || []).length, "read from execution-horizons.md (the phrase survives only as the retyping note and the alignment header)");
  return loaded;
}

// ---- mutation: planted defects against the oracles ---------------------------------------------------
function mutation() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-undeniable-mutation-"));
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  try {
    const base = readJson(PROFILE_PATH);
    const write = (name, doc) => { const p = path.join(scratch, name); fs.writeFileSync(p, JSON.stringify(doc, null, 2)); return p; };
    const refixtured = { ...base, fixture: { ...base.fixture, fixture_id: "hosted_single_operator" } };
    let f = profileFindings(loadProfile(write("refixtured.json", refixtured)));
    plant("a profile re-fixtured away from embedded_single_operator_offline", f.some((x) => x.startsWith("fixture_mismatch")), f[0]);
    const noNeg = { ...base, negative_tests: [] };
    f = profileFindings(loadProfile(write("no-negatives.json", noNeg)));
    plant("a profile with its negative tests removed (the registered invariant and the gate's own rule)", f.some((x) => x.startsWith("negative_tests_incomplete")) && f.some((x) => x.startsWith("invariant:")), f.join("; "));
    const otherEnvelope = { ...base, declared_envelope_ref: "canon://docs/architecture/components/hypervisor/bounded-alpha-profile.md#intended-user-and-supported-deployment" };
    f = profileFindings(loadProfile(write("other-envelope.json", otherEnvelope)));
    plant("a profile declaring the bounded-alpha envelope instead of the selected profile", f.some((x) => x.startsWith("envelope_not_the_selected_profile")), f[0]);
    const noTaxonomy = { ...base, negative_tests: base.negative_tests.filter((t) => !/fabricated success row/u.test(t.condition)) };
    f = profileFindings(loadProfile(write("no-taxonomy.json", noTaxonomy)));
    plant("a profile whose negative tests omit the gate's failure taxonomy", f.includes("negative_tests_lack_the_failure_taxonomy"), f.join("; "));
    const rootPkg = readJson(path.join(ROOT, "package.json"));
    const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
    const floors = readJson(FLOORS);
    const ghost = STEPS.map((s) => (s.n === 11 ? { ...s, executed_by: { script: "check:a-script-that-does-not-exist", workspace: APP, extra: [], floor: "system-record-seam", minutes: 1 } } : s));
    f = bindingFindings(ghost, { rootPkg, appPkg, floors });
    plant("a step bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
    const unowned = STEPS.map((s) => (s.n === 14 ? { ...s, absence: { what: s.absence.what, owner: "" } } : s));
    f = bindingFindings(unowned, { rootPkg, appPkg, floors });
    plant("a named failure without an owner", f.some((x) => /absence_without_owner/u.test(x)), f[0]);
    const unpinned = STEPS.map((s) => (s.n === 17 ? { ...s, executed_by: { ...s.executed_by, floor: "a-floor-nobody-pinned" } } : s));
    f = bindingFindings(unpinned, { rootPkg, appPkg, floors });
    plant("an executed clause whose floor row does not exist", f.some((x) => /floor_missing/u.test(x)), f[0]);
    const dropped = STEPS.filter((s) => s.n !== 9);
    f = bindingFindings(dropped, { rootPkg, appPkg, floors });
    plant("a step silently dropped from the twenty-two", f.some((x) => /step_missing: 9/u.test(x)), f[0]);
    const fake = verdict(STEPS.map((s) => ({ n: s.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
    plant("a run whose every clause reports success without evidence (fabricated success rows)", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
    const untyped = { ...MEASUREMENTS, "time to genesis": { not_measured: "skipped" } };
    f = measurementFindings(untyped);
    plant("a measurement typed not_measured without an owner", f.some((x) => /measurement_untyped/u.test(x)), f[0]);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full gate: every executed clause inside the harness, then the verdict --------------------------
async function runClause(gate, workDir, n) {
  const argvNpm = ["npm", "run", "-s", gate.script, ...(gate.workspace ? [`--workspace=${gate.workspace}`] : []), ...gate.extra];
  const censusDir = path.join(workDir, "census", `clause-${n}-${gate.script.replace(/[^A-Za-z0-9]+/gu, "-")}`);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1200000", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const t0 = Date.now();
  let run;
  if (gate.packaged) {
    // The packaged runners carry their OWN harness (the standalone check) or their own package
    // qualification (zero-to-operable); they are not nested inside a second namespace.
    const r = spawnSync(argvNpm[0], argvNpm.slice(1), { cwd: ROOT, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: gate.minutes * 60_000, maxBuffer: 1 << 28 });
    fs.writeFileSync(path.join(workDir, `clause-${n}-${gate.script.replace(/[^A-Za-z0-9]+/gu, "-")}.log`), `${r.stdout || ""}\n${r.stderr || ""}`);
    run = { status: r.status, seconds: Math.round((Date.now() - t0) / 1000), ledger: null, isolation: "own harness" };
  } else {
    const iso = await runIsolated({ label: `clause-${n}-${gate.script.replace(/[^A-Za-z0-9]+/gu, "-")}`, argv: argvNpm, cwd: ROOT, env, workDir, bridges: [], timeoutMs: gate.minutes * 60_000 });
    const classified = classifyLedger(iso.ledger, { declaredHosts: [], declaredNames: [] });
    run = { status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0), undeclared: (classified.undeclared ?? []).slice(0, 5), names: (classified.undeclared_names ?? []).slice(0, 5) } };
  }
  const census = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = census[0] || null;
  return { script: gate.script, workspace: gate.workspace, status: run.status, seconds: run.seconds, isolation: run.isolation, ledger: run.ledger, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256(fs.readFileSync(evidenceFile)) : null, executed_assertions: evidenceFile ? readJson(evidenceFile).executed_assertions ?? null : null };
}

async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-undeniable-"));
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  const done = new Map(); // script+extra → run (a gate proving several steps runs once)
  const rows = [];
  for (const s of STEPS) {
    const gates = Array.isArray(s.executed_by) ? s.executed_by : s.executed_by ? [s.executed_by] : [];
    const row = { n: s.n, step: s.step, executed: [], absence: s.absence || null };
    for (const g of gates) {
      const key = `${g.script} ${g.extra.join(" ")}`;
      if (g.packaged && !WITH_PACKAGED) { row.not_executed = `${g.script} (packaged; pass --with-packaged)`; continue; }
      if (ONLY && !ONLY.has(s.n)) { row.not_executed = `${g.script} (--only)`; continue; }
      if (!done.has(key)) {
        console.log(`\n# clause ${s.n}: ${g.script}${g.workspace ? ` (${g.workspace})` : ""} ${g.extra.join(" ")} — inside the harness`);
        done.set(key, await runClause(g, workDir, s.n));
        const r = done.get(key);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"} assertions · ledger ${r.ledger ? `${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach` : "own harness"}`);
      }
      row.executed.push(done.get(key));
    }
    rows.push(row);
  }
  rows.push({ n: 0, profile_2: PROFILE_2 });
  const v = verdict(rows.filter((r) => r.n >= 1));
  if (!rows.some((r) => r.n >= 1 && r.absence)) v.absences.push({ n: 0, ...PROFILE_2 }); else v.absences.push({ n: 0, ...PROFILE_2 });
  if (v.kind === "pass") v.kind = "named_failure"; // profile 2 is always a named absence of this runner
  // measurements: seconds per clause where the source is a clause; the rest typed
  const m = {};
  for (const [name, spec] of Object.entries(MEASUREMENTS)) {
    if (spec.from && spec.from.startsWith("clause:")) {
      const n = Number(spec.from.slice(7));
      const row = rows.find((r) => r.n === n);
      const run = row?.executed?.[0];
      m[name] = run ? { value_seconds: run.seconds, from: `${spec.from} ${run.script}`, note: spec.source } : { not_measured: `clause ${n} not executed in this run`, owner: "this runner (on demand)" };
    } else if (spec.from === "ledger") {
      // A gate proving several steps ran ONCE (clauses 10 and 11 share the seam run): sum each run once.
      const seen = new Set();
      const ledgers = rows.flatMap((r) => (r.executed ?? []).filter((g) => g.ledger && !seen.has(g.evidence_sha256 || g.script) && seen.add(g.evidence_sha256 || g.script)).map((g) => g.ledger));
      m[name] = ledgers.length ? { value: { runs: ledgers.length, attempts: ledgers.reduce((a, l) => a + l.attempts, 0), reach: ledgers.reduce((a, l) => a + l.reach, 0) }, note: spec.source } : { not_measured: "no clause ran inside the harness", owner: "this runner (on demand)" };
    } else m[name] = { not_measured: spec.not_measured, owner: spec.owner };
  }
  evidence.clauses = rows;
  evidence.measurements = m;
  evidence.verdict = v;
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  ${a.n ? `step ${a.n}` : "profile 2"}: ${a.what.slice(0, 160)} → owner ${a.owner}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") {
    exit = mutation() ? 0 : 1;
  } else {
    drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "undeniable-product-proof", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") {
      const v = await full();
      exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1;
    }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => {
  console.error("verifier crashed:", error);
  writeEvidence();
  process.exit(1);
});
