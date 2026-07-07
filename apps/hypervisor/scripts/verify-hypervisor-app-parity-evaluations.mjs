#!/usr/bin/env node
// Application UX Parity Baseline — Evaluations owner-family done-bar (evalsuites seed only).
//
// The parity phase's sixth surface, and the start of the assessment-over-execution story. The
// reference capture (/__apps/evalsuites = the eval-suite library) is the familiar baseline; the
// IOI-owned /__ioi/evaluations renders the SAME table/list grammar over REAL daemon truth — the
// INERT eval-suite contract (a suite DECLARES subject_scope + evidence/consent requirements + named
// candidate handoffs; it never scores or executes), the real assessment SUBJECTS from the Missions
// plane, the consent ladder, and the feedback candidate source.
//
// SCOPE (tight, by direction): only `evalsuites` binds. `analysis` + `quiver` stay reference_capture.
// Nothing claims EvalRun execution, scoring/verdicts, judges, scorecards, or the analysis/Quiver
// canvases — those are named gaps.
//
// Naming resolution: Evaluations is the owner surface (/__ioi/evaluations); /__ioi/feedback stays a
// compatibility sublane. The suite card no longer points Evaluations at /__ioi/feedback.
//
// Asserts:
//   - MATRIX: evalsuites = daemon_bound → /__ioi/evaluations (Evaluations); analysis + quiver stay
//     reference_capture; nothing over-claimed.
//   - REFERENCE BASELINE: /__apps/evalsuites boots the eval-suite library grammar.
//   - INERT DAEMON CONTRACT: create declares a suite (health=declared, status=draft, NO score field);
//     consent is a GATE (never_train-only + empty both fail closed); unknown subject kind fails
//     closed; there is NO run/execute endpoint.
//   - IOI SURFACE = SAME GRAMMAR OVER REAL TRUTH: the created suite renders (name, ref, subject_scope,
//     consent, evidence, health); a real Missions subject appears in the subjects lane; honest empty
//     when no suites; the consent ladder is shown.
//   - NO FALSE COVERAGE: named gaps present (EvalRun execution · scoring/verdicts · judge · scorecards
//     · auto-mining · analysis · quiver · promotion); brand-clean.
//   - DISCOVERABILITY / DRIFT: suite card opens /__ioi/evaluations (not /__ioi/feedback); the feedback
//     sublane still serves; Evaluations links to it + the proof stream.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-evaluations.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, bodyObj) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: bodyObj ? JSON.stringify(bodyObj) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/eval-suites/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon eval-suite plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix binds evalsuites as daemon_bound → /__ioi/evaluations (Evaluations)", bySlug.evalsuites?.parity_class === "daemon_bound" && bySlug.evalsuites?.daemon_surface === "/__ioi/evaluations" && bySlug.evalsuites?.surface_name === "Evaluations");
  ok("matrix keeps analysis + quiver reference_capture (NOT over-claimed in this cut)", bySlug.analysis?.parity_class === "reference_capture" && bySlug.quiver?.parity_class === "reference_capture");
  ok("no 'covered' anywhere; prior daemon_bound surfaces intact (pipeline/lineage/vertex/jobs/incidents)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex", "jobs", "incidents"].every((k) => bySlug[k]?.parity_class === "daemon_bound"));

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/evalsuites`);
  ok("reference baseline /__apps/evalsuites boots the eval-suite library grammar", ref.status === 200 && /<title>[^<]*(Eval|Suite)/i.test(ref.text));

  // 2. INERT DAEMON CONTRACT — declaration + fail-closed gates + no execution.
  const good = await jd("POST", "/v1/hypervisor/eval-suites", { name: "parity-suite", subject_scope: ["failed_run", "goal_run_blocker"], evidence_requirements: ["proof_ref", "timeline_ref"], consent_requirements: ["synthetic_only", "org_policy"], rubric_refs: ["rubric://parity"], candidate_refs: ["eval://c1", "feedback://f1"] });
  const suite = good.j.eval_suite;
  if (suite?.id) cleanup.push(["DELETE", `/v1/hypervisor/eval-suites/${suite.id}`]);
  ok("create declares a suite (201, ref, status=draft, health=declared)", good.status === 201 && suite?.ref?.startsWith("eval-suite://") && suite?.status === "draft" && suite?.health === "declared");
  ok("the suite is INERT — no score / verdict / result field is minted", suite && !("score" in suite) && !("verdict" in suite) && !("result" in suite) && !("scorecard" in suite));
  const badNeverOnly = await jd("POST", "/v1/hypervisor/eval-suites", { name: "x", subject_scope: ["failed_run"], consent_requirements: ["never_train"] });
  ok("consent GATE: a never_train-only requirement fails closed (nothing could ever be assessed)", badNeverOnly.status === 400 && /consent/.test(badNeverOnly.j.error?.code || ""));
  const badNoConsent = await jd("POST", "/v1/hypervisor/eval-suites", { name: "x", subject_scope: ["failed_run"], consent_requirements: [] });
  ok("consent GATE: an absent consent requirement fails closed", badNoConsent.status === 400 && /consent/.test(badNoConsent.j.error?.code || ""));
  const badSubject = await jd("POST", "/v1/hypervisor/eval-suites", { name: "x", subject_scope: ["not_a_subject"], consent_requirements: ["org_policy"] });
  ok("subject scope is validated (unknown kind fails closed)", badSubject.status === 400 && /subject_scope/.test(badSubject.j.error?.code || ""));
  const runAttempt = await jd("POST", `/v1/hypervisor/eval-suites/${suite?.id}/run`, {});
  ok("there is NO run/execute endpoint (assessment does not execute here)", runAttempt.status >= 400);

  // 3. IOI surface = the library grammar over real truth.
  const ev = await page(`${SERVE}/__ioi/evaluations`);
  const t = ev.text;
  ok("IOI /__ioi/evaluations renders the eval-suite library grammar (title + library heading)", ev.status === 200 && /<h1[^>]*>Evaluations/.test(t) && /id="eval-suite-library"/.test(t));
  ok("the created suite renders with its real ref, subject scope, consent + evidence requirements, health", suite && t.includes(suite.ref) && t.includes("parity-suite") && t.includes("failed_run") && t.includes("synthetic_only") && t.includes("proof_ref") && />declared</.test(t));
  // Real assessment subjects from the Missions plane appear in scope.
  const ops = await jd("GET", "/v1/hypervisor/operations");
  const gr = (await jd("GET", "/v1/hypervisor/goal-runs")).j.goal_runs || [];
  const blocked = gr.filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const sampleSubject = blocked[0];
  ok("assessment SUBJECTS lane shows real Missions execution truth (a real blocker's proof link)", /id="eval-subjects"/.test(t) && (!sampleSubject || t.includes(`/__ioi/run-timeline/goal-run/${sampleSubject.goal_run_id}`)), sampleSubject ? sampleSubject.goal_run_id : "no blockers (honest ok)");
  ok("the consent ladder is shown as the admission gate", /Consent ladder/.test(t) && t.includes("never_train") && t.includes("org_policy"));

  // 4. No false coverage — named gaps + brand-clean.
  ok("named gaps: EvalRun execution · scoring/verdicts · judge · scorecards · auto-mining · analysis · quiver · promotion", /EvalRun execution/.test(t) && /scoring \/ verdicts/.test(t) && /judge \/ model evaluation/.test(t) && /scorecards/.test(t) && /auto-mining/.test(t) && /promotion decisions/.test(t) && t.includes("/__apps/analysis") && t.includes("/__apps/quiver"));
  ok("surface states nothing scores/executes here", /nothing scores or executes here/i.test(t) || /never scores/.test(t));
  ok("reference capture linked as secondary baseline; IOI surface brand-clean (no Palantir/Foundry brand)", t.includes("/__apps/evalsuites") && !/\bPalantir\b/.test(t));

  // 5. Discoverability / drift resolution.
  const apps = await page(`${SERVE}/__ioi/applications`);
  ok("the suite Evaluations card opens /__ioi/evaluations (drift from /__ioi/feedback resolved)", apps.status === 200 && new RegExp(`href="/__ioi/evaluations"[\\s\\S]{0,400}?Evaluations`).test(apps.text));
  const fb = await page(`${SERVE}/__ioi/feedback`);
  ok("/__ioi/feedback still serves as a compatibility sublane (not broken by the move)", fb.status === 200 && /Feedback/.test(fb.text));
  ok("Evaluations links its feedback sublane + the proof stream first-class", t.includes("/__ioi/feedback") && t.includes("/__ioi/work-ledger"));

  // 6. Honest empty — with no suites, the library says so (delete the fixture, re-render).
  for (const [method, p] of cleanup) await jd(method, p);
  cleanup.length = 0;
  const remaining = (await jd("GET", "/v1/hypervisor/eval-suites")).j.eval_suites || [];
  const evEmpty = await page(`${SERVE}/__ioi/evaluations`);
  ok("honest empty: with no suites declared the library says 'No eval suites declared yet' (no fabrication)", remaining.length > 0 ? true : /No eval suites declared yet/.test(evEmpty.text), remaining.length ? `${remaining.length} pre-existing suite(s)` : "empty");
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-evaluations readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
