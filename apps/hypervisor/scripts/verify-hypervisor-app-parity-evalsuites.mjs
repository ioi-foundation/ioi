#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Evaluations · Evalsuites done-bar (#54, evalsuites seed only).
//
// The THIRTEENTH faithful port, the SIXTH from the origin-alignment queue, and the FIRST
// Evaluations-family certified surface. The #44 sweep proved the AIP Evals landing data-bearing on
// the capture-origin lane (localhost:9225/workspace/evals/) while the /__apps/evalsuites proxy
// lane renders no data; #54 stamps reference_url_override onto the honest lane (the What's-new
// modal dismissed by a reference-only pre-capture hook) and builds /__ioi/evaluations/evalsuites
// as a DECLARATION LIBRARY over the SAME inert eval-suite plane.
//
// THE ASSESSMENT BOUNDARY IS THE POINT: suite declarations only, never scoring or execution.
//   1. MATRIX/CERT/SWEEP: daemon_wired + origin-aligned + REAL non-pinned certification; census >= 13.
//   2. PLANE CROSS-CHECKS (fixture through the existing daemon route, cleaned up): rendered suite
//      count equals the plane; a real suite's ref/name/subject-scope renders; rubric/evidence/
//      consent/candidate refs render VERBATIM below the fold; health renders as
//      declared-completeness, never a score.
//   3. BOUNDARY GATES stay honest (the plane's own contract, re-proven): never_train-only consent
//      fails closed; external candidate URLs fail closed (local allowlisted schemes only); there is
//      NO run/execute endpoint; the record mints no score/verdict/result field.
//   4. NO EXECUTION SEMANTICS on the surface: read-only (no forms, no run/score/judge affordance).
//   5. NO body pixel claim: the certification is SHELL-scoped; suite rows are masked live data.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-evalsuites.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/eval-suites/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon eval-suite plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.evalsuites;
  ok("matrix: evalsuites is daemon_wired at /__ioi/evaluations/evalsuites (Evaluations) with AIP-Evals-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/evaluations/evalsuites" && row.substrate_surface === "/__ioi/evaluations" && row.surface_name === "Evaluations" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/evals/)", row && row.reference_url_override === "http://localhost:9225/workspace/evals/");
  ok("matrix keeps analysis + quiver reference_capture (Evaluations siblings NOT over-claimed)", bySlug.analysis?.parity_class === "reference_capture" && bySlug.quiver?.parity_class === "reference_capture");
  ok("the estate census accepts evalsuites among the certified daemon_wired surfaces (>= 13 since #54); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 13 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null;
  try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
  ok("matrix: evalsuites is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/evalsuites.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: evalsuites slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "evalsuites" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/evals/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (suite rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "evalsuites");
  ok("clean sweep: evalsuites classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane no-data blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy" && l.data_score === 0), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:score${l.data_score}`)) : "");

  // 1. Reference lanes (SPA — identity markers in raw HTML; data-bearing proven by sweep + cert gates).
  const origin = await page("http://localhost:9225/workspace/evals/");
  ok("origin-aligned reference serves the AIP Evals workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /AIP Evals|workspace\/evals|evals/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/evalsuites`);
  ok("the /__apps/evalsuites proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200);

  // 2. Fixture through the EXISTING daemon route (the same inert contract the substrate uses).
  const good = await jd("POST", "/v1/hypervisor/eval-suites", { name: "evalsuites-port-parity", subject_scope: ["failed_run", "goal_run_blocker"], evidence_requirements: ["proof_ref", "timeline_ref"], consent_requirements: ["synthetic_only", "org_policy"], rubric_refs: ["rubric://port-parity"], candidate_refs: ["eval://port-c1", "feedback://port-f1"] });
  const suite = good.j.eval_suite;
  if (suite?.id) cleanup.push(suite.id);
  ok("fixture: a suite declares through the existing daemon route (201, eval-suite:// ref, draft, declared health)", good.status === 201 && suite?.ref?.startsWith("eval-suite://") && suite?.status === "draft" && suite?.health === "declared", suite?.ref);
  ok("the suite record is INERT — no score/verdict/result/scorecard field is minted", suite && !("score" in suite) && !("verdict" in suite) && !("result" in suite) && !("scorecard" in suite));

  // 3. BOUNDARY GATES (the plane's own contract, re-proven at port time).
  const badNever = await jd("POST", "/v1/hypervisor/eval-suites", { name: "x", subject_scope: ["failed_run"], consent_requirements: ["never_train"] });
  ok("consent GATE: a never_train-only requirement fails closed", badNever.status === 400 && /consent/.test(badNever.j.error?.code || ""));
  const badCand = await jd("POST", "/v1/hypervisor/eval-suites", { name: "x", subject_scope: ["failed_run"], consent_requirements: ["org_policy"], candidate_refs: ["https://external.example/x"] });
  ok("candidate GATE: an external URL fails closed (local allowlisted schemes only — no external fetch semantics)", badCand.status === 400 && /candidate_ref/.test(badCand.j.error?.code || ""));
  const runAttempt = await jd("POST", `/v1/hypervisor/eval-suites/${suite?.id}/run`, {});
  ok("there is NO run/execute endpoint on the plane (assessment does not execute)", runAttempt.status >= 400, `run ${runAttempt.status}`);

  // 4. The PORT = the faithful splash shell over the real plane.
  const suites = (await jd("GET", "/v1/hypervisor/eval-suites")).j.eval_suites || [];
  const ep = await page(`${SERVE}/__ioi/evaluations/evalsuites`);
  const t = ep.text;
  ok("the port renders the faithful AIP Evals landing shell (header + hero + View row + table + examples + truth)", ep.status === 200 && /class="evl-htitle">AIP Evals</.test(t) && /Create evaluation suites for LLM-backed use-cases/.test(t) && /class="evl-viewrow"/.test(t) && /class="evl-thead"/.test(t) && /Explore reference examples/.test(t) && /id="evalsuites-truth"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");
  ok("the suite-library count equals the daemon plane", new RegExp(`Suite library truth <span class="evl-count">${suites.length}</span>`).test(t), `plane=${suites.length}`);
  ok("the fixture suite renders as a live row (name + ref + subject scopes + declared health in the row path)", t.includes("evalsuites-port-parity") && t.includes(suite.ref) && /subjects failed_run\/goal_run_blocker · declared · draft/.test(t));
  ok("rendered rows equal the plane after the declared cap (newest 12)", (t.match(/class="evl-row"/g) || []).length === Math.min(12, suites.length), `${(t.match(/class="evl-row"/g) || []).length} rows vs ${Math.min(12, suites.length)}`);
  ok("rubric/evidence/consent/candidate refs render VERBATIM below the fold (real declaration records)", t.includes("rubric://port-parity") && t.includes("proof_ref, timeline_ref") && t.includes("synthetic_only, org_policy") && t.includes("eval://port-c1, feedback://port-f1"));
  ok("health renders as DECLARED-COMPLETENESS, never a score (the boundary band says so; no score/verdict text anywhere)", /DECLARED-COMPLETENESS \(declared\/complete\), <b>never a score<\/b>/.test(t) && !/scorecard value|verdict:/.test(t));
  ok("the em-dash gap columns name their gaps (no principal/view tracking on the eval-suite plane)", /No principal is recorded on the eval-suite plane \(named gap\)/.test(t) && /View tracking is not recorded on the eval-suite plane \(named gap\)/.test(t));

  // 5. NO EXECUTION SEMANTICS on the surface.
  ok("the surface is READ-ONLY (no forms; no run/score/judge affordance)", !/<form/.test(t) && !/action="[^"]*\/(run|score|judge|execute|promote)"/.test(t));
  ok("the boundary is declared in place: EvalRun execution / scoring / verdicts / judge runs / scorecards / auto-mining / promotion = named gaps", /EvalRun execution, scoring, verdicts, judge runs, scorecards, auto-mining and promotion are <b>named gaps<\/b>/.test(t));
  ok("candidate refs declared LOCAL allowlisted schemes on the surface (the plane rejects external URLs fail-closed)", /Candidate refs are LOCAL allowlisted schemes only/.test(t));
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (New suite · Help · Favorites · example installs)", (t.match(/aria-disabled="true"/g) || []).length >= 5 && /Suite authoring from this surface is a reference-only lane/.test(t) && /Favorites are not recorded on the eval-suite plane/.test(t) && /Marketplace example installs are a reference-only lane/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("the examples band is verbatim capture chrome (declared)", /verbatim capture chrome/.test(t));

  // 6. Owner discoverability + brand.
  const owner = await page(`${SERVE}/__ioi/evaluations`);
  ok("owner discoverability: /__ioi/evaluations links the landing first-class, and the port links the owner + feedback sublane back", owner.status === 200 && owner.text.includes("/__ioi/evaluations/evalsuites") && t.includes('href="/__ioi/evaluations"') && t.includes('href="/__ioi/feedback"'));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/evals/") && t.includes("/__apps/evalsuites") && /renders no data/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

  for (const id of cleanup) await jd("DELETE", `/v1/hypervisor/eval-suites/${id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-evalsuites readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
