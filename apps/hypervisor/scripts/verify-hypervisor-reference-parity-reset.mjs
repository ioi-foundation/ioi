#!/usr/bin/env node
// Reference UX Port — Parity Reset Infrastructure done-bar (PR #31).
//
// The presentation-layer rebase. This verifier proves the reset is honest: the matrix taxonomy has
// the five reference-port states, the 10 dark IOI surfaces built #3–#30 are reclassified as
// `substrate_bound` (NOT parity), NOTHING yet claims true parity (`daemon_wired`), and the Playwright
// visual/structural harness confirms — by looking at the rendered DOM — that those substrate surfaces
// do NOT reproduce the reference shell. The daemon planes + truth verifiers are untouched (that is
// the regression sweep, run separately).
//
// Asserts:
//   - TAXONOMY: matrix schema v2, phase "Reference UX Port", explicit parity_rule, the 5 legend
//     states, and the estate backstop (39 seeds + 45-app crosswalk).
//   - RECLASSIFICATION: the 10 former daemon_bound surfaces are now `substrate_bound` with a
//     `substrate_surface` + `reference_workspace`; the retired `daemon_bound` class appears nowhere.
//   - NO FALSE PARITY: 0 seeds are `daemon_wired` (nothing ported yet); reference_capture is the
//     majority; coverage is all 39 seeds.
//   - HARNESS PROVES SUBSTRATE, NOT PARITY: running the Playwright harness on representative surfaces,
//     the reference workspace HAS the shell regions (rail/header/body) and the IOI candidate does NOT
//     reproduce them → structural parity FALSE → correctly `substrate_bound`.
//   - ARTIFACT: the harness emits result.json + a contact-sheet.html.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-reference-parity-reset.mjs
// Exit 2 = BLOCKED (serve/mirror not reachable).

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const up = await fetch(`${SERVE}/__apps/pipeline`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: serve + reference mirror not reachable at " + SERVE); process.exit(2); }

  // 0. Matrix is current + the taxonomy is the reset taxonomy.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  ok("matrix schema is v2 + phase 'Reference UX Port'", matrix.schema_version === "ioi.hypervisor.app-parity-matrix.v2" && matrix.phase === "Reference UX Port");
  ok("matrix states an explicit parity RULE (only daemon_wired = true parity)", /only `daemon_wired`/i.test(matrix.parity_rule || "") && /substrate_bound/.test(matrix.parity_rule || "") && /NOT parity/i.test(matrix.parity_rule || ""));
  ok("legend defines all 5 reference-port states", ["reference_capture", "substrate_bound", "reference_port_pending", "reference_ported", "daemon_wired"].every((k) => matrix.legend && matrix.legend[k]));
  ok("estate backstop: 39 executable seeds + the 45-app crosswalk", matrix.total_seeds === 39 && (matrix.seeds || []).length === 39 && /local-composition-application-crosswalk/.test(matrix.estate_backstop?.crosswalk || ""));

  // 1. Reclassification — the 10 dark surfaces are substrate_bound, not the retired daemon_bound.
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const FORMER = ["pipeline", "lineage", "vertex", "jobs", "incidents", "evalsuites", "designer", "approvals", "models", "machinery"];
  ok("the 10 former daemon_bound surfaces are now substrate_bound (with substrate_surface + reference_workspace)", FORMER.every((k) => bySlug[k]?.parity_class === "substrate_bound" && bySlug[k]?.substrate_surface && bySlug[k]?.reference_workspace), FORMER.filter((k) => bySlug[k]?.parity_class !== "substrate_bound").join(",") || "all substrate_bound");
  ok("the retired `daemon_bound` class appears on NO seed", !(matrix.seeds || []).some((s) => s.parity_class === "daemon_bound"));
  ok("by_parity_class = substrate_bound 10 / reference_capture 29 (no over-claim)", matrix.by_parity_class?.substrate_bound === 10 && matrix.by_parity_class?.reference_capture === 29);

  // 2. No false parity — nothing is daemon_wired yet; the reset claims nothing ported.
  ok("NO seed claims true parity yet: 0 daemon_wired, 0 reference_ported", !(matrix.by_parity_class?.daemon_wired) && !(matrix.by_parity_class?.reference_ported));
  ok("no 'covered' anywhere; reference_capture is the majority class", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && matrix.by_parity_class.reference_capture > matrix.by_parity_class.substrate_bound);

  // 3. The Playwright harness proves — by rendered DOM — that the substrate surfaces are NOT parity.
  const artDir = path.join(appRoot, ".artifacts", "reference-parity-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], {
    encoding: "utf8", timeout: 120000,
    env: { ...process.env, IOI_HARNESS_SURFACES: "pipeline,lineage", IOI_HARNESS_ARTIFACT_DIR: artDir },
  });
  const harnessRan = h.status === 0 && existsSync(path.join(artDir, "result.json"));
  ok("Playwright harness runs headless + emits result.json + contact-sheet.html", harnessRan && existsSync(path.join(artDir, "contact-sheet.html")), (h.stderr || "").trim().slice(0, 100));
  if (harnessRan) {
    const res = JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8"));
    const bySurface = Object.fromEntries((res.surfaces || []).map((s) => [s.slug, s]));
    const pipe = bySurface.pipeline, lin = bySurface.lineage;
    ok("the REFERENCE workspaces render the shell regions (rail + header + body present)", pipe && lin && ["rail", "header", "body"].every((r) => pipe.reference_regions.includes(r)) && ["rail", "header", "body"].every((r) => lin.reference_regions.includes(r)), `pipe ref[${pipe?.reference_regions}] · lin ref[${lin?.reference_regions}]`);
    ok("the IOI substrate surfaces do NOT reproduce the reference shell (structural parity FALSE)", pipe && lin && pipe.structural_parity === false && lin.structural_parity === false, `pipe score ${pipe?.parity_score} · lin score ${lin?.parity_score}`);
    ok("the structural gap is real: each IOI surface renders fewer reference regions than its reference", pipe && lin && pipe.ioi_regions.length < pipe.reference_regions.length && lin.ioi_regions.length < lin.reference_regions.length);
    ok("harness verdict agrees with the matrix: these surfaces are substrate_bound, not daemon_wired", pipe?.matrix_class === "substrate_bound" && lin?.matrix_class === "substrate_bound" && !res.surfaces.some((s) => s.structural_parity && s.matrix_class !== "daemon_wired"));
  }

  // 4. The daemon truth verifiers are preserved (spot-check one still passes end-to-end).
  const spot = spawnSync("node", [path.join(here, "verify-hypervisor-app-parity-approvals.mjs")], { encoding: "utf8", timeout: 60000 });
  ok("existing daemon-truth verifiers preserved (spot-check: approvals still passes under substrate_bound)", spot.status === 0, (spot.stdout || "").trim().split("\n").pop());
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`reference-parity-reset readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
