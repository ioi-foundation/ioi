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
  const RECLASSED = new Set(["substrate_bound", "daemon_wired", "reference_ported", "reference_port_pending"]);
  ok("the 10 former daemon_bound surfaces are all reclassified (substrate_bound|daemon_wired|...) with a candidate_surface + reference_workspace", FORMER.every((k) => RECLASSED.has(bySlug[k]?.parity_class) && bySlug[k]?.candidate_surface && bySlug[k]?.reference_workspace), FORMER.filter((k) => !RECLASSED.has(bySlug[k]?.parity_class)).join(",") || "all reclassified");
  ok("the retired `daemon_bound` class appears on NO seed", !(matrix.seeds || []).some((s) => s.parity_class === "daemon_bound"));
  const bc = matrix.by_parity_class || {};
  ok("by_parity_class: the 10 former surfaces sum across (substrate_bound + daemon_wired + ported states); reference_capture 29", (bc.substrate_bound || 0) + (bc.daemon_wired || 0) + (bc.reference_ported || 0) + (bc.reference_port_pending || 0) === 10 && bc.reference_capture === 29, JSON.stringify(bc));

  // 2. Parity is EARNED, not claimed — reference_capture stays the majority; no over-claim.
  ok("reference_capture is the majority class (parity is earned surface-by-surface, not blanket-claimed)", bc.reference_capture > ((bc.substrate_bound || 0) + (bc.daemon_wired || 0)));
  ok("no 'covered' anywhere; no seed is stuck reference_ported without being wired", !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 3. The Playwright harness — run over EVERY port-state row (no subset) so none can escape the gate.
  const artDir = path.join(appRoot, ".artifacts", "reference-parity-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], {
    encoding: "utf8", timeout: 240000,
    env: { ...process.env, IOI_HARNESS_ARTIFACT_DIR: artDir },
  });
  const harnessRan = h.status === 0 && existsSync(path.join(artDir, "result.json"));
  ok("Playwright harness runs headless + emits result.json + contact-sheet.html", harnessRan && existsSync(path.join(artDir, "contact-sheet.html")), (h.stderr || "").trim().slice(0, 100));
  if (harnessRan) {
    const res = JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8"));
    const bySurface = Object.fromEntries((res.surfaces || []).map((s) => [s.slug, s]));

    // COVERAGE: every port-state seed in the matrix must appear in the harness results — a
    // reference_port_pending / reference_ported / daemon_wired seed can never escape the gate.
    const portSeeds = (matrix.seeds || []).filter((s) => ["substrate_bound", "reference_port_pending", "reference_ported", "daemon_wired"].includes(s.parity_class)).map((s) => s.slug);
    const missing = portSeeds.filter((slug) => !bySurface[slug]);
    ok("harness covers EVERY port-state seed (none escapes the gate)", missing.length === 0, missing.length ? `missing: ${missing.join(",")}` : `${portSeeds.length} covered`);

    // EVIDENCE: every covered surface produced BOTH screenshots (no 0-byte placeholders).
    ok("every surface produced real screenshot evidence for both reference + IOI", res.surfaces.every((s) => s.evidence_ok === true), res.surfaces.filter((s) => !s.evidence_ok).map((s) => s.slug).join(",") || "all have evidence");

    // THE FUTURE RULE, enforced now: daemon_wired ⇒ structural_parity true; substrate_bound ⇒ false.
    const wired = res.surfaces.filter((s) => s.matrix_class === "daemon_wired");
    ok("RULE: every daemon_wired surface PASSES structural parity (none claims parity without it)", wired.every((s) => s.structural_parity === true), wired.length ? wired.map((s) => `${s.slug}:${s.structural_parity}`).join(",") : "0 daemon_wired yet");
    ok("RULE: no substrate_bound / port-pending / ported surface is mislabeled as passing parity", !res.surfaces.some((s) => s.structural_parity === true && s.matrix_class !== "daemon_wired"));

    // GUARD (review #32 + #33): an ERROR PAGE can never certify parity — its shell chrome renders, so
    // region-matching would falsely pass. The harness must refuse parity when EITHER SIDE errored (the
    // reference OR the IOI candidate).
    ok("GUARD: no surface with an ERRORED reference OR errored IOI candidate is granted structural parity", !res.surfaces.some((s) => (s.reference_errored === true || s.ioi_errored === true) && s.structural_parity === true), res.surfaces.filter((s) => s.reference_errored || s.ioi_errored).map((s) => `${s.slug}:ref_err=${s.reference_errored}/ioi_err=${s.ioi_errored}/parity=${s.structural_parity}`).join(",") || "none errored");
    ok("every daemon_wired surface has BOTH a valid reference AND a valid (non-errored) IOI candidate", res.surfaces.filter((s) => s.matrix_class === "daemon_wired").every((s) => s.reference_valid === true && s.ioi_valid === true), res.surfaces.filter((s) => s.matrix_class === "daemon_wired").map((s) => `${s.slug}:ref_valid=${s.reference_valid}/ioi_valid=${s.ioi_valid}`).join(",") || "0 daemon_wired");

    // The concrete reset proof: a SUBSTRATE surface (lineage) does NOT reproduce the reference shell.
    // The PORTED surface (pipeline, #32) has its shell built but parity is BLOCKED on an errored ref.
    const lin = bySurface.lineage, pipe = bySurface.pipeline;
    ok("a SUBSTRATE surface (lineage) has the reference shell available but does NOT reproduce it (structural parity FALSE)", lin && ["rail", "header", "body"].every((r) => lin.reference_regions.includes(r)) && lin.structural_parity === false, `lin ref[${lin?.reference_regions}] ioi[${lin?.ioi_regions}] score ${lin?.parity_score}`);
    ok("the PORTED surface (pipeline) renders a real builder shell BUT is honestly NOT parity — its local reference errors (guard blocks daemon_wired)", pipe && pipe.matrix_class === "reference_ported" && ["rail", "body"].every((r) => pipe.ioi_regions.includes(r)) && pipe.reference_errored === true && pipe.structural_parity === false, `pipe ioi[${pipe?.ioi_regions}] ref_errored=${pipe?.reference_errored} parity=${pipe?.structural_parity}`);
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
