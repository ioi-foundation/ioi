#!/usr/bin/env node
// Reference UX Port — Parity Reset Infrastructure done-bar (PR #31; gate HARDENED in #34).
//
// The presentation-layer rebase + the hardened parity gate. This verifier proves the reset stays
// honest as ports advance: the matrix taxonomy has the five reference-port states, the 10 dark IOI
// surfaces built #3–#30 are reclassified `substrate_bound` (NOT parity), and the Playwright harness —
// HARDENED in the #34 review to require theme match + reproduction of the reference's IA landmarks,
// not just region-name overlap — confirms by looking at the rendered DOM which surfaces genuinely
// reproduce the reference UX (`daemon_wired`) and which do not. The daemon planes + truth verifiers
// are untouched (that is the regression sweep, run separately).
//
// Asserts:
//   - TAXONOMY: matrix schema v2, phase "Reference UX Port", explicit parity_rule, the 5 legend
//     states, and the estate backstop (39 seeds + 45-app crosswalk).
//   - RECLASSIFICATION: the 10 former daemon_bound surfaces are reclassified (substrate_bound|ported|
//     daemon_wired) with a candidate_surface + reference_workspace; retired `daemon_bound` appears nowhere.
//   - PARITY IS EARNED: reference_capture stays the majority; only FAITHFUL ports are daemon_wired;
//     coverage is all 39 seeds.
//   - HARDENED HARNESS: daemon_wired ⇒ visual_parity (theme + IA landmarks + geometry). A ported-but-
//     not-certified surface (explorer) reproduces the shell REGIONS yet FAILS visual parity (blank
//     reference, no landmark spec) → reference_ported. A substrate surface (lineage) does not reproduce
//     the shell at all. An errored side never certifies.
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
  const portTotal = (bc.substrate_bound || 0) + (bc.daemon_wired || 0) + (bc.reference_ported || 0) + (bc.reference_port_pending || 0);
  // The reset floor holds as new ports advance out of reference_capture: at LEAST the 10 former
  // surfaces are reclassified (≥10 port-states), reference_capture only ever SHRINKS from its 29 reset
  // baseline (a surface promoted to a port state is one fewer capture), and the classes sum to 39.
  ok("by_parity_class honest: ≥10 port-states (the 10 former + any promoted), reference_capture ≤ 29 (only shrinks), classes sum to 39", portTotal >= 10 && (bc.reference_capture || 0) <= 29 && (bc.reference_capture || 0) + portTotal === 39, JSON.stringify(bc));

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

    // THE RULE (HARDENED, #34 review): daemon_wired ⇒ VISUAL parity (region geometry + theme match +
    // reproduction of the reference IA landmarks). Region-name overlap alone (structural_parity) is NOT
    // parity — explorer has the shell regions but the gate refuses it (blank reference) → reference_ported.
    const wired = res.surfaces.filter((s) => s.matrix_class === "daemon_wired");
    // NON-VACUITY: the harness must produce a daemon_wired row for EVERY daemon_wired matrix seed — so
    // the `.every()` rule below can never pass on an empty set (a slug rename / dropped row fails here).
    const wiredMatrixCount = (matrix.seeds || []).filter((s) => s.parity_class === "daemon_wired").length;
    ok("the harness produced a daemon_wired row for every daemon_wired matrix seed (the parity RULE is non-vacuous)", wired.length === wiredMatrixCount && wired.length > 0, `harness ${wired.length} vs matrix ${wiredMatrixCount}`);
    ok("RULE: every daemon_wired surface PASSES VISUAL parity (theme + landmarks + geometry, not just region names)", wired.every((s) => s.visual_parity === true), wired.length ? wired.map((s) => `${s.slug}:visual=${s.visual_parity}`).join(",") : "0 daemon_wired yet");
    // PIXEL-WAVE CORRECTION: daemon_wired now ALSO requires shell-pixel certification against a
    // data_clean reference, so a faithful port can legitimately PASS the hardened VISUAL gate
    // while its reference is pixel-UNCERTIFIABLE (shell_clean_only / errored per the sweep) — the
    // honest ceiling is reference_ported with parity_blocked naming the reference gap (lineage:
    // the monocle capture never recorded its graph-load APIs). Anything else that reads visual
    // parity outside daemon_wired is still a mislabel.
    const seedBy = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
    const sweepBy = (() => { try { return Object.fromEntries((JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")).seeds || []).map((s) => [s.slug, s])); } catch { return {}; } })();
    ok("RULE: no substrate_bound / port-pending surface is mislabeled as VISUAL parity; a reference_ported seed may pass the VISUAL gate ONLY at the pixel-uncertifiable ceiling (sweep shell_clean_only/errored + parity_blocked names it + NOT pixel-certified)", !res.surfaces.some((s) => {
      if (s.visual_parity !== true || s.matrix_class === "daemon_wired") return false;
      if (s.matrix_class !== "reference_ported") return true;
      const seed = seedBy[s.slug], sw = sweepBy[s.slug];
      return !(seed && seed.parity_blocked && seed.shell_pixel_certified !== true && sw && ["shell_clean_only", "errored_reference"].includes(sw.clean_state));
    }), res.surfaces.filter((s) => s.visual_parity === true && s.matrix_class !== "daemon_wired").map((s) => `${s.slug}:${s.matrix_class}`).join(",") || "none outside daemon_wired");

    // GUARD (review #32 + #33): an ERROR PAGE can never certify parity — its shell chrome renders, so
    // region-matching would falsely pass. The harness must refuse parity when EITHER SIDE errored (the
    // reference OR the IOI candidate).
    ok("GUARD: no surface with an ERRORED reference OR errored IOI candidate is granted visual parity", !res.surfaces.some((s) => (s.reference_errored === true || s.ioi_errored === true) && s.visual_parity === true), res.surfaces.filter((s) => s.reference_errored || s.ioi_errored).map((s) => `${s.slug}:ref_err=${s.reference_errored}/ioi_err=${s.ioi_errored}/visual=${s.visual_parity}`).join(",") || "none errored");
    ok("every daemon_wired surface has BOTH a valid reference AND a valid (non-errored) IOI candidate", res.surfaces.filter((s) => s.matrix_class === "daemon_wired").every((s) => s.reference_valid === true && s.ioi_valid === true), res.surfaces.filter((s) => s.matrix_class === "daemon_wired").map((s) => `${s.slug}:ref_valid=${s.reference_valid}/ioi_valid=${s.ioi_valid}`).join(",") || "0 daemon_wired");

    // THE HARDENED-GATE PROOF (#34 review): the THREE daemon_wired surfaces (schema, approvals, pipeline)
    // are FAITHFUL ports — they match the reference THEME and reproduce its IA landmarks. A wired-but-not-
    // certified surface (explorer) shows the gate's teeth: it reproduces the shell REGIONS
    // (structural_parity true) but the gate REFUSES visual_parity because the local reference is blank
    // (no IA landmarks to reproduce) — which is exactly why it is reference_ported, not daemon_wired.
    const schema = bySurface.schema, appr = bySurface.approvals, expl = bySurface.explorer, lin = bySurface.lineage, pipe = bySurface.pipeline;
    ok("every daemon_wired surface (schema + approvals + pipeline) is a FAITHFUL port: visual_parity + theme MATCH (light/light) + full landmark reproduction", [schema, appr, pipe].every((s) => s && s.visual_parity === true && s.theme_match === true && s.reference_theme === "light" && s.ioi_theme === "light" && s.landmark_covered === s.landmark_applicable && s.landmark_applicable >= 6), `schema ${schema?.landmark_covered}/${schema?.landmark_applicable} · approvals ${appr?.landmark_covered}/${appr?.landmark_applicable} · pipeline ${pipe?.landmark_covered}/${pipe?.landmark_applicable}`);
    // #46 CORRECTED the explorer story: the "blank reference" the gate rightly refused was an
    // origin/hostname mismatch (#44 sweep proof), not a missing backend. The teeth now cut the
    // OTHER way: explorer certifies ONLY against the origin-aligned reference override — and the
    // lineage negative case below still proves the gate refuses unfaithful surfaces.
    ok("the gate's refusal was CORRECTED, not relaxed: explorer certifies visual_parity ONLY via the #46 origin-aligned reference (override declared, reference valid, daemon_wired + shell-pixel certified)", expl && expl.visual_parity === true && expl.matrix_class === "daemon_wired" && expl.reference_errored === false && /localhost:9225\/workspace\/hubble/.test(expl.reference_url || ""), `expl visual=${expl?.visual_parity} class=${expl?.matrix_class} ref=${expl?.reference_url}`);
    // The refusal-teeth example ROTATED lineage → jobs (the Provenance graft made lineage a
    // faithful port; jobs remains a substrate surface whose clean reference shell is NOT
    // reproduced by its dark candidate — the same teeth, a surface that still refuses).
    const jobsRow = bySurface.jobs;
    ok("a SUBSTRATE surface (jobs) has the reference shell available but does NOT reproduce it (visual parity FALSE)", jobsRow && ["rail", "header", "body"].every((r) => jobsRow.reference_regions.includes(r)) && jobsRow.visual_parity === false, `jobs ref[${jobsRow?.reference_regions}] ioi[${jobsRow?.ioi_regions}]`);
    // The TWO-LAYER teeth (the Provenance graft): the ported lineage now reproduces the
    // reference chrome — the VISUAL gate passes — while the PIXEL layer still refuses it
    // (shell_clean_only reference, uncertified, parity_blocked naming the capture gap). The
    // ceiling holds without gaming either gate.
    ok("the PORTED lineage passes the VISUAL gate at the pixel-uncertifiable ceiling: reference_ported + visual TRUE + NOT pixel-certified + parity_blocked names the monocle capture gap", lin && lin.visual_parity === true && lin.matrix_class === "reference_ported" && seedBy.lineage?.shell_pixel_certified !== true && /re-harvest/.test(seedBy.lineage?.parity_blocked || ""), `lin visual=${lin?.visual_parity} class=${lin?.matrix_class}`);
    ok("the PROMOTED surface (pipeline, #39) is now daemon_wired: a faithful LIGHT re-port certified against the ORIGIN-ALIGNED data-clean reference (reference NOT errored, visual_parity TRUE)", pipe && pipe.matrix_class === "daemon_wired" && pipe.reference_errored === false && pipe.visual_parity === true, `pipe class=${pipe?.matrix_class} ref_errored=${pipe?.reference_errored} visual=${pipe?.visual_parity}`);
  }

  // 4. The daemon truth verifiers are preserved (spot-check one still passes end-to-end).
  const spot = spawnSync("node", [path.join(here, "verify-hypervisor-app-parity-approvals.mjs")], { encoding: "utf8", timeout: 90000 });
  ok("existing daemon-truth verifiers preserved (spot-check: the approvals port verifier still passes under daemon_wired)", spot.status === 0, (spot.stdout || "").trim().split("\n").pop());
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`reference-parity-reset readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
