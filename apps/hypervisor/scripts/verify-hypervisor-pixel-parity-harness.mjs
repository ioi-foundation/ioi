#!/usr/bin/env node
// PIXEL-PARITY HARNESS — the fail-closed verifier (PR #40).
//
// Pins the certification CONTRACT so it cannot rot or be gamed:
//   A. PURE cases against the exported verdict/guards (no browser): an errored reference or IOI side can
//      never pixel-pass; missing screenshots/metrics/dims fail closed; a GEOMETRY-ONLY spoof (all visual
//      gates green, pixels wildly different) cannot pass; OVER-MASKING (too much area, chrome-zone
//      masking, or a mask hiding a reference landmark/toolbar label) fails; thresholds bind at their
//      exact boundaries.
//   B. END-TO-END against the LIVE estate: the harness runs, emits real artifacts (screens + heatmap +
//      mask manifest + result.json), reports the HONEST baseline (schema is NOT yet pixel-certified in
//      #40 — the wave certifies it in #41), and REFUSES an errored-reference surface (designer).
//   C. MATRIX: every port-state row carries a boolean pixel_certified; none is true in #40; a true row
//      would require daemon_wired + an artifact pointer (generation-time invariant).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-pixel-parity-harness.mjs

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { THRESHOLDS, pixelVerdict, maskGuard, bboxDeltas, zonesFor, inChrome, MASK_MANIFESTS } from "./harness-reference-pixel-parity.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// ---- A. PURE fail-closed contract ------------------------------------------------------------------
// THE THRESHOLDS OF RECORD — deep-pinned value by value. Quietly loosening ANY knob (including the mask
// caps, the landmark overlap budget, the per-pixel sensitivity, and the palette budget) fails this
// verifier (adversarial review: the earlier boundary literals left loosening windows).
const THRESHOLDS_OF_RECORD = {
  full_diff_pct_max: 2.5, chrome_diff_pct_max: 0.75, bbox_delta_px_max: 8,
  mask_total_fraction_max: 0.35, mask_chrome_fraction_max: 0.15, landmark_mask_overlap_max: 0.3,
  pixel_delta_threshold: 0.1, palette_delta_max: 0.05,
};
ok("THRESHOLDS are pinned DEEP-EQUAL to the values of record (no quiet loosening of ANY knob)", (() => {
  const keys = Object.keys(THRESHOLDS_OF_RECORD);
  return Object.keys(THRESHOLDS).length === keys.length && keys.every((k) => THRESHOLDS[k] === THRESHOLDS_OF_RECORD[k]);
})(), JSON.stringify(THRESHOLDS));

const GOOD = {
  evidence_ok: true, reference_errored: false, ioi_errored: false, reference_valid: true, ioi_valid: true,
  structural_parity: true, theme_match: true, landmark_ok: true, dims_match: true,
  full_diff_pct: 1.2, chrome_diff_pct: 0.4, bbox_deltas: { rail: 2, header: 3, body: 5 },
  mask: { total_fraction: 0.12, chrome_fraction: 0.01, landmarks_masked: [], ok: true },
  palette: { chrome: { delta: 0.01 }, body: { delta: 0.0 } },
};
ok("a fully-green capture CERTIFIES (the contract is satisfiable)", pixelVerdict(GOOD).certified === true);
ok("PALETTE gate: a uniform whole-page tint (zone drift 0.06 > 0.05) cannot certify even at 0.00% pixel diff", (() => { const v = pixelVerdict({ ...GOOD, full_diff_pct: 0, chrome_diff_pct: 0, palette: { chrome: { delta: 0.01 }, body: { delta: 0.06 } } }); return v.certified === false && v.reasons.some((r) => /palette drift/i.test(r)); })());
ok("PALETTE gate binds at its boundary (0.05 passes, 0.051 fails) and MISSING palette data fails closed", pixelVerdict({ ...GOOD, palette: { chrome: { delta: 0.05 }, body: { delta: 0.05 } } }).certified === true && pixelVerdict({ ...GOOD, palette: { chrome: { delta: 0.051 }, body: { delta: 0 } } }).certified === false && pixelVerdict({ ...GOOD, palette: null }).certified === false);
ok("an ERRORED REFERENCE can never pixel-pass", (() => { const v = pixelVerdict({ ...GOOD, reference_errored: true, reference_valid: false }); return v.certified === false && v.reasons.some((r) => /reference is an ERROR/i.test(r)); })());
ok("an ERRORED IOI candidate can never pixel-pass", (() => { const v = pixelVerdict({ ...GOOD, ioi_errored: true, ioi_valid: false }); return v.certified === false && v.reasons.some((r) => /IOI candidate is an ERROR/i.test(r)); })());
ok("MISSING SCREENSHOTS fail closed", (() => { const v = pixelVerdict({ ...GOOD, evidence_ok: false }); return v.certified === false && v.reasons.some((r) => /fail closed/i.test(r)); })());
ok("MISSING pixel metrics fail closed", (() => { const v = pixelVerdict({ ...GOOD, full_diff_pct: undefined, chrome_diff_pct: undefined }); return v.certified === false && v.reasons.some((r) => /metrics missing/i.test(r)); })());
ok("a DIMS MISMATCH fails closed", pixelVerdict({ ...GOOD, dims_match: false }).certified === false);
ok("a GEOMETRY-ONLY SPOOF cannot pixel-pass: all visual gates green but full diff 20% → refused", (() => { const v = pixelVerdict({ ...GOOD, full_diff_pct: 20 }); return v.certified === false && v.reasons.some((r) => /NOT pixel parity/i.test(r)); })());
ok("chrome diff binds at its boundary: 0.75% passes, 0.76% fails", pixelVerdict({ ...GOOD, chrome_diff_pct: 0.75 }).certified === true && pixelVerdict({ ...GOOD, chrome_diff_pct: 0.76 }).certified === false);
ok("full diff binds at its boundary: 2.5% passes, 2.51% fails", pixelVerdict({ ...GOOD, full_diff_pct: 2.5 }).certified === true && pixelVerdict({ ...GOOD, full_diff_pct: 2.51 }).certified === false);
ok("bbox delta binds at its boundary: 8px passes, 9px fails (region named in the reason)", (() => { const p = pixelVerdict({ ...GOOD, bbox_deltas: { body: 8 } }); const f = pixelVerdict({ ...GOOD, bbox_deltas: { body: 9 } }); return p.certified === true && f.certified === false && f.reasons.some((r) => /body=9px/.test(r)); })());
ok("OVER-MASK (total area) fails: mask.ok=false via total_fraction 0.5", (() => { const v = pixelVerdict({ ...GOOD, mask: { total_fraction: 0.5, chrome_fraction: 0.01, landmarks_masked: [], ok: false } }); return v.certified === false && v.reasons.some((r) => /OVER-MASK: total/i.test(r)); })());
ok("OVER-MASK (chrome zone) fails: nav/toolbar cannot be masked away", (() => { const v = pixelVerdict({ ...GOOD, mask: { total_fraction: 0.1, chrome_fraction: 0.3, landmarks_masked: [], ok: false } }); return v.certified === false && v.reasons.some((r) => /OVER-MASK: chrome/i.test(r)); })());
ok("OVER-MASK (landmark hidden) fails and NAMES the landmark", (() => { const v = pixelVerdict({ ...GOOD, mask: { total_fraction: 0.1, chrome_fraction: 0.01, landmarks_masked: ["Pipeline outputs"], ok: false } }); return v.certified === false && v.reasons.some((r) => /Pipeline outputs/.test(r)); })());
ok("MISSING mask stats fail closed", pixelVerdict({ ...GOOD, mask: null }).certified === false);
ok("visual gates remain load-bearing: theme mismatch / landmarks / structural each refuse alone", pixelVerdict({ ...GOOD, theme_match: false }).certified === false && pixelVerdict({ ...GOOD, landmark_ok: false }).certified === false && pixelVerdict({ ...GOOD, structural_parity: false }).certified === false);

// maskGuard geometry: a landmark fully covered by a mask is caught; a small data mask in the body is fine;
// a giant mask trips the area cap; a chrome-band mask trips the chrome cap.
const VW = 1440, VH = 900;
const lmRect = { "Pipeline outputs": { left: 1150, top: 120, w: 120, h: 18 } };
const gCoverLm = maskGuard([{ left: 1140, top: 110, w: 200, h: 60 }], lmRect, VW, VH);
ok("maskGuard: a mask covering a landmark rect reports it and refuses", gCoverLm.ok === false && gCoverLm.landmarks_masked.includes("Pipeline outputs"));
const gSmall = maskGuard([{ left: 400, top: 500, w: 300, h: 100 }], lmRect, VW, VH);
ok("maskGuard: a small body-zone data mask is fine", gSmall.ok === true && gSmall.total_fraction < 0.05);
const gHuge = maskGuard([{ left: 0, top: 0, w: VW, h: VH * 0.6 }], {}, VW, VH);
ok("maskGuard: a giant mask trips the total-area cap", gHuge.ok === false && gHuge.total_fraction > THRESHOLDS.mask_total_fraction_max);
const gChrome = maskGuard([{ left: 0, top: 0, w: VW * 0.16, h: VH }], {}, VW, VH);
ok("maskGuard: masking the whole rail strip trips the chrome cap (chrome cannot be masked away)", gChrome.ok === false && gChrome.chrome_fraction > THRESHOLDS.mask_chrome_fraction_max);
ok("bboxDeltas: a shifted region reports the max edge delta; one-sided regions are skipped", (() => { const d = bboxDeltas({ body: { left: 230, top: 148, w: 900, h: 700 }, right: { left: 1140, top: 100, w: 300, h: 800 } }, { body: { left: 236, top: 150, w: 900, h: 706 } }); return d.body === 8 && !("right" in d); })());
ok("zones: chrome = rail strip + header band; a canvas-center point is body", inChrome(10, 500, zonesFor(VW, VH)) === true && inChrome(700, 50, zonesFor(VW, VH)) === true && inChrome(700, 500, zonesFor(VW, VH)) === false);
ok("mask manifests exist for the three wave surfaces and declare the data-only rule per side", ["schema", "approvals", "pipeline"].every((s) => MASK_MANIFESTS[s] && Array.isArray(MASK_MANIFESTS[s].ref) && Array.isArray(MASK_MANIFESTS[s].ioi)));

// ---- B. END-TO-END against the live estate ----------------------------------------------------------
const artDir = path.join(appRoot, ".artifacts", "pixel-parity-verify");
const resPath = path.join(artDir, "result.json");
// Stale-artifact discipline (the recurring bug class): remove before spawn, parse only on exit 0.
try { if (existsSync(resPath)) rmSync(resPath); } catch { /* */ }
const run1 = spawnSync("node", [path.join(here, "harness-reference-pixel-parity.mjs")], { encoding: "utf8", timeout: 240000, env: { ...process.env, IOI_PIXEL_SURFACES: "schema", IOI_PIXEL_VIEWPORTS: "1440x900", IOI_PIXEL_ARTIFACT_DIR: artDir } });
let r1 = null;
if (run1.status === 0 && existsSync(resPath)) { try { r1 = JSON.parse(readFileSync(resPath, "utf8")); } catch { /* */ } }
const sRow = r1 && (r1.surfaces || []).find((s) => s.slug === "schema");
const sVp = sRow && (sRow.viewports || [])[0];
ok("E2E: the pixel harness runs + emits result.json (exit-0 gated, stale removed first)", !!sVp, sVp ? `exit ${run1.status}` : `exit ${run1.status}: ${(run1.stderr || "").slice(0, 100)}`);
ok("E2E: HONEST baseline — schema is NOT pixel-certified in #40 (the instrument precedes the certification; #41 does the work)", sRow && sRow.pixel_certified === false && sVp.certified === false && sVp.reasons.length > 0, sVp ? `full=${sVp.metrics.full_diff_pct}% chrome=${sVp.metrics.chrome_diff_pct}%` : "n/a");
ok("E2E: an env-PINNED-viewport run can NEVER certify (no cherry-picking one easy viewport) — the run records viewports_pinned", sRow && sRow.viewports_pinned === true && sRow.pixel_certified === false);
ok("E2E: metrics are REAL numbers with real screenshot evidence (>10KB each) + a heatmap + a mask manifest on disk", (() => {
  if (!sVp) return false;
  const m = sVp.metrics;
  const files = ["ref-1440x900.png", "ioi-1440x900.png", "heatmap-1440x900.png", "mask-manifest.json"].map((f) => path.join(artDir, "schema", f));
  return typeof m.full_diff_pct === "number" && typeof m.chrome_diff_pct === "number" && m.dims_match === true && files.every((f) => existsSync(f)) && statSync(files[0]).size > 10000 && statSync(files[2]).size > 10000;
})());
ok("E2E: the visual gates are carried inside the pixel result (theme/landmarks/structural — the layer composes, not replaces)", sVp && sVp.gates && sVp.gates.theme_match === true && sVp.gates.structural_parity === true && sVp.gates.landmark_applicable >= 5, sVp ? `landmarks ${sVp.gates.landmark_covered}/${sVp.gates.landmark_applicable}` : "n/a");
ok("E2E: the over-mask guard ran with sane numbers (schema masks are small data-cells only)", sVp && sVp.mask && sVp.mask.ok === true && sVp.mask.total_fraction < THRESHOLDS.mask_total_fraction_max, sVp ? `mask=${sVp.mask.total_fraction}` : "n/a");

// Errored-reference refusal, live: designer's reference is an error page.
const artDir2 = path.join(appRoot, ".artifacts", "pixel-parity-verify-err");
const resPath2 = path.join(artDir2, "result.json");
try { if (existsSync(resPath2)) rmSync(resPath2); } catch { /* */ }
const run2 = spawnSync("node", [path.join(here, "harness-reference-pixel-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_PIXEL_SURFACES: "designer", IOI_PIXEL_VIEWPORTS: "1440x900", IOI_PIXEL_ARTIFACT_DIR: artDir2 } });
let r2 = null;
if (run2.status === 0 && existsSync(resPath2)) { try { r2 = JSON.parse(readFileSync(resPath2, "utf8")); } catch { /* */ } }
const dVp = r2 && ((r2.surfaces || []).find((s) => s.slug === "designer") || {}).viewports?.[0];
ok("E2E: an ERRORED-REFERENCE surface (designer) is REFUSED with the reference-error reason (live proof of the fail-closed path)", dVp && dVp.certified === false && dVp.reasons.some((r) => /reference is an ERROR/i.test(r)), dVp ? dVp.reasons[0] : `exit ${run2.status}`);

// ---- C. MATRIX contract ------------------------------------------------------------------------------
const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
ok("matrix is current (regenerated == committed)", check.status === 0);
const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
const portRows = (matrix.seeds || []).filter((s) => s.parity_class !== "reference_capture");
ok("every port-state row carries a BOOLEAN pixel_certified; NONE is true in #40 (no certification without the #41–#43 work)", portRows.length >= 10 && portRows.every((s) => typeof s.pixel_certified === "boolean") && portRows.every((s) => s.pixel_certified === false), `${portRows.length} port-state rows`);
const genSrc = readFileSync(path.join(here, "build-app-parity-matrix.mjs"), "utf8");
ok("a true pixel_certified row would require daemon_wired + a COMMITTED, PARSED pixel-certifications/<slug>.json (generator invariant: existence + schema + slug + certified + non-pinned)", /pixel-certifications\\\/\[a-z0-9-\]\+\\\.json/.test(genSrc) && /viewports_pinned !== false/.test(genSrc) && typeof matrix.pixel_rule === "string" && /over-?mask/i.test(matrix.pixel_rule));
// ARMED for #41+: any row that IS pixel_certified must carry a committed cert file whose recorded
// thresholds deep-equal the harness's THRESHOLDS of record — a certification made under quietly-loosened
// thresholds is rejected here even if the generator accepted the file shape.
ok("every pixel_certified=true row (none today) has a committed cert file with thresholds DEEP-EQUAL to THRESHOLDS", portRows.filter((s) => s.pixel_certified).every((s) => {
  try {
    const cert = JSON.parse(readFileSync(path.join(appRoot, s.pixel_certification_artifact), "utf8"));
    const keys = Object.keys(THRESHOLDS);
    return cert.schema === "ioi.hypervisor.pixel-certification.v1" && cert.slug === s.slug && cert.pixel_certified === true && cert.viewports_pinned === false && cert.thresholds && Object.keys(cert.thresholds).length === keys.length && keys.every((k) => cert.thresholds[k] === THRESHOLDS[k]);
  } catch { return false; }
}));
ok("the mask-rect resolver applies the OPACITY visibility discipline (no invisible planted mask-steering elements)", /s\.opacity !== "0".*maskRects\.push|maskRects[\s\S]{0,600}s\.opacity !== "0"|s\.opacity !== "0"[\s\S]{0,400}maskRects\.push/.test(readFileSync(path.join(here, "harness-reference-parity.mjs"), "utf8")));
ok("parity classes are UNTOUCHED by the pixel layer (daemon_wired 3 · reference_ported 1 · substrate_bound 8)", (matrix.by_parity_class?.daemon_wired || 0) === 3 && (matrix.by_parity_class?.reference_ported || 0) === 1 && (matrix.by_parity_class?.substrate_bound || 0) === 8);

// ---- report ------------------------------------------------------------------------------------------
let fail = 0;
for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
console.log(`\n${results.length - fail}/${results.length} passed`);
console.log(`pixel-parity-harness readiness: ${fail ? "FAIL" : "OK"}`);
process.exit(fail ? 1 : 0);
