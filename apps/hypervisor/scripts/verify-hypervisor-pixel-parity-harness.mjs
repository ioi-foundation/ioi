#!/usr/bin/env node
// SHELL-PIXEL parity harness — the fail-closed verifier (PR #40, re-scoped in the pixel wave).
//
// Pins the certification CONTRACT so it cannot rot or be gamed:
//   A. PURE cases against the exported verdict/guards (no browser): an errored reference or IOI side can
//      never certify; missing screenshots/metrics/dims fail closed; a geometry-only spoof cannot pass;
//      the certified SHELL cannot be masked away (min coverage); data masks cannot swallow the shell nor
//      an in-shell landmark; thresholds bind at their exact boundaries; and — the core re-scope — the
//      SHELL is what is diffed while the BODY is excluded by design.
//   B. END-TO-END against the LIVE estate: the harness runs, emits real artifacts (shell heatmap + shell
//      manifest + result.json), reports the HONEST baseline (schema shell is NOT yet certified in #40 —
//      the wave certifies it per surface in #41+), and REFUSES an UNPORTED surface live (jobs —
//      no declared shell geometry, data-empty reference: the #34 gates + the coverage floor all
//      refuse; evalsuites, the previous example, was origin-aligned + certified by #54). The
//      ERRORED-REFERENCE branch is SOURCE-PINNED below: designer (#49) and machinery (#50) were
//      its live examples until their origin alignment removed the last port-state seed with an
//      erroring reference — the branch stays pinned in source so it cannot be dropped.
//   C. MATRIX: every port-state row carries a boolean shell_pixel_certified; none is true in #40; a true
//      row would require daemon_wired + a committed, parsed shell-certification file (generation invariant).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-pixel-parity-harness.mjs

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { THRESHOLDS, shellVerdict, shellGuard, bboxDeltas, resolveShellRects, SURFACE_SHELL } from "./harness-reference-pixel-parity.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// ---- A. PURE fail-closed contract ------------------------------------------------------------------
// The dilated/raw split is the PR#41 CALIBRATION: with the shell geometrically aligned (anchors 0,0,
// container bbox 0px, identical platform fonts), the measured raw floor was ~1.7% with ZERO run-to-run
// variance — whole-run sub-pixel bold-text drift (the AA class) + the intentional brand-mark delta.
// The DILATED metric certifies (forgives <=1px drift, still catches wrong icons/colors/blocks); the RAW
// ceiling stops gross-but-dilatable drift. Measured, not convenient.
const THRESHOLDS_OF_RECORD = {
  shell_diff_dilated_pct_max: 1.25, shell_diff_raw_pct_max: 3.0, shell_bbox_delta_px_max: 8, min_shell_certified_fraction: 0.05,
  data_mask_in_shell_fraction_max: 0.5, landmark_mask_overlap_max: 0.3, pixel_delta_threshold: 0.1, palette_delta_max: 0.05,
};
ok("THRESHOLDS are pinned DEEP-EQUAL to the values of record (no quiet loosening of ANY knob)", (() => {
  const keys = Object.keys(THRESHOLDS_OF_RECORD);
  return Object.keys(THRESHOLDS).length === keys.length && keys.every((k) => THRESHOLDS[k] === THRESHOLDS_OF_RECORD[k]);
})(), JSON.stringify(THRESHOLDS));

const GOOD = {
  evidence_ok: true, reference_errored: false, ioi_errored: false, reference_valid: true, ioi_valid: true,
  structural_parity: true, theme_match: true, landmark_ok: true, dims_match: true,
  shell_diff_dilated_pct: 0.6, shell_diff_raw_pct: 1.7, bbox_deltas: { rail: 2, header: 3, apprail: 5 },
  coverage: { certified_fraction: 0.2, data_in_shell_fraction: 0.1, landmarks_masked: [] },
  palette: { shell: { delta: 0.01 } },
};
ok("a fully-green shell capture CERTIFIES (the contract is satisfiable)", shellVerdict(GOOD).certified === true);
ok("an ERRORED REFERENCE can never certify", (() => { const v = shellVerdict({ ...GOOD, reference_errored: true, reference_valid: false }); return v.certified === false && v.reasons.some((r) => /reference is an ERROR/i.test(r)); })());
ok("an ERRORED IOI candidate can never certify", (() => { const v = shellVerdict({ ...GOOD, ioi_errored: true, ioi_valid: false }); return v.certified === false && v.reasons.some((r) => /IOI candidate is an ERROR/i.test(r)); })());
ok("MISSING SCREENSHOTS fail closed", shellVerdict({ ...GOOD, evidence_ok: false }).certified === false);
ok("MISSING shell metrics fail closed", (() => { const v = shellVerdict({ ...GOOD, shell_diff_dilated_pct: undefined, shell_diff_raw_pct: undefined }); return v.certified === false && v.reasons.some((r) => /metrics missing/i.test(r)); })());
ok("a DIMS MISMATCH fails closed", shellVerdict({ ...GOOD, dims_match: false }).certified === false);
ok("a GEOMETRY-ONLY SPOOF cannot certify: gates green but the dilated shell diff is 20% → refused", (() => { const v = shellVerdict({ ...GOOD, shell_diff_dilated_pct: 20, shell_diff_raw_pct: 22 }); return v.certified === false && v.reasons.some((r) => /structural shell difference/i.test(r)); })());
ok("the DILATED budget binds at its boundary: 1.25% passes, 1.26% fails", shellVerdict({ ...GOOD, shell_diff_dilated_pct: 1.25 }).certified === true && shellVerdict({ ...GOOD, shell_diff_dilated_pct: 1.26 }).certified === false);
ok("the RAW ceiling binds independently: dilated fine but raw 3.01% fails (no gross-but-dilatable drift)", (() => { const v = shellVerdict({ ...GOOD, shell_diff_raw_pct: 3.01 }); return v.certified === false && v.reasons.some((r) => /gross drift ceiling/i.test(r)); })() && shellVerdict({ ...GOOD, shell_diff_raw_pct: 3.0 }).certified === true);
ok("shell bbox delta binds at its boundary: 8px passes, 9px fails (region named)", (() => { const p = shellVerdict({ ...GOOD, bbox_deltas: { apprail: 8 } }); const f = shellVerdict({ ...GOOD, bbox_deltas: { apprail: 9 } }); return p.certified === true && f.certified === false && f.reasons.some((r) => /apprail=9px/.test(r)); })());
ok("the SHELL cannot be masked away: certified-shell fraction below 5% fails (a shell must actually be compared)", (() => { const v = shellVerdict({ ...GOOD, coverage: { certified_fraction: 0.03, data_in_shell_fraction: 0.1, landmarks_masked: [] } }); return v.certified === false && v.reasons.some((r) => /shell cannot be masked away/i.test(r)); })());
ok("data masks cannot SWALLOW the shell: >50% of the shell masked fails", (() => { const v = shellVerdict({ ...GOOD, coverage: { certified_fraction: 0.2, data_in_shell_fraction: 0.6, landmarks_masked: [] } }); return v.certified === false && v.reasons.some((r) => /too much of the shell is masked/i.test(r)); })());
ok("OVER-MASK (in-shell landmark hidden) fails and NAMES the landmark", (() => { const v = shellVerdict({ ...GOOD, coverage: { certified_fraction: 0.2, data_in_shell_fraction: 0.1, landmarks_masked: ["Ontology Manager"] } }); return v.certified === false && v.reasons.some((r) => /Ontology Manager/.test(r)); })());
ok("MISSING coverage stats fail closed", shellVerdict({ ...GOOD, coverage: null }).certified === false);
ok("PALETTE gate: a uniform shell tint (drift 0.06 > 0.05) cannot certify + missing palette fails closed", shellVerdict({ ...GOOD, palette: { shell: { delta: 0.06 } } }).certified === false && shellVerdict({ ...GOOD, palette: null }).certified === false);
ok("visual gates remain load-bearing: theme / landmarks / structural each refuse alone", shellVerdict({ ...GOOD, theme_match: false }).certified === false && shellVerdict({ ...GOOD, landmark_ok: false }).certified === false && shellVerdict({ ...GOOD, structural_parity: false }).certified === false);

// shellGuard geometry: body (outside shell) is excluded; a data mask in the shell is fine; masking the
// whole shell trips the coverage floor; an in-shell landmark fully covered is caught; a BODY landmark is
// NOT counted (excluded by design).
const VW = 1440, VH = 900;
const shellRects = resolveShellRects(SURFACE_SHELL.schema.rects, VW, VH);
const gClean = shellGuard(shellRects, [{ left: 300, top: 200, w: 60, h: 16 }], { "Object types": [{ left: 300, top: 200, w: 90, h: 16 }] }, VW, VH);
ok("shellGuard: a small in-shell data mask is fine; certified fraction is a real slice of the image", gClean.certified_fraction > 0.1 && gClean.data_in_shell_fraction < 0.2);
const gBodyLm = shellGuard(shellRects, [], { "test Ontology": [{ left: 900, top: 400, w: 120, h: 18 }] }, VW, VH);
ok("shellGuard: a BODY landmark (outside the shell) is EXCLUDED by design — not a masking violation", gBodyLm.landmarks_masked.length === 0);
const gCoverLm = shellGuard(shellRects, [{ left: 235, top: 220, w: 120, h: 24 }], { "Object types": [{ left: 240, top: 225, w: 90, h: 16 }] }, VW, VH);
ok("shellGuard: an IN-SHELL landmark fully covered by a data mask is reported", gCoverLm.landmarks_masked.includes("Object types"));
ok("resolveShellRects: left rail is a fixed-width full-height strip; the topbar spans the width; both viewport-anchored", (() => { const a = resolveShellRects(SURFACE_SHELL.schema.rects, VW, VH); const rail = a.find((r) => r.key === "rail"), hdr = a.find((r) => r.key === "header"); return rail.left === 0 && rail.w === 230 && rail.h === VH && hdr.top === 0 && hdr.w > VW * 0.7; })());
ok("bboxDeltas: a shifted region reports the max edge delta; one-sided regions are skipped", (() => { const d = bboxDeltas({ header: { left: 230, top: 0, w: 1210, h: 50 } }, { header: { left: 236, top: 0, w: 1204, h: 52 } }); return d.header === 6 && Object.keys(d).length === 1; })());
ok("SURFACE_SHELL declares shell geometry + data masks for the three wave surfaces", ["schema", "approvals", "pipeline"].every((s) => SURFACE_SHELL[s] && Array.isArray(SURFACE_SHELL[s].rects) && SURFACE_SHELL[s].rects.length >= 2 && SURFACE_SHELL[s].data));

// ---- B. END-TO-END against the live estate ----------------------------------------------------------
const artDir = path.join(appRoot, ".artifacts", "pixel-parity-verify");
const resPath = path.join(artDir, "result.json");
try { if (existsSync(resPath)) rmSync(resPath); } catch { /* */ }
const run1 = spawnSync("node", [path.join(here, "harness-reference-pixel-parity.mjs")], { encoding: "utf8", timeout: 240000, env: { ...process.env, IOI_PIXEL_SURFACES: "schema", IOI_PIXEL_VIEWPORTS: "1440x900", IOI_PIXEL_ARTIFACT_DIR: artDir } });
let r1 = null;
if (run1.status === 0 && existsSync(resPath)) { try { r1 = JSON.parse(readFileSync(resPath, "utf8")); } catch { /* */ } }
const sRow = r1 && (r1.surfaces || []).find((s) => s.slug === "schema");
const sVp = sRow && (sRow.viewports || [])[0];
ok("E2E: the shell-pixel harness runs + emits result.json (exit-0 gated, stale removed first)", !!sVp, sVp ? `exit ${run1.status}` : `exit ${run1.status}: ${(run1.stderr || "").slice(0, 100)}`);
ok("E2E: it certifies the SHELL and EXCLUDES the body — the certified shell is a real fraction, not the whole image", sVp && sVp.metrics.coverage && sVp.metrics.coverage.certified_fraction > 0.1 && sVp.metrics.coverage.certified_fraction < 0.9, sVp ? `certified-shell ${sVp.metrics.coverage.certified_fraction} of image` : "n/a");
ok("E2E: metrics are REAL numbers + real screenshot evidence (>10KB) + a shell heatmap + a shell manifest on disk", (() => {
  if (!sVp) return false;
  const files = ["ref-1440x900.png", "ioi-1440x900.png", "heatmap-1440x900.png", "shell-manifest.json"].map((f) => path.join(artDir, "schema", f));
  return typeof sVp.metrics.shell_diff_dilated_pct === "number" && typeof sVp.metrics.shell_diff_raw_pct === "number" && sVp.metrics.dims_match === true && files.every((f) => existsSync(f)) && statSync(files[0]).size > 10000 && statSync(files[2]).size > 10000;
})());
ok("E2E: the visual gates are carried inside the shell result (theme/structural/landmarks compose, not replace)", sVp && sVp.gates && sVp.gates.theme_match === true && sVp.gates.structural_parity === true && sVp.gates.landmark_applicable >= 5, sVp ? `landmarks ${sVp.gates.landmark_covered}/${sVp.gates.landmark_applicable}` : "n/a");
ok("E2E: a pinned run is honestly recorded (certification state comes from the full default-viewport run, not this pinned one)", sRow && sRow.shell_pixel_certified === false, sVp ? `dilatedΔ ${sVp.metrics.shell_diff_dilated_pct}% rawΔ ${sVp.metrics.shell_diff_raw_pct}%` : "n/a");
ok("E2E: a pinned-viewport run records viewports_pinned + cannot certify (no cherry-picking one viewport)", sRow && sRow.viewports_pinned === true && sRow.shell_pixel_certified === false);

const artDir2 = path.join(appRoot, ".artifacts", "pixel-parity-verify-err");
const resPath2 = path.join(artDir2, "result.json");
try { if (existsSync(resPath2)) rmSync(resPath2); } catch { /* */ }
const run2 = spawnSync("node", [path.join(here, "harness-reference-pixel-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_PIXEL_SURFACES: "jobs", IOI_PIXEL_VIEWPORTS: "1440x900", IOI_PIXEL_ARTIFACT_DIR: artDir2 } });
let r2 = null;
if (run2.status === 0 && existsSync(resPath2)) { try { r2 = JSON.parse(readFileSync(resPath2, "utf8")); } catch { /* */ } }
const dVp = r2 && ((r2.surfaces || []).find((s) => s.slug === "jobs") || {}).viewports?.[0];
ok("E2E: an UNPORTED surface (jobs — no declared shell geometry, data-empty reference) is REFUSED live: the #34 gates + the coverage floor fail closed", dVp && dVp.certified === false && dVp.reasons.some((r) => /shell cannot be masked away/i.test(r)) && dVp.reasons.some((r) => /#34 gate/i.test(r)), dVp ? dVp.reasons.slice(0, 2).join(" | ") : `exit ${run2.status}`);
// The ERRORED-REFERENCE refusal branch, SOURCE-PINNED: after #49/#50 origin-aligned designer and
// machinery (the branch's live examples through the wave), no port-state seed retains an erroring
// reference to prove it live — pin the branch in source so it cannot be quietly dropped.
const pixSrc = readFileSync(path.join(here, "harness-reference-pixel-parity.mjs"), "utf8");
const parSrc = readFileSync(path.join(here, "harness-reference-parity.mjs"), "utf8");
ok("SOURCE-PIN: the errored-reference refusal branch survives (ERROR_PAGE_RE gate + the 'reference is an ERROR' refusal reason)", /reference is an ERROR/i.test(pixSrc) && /reference_errored/.test(pixSrc) && /ERROR_PAGE_RE\s*=/.test(parSrc) && /failed to load|an error occurred/.test(String((parSrc.match(/ERROR_PAGE_RE\s*=\s*\/(.*?)\//) || [""])[0])));

// ---- C. MATRIX contract ------------------------------------------------------------------------------
const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
ok("matrix is current (regenerated == committed)", check.status === 0);
const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
const portRows = (matrix.seeds || []).filter((s) => s.parity_class !== "reference_capture");
ok("every port-state row carries a BOOLEAN shell_pixel_certified; every certified row is daemon_wired AND its committed cert file exists (per-slug re-validation below)", portRows.length >= 10 && portRows.every((s) => typeof s.shell_pixel_certified === "boolean") && portRows.filter((s) => s.shell_pixel_certified).every((s) => s.parity_class === "daemon_wired" && existsSync(path.join(appRoot, s.shell_pixel_certification_artifact || "__missing__"))), `certified: ${portRows.filter((s) => s.shell_pixel_certified).map((s) => s.slug).join(",") || "(none)"}`);
const genSrc = readFileSync(path.join(here, "build-app-parity-matrix.mjs"), "utf8");
ok("a true shell_pixel_certified row requires daemon_wired + a COMMITTED, PARSED pixel-certifications/<slug>.json (existence + schema + slug + certified + non-pinned)", /pixel-certifications\\\/\[a-z0-9-\]\+\\\.json/.test(genSrc) && /shell-pixel-certification\.v1/.test(genSrc) && /viewports_pinned !== false/.test(genSrc) && typeof matrix.pixel_rule === "string" && /pixel-identical shell/i.test(matrix.pixel_rule));
ok("every shell_pixel_certified=true row has a committed cert file with thresholds DEEP-EQUAL to THRESHOLDS (a cert made under loosened thresholds is rejected)", portRows.filter((s) => s.shell_pixel_certified).every((s) => {
  try {
    const cert = JSON.parse(readFileSync(path.join(appRoot, s.shell_pixel_certification_artifact), "utf8"));
    const keys = Object.keys(THRESHOLDS);
    return cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === s.slug && cert.shell_pixel_certified === true && cert.viewports_pinned === false && cert.thresholds && keys.every((k) => cert.thresholds[k] === THRESHOLDS[k]);
  } catch { return false; }
}));
ok("the mask-rect resolver applies the OPACITY visibility discipline (no invisible planted mask-steering elements)", /s\.opacity !== "0"[\s\S]{0,400}maskRects\.push|maskRects\.push[\s\S]{0,600}s\.opacity !== "0"/.test(readFileSync(path.join(here, "harness-reference-parity.mjs"), "utf8")));
// The pixel layer NEVER GRANTS parity: certification is evidence ON TOP of daemon_wired
// (ports move parity through their own port PRs + per-surface verifiers — #34/#36/#39/#45).
// The invariant is therefore structural, not a frozen census: every certified row is
// daemon_wired, every daemon_wired row is certified, and no other class carries a cert.
ok("parity classes are never GRANTED by the pixel layer: certified ⊆ daemon_wired, daemon_wired ⊆ certified, no cert outside daemon_wired", (matrix.seeds || []).every((s) => (s.shell_pixel_certified === true) === (s.parity_class === "daemon_wired")) && (matrix.by_parity_class?.daemon_wired || 0) >= 3 && (matrix.by_parity_class?.reference_ported || 0) <= 1, `daemon_wired=${matrix.by_parity_class?.daemon_wired} certified=${(matrix.seeds || []).filter((s) => s.shell_pixel_certified).length}`);

// ---- report ------------------------------------------------------------------------------------------
let fail = 0;
for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
console.log(`\n${results.length - fail}/${results.length} passed`);
console.log(`shell-pixel-parity-harness readiness: ${fail ? "FAIL" : "OK"}`);
process.exit(fail ? 1 : 0);
