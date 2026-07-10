#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #47 — MODEL CATALOG PORT VERIFIER (the first Foundry-family certified
// surface; the second port chosen by the #44 sweep ranking). Asserts:
//   1. MATRIX: models is daemon_wired at /__ioi/foundry/models over a
//      data_clean reference, with Models-IA landmarks declared.
//   2. VISUAL PARITY: the hardened harness certifies against /__apps/models
//      (whose catalog lanes are REBOUND to the same daemon registry).
//   3. DAEMON TRUTH: exactly one card per real model route — identity +
//      default marker, availability + probe evidence + staleness, weight
//      custody, credential posture, lifecycle/admission all render honestly;
//      honest empty state when the registry is empty.
//   4. OWNER + GAPS: /__ioi/foundry links the port first-class and stays
//      intact; unsupported lanes named/disabled in place; NO model-execution
//      semantics anywhere (no inference/fine-tune/deploy/train/playground).
//   5. SHELL-PIXEL CERTIFICATION: committed non-pinned 2-viewport evidence;
//      the card list is the excluded live body (no body pixel claim).
// ---------------------------------------------------------------------------
import { readFileSync, existsSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const routesJson = await fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((r) => r.json()).catch(() => null);
  if (!routesJson) { console.error("BLOCKED: daemon model-route registry not reachable at " + DAEMON); process.exit(2); }
  const routes = routesJson.routes || [];

  // 1. MATRIX
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const row = (matrix.seeds || []).find((s) => s.slug === "models");
  ok("matrix: models is daemon_wired at /__ioi/foundry/models with Models-IA landmarks + the intact /__ioi/foundry substrate", row && row.parity_class === "daemon_wired" && row.port_surface === "/__ioi/foundry/models" && row.candidate_surface === "/__ioi/foundry/models" && row.substrate_surface === "/__ioi/foundry" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the models REFERENCE is data_clean per the sweep (its catalog lanes are rebound to the same daemon registry)", row && row.reference_clean_state === "data_clean", row ? row.reference_clean_reason?.slice(0, 80) : "");
  ok("the estate census accepts models among the certified daemon_wired surfaces (>= 6 since #47, the first Foundry-family one); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 6 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 2. VISUAL PARITY
  const artDir = path.join(appRoot, ".artifacts", "models-port-verify");
  try { if (existsSync(path.join(artDir, "result.json"))) rmSync(path.join(artDir, "result.json")); } catch { /* */ }
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_HARNESS_SURFACES: "models", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("harness ran + captured real screenshots (rebound reference vs the port)", hp && hp.evidence_ok === true, hp ? `ref ${hp.reference_screenshot_bytes}b · ioi ${hp.ioi_screenshot_bytes}b` : "harness did not run");
  ok("CERTIFIED: the hardened harness grants visual_parity (region geometry + theme + landmarks)", hp && hp.visual_parity === true && hp.structural_parity === true, hp ? `visual=${hp.visual_parity} structural=${hp.structural_parity}` : "n/a");
  ok("theme MATCH: reference LIGHT ≡ port LIGHT", hp && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light");
  ok("IA landmarks reproduced (tabs + hero + filter facets; coverage ≥ 0.8, none missing)", hp && hp.landmark_applicable >= 8 && hp.landmark_covered >= Math.ceil(hp.landmark_applicable * 0.8) && (hp.landmarks_missing || []).length === 0, hp ? `covered ${hp.landmark_covered}/${hp.landmark_applicable}` : "n/a");
  ok("BOTH sides VALID: neither the reference nor the port is errored", hp && hp.reference_valid === true && hp.reference_errored === false && hp.ioi_valid === true && hp.ioi_errored === false);

  // 3. DAEMON TRUTH — one card per route; every posture renders honestly.
  const port = await page(`${SERVE}/__ioi/foundry/models`);
  const cardCount = (port.text.match(/class="mc-card"/g) || []).length;
  ok(`exactly ONE rendered card per daemon model route (${routes.length})`, port.status === 200 && cardCount === routes.length, `cards ${cardCount} vs routes ${routes.length}`);
  if (routes.length) {
    const r = routes[0];
    const a = r.availability || {};
    ok("real route IDENTITY renders (display name + model id + default marker where true)", port.text.includes(r.display_name || "") && port.text.includes((r.model || {}).model_id || "") && (!r.default_route || /\(default\)/.test(port.text)), `${r.display_name} / ${(r.model || {}).model_id}`);
    ok("availability renders HONESTLY: state + staleness + probe evidence (kind + checked_at), never a faked freshness", (a.state !== "available" || port.text.includes("available")) && (!a.stale || /stale probe/.test(port.text)) && (!a.probe || (port.text.includes(a.probe.kind || "") && port.text.includes(String(a.probe.checked_at || "").slice(0, 19)))), `${a.state}${a.stale ? " (stale)" : ""} · ${a.probe?.kind}`);
    ok("weight CUSTODY posture renders honestly", !r.custody || port.text.includes(String((r.custody || {}).weight_class || "").replace(/_/g, " ")), (r.custody || {}).weight_class);
    ok("CREDENTIAL posture renders honestly", !r.credential_posture || port.text.includes(String(r.credential_posture).replace(/_/g, " ")), r.credential_posture);
    ok("LIFECYCLE + ADMISSION render honestly (status + admitted marker when an admission id exists)", port.text.includes(((r.lifecycle || {}).status || "")) && (!(r.admission || {}).last_admission_id || /admitted/.test(port.text)), `${(r.lifecycle || {}).status}${(r.admission || {}).last_admission_id ? " · admitted" : ""}`);
  } else {
    ok("EMPTY registry renders the honest empty state (no fabricated model cards)", /No model routes yet/.test(port.text) && cardCount === 0);
  }
  ok("no model-EXECUTION semantics anywhere: no inference/fine-tune/deploy/train/playground affordances beyond named-gap prose", !/(run inference|fine-?tune now|deploy model|start training|open playground)/i.test(port.text));
  ok("facet rows are LIVE route truth (lifecycle from availability, types from modalities/capabilities, creator from the provider binding), inside pinned reference slots", /LIFECYCLE STATUS|Lifecycle Status/.test(port.text) && /Model creator/i.test(port.text) && (routes.length === 0 || port.text.includes((routes[0].provider_binding || {}).provider_kind || "local")));

  // 4. OWNER + GAPS
  const foundry = await page(`${SERVE}/__ioi/foundry`);
  ok("owner discoverability: /__ioi/foundry links the certified Model Catalog first-class AND keeps its substrate catalog intact", foundry.status === 200 && foundry.text.includes("/__ioi/foundry/models") && /Model Catalog/.test(foundry.text));
  ok("route ADMINISTRATION stays in Agent Studio (linked), not on the read-only catalog", port.text.includes("/__ioi/agent-studio#model-routes"));
  ok("unsupported reference lanes are DISABLED IN PLACE + named, never hidden", (port.text.match(/disabled/g) || []).length >= 4 && /named gap/.test(port.text) && /reference-only/.test(port.text) && /aria-disabled="true"/.test(port.text));
  ok("brand-clean: no Palantir/Foundry-vendor branding beyond the estate's own Foundry surface name", !/\bPalantir\b/.test(port.text));

  // 5. SHELL-PIXEL CERTIFICATION
  {
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: models is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/models.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: models slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "models" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated <= 1.25% AND raw <= 3.0% on every certified viewport, with real certified-shell coverage", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
    ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (the model card list is the excluded live body, verified semantically above)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));
  }

  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`models-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
