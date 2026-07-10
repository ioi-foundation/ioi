#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #46 — OBJECT EXPLORER PORT VERIFIER (the CORRECTION promotion).
// History: #35 ported the shell blind and stayed reference_ported behind a
// "blank/failed local Hubble reference" blocker. The #44 estate sweep PROVED
// that blocker wrong — the capture-origin lane (localhost:9225/workspace/
// hubble/) renders the full data-clean Object Explorer; the failure was an
// origin/hostname mismatch (the pipeline #38 class), not a missing backend.
// #46 origin-aligned the reference, re-ported the shell against it, certified
// shell-pixel parity at both viewports, and promoted explorer to daemon_wired.
// This verifier asserts all of it:
//   1. MATRIX: daemon_wired + origin-aligned override + landmarks; the stale
//      parity_blocked prose is GONE; the sweep records the corrected story.
//   2. REFERENCE: the origin-aligned reference is VALID + data-clean.
//   3. VISUAL PARITY: the hardened harness certifies against THAT reference.
//   4. DAEMON TRUTH: object types across live DomainOntologies, counts from
//      materialized sets, the object-set catalog, a WORKING ?q= filter that
//      drops a guaranteed decoy — and first-class Ontology-pair backlinks.
//   5. SHELL-PIXEL CERTIFICATION: committed non-pinned 2-viewport evidence;
//      the catalog/set ROWS are the excluded live body (no body pixel claim).
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
const jd = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ODK plane not reachable at " + DAEMON); process.exit(2); }

  // 1. MATRIX — the correction is complete and recorded.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const row = (matrix.seeds || []).find((s) => s.slug === "explorer");
  ok("matrix: explorer is daemon_wired at /__ioi/ontology/explorer with the ORIGIN-ALIGNED reference override + landmarks declared", row && row.parity_class === "daemon_wired" && row.port_surface === "/__ioi/ontology/explorer" && row.candidate_surface === "/__ioi/ontology/explorer" && row.reference_url_override === "http://localhost:9225/workspace/hubble/" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("the OLD BLOCKER is corrected: no stale parity_blocked prose survives; the note records the origin-mismatch correction", row && !row.parity_blocked && /origin mismatch|origin-aligned|ORIGIN-ALIGNED/i.test(row.note || ""));
  ok("the sweep records the corrected reference story (data_clean via the origin-aligned lane)", row && row.reference_clean_state === "data_clean", row ? `${row.reference_clean_state} · ${String(row.reference_clean_reason).slice(0, 70)}` : "");
  ok("the estate census accepts explorer among the certified daemon_wired surfaces (>= 5 since #46); reference_ported stays empty; reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 5 && !(matrix.by_parity_class?.reference_ported) && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 2. REFERENCE VALIDITY — the origin-aligned reference renders (machine-checked, not prose).
  const ref = await page("http://localhost:9225/workspace/hubble/");
  ok("the origin-aligned Hubble reference BOOTS (no blank body, no error page)", ref.status === 200 && ref.text.length > 5000 && !/an error occurred|failed to load current/i.test(ref.text));

  // 3. VISUAL PARITY — hardened harness against the origin-aligned reference.
  const artDir = path.join(appRoot, ".artifacts", "explorer-port-verify");
  try { if (existsSync(path.join(artDir, "result.json"))) rmSync(path.join(artDir, "result.json")); } catch { /* */ }
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_HARNESS_SURFACES: "explorer", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("harness ran + captured real screenshots (origin-aligned reference vs the port)", hp && hp.evidence_ok === true, hp ? `ref ${hp.reference_screenshot_bytes}b · ioi ${hp.ioi_screenshot_bytes}b` : "harness did not run");
  ok("CERTIFIED: the hardened harness grants visual_parity — the gate that REFUSED under the broken proxy reference now passes against the valid one", hp && hp.visual_parity === true && hp.structural_parity === true, hp ? `visual=${hp.visual_parity} structural=${hp.structural_parity}` : "n/a");
  ok("theme MATCH: reference LIGHT ≡ port LIGHT", hp && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light");
  ok("IA landmarks reproduced (search hero + shortcuts + catalogs; coverage ≥ 0.8, none missing)", hp && hp.landmark_applicable >= 8 && hp.landmark_covered >= Math.ceil(hp.landmark_applicable * 0.8) && (hp.landmarks_missing || []).length === 0, hp ? `covered ${hp.landmark_covered}/${hp.landmark_applicable}` : "n/a");
  ok("BOTH sides VALID: the origin-aligned reference is data-clean (not errored/blank) + the port is not errored", hp && hp.reference_valid === true && hp.reference_errored === false && hp.ioi_valid === true && hp.ioi_errored === false);

  // 4. DAEMON TRUTH — real ODK object/type/set truth + the working filter + backlinks.
  const [o, ms] = await Promise.all([jd("/v1/hypervisor/odk/domain-ontologies"), jd("/v1/hypervisor/odk/materialized-object-sets")]);
  const ontologies = o.ontologies || [];
  const msets = ms.materialized_object_sets || [];
  const allTypes = ontologies.flatMap((oo) => (((oo.canonical_object_model || {}).object_types) || []).map((t) => ({ oo, t })));
  const port = await page(`${SERVE}/__ioi/ontology/explorer`);
  ok("the port renders the reference IA (Object Explorer search · Shortcuts · Object type catalog · Object set catalog · filter/sort/lane chrome)", port.status === 200 && ["Object Explorer search", "Shortcuts", "Object type catalog", "Object set catalog", "Filter for an object type", "Relevancy", "All Ontologies", "New exploration"].every((l) => port.text.includes(l)));
  ok(`rendered object-type COUNT equals daemon truth (${allTypes.length} across ${ontologies.length} live ontologies — the "N of M" tag)`, port.text.includes(`>${allTypes.length} of ${allTypes.length}<`), `expected ${allTypes.length}`);
  const sample = allTypes.find(({ t }) => t.name) || allTypes[0];
  ok("at least one REAL object type row renders (name from a live DomainOntology, never the capture's example types)", sample && port.text.includes(sample.t.name || sample.t.id) && !/\[Example rk46\] Email Claims/.test(port.text), sample ? (sample.t.name || sample.t.id) : "no types in daemon");
  const sampleSet = msets[0];
  ok("a REAL materialized set renders with its daemon object count (the object-set catalog + shortcuts read real sets)", !msets.length || (port.text.includes(sampleSet.name || sampleSet.set_id || sampleSet.object_type_id) && new RegExp(`${sampleSet.count} object`).test(port.text)), sampleSet ? `${sampleSet.name || sampleSet.set_id} -> ${sampleSet.count}` : "no sets (honest empty)");
  {
    // GUARANTEED decoy: a fixture ontology whose type name can never match the query below.
    const jdp = (method, pth, body) => fetch(`${DAEMON}${pth}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json()).catch(() => ({}));
    const fix = await jdp("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "explorer-decoy-check", canonical_object_model: { object_types: [{ id: "zzdecoy", name: "ZZDecoyNeverMatches", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "zzdecoy" }] } });
    const decoyId = fix.ontology?.id;
    const q = "explorer-decoy-check"; // matches ONLY the decoy's ontology domain
    const filtered = await page(`${SERVE}/__ioi/ontology/explorer?q=${encodeURIComponent(q)}`);
    const m = filtered.text.match(/>(\d+) of (\d+)</);
    ok("the ?q= filter WORKS server-side: the query keeps ONLY the matching fixture type and drops every other (decoy-guaranteed) type", m && Number(m[1]) === 1 && Number(m[2]) > 1 && filtered.text.includes("ZZDecoyNeverMatches") && (!sample || !filtered.text.includes(`>${(sample.t.name || sample.t.id)}<`) || (sample.t.name || "").toLowerCase().includes(q)), m ? `${m[1]} of ${m[2]} for q=${q}` : "no count tag");
    if (decoyId) await jdp("DELETE", `/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(decoyId)}`);
  }
  ok("Ontology-pair backlinks are FIRST-CLASS: Explorer -> Ontology Manager", port.text.includes("/__ioi/ontology/manager"));
  const om = await page(`${SERVE}/__ioi/ontology/manager`);
  ok("Ontology Manager -> Explorer stays first-class (the #34/#46 pair, now both daemon_wired)", om.status === 200 && om.text.includes("/__ioi/ontology/explorer"));
  const odk = await page(`${SERVE}/__ioi/odk`);
  ok("/__ioi/odk (substrate) links the Explorer first-class", odk.status === 200 && odk.text.includes("/__ioi/ontology/explorer"));
  ok("unsupported reference lanes are DISABLED IN PLACE + named (object search · Filter-by · Recents/Favorites · sort · type-group/application · exploration tabs · ontology selector · per-user set lanes), never hidden", (port.text.match(/disabled/g) || []).length >= 5 && /named gap/.test(port.text) && /reference-only/.test(port.text));
  ok("brand-clean: no Palantir/Foundry branding on the port", !/\bPalantir\b/.test(port.text) && !/\bFoundry\b/.test(port.text));

  // 5. SHELL-PIXEL CERTIFICATION — committed, non-pinned, both viewports; body excluded by design.
  {
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: explorer is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/explorer.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: explorer slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "explorer" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated <= 1.25% AND raw <= 3.0% on every certified viewport, with real certified-shell coverage", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
    ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (the catalog/set rows are the excluded live body, verified semantically above)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));
  }

  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`object-explorer-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
