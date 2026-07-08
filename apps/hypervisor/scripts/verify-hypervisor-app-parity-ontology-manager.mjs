#!/usr/bin/env node
// ONTOLOGY MANAGER (schema) REFERENCE PORT — #34 done-bar (a true daemon_wired / reference UX parity).
//
// /__ioi/ontology/manager is a ported source-neutral "Ontology Manager" schema-workbench SHELL (left
// rail of ontologies + schema-section nav · header · toolbar · a typed schema BODY · right detail
// panel · bottom tray) — NOT the dark automationsShell — over the REAL ODK CanonicalObjectModel
// (typed object / value / link / action types + functions + health + resources). It is READ-ONLY:
// authoring + object materialization stay in the /__ioi/odk substrate. The local /__apps/schema
// reference BOOTS (non-errored), so the Playwright harness certifies structural parity → daemon_wired.
//
// Asserts:
//   - MATRIX: schema = daemon_wired → /__ioi/ontology/manager (port_surface == candidate_surface).
//   - REFERENCE VALID: /__apps/schema boots the Ontology-Manager grammar, non-errored, brand-clean.
//   - PORTED SHELL (not automationsShell): the page is the om-shell (rail + <main> body + right); no
//     .wrap / max-width:920px document.
//   - STRUCTURAL PARITY (harness): structural_parity TRUE against a VALID reference — BOTH sides valid,
//     real screenshots, the core shell regions (rail + header + body), score ≥ 0.8.
//   - DAEMON TRUTH: a real fixture DomainOntology's typed CanonicalObjectModel renders in the workbench
//     (domain · ref · object type · property · value type · link · action · function); the rail
//     ontology count matches the live daemon; the header object-type count matches the fixture.
//   - READ-ONLY + NAMED GAPS DISABLED IN PLACE: in-canvas schema editing is a disabled control; action/
//     function execution are named gaps; the authoring lane routes to the /__ioi/odk substrate.
//   - DISCOVERABILITY: the /__ioi/odk substrate links the ported manager first-class; brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-ontology-manager.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (method, p, body) => { const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ODK plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix — schema is daemon_wired (the port), not reference_capture / substrate_bound.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies schema as daemon_wired → /__ioi/ontology/manager (TRUE parity)", bySlug.schema?.parity_class === "daemon_wired" && bySlug.schema?.port_surface === "/__ioi/ontology/manager" && bySlug.schema?.candidate_surface === "/__ioi/ontology/manager");
  ok("estate honest: reference_capture still the majority; no false 'covered'", (matrix.by_parity_class?.reference_capture || 0) > (matrix.by_parity_class?.daemon_wired || 0) && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference boots (valid, non-errored). NOTE: the reference is a genuine third-party capture, so
  // it legitimately carries the source's brand strings — brand-clean is asserted on the IOI PORT (below),
  // NOT on the capture (per doctrine: brand-clean on the IOI surface, not on the reference).
  const ref = await page(`${SERVE}/__apps/schema`);
  ok("reference /__apps/schema boots the Ontology-Manager grammar (non-errored)", ref.status === 200 && /Ontology Manager/i.test(ref.text) && !/an error occurred|something went wrong|failed to load/i.test(ref.text));

  // Fixture: one real DomainOntology with a fully typed CanonicalObjectModel (health ready).
  const DOM = `om-port-fixture-${process.pid}`;
  const com = {
    value_types: [{ id: "vt_label", name: "LabelText", base: "string" }],
    object_types: [{ id: "ot_gadget", name: "GadgetKind", title_property: "p_title", properties: [{ id: "p_title", name: "TitleProp", value_type: "vt_label", required: true }] }],
    link_types: [{ id: "lt_rel", name: "RelatedGadget", from: "ot_gadget", to: "ot_gadget", cardinality: "many_to_many" }],
    action_types: [{ id: "at_make", name: "MakeGadget", kind: "create_object", applies_to: "ot_gadget" }, { id: "fn_score", name: "ScoreGadget", kind: "function" }],
  };
  const created = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: DOM, version: "0.1.0", description: "#34 ontology-manager port fixture", canonical_object_model: com });
  const fix = created.j.ontology;
  ok("fixture DomainOntology created with typed COM (health ready)", created.status === 201 && fix?.id && (fix.health || {}).status === "ready", fix ? `${fix.id} · ${(fix.health || {}).status}` : "");

  // 2. PORTED SHELL — the om-shell, not automationsShell.
  const portDefault = await page(`${SERVE}/__ioi/ontology/manager`);
  const td = portDefault.text;
  ok("the ported manager is the om-shell (rail + <main> body + right), NOT automationsShell", portDefault.status === 200 && /class="om-shell"/.test(td) && /class="om-rail"/.test(td) && /<main class="om-body"[^>]*role="main"/.test(td) && /class="om-right"/.test(td) && !/max-width:920px/.test(td) && !/class="wrap"/.test(td));
  ok("<title>Ontology Manager</title> + schema-section nav (Object types / Value types / Link types / Actions / Functions / Health)", /<title>Ontology Manager/.test(td) && ["#om-object-types", "#om-value-types", "#om-link-types", "#om-action-types", "#om-functions", "#om-health"].every((h) => td.includes(h)));

  // 3. STRUCTURAL PARITY — the harness certifies against the VALID reference.
  const artDir = path.join(appRoot, ".artifacts", "ontology-manager-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "schema", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("Playwright harness: the port PASSES structural parity — BOTH reference and IOI valid (non-errored), real screenshots", hp && hp.structural_parity === true && hp.reference_valid === true && hp.reference_errored === false && hp.ioi_valid === true && hp.ioi_errored === false && hp.evidence_ok === true, hp ? `ref[${hp.reference_regions}] ioi[${hp.ioi_regions}] score ${hp.parity_score} ref_err=${hp.reference_errored} ioi_err=${hp.ioi_errored}` : "harness did not run");
  ok("the port reproduces the reference shell core regions (rail + header + body) at score ≥ 0.8", hp && ["rail", "header", "body"].every((r) => hp.ioi_regions.includes(r)) && hp.parity_score >= 0.8);

  // 4. DAEMON TRUTH — the real fixture's typed COM renders + counts cross-check the live daemon.
  const onts = (await jd("GET", "/v1/hypervisor/odk/domain-ontologies")).j.ontologies || [];
  const portFix = await page(`${SERVE}/__ioi/ontology/manager?ontology=${encodeURIComponent(fix.id)}`);
  const t = portFix.text;
  ok("the fixture ontology renders (domain · ref) — real daemon truth", fix && t.includes(DOM) && t.includes(fix.ref));
  ok("the typed CanonicalObjectModel renders (object type · property · value type · link · action · function)", ["GadgetKind", "TitleProp", "LabelText", "RelatedGadget", "MakeGadget", "ScoreGadget"].every((s) => t.includes(s)), ["GadgetKind", "TitleProp", "LabelText", "RelatedGadget", "MakeGadget", "ScoreGadget"].filter((s) => !t.includes(s)).join(",") || "all present");
  ok("CROSS-CHECK: the rail lists every ontology in the live daemon (count matches)", (t.match(/class="om-onto /g) || []).length === onts.length, `rail ${(t.match(/class="om-onto /g) || []).length} · daemon ${onts.length}`);
  ok("CROSS-CHECK: the header object-type count matches the fixture COM (1 object type)", /1 object type ·/.test(t), (t.match(/\d+ object types? ·/) || [])[0] || "");
  ok("health readiness renders (status pill + counts) from the daemon health projection", /Readiness/.test(t) && />ready</.test(t) && /object instances/.test(t));

  // 5. READ-ONLY + named gaps DISABLED IN PLACE; authoring routes to the substrate.
  ok("in-canvas schema editing is a DISABLED control in place (not hidden)", /<button[^>]*disabled[^>]*>Edit in canvas<\/button>/.test(t));
  ok("action + function EXECUTION are named gaps (declarations only)", /Action <b>declarations<\/b> only/.test(t) && /Function <b>declarations<\/b> only/.test(t) && /in-canvas schema editing · action\/function execution/.test(t));
  ok("the authoring lane routes to the /__ioi/odk substrate (Configure model)", />Configure model<\/a>/.test(t) && new RegExp(`/__ioi/odk/ontologies/${fix.id}/edit`).test(t));

  // 6. DISCOVERABILITY — the /__ioi/odk substrate links the ported manager first-class; brand-clean.
  const odk = await page(`${SERVE}/__ioi/odk`);
  ok("the /__ioi/odk substrate links the ported Ontology Manager first-class", odk.status === 200 && odk.text.includes("/__ioi/ontology/manager"));
  ok("reference linked as secondary; substrate reachable from the port; brand-clean", t.includes("/__apps/schema") && t.includes("/__ioi/odk") && !/\bPalantir\b|\bFoundry\b/.test(t));

  // 7. Cleanup.
  if (fix?.id) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${fix.id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ontology-manager-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
