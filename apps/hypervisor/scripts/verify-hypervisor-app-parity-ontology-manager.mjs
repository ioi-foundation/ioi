#!/usr/bin/env node
// ONTOLOGY MANAGER (schema) REFERENCE PORT — #34 done-bar (the first surface to clear the HARDENED gate).
//
// /__ioi/ontology/manager is a FAITHFUL source-neutral port of the reference Ontology Manager UX:
// a DARK global platform rail + a LIGHT app rail (Discover / Proposals / History · Resources: object/
// property/link/action/value types + functions · Health issues / Cleanup / Ontology configuration) +
// a LIGHT header (title · ontology switcher · "Search resources…" · New) + a LIGHT card-first body
// ("Object types recently modified" as object-type CARDS), then the typed schema detail below. It is
// wired to the REAL ODK CanonicalObjectModel and is READ-ONLY (authoring + object materialization stay
// in /__ioi/odk). The local /__apps/schema reference BOOTS (light, non-errored).
//
// This verifier enforces the #34-review HARDENED bar — region-NAME overlap is NOT enough:
//   - MATRIX: schema = daemon_wired → /__ioi/ontology/manager, with a real reference_landmarks spec.
//     approvals is also daemon_wired → /__ioi/governance/approvals (the faithful light re-port, #36).
//   - REFERENCE VALID + LIGHT: /__apps/schema boots the Ontology-Manager grammar, non-errored.
//   - FAITHFUL PORTED SHELL: the og-shell (dark global rail + light app rail + light card-first body),
//     LIGHT theme, card-first — NOT the dark automationsShell and NOT the earlier dark om-shell.
//   - VISUAL PARITY (hardened harness): visual_parity TRUE — region geometry + THEME MATCH (light/light)
//     + full reproduction of the reference IA landmarks — both sides valid, real screenshots.
//   - DAEMON TRUTH: a real fixture DomainOntology's typed COM renders (object type card · property ·
//     value type · link · action · function); the app-rail "Object types" count matches the fixture;
//     the ontology switcher lists every ontology in the live daemon.
//   - READ-ONLY + NAMED GAPS: Proposals / Shared properties / Groups / Interfaces / Cleanup are disabled
//     lanes in place; action/function execution are declarations-only; authoring routes to /__ioi/odk.
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

  // 0. Matrix — schema is daemon_wired with a real landmark spec; approvals is also daemon_wired (#36).
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies schema as daemon_wired → /__ioi/ontology/manager (TRUE parity)", bySlug.schema?.parity_class === "daemon_wired" && bySlug.schema?.port_surface === "/__ioi/ontology/manager" && bySlug.schema?.candidate_surface === "/__ioi/ontology/manager");
  ok("schema carries a real reference_landmarks spec (≥ 5 IA labels the hardened harness requires)", Array.isArray(bySlug.schema?.reference_landmarks) && bySlug.schema.reference_landmarks.length >= 5 && bySlug.schema.reference_landmarks.includes("Discover") && bySlug.schema.reference_landmarks.includes("Object types"), (bySlug.schema?.reference_landmarks || []).length + " landmarks");
  ok("approvals is also daemon_wired (the faithful light re-port, #36) — schema is not the only parity surface", bySlug.approvals?.parity_class === "daemon_wired" && Array.isArray(bySlug.approvals?.reference_landmarks) && bySlug.approvals.reference_landmarks.length >= 5);
  ok("daemon_wired is sacred: reference_capture is the majority; no false 'covered'", (matrix.by_parity_class?.reference_capture || 0) > (matrix.by_parity_class?.daemon_wired || 0) && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference boots (valid, non-errored). It is a third-party light capture — brand strings on the
  // reference are expected; brand-clean is asserted on the IOI PORT below, not on the capture.
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

  // 2. FAITHFUL PORTED SHELL — the og-shell (dark global rail + light app rail + light card-first body),
  //    LIGHT theme, NOT automationsShell and NOT the earlier dark om-shell.
  const portDefault = await page(`${SERVE}/__ioi/ontology/manager`);
  const td = portDefault.text;
  ok("the ported manager is the two-rail og-shell (global rail + app rail + <main> body + header)", portDefault.status === 200 && /class="og-shell"/.test(td) && /class="og-grail"/.test(td) && /class="og-arail"/.test(td) && /<main class="og-body"[^>]*role="main"/.test(td) && /class="og-header"/.test(td));
  ok("the port is LIGHT-themed (not automationsShell, not the earlier dark om-shell)", /html\{color-scheme:light\}/.test(td) && /background:#f4f5f7/.test(td) && !/color-scheme:dark/.test(td) && !/background:#0c0d10/.test(td) && !/class="wrap"/.test(td) && !/class="om-shell"/.test(td) && !/max-width:920px/.test(td));
  ok("<title>Ontology Manager</title> + card-first body (Discover object-type cards)", /<title>Ontology Manager/.test(td) && /id="og-discover"/.test(td) && /class="og-cards"/.test(td) && /Object types recently modified in/.test(td));
  ok("the app rail reproduces the reference IA (Discover / Resources · typed sections · Health / Configuration)", ["Discover", "Resources", "Object types", "Properties", "Link types", "Action types", "Value types", "Functions", "Health issues", "Ontology configuration"].every((l) => td.includes(l)));

  // 3. VISUAL PARITY — the HARDENED harness certifies against the VALID light reference.
  const artDir = path.join(appRoot, ".artifacts", "ontology-manager-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "schema", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("HARDENED harness: the port PASSES visual_parity — theme MATCH (light/light) + full IA-landmark reproduction + region geometry, both sides valid", hp && hp.visual_parity === true && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light" && hp.reference_valid === true && hp.ioi_valid === true && hp.evidence_ok === true, hp ? `visual=${hp.visual_parity} regions ${hp.region_score} theme ${hp.reference_theme}/${hp.ioi_theme} landmarks ${hp.landmark_covered}/${hp.landmark_applicable}` : "harness did not run");
  ok("the port reproduces ALL of the reference's IA landmarks (coverage 1.0) + the core shell regions", hp && hp.landmark_applicable >= 8 && hp.landmark_covered === hp.landmark_applicable && ["rail", "header", "body"].every((r) => hp.ioi_regions.includes(r)) && (hp.landmarks_missing || []).length === 0, hp ? `missing: ${(hp.landmarks_missing || []).join(",") || "none"}` : "");

  // 4. DAEMON TRUTH — the real fixture's typed COM renders + counts cross-check the live daemon.
  const onts = (await jd("GET", "/v1/hypervisor/odk/domain-ontologies")).j.ontologies || [];
  const portFix = await page(`${SERVE}/__ioi/ontology/manager?ontology=${encodeURIComponent(fix.id)}`);
  const t = portFix.text;
  ok("the fixture ontology renders (domain · ref) — real daemon truth", fix && t.includes(DOM) && t.includes(fix.ref));
  ok("the typed CanonicalObjectModel renders (object-type card · property · value type · link · action · function)", ["GadgetKind", "TitleProp", "LabelText", "RelatedGadget", "MakeGadget", "ScoreGadget"].every((s) => t.includes(s)), ["GadgetKind", "TitleProp", "LabelText", "RelatedGadget", "MakeGadget", "ScoreGadget"].filter((s) => !t.includes(s)).join(",") || "all present");
  ok("CROSS-CHECK: the app-rail 'Object types' count matches the fixture COM (1)", /Object types<span class="og-c">1<\/span>/.test(t), (t.match(/Object types<span class="og-c">\d+<\/span>/) || [])[0] || "");
  ok("CROSS-CHECK: the ontology switcher lists every ontology in the live daemon", (t.match(/class="og-ontoitem/g) || []).length === onts.length && onts.length > 0, `menu ${(t.match(/class="og-ontoitem/g) || []).length} · daemon ${onts.length}`);
  ok("the fixture object-type card renders its real object + dependent counts", /class="og-card"/.test(t) && /object/.test(t) && /dependent/.test(t));

  // 5. READ-ONLY + NAMED GAPS disabled in place; authoring routes to the substrate.
  ok("named-gap lanes are DISABLED in place (Proposals · Shared properties · Groups · Interfaces · Cleanup), not hidden", ["Proposals", "Shared properties", "Groups", "Interfaces", "Cleanup"].every((l) => new RegExp(`<span class="og-nav gap"[^>]*>${l}`).test(t)));
  ok("action + function EXECUTION are named gaps (declarations only)", /Action <b>declarations<\/b> only/.test(t) && /Function <b>declarations<\/b> only/.test(t) && /in-canvas schema editing/.test(t));
  ok("the authoring lane routes to the /__ioi/odk substrate (Configure model)", /Configure model in substrate/.test(t) && new RegExp(`/__ioi/odk/ontologies/${fix.id}/edit`).test(t));

  // 6. DISCOVERABILITY — the /__ioi/odk substrate links the ported manager first-class; brand-clean.
  const odk = await page(`${SERVE}/__ioi/odk`);
  ok("the /__ioi/odk substrate links the ported Ontology Manager first-class", odk.status === 200 && odk.text.includes("/__ioi/ontology/manager"));
  ok("reference linked as secondary; substrate reachable from the port; brand-clean IOI surface", t.includes("/__apps/schema") && t.includes("/__ioi/odk") && !/\bPalantir\b|\bFoundry\b/.test(t));

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
