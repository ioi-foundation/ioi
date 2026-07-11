#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Studio · Solution Designer done-bar (#49, designer seed only).
//
// The EIGHTH faithful port and the FIRST from the origin-alignment queue (post-#48 clean-pool
// close). The #44 sweep proved the designer reference data-bearing on the capture-origin lane
// (localhost:9225/workspace/solution-design/) while the /__apps/designer proxy lane manufactures
// CORS noise + a favorites-load failure; #49 stamps reference_url_override onto the honest lane,
// REBUILDS /__ioi/studio/designer in place as the faithful light Solution-Designer landing shell,
// and certifies shell-pixel parity against it. What this asserts:
//   1. MATRIX: designer is daemon_wired at /__ioi/studio/designer, origin-aligned
//      (reference_url_override), landmark-pinned, shell_pixel_certified with a REAL committed
//      NON-pinned certification; the census FLOOR accepts the eighth certified surface.
//   2. REFERENCE: the origin lane renders the data-bearing landing (valid, failure-free); the
//      proxy lane stays served AND documented-insufficient (the sweep reason names why).
//   3. SUBSTRATE TRUTH (the same cross-check ladder as the pre-port verifier): a real ontology +
//      full ODK ladder (mapping → policy view → projection → materialized set) + a real DomainApp
//      surface descriptor, then the port must render:
//        * the fixture ontology as a live diagram ROW (name + ref + composition census);
//        * CONCEPTS (Loan object · Money value · Approve action) from the real COM;
//        * COMPONENTS (mapping/view/projection) by their REAL refs;
//        * RESOURCES (materialized set ref + "N obj" count · DomainApp + surface-descriptor refs);
//        * honest em-dashes for creator/edited-by/viewed (no principal/view tracking on the plane);
//        * a fresh ontology stays honest-empty (no fabricated components/resources).
//   4. FAITHFUL SHELL: reference landmarks render; unsupported authoring/planning/browse lanes are
//      DISABLED IN PLACE (named gaps), never silently hidden; read-only; brand-clean.
//   5. NO body pixel claim: the certification is SHELL-scoped; diagram rows are masked live data.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-studio-designer.mjs
// Exit 2 = BLOCKED.

import http from "node:http";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const grantFor = (ch) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/materialized-object-sets/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ODK plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const SENTINEL = "designer-parity-bearer";

  // 0. Matrix current + honest: daemon_wired, origin-aligned, landmark-pinned, census floor.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.designer;
  ok("matrix: designer is daemon_wired at /__ioi/studio/designer (Studio) with Designer-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/studio/designer" && row.surface_name === "Studio" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/solution-design/)", row && row.reference_url_override === "http://localhost:9225/workspace/solution-design/");
  // machinery legally advanced substrate_bound → daemon_wired in #50 (its own certified port PR);
  // a class SET, not a frozen pin — the recurring frozen-pin lesson.
  ok("matrix keeps workshop + module reference_capture and machinery bound (substrate_bound|daemon_wired) — siblings NOT over-claimed", ["workshop", "module"].every((k) => bySlug[k]?.parity_class === "reference_capture") && ["substrate_bound", "daemon_wired"].includes(bySlug.machinery?.parity_class));
  ok("the estate census accepts designer among the certified daemon_wired surfaces (>= 8 since #49); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 8 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Shell-pixel certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null;
  try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
  ok("matrix: designer is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/designer.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: designer slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "designer" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks 10/10, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/solution-design/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (diagram rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract: designer's reference is data_clean on the aligned lane; the proxy lane's
  // insufficiency stays DOCUMENTED (the reason names the CORS/failure evidence).
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sd0 = sweep && (sweep.seeds || []).find((s) => s.slug === "designer");
  ok("clean sweep: designer classifies data_clean on the aligned (origin/override) lane, with real data evidence", sd0 && sd0.clean_state === "data_clean" && ["origin", "override"].includes(sd0.lane_used) && (sd0.data_evidence?.table_rows > 0 || sd0.data_evidence?.cards > 0), sd0 ? `${sd0.clean_state} via ${sd0.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane insufficiency stays documented (CORS/failure evidence in the recorded lanes)", sd0 && (sd0.lanes_summary || []).some((l) => l.lane === "proxy" && (l.cors_signals > 0 || l.api_failures > 0 || l.console_errors > 0)), sd0 ? JSON.stringify((sd0.lanes_summary || []).map((l) => `${l.lane}:cors${l.cors_signals}`)) : "");

  // 1. Reference lanes: the ORIGIN lane renders the data-bearing landing; the proxy lane still serves.
  const origin = await page("http://localhost:9225/workspace/solution-design/");
  ok("origin-aligned reference renders the Solution Designer landing (valid, data-bearing)", origin.status === 200 && /Solution Designer/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/designer`);
  ok("the /__apps/designer proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200 && /<title>[^<]*(Design|Solution)/i.test(ref.text));

  // 2. Build a real ontology + full ladder → the composition the port must reflect.
  const rows = [{ id: "D-1", disp: "First Loan", amt: 1250.5 }, { id: "D-2", disp: "Second Loan", amt: 90000 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "dsg-parity", base_url: `http://127.0.0.1:${port}`, name: "Dsg Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "dsg-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "dsg-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "dsg-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "dsg-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "dsg-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "dsg-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "dsg-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "dsg-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "dsg-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setRec = ex.j.materialized_object_set;
  if (setRec?.id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setRec.id}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the designer fixture"); srv.close(); process.exit(2); }
  const mapRec = (await jd("GET", `/v1/hypervisor/odk/connector-mappings/${map}`)).j.connector_mapping;
  const projRec = (await jd("GET", `/v1/hypervisor/odk/ontology-projections/${proj}`)).j.ontology_projection;
  const viewRec = (await jd("GET", `/v1/hypervisor/odk/policy-bound-data-views/${view}`)).j.policy_bound_data_view;

  // A real DomainApp RESOURCE: a domain_app surface descriptor carrying this ontology_ref → a DomainApp
  // whose ontology_refs (an ARRAY, DERIVED from the descriptor) includes it. This is the resource the
  // Resources lane must render — the regression the earlier review caught (filter was on the singular field).
  const sd = (await jd("POST", "/v1/hypervisor/odk/surface-descriptors", { name: "dsg-parity-sd", composition_pattern: "domain_app", ontology_ref: ont.ref, recipe_refs: [] })).j.surface_descriptor;
  const dapp = (await jd("POST", "/v1/hypervisor/domain-apps", { name: "Dsg Parity App", description: "draft", surface_descriptor_ref: sd?.ref, visibility: "private" })).j.domain_app;
  if (dapp?.domain_app_id) cleanup.unshift(["DELETE", `/v1/hypervisor/domain-apps/${dapp.domain_app_id}`]);
  if (sd?.id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/surface-descriptors/${sd.id}`]);
  ok("fixture sanity: the DomainApp derived ontology_refs (array) includes this ontology", Array.isArray(dapp?.ontology_refs) && dapp.ontology_refs.includes(ont.ref), JSON.stringify(dapp?.ontology_refs || null));

  // 3. The PORT = the faithful landing shell over real composition.
  const dsg = await page(`${SERVE}/__ioi/studio/designer?ontology=${encodeURIComponent(ont.id)}`);
  const t = dsg.text;
  ok("the port renders the faithful Solution-Designer landing shell (header + hero + AIP card + gallery + View row + table + truth band)", dsg.status === 200 && /class="dsg-htitle">Solution Designer</.test(t) && /Have a workflow in mind\? Use AIP Architect/.test(t) && /Explore our library of reference solution architecture diagrams/.test(t) && /class="dsg-viewrow"/.test(t) && /class="dsg-thead"/.test(t) && /id="designer-truth"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");
  // Diagram ROWS = real ontologies (the estate's solution designs).
  ok("the fixture ontology renders as a live diagram ROW (name + ref + composition census in the row path)", /class="dsg-row"/.test(t) && t.includes("dsg-parity") && t.includes(ont.ref) && /concepts · \d+ components · \d+ resources/.test(t));
  ok("creator / last-edited-by / last-viewed cells are HONEST em-dashes naming the gap (no principal/view tracking on the ODK plane)", /dsg-dash/.test(t) && /No principal is recorded on the ODK object plane \(named gap\)/.test(t) && /View tracking is not recorded on the ODK object plane \(named gap\)/.test(t));
  // CONCEPTS = the real object model.
  ok("CONCEPTS render the real object model (Loan object · Money value · Approve action) with the census", t.includes("Loan") && t.includes("Money") && t.includes("Approve") && /1 object · 1 value · 1 action · 0 link types/.test(t));
  // COMPONENTS = the real composition refs.
  ok("COMPONENTS render the real mapping · policy view · projection refs (not fabricated labels)", mapRec?.ref && viewRec?.ref && projRec?.ref && t.includes(mapRec.ref) && t.includes(viewRec.ref) && t.includes(projRec.ref));
  // RESOURCES = the real generated set + the real DomainApp surface descriptor.
  ok("RESOURCES render the real materialized object set (ref + object count)", setRec?.ref && t.includes(setRec.ref) && new RegExp(`${setRec.count || 2} obj`).test(t));
  ok("RESOURCES render the real DomainApp surface descriptor (domain-app ref + surface-descriptor ref)", dapp?.domain_app_ref && t.includes(dapp.domain_app_ref) && sd?.ref && t.includes(sd.ref), dapp?.domain_app_ref || "no domain app");

  // 4. NO AUTHORING — read-only; unsupported lanes DISABLED IN PLACE (named gaps), never hidden.
  ok("the surface is READ-ONLY (no authoring form posts to /__ioi/studio/designer)", !/action="\/__ioi\/studio\/designer/.test(t));
  const gapControls = ["New Diagram", "Help", "Start planning", "Browse all", "Favorites", "Open Diagram"];
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (New Diagram · Help · Start planning · Browse all · Favorites · Open Diagram · gallery arrow)", gapControls.every((c) => new RegExp(`aria-disabled="true"[^>]*title="[^"]*named gap[^"]*"[^>]*>(?:<[^>]+>)*(?:<span>)?${c}|${c}(?:</span>)?(?:<svg[\\s\\S]{0,600}?)?</span>`).test(t)) && (t.match(/aria-disabled="true"/g) || []).length >= 7 && /dsg-galarrow gap/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("named gaps prose: in-canvas authoring / New-Open Diagram / save-open / drag-to-reference / AIP planning / favorites / Browse all", /in-canvas authoring/.test(t) && /save\/open/.test(t) && /drag-to-reference/.test(t) && /AIP Architect planning/.test(t));

  // 5. Honest empty — a fresh ontology has concepts but NO components/resources (no fabrication).
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "dsg-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "Alpha", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const ft = (await page(`${SERVE}/__ioi/studio/designer?ontology=${encodeURIComponent(fresh)}`)).text;
  ok("fresh ontology: CONCEPTS render but COMPONENTS + RESOURCES are honest-empty (no fabrication)", /Alpha/.test(ft) && /No components compose this ontology yet/.test(ft) && /generated <b>no resources<\/b> yet/.test(ft));

  // 6. Discoverability + brand + verbatim-chrome honesty.
  ok("sibling Studio seeds named reference-only (machinery process graph, workshop/module builders) + machinery substrate linked", t.includes("/__apps/machinery") && t.includes("/__apps/workshop") && t.includes("/__ioi/studio/machinery"));
  ok("owner discoverability: Designer links back to /__ioi/agent-studio, and the owner links to the designer", t.includes("/__ioi/agent-studio") && (await page(`${SERVE}/__ioi/agent-studio`)).text.includes("/__ioi/studio/designer"));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/solution-design/") && t.includes("/__apps/designer") && /CORS noise/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));
  ok("the template gallery is declared verbatim capture chrome (vendor template library, never estate data)", /verbatim capture chrome/i.test(t) || /Reference solution-architecture template previews \(verbatim capture chrome\)/.test(t));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-studio-designer readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
