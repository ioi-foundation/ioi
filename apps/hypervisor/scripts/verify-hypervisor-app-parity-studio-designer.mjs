#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier (reclassified substrate_bound by the #31 Reference-UX-Port reset — checks DAEMON TRUTH, NOT reference UX parity) — Studio · Designer done-bar (designer seed only).
//
// The parity phase's seventh surface, and the first of the Studio canvas family. The reference
// capture (/__apps/designer = the solution-design canvas) is the familiar typed concept/component/
// resource DESIGN canvas; the IOI-owned /__ioi/studio/designer renders the SAME grammar as a
// READ-ONLY typed map over REAL daemon composition truth:
//   * CONCEPTS   — an ontology's canonical object model (object / value / action / link types);
//   * COMPONENTS — the composition that shapes them (connector mappings · policy views · projections);
//   * RESOURCES  — what that composition generates (materialized object sets · domain-app descriptors).
// Nothing is authored/saved here.
//
// SCOPE (tight, by direction): only `designer` binds. `machinery`, `workshop`, `module` stay
// reference_capture. Owner surface stays /__ioi/agent-studio (no route rename); the designer gets a
// dedicated /__ioi/studio/designer surface the owner links to.
//
// Because the map is a read-only projection over real ODK composition, the guard is a CROSS-CHECK:
// build a real ontology + its full ladder (mapping → view → projection → materialized set), then
// assert the map renders those exact concepts/components/resources — and an unbound ontology shows
// honest-empty component/resource lanes (no fabrication).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-studio-designer.mjs
// Exit 2 = BLOCKED.

import http from "node:http";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

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

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix binds designer as substrate_bound → /__ioi/studio/designer (Studio)", bySlug.designer?.parity_class === "substrate_bound" && bySlug.designer?.substrate_surface === "/__ioi/studio/designer" && bySlug.designer?.surface_name === "Studio");
  ok("matrix keeps workshop + module reference_capture (designer's siblings NOT over-claimed)", ["workshop", "module"].every((k) => bySlug[k]?.parity_class === "reference_capture"));
  ok("no 'covered' anywhere; prior substrate_bound surfaces intact (pipeline/lineage/vertex/jobs/incidents/evalsuites)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex", "jobs", "incidents", "evalsuites"].every((k) => bySlug[k]?.parity_class === "substrate_bound"));

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/designer`);
  ok("reference baseline /__apps/designer boots the design-canvas grammar", ref.status === 200 && /<title>[^<]*(Design|Solution)/i.test(ref.text));

  // 2. Build a real ontology + full ladder → the composition the map reflects.
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
  // Resources lane must render — the regression the review caught (filter was on the singular field).
  const sd = (await jd("POST", "/v1/hypervisor/odk/surface-descriptors", { name: "dsg-parity-sd", composition_pattern: "domain_app", ontology_ref: ont.ref, recipe_refs: [] })).j.surface_descriptor;
  const dapp = (await jd("POST", "/v1/hypervisor/domain-apps", { name: "Dsg Parity App", description: "draft", surface_descriptor_ref: sd?.ref, visibility: "private" })).j.domain_app;
  if (dapp?.domain_app_id) cleanup.unshift(["DELETE", `/v1/hypervisor/domain-apps/${dapp.domain_app_id}`]);
  if (sd?.id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/surface-descriptors/${sd.id}`]);
  ok("fixture sanity: the DomainApp derived ontology_refs (array) includes this ontology", Array.isArray(dapp?.ontology_refs) && dapp.ontology_refs.includes(ont.ref), JSON.stringify(dapp?.ontology_refs || null));

  // 3. IOI surface = the design-map grammar over real composition.
  const dsg = await page(`${SERVE}/__ioi/studio/designer?ontology=${encodeURIComponent(ont.id)}`);
  const t = dsg.text;
  ok("IOI /__ioi/studio/designer renders the design-map grammar (title + concepts/components/resources lanes)", dsg.status === 200 && /<h1[^>]*>Designer/.test(t) && /id="designer-concepts"/.test(t) && /id="designer-components"/.test(t) && /id="designer-resources"/.test(t));
  // CONCEPTS = the real object model.
  ok("CONCEPTS render the real object model (object type Loan + Money value type + Approve action)", t.includes("Loan") && t.includes("Money") && t.includes("Approve") && /🧩 3/.test(t), "1 object + 1 value + 1 action + 0 link = 3 concepts");
  // COMPONENTS = the real composition refs.
  ok("COMPONENTS render the real mapping · policy view · projection refs (not fabricated labels)", mapRec?.ref && viewRec?.ref && projRec?.ref && t.includes(mapRec.ref) && t.includes(viewRec.ref) && t.includes(projRec.ref));
  // RESOURCES = the real generated set + the real DomainApp surface descriptor.
  ok("RESOURCES render the real materialized object set (ref + object count)", setRec?.ref && t.includes(setRec.ref) && new RegExp(`${setRec.count || 2} obj`).test(t));
  ok("RESOURCES render the real DomainApp surface descriptor (domain-app ref + surface-descriptor ref)", dapp?.domain_app_ref && t.includes(dapp.domain_app_ref) && sd?.ref && t.includes(sd.ref), dapp?.domain_app_ref || "no domain app");

  // 4. NO AUTHORING — the map is read-only (no create/save form posting to the surface).
  ok("the surface is READ-ONLY (no authoring form posts to /__ioi/studio/designer)", !/action="\/__ioi\/studio\/designer/.test(t));

  // 5. Honest empty — a fresh ontology has concepts but NO components/resources (no fabrication).
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "dsg-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "Alpha", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const ft = (await page(`${SERVE}/__ioi/studio/designer?ontology=${encodeURIComponent(fresh)}`)).text;
  ok("fresh ontology: CONCEPTS render but COMPONENTS + RESOURCES are honest-empty (no fabrication)", /Alpha/.test(ft) && /No components compose this ontology yet/.test(ft) && /generated <b>no resources<\/b> yet/.test(ft));

  // 6. Named gaps + owner discoverability + brand-clean.
  ok("named gaps: in-canvas authoring / save-open / drag-to-reference / load-lineage", /in-canvas authoring/.test(t) && /save\/open/.test(t) && /load-lineage/.test(t));
  ok("sibling Studio seeds named reference-only (machinery process graph, workshop/module builders)", t.includes("/__apps/machinery") && t.includes("/__apps/workshop") && /workshop<\/a> and module builders/.test(t));
  ok("owner discoverability: Designer links back to /__ioi/agent-studio, and the owner links to the designer", t.includes("/__ioi/agent-studio") && (await page(`${SERVE}/__ioi/agent-studio`)).text.includes("/__ioi/studio/designer"));
  ok("reference capture linked as secondary; IOI surface brand-clean (no Palantir)", t.includes("/__apps/designer") && !/\bPalantir\b/.test(t));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`substrate-truth-studio-designer readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
