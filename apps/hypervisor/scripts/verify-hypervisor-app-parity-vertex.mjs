#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier (reclassified substrate_bound by the #31 Reference-UX-Port reset — checks DAEMON TRUTH, NOT reference UX parity) — Vertex (Provenance graph/exploration lens) done-bar.
//
// The parity phase's fourth surface, and the cross-plane one. /__apps/vertex is the reference
// baseline; the IOI-owned /__ioi/vertex renders the SAME graph-exploration grammar (node-type
// catalog + node inventory + neighborhood expansion + relations) but over REAL materialized truth:
// object sets, projections, materializing runs, objects, and — crucially — the THREADED Provenance
// proof-stream `odk_materialization` edges (#23), which make this a CROSS-PLANE graph (ODK ↔
// Provenance) rather than another isolated view over ODK records. No graph is invented: an ontology
// with no materialized objects shows NO graph; freeform Vertex lanes are named gaps.
//
// Asserts:
//   - REFERENCE BASELINE: /__apps/vertex boots the Vertex graph grammar, brand-clean.
//   - IOI SURFACE = DAEMON TRUTH (substrate, not reference UX parity): for a freshly materialized fixture object set,
//     /__ioi/vertex renders the node-type catalog (real counts), the node inventory (real ladder
//     refs), and a neighborhood expansion of the newest set with typed relations (projected_by /
//     produced_by / proven_by / contains) carrying real projection · run · proof · object refs.
//   - CROSS-PLANE: the neighborhood's `proven_by` relation is the threaded proof-stream
//     odk_materialization edge, and the cross-plane note links to the Provenance proof stream.
//   - NO FAKE NODES: a fresh/unmaterialized ontology shows "no graph to explore" — empty graph, zero
//     catalog, zero source hashes (the grammar remains, but no data is fabricated).
//   - HONEST GAPS: unsupported Vertex lanes named (freeform canvas / path-finding / cross-tenant /
//     saved explorations). Reference capture linked as secondary; brand-clean.
//   - MATRIX current + honest: vertex=substrate_bound → /__ioi/vertex, Provenance lens.
//   - Regression: the lineage surface (#22/#23) still renders and now links back to Vertex.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-vertex.mjs
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
  const SENTINEL = "vertex-parity-bearer";

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies vertex as substrate_bound → /__ioi/vertex", bySlug.vertex?.parity_class === "substrate_bound" && bySlug.vertex?.substrate_surface === "/__ioi/vertex");
  ok("matrix keeps vertex a Provenance lens (canon: Work Ledger evolves into Provenance)", bySlug.vertex?.surface_name === "Provenance" && /Provenance graph\/exploration lens/.test(bySlug.vertex?.binding || ""));
  ok("matrix declares vertex cross-plane (ODK ↔ Provenance proof-stream edges)", /cross-plane/.test(bySlug.vertex?.binding || "") && /odk_materialization/.test(bySlug.vertex?.binding || ""));

  // 1. Reference baseline. (The /__apps/ capture is the raw familiar original; brand-clean is
  // enforced on the IOI-owned /__ioi/vertex surface below, not on the captured baseline.)
  const ref = await page(`${SERVE}/__apps/vertex`);
  ok("reference baseline /__apps/vertex boots the Vertex graph grammar", ref.status === 200 && /<title>[^<]*[Vv]ertex/.test(ref.text));

  // Build a REAL materialized object set (fixture) → the graph Vertex explores.
  const rows = [{ id: "V-1", disp: "First Loan", amt: 1250.5 }, { id: "V-2", disp: "Second Loan", amt: 90000 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "vtx-parity", base_url: `http://127.0.0.1:${port}`, name: "Vtx Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "vtx-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "vtx-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "vtx-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "vtx-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "vtx-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "vtx-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "vtx-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "vtx-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "vtx-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setRec = ex.j.materialized_object_set;
  const setId = setRec?.id;
  if (setId) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the vertex fixture"); srv.close(); process.exit(2); }

  // Resolve the real ladder refs the graph should carry.
  const projRec = (await jd("GET", `/v1/hypervisor/odk/ontology-projections/${proj}`)).j.ontology_projection;

  // 2. IOI Vertex = graph grammar over real truth.
  const vtx = await page(`${SERVE}/__ioi/vertex?ontology=${encodeURIComponent(ont.id)}`);
  const t = vtx.text;
  ok("IOI /__ioi/vertex renders the Vertex graph grammar (title + node catalog + neighborhood)", vtx.status === 200 && /<h1[^>]*>Vertex/.test(t) && /id="vertex-nodes"/.test(t) && /id="vertex-neighborhood"/.test(t));
  ok("node-type catalog present (Object set · Projection · Materializing run · Object · Proof-stream edge)", ["Object set", "Projection", "Materializing run", "Object", "Proof-stream edge"].every((l) => t.includes(l)));
  ok("catalog counts are REAL (≥1 set, 2 objects, 1 cross-plane proof edge)", /📦 1/.test(t) && /▪ 2/.test(t) && /🧾 1/.test(t) && /cross-plane/.test(t));

  // 3. Node inventory carries the real resolved refs.
  ok("node inventory carries the REAL set + projection refs (not fabricated labels)", setRec?.ref && projRec?.ref && t.includes(String(setRec.ref).slice(0, 26)) && t.includes(String(projRec.ref).slice(0, 26)));

  // 4. Neighborhood expansion = typed relations over the newest set.
  ok("neighborhood expands the newest set with typed relations (projected_by · produced_by · proven_by · contains)", ["projected_by", "produced_by", "proven_by", "contains"].every((r) => t.includes(`>${r}<`)));
  ok("relations carry real targets — the set's materializing_run_ref + a real object (V-1) with source hash (sha256)", setRec?.materializing_run_ref && t.includes(String(setRec.materializing_run_ref).slice(0, 20)) && /Object V-1/.test(t) && /sha256:/.test(t));

  // 5. CROSS-PLANE — the proof-stream edge makes this a cross-plane graph.
  ok("cross-plane: a threaded odk_materialization proof edge connects the set to the Provenance proof stream", /Cross-plane:/.test(t) && />odk_materialization</.test(t) && t.includes("/__ioi/work-ledger") && /threaded/.test(t));
  ok("proof edge is a first-class graph node (proven_by relation → Provenance), not an isolated ODK record", /proven_by/.test(t) && /Proof-stream edge \(Provenance\)/.test(t));

  // 6. Honest gaps + cross-links + brand-clean.
  ok("unsupported Vertex lanes named (freeform canvas / path-finding / cross-tenant / saved explorations)", /freeform graph canvas, arbitrary path-finding, cross-tenant object search, saved explorations/.test(t));
  ok("cross-links to the Lineage path + Pipeline; reference capture linked as secondary", t.includes("/__ioi/lineage") && t.includes("/__ioi/pipeline") && t.includes("/__apps/vertex"));
  ok("terminology: no 'Work Ledger' UI prose leaks; brand-clean (no Palantir/Foundry)", !/Work Ledger app/.test(t) && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));
  // DISCOVERABILITY: Vertex is a substrate_bound PROVENANCE lens, so the owning Provenance surface
  // (/__ioi/work-ledger) must link to it first-class — not only via Lineage/Pipeline deep links.
  const prov = await page(`${SERVE}/__ioi/work-ledger`);
  ok("the owning Provenance surface (/__ioi/work-ledger) links to Vertex first-class", prov.status === 200 && prov.text.includes("/__ioi/vertex"));

  // 7. NO FAKE NODES for an unmaterialized ontology.
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "vtx-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "A", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const freshPage = await page(`${SERVE}/__ioi/vertex?ontology=${encodeURIComponent(fresh)}`);
  const ft = freshPage.text;
  ok("fresh ontology shows 'no graph to explore' — empty graph, ZERO catalog, ZERO source hashes (no fabrication)", /no graph to explore/.test(ft) && /empty graph/.test(ft) && !/id="vertex-nodes"/.test(ft) && !/sha256:/.test(ft));
  ok("fresh ontology keeps the grammar (title + reference baseline) but invents no data", /<h1[^>]*>Vertex/.test(ft) && ft.includes("/__apps/vertex"));

  // 8. Regression: the lineage surface still renders and now links back to Vertex.
  const lin = await page(`${SERVE}/__ioi/lineage?ontology=${encodeURIComponent(ont.id)}`);
  ok("regression: the #22/#23 lineage surface still renders and links back to Vertex (Explore graph)", /Data lineage/.test(lin.text) && lin.text.includes("/__ioi/vertex") && />Explore graph</.test(lin.text));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`substrate-truth-vertex readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
