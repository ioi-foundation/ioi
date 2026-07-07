#!/usr/bin/env node
// Application UX Parity Baseline — Monocle / Data Lineage done-bar.
//
// The parity phase's second surface. /__apps/lineage (Monocle) is the reference baseline; the
// IOI-owned /__ioi/lineage renders the SAME lineage-graph grammar (typed nodes + edges + legend) but
// over REAL PROVENANCE from the ODK materialization chain. No graph data is invented: an ontology
// with no materialized objects shows NO lineage; freeform Monocle lanes are named gaps.
//
// Asserts:
//   - REFERENCE BASELINE: /__apps/lineage boots the Monocle "Data lineage" grammar, brand-clean.
//   - IOI SURFACE = SAME GRAMMAR OVER REAL PROVENANCE: for a freshly materialized fixture object set,
//     /__ioi/lineage renders the typed provenance path (Datasource → Mapping → Projection → Lease +
//     session → Materializing run → Pre-output receipt → Object set) with typed edges, plus
//     PER-OBJECT provenance (real source hashes + property ← source-field mapped_from edges) and the
//     run's receipt chain.
//   - NO FAKE NODES: a fresh/unmaterialized ontology shows "no lineage" with zero provenance nodes
//     and zero source hashes (the legend grammar remains, but no data is fabricated).
//   - HONEST GAPS: Work Ledger edges shown "where available" (0 for the ODK chain today, named);
//     unsupported Monocle lanes (resource search / graph expansion / cross-tenant catalog) named.
//   - MATRIX current + honest: lineage=daemon_bound → /__ioi/lineage; vertex stays queued.
//   - Brand-clean; the pipeline surface (#21) still renders (regression hold).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-lineage.mjs
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
  const SENTINEL = "lineage-parity-bearer";

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies lineage as daemon_bound → /__ioi/lineage", bySlug.lineage?.parity_class === "daemon_bound" && bySlug.lineage?.daemon_surface === "/__ioi/lineage");
  ok("matrix keeps vertex queued (not claimed covered); pipeline still daemon_bound", bySlug.vertex?.parity_class === "queued" && bySlug.pipeline?.parity_class === "daemon_bound");

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/lineage`);
  ok("reference baseline /__apps/lineage boots the Monocle 'Data lineage' grammar (brand-clean)", ref.status === 200 && /<title>[^<]*[Ll]ineage/.test(ref.text) && !/\bPalantir\b/.test(ref.text));

  // Build a REAL materialized object set (fixture) → the provenance the lineage traces.
  const rows = [{ id: "L-1", disp: "First Loan", amt: 1250.5 }, { id: "L-2", disp: "Second Loan", amt: 90000 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "lin-parity", base_url: `http://127.0.0.1:${port}`, name: "Lin Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "lin-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "lin-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "lin-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "lin-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "lin-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "lin-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "lin-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "lin-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "lin-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setId = ex.j.materialized_object_set?.id;
  if (setId) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the lineage fixture"); srv.close(); process.exit(2); }

  // 2. Real provenance path + edges.
  const lin = await page(`${SERVE}/__ioi/lineage?ontology=${encodeURIComponent(ont.id)}`);
  const t = lin.text;
  ok("IOI /__ioi/lineage renders the Monocle 'Data lineage' grammar (title + legend)", lin.status === 200 && /<h1[^>]*>Data lineage/.test(t) && /chiplabel">Nodes/.test(t) && /chiplabel">Edges/.test(t));
  ok("typed provenance PATH present (datasource → … → object set)", ["Datasource", "Mapping", "Projection", "Lease + session", "Materializing run", "Pre-output receipt", "Object set"].every((n) => t.includes(`${n}<`)));
  ok("typed EDGES present (mapped_by · projected_as · produced_by · receipted_by · contains)", ["mapped_by", "projected_as", "produced_by", "receipted_by", "contains"].every((e) => t.includes(`>${e}<`)));

  // 3. Per-object provenance — the real new truth.
  ok("object provenance pane renders real objects (L-1) + source hashes (sha256)", /id="lineage-objects"/.test(t) && />L-1</.test(t) && /sha256:/.test(t));
  ok("mapped_from edges are REAL (each property ← its source field)", /mapped_from/.test(t) && t.includes(">loan_id</code>") && t.includes(">title</code>") && t.includes(">amount</code>"));
  ok("receipt chain shows the run's registration act", /id="lineage-receipts"/.test(t) && /materialized_output_registered/.test(t));

  // 4. Honest gaps.
  ok("Work Ledger edges shown 'where available' — honest 0 for the ODK chain (named gap)", /0 Work Ledger edges/.test(t));
  ok("unsupported Monocle lanes named (resource search / graph expansion / cross-tenant catalog)", /resource search, arbitrary graph expansion, cross-tenant catalog/.test(t));
  ok("reference capture linked as secondary baseline; brand-clean", t.includes("/__apps/lineage") && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // 5. NO FAKE NODES for an unmaterialized ontology.
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "lin-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "A", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const freshPage = await page(`${SERVE}/__ioi/lineage?ontology=${encodeURIComponent(fresh)}`);
  const ft = freshPage.text;
  ok("fresh ontology shows 'no lineage' with ZERO provenance nodes + ZERO source hashes (no fabrication)", /no lineage/.test(ft) && /no lineage to show/.test(ft) && !/id="lineage-graph"/.test(ft) && !/sha256:/.test(ft));
  ok("fresh ontology keeps the grammar (legend + title) but invents no data", /Data lineage/.test(ft) && /chiplabel">Nodes/.test(ft));

  // 6. Regression: the pipeline surface still renders.
  const pipe = await page(`${SERVE}/__ioi/pipeline?ontology=${encodeURIComponent(ont.id)}`);
  ok("regression: the #21 Pipeline Builder still renders + links to lineage", /Pipeline Builder/.test(pipe.text) && pipe.text.includes("/__ioi/lineage"));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-lineage readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
