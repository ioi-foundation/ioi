#!/usr/bin/env node
// Application UX Parity Baseline — Pipeline Builder done-bar.
//
// The estate-wide parity phase, proven on its first surface. Doctrine: reference UX parity first
// (local capture, no live re-harvest, no invented daemon truth), IOI substrate underneath (bind
// supported lanes to daemon truth, keep unsupported lanes as honest named gaps), IOI-native later.
//
// Asserts:
//   - REFERENCE BASELINE: /__apps/pipeline boots the reference Pipeline Builder grammar (title +
//     Build/Preview/Transform toolbar) brand-clean — the familiar starting point.
//   - IOI SURFACE = SAME GRAMMAR: /__ioi/pipeline renders "Pipeline Builder" with the same
//     datasource → transform → output node flow + Build/Preview toolbar, over DAEMON TRUTH.
//   - SUPPORTED LANES = DAEMON TRUTH: a fully-built pipeline (a real materializing run, executed)
//     shows 7/7 stages live, a "built" banner, the real object-instance count, and the first
//     materialized rows in Preview.
//   - UNSUPPORTED LANES = NAMED GAPS: Schedule + Deploy shown unavailable; freeform authoring is a
//     reference-only lane; the capture is linked as the secondary baseline, never rebound.
//   - CONDITIONALLY HONEST: a fresh ontology's pipeline is "not built" with 0/7 stages live.
//   - PARITY MATRIX current + honest: pipeline=daemon_bound, vertex+lineage=queued, rest
//     reference_capture; no false "covered".
//   - No brand/reference leak; the ODK ladder itself remains intact (Ontology Manager still renders).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-pipeline.mjs
// Exit 2 = BLOCKED (daemon/capture not running).

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
  const SENTINEL = "pipeline-parity-bearer";

  // 0. The parity matrix is current + honest (child process --check).
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies pipeline as daemon_bound → /__ioi/pipeline", bySlug.pipeline?.parity_class === "daemon_bound" && bySlug.pipeline?.daemon_surface === "/__ioi/pipeline");
  ok("matrix queues the graph pair (vertex + lineage) — named, not claimed covered", bySlug.vertex?.parity_class === "queued" && bySlug.lineage?.parity_class === "queued");
  ok("matrix is honest estate-wide: most seeds are reference_capture only, none over-claimed", (matrix.by_parity_class?.reference_capture || 0) >= 30 && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference baseline boots the familiar grammar, brand-clean.
  const ref = await page(`${SERVE}/__apps/pipeline`);
  ok("reference baseline /__apps/pipeline boots the Pipeline Builder grammar (brand-clean)", ref.status === 200 && /<title>[^<]*Pipeline Builder/.test(ref.text) && !/\bPalantir\b/.test(ref.text));

  // Fixture row server (auth-checked) → build a REAL pipeline end to end.
  const rows = [{ id: "L-1", disp: "First Loan", amt: 1250.5 }, { id: "L-2", disp: "Second Loan", amt: 90000 }, { id: "L-3", disp: "Third Loan", amt: 42.0 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "pipe-parity", base_url: `http://127.0.0.1:${port}`, name: "Pipe Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });

  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "pipe-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "pipe-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "pipe-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "pipe-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "pipe-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "pipe-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "pipe-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "pipe-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "pipe-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setId = ex.j.materialized_object_set?.id;
  if (setId) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the pipeline fixture"); srv.close(); process.exit(2); }

  // 2. The IOI surface renders the SAME grammar over the built pipeline's daemon truth.
  const built = await page(`${SERVE}/__ioi/pipeline?ontology=${encodeURIComponent(ont.id)}`);
  const t = built.text;
  ok("IOI /__ioi/pipeline renders the Pipeline Builder grammar (title + Build/Preview toolbar)", built.status === 200 && /<h1[^>]*>Pipeline Builder/.test(t) && />▶ Build</.test(t) && /#pipeline-preview/.test(t));
  ok("same node grammar: datasource → transform → output stages present", ["Datasource", "Object mapping", "Policy gate", "Transform plan", "Read projection", "Materialized objects"].every((n) => t.includes(`>${n}<`)));
  ok("SUPPORTED LANES = daemon truth: a built pipeline shows 7/7 stages live + built banner", /7\/7 stages live/.test(t) && /pill ok">built/.test(t));
  ok("output node carries the real object-instance count (3)", /3 object instances/.test(t) || /<b>3<\/b> objects/.test(t));
  ok("Preview shows the first materialized rows (daemon truth, not a mock)", /id="pipeline-preview"/.test(t) && />L-1</.test(t) && />First Loan</.test(t));

  // 3. Unsupported lanes are honest named gaps; capture is the secondary baseline.
  ok("UNSUPPORTED LANES = named gaps: Schedule + Deploy shown unavailable", /Schedule · unavailable/.test(t) && /Deploy · unavailable/.test(t));
  ok("freeform authoring is a reference-only lane (honest)", /reference-only lanes/.test(t));
  ok("reference capture linked as the secondary baseline, never rebound", t.includes("/__apps/pipeline"));
  ok("IOI surface is brand/reference clean", !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // 4. Conditionally honest — a fresh ontology's pipeline is "not built".
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "pipe-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "A", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const freshPage = await page(`${SERVE}/__ioi/pipeline?ontology=${encodeURIComponent(fresh)}`);
  ok("a fresh ontology's pipeline is honestly 'not built' (0/7 stages live)", /pill muted">not built/.test(freshPage.text) && /0\/7 stages live/.test(freshPage.text));

  // 5. The ODK ladder itself is intact + cross-links to the pipeline view.
  const odk = await page(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ont.id)}`);
  ok("the ODK ladder is intact (Ontology Manager still renders) + links to the pipeline view", /Ontology Manager/.test(odk.text) && odk.text.includes("/__ioi/pipeline"));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-pipeline readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
