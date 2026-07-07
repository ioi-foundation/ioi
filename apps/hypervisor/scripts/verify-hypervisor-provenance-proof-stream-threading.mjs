#!/usr/bin/env node
// Provenance proof-stream threading done-bar.
//
// The ODK materialization receipts (each materialized object set registered behind a pre-output
// receipt) are now THREADED into the Provenance proof stream (backing route /v1/hypervisor/work-
// ledger; surface Provenance) — BY REFERENCE. The projection is read-time: it references the
// EXISTING receipts and mints nothing, so receipt authority is not duplicated. This turns the
// lineage surface's "0 Provenance proof-stream edges" into real cross-plane edges.
//
// Asserts:
//   - A freshly materialized object set appears in the proof stream as an `odk_materialization`
//     entry that references the full chain (set · run · session · plan) and whose proof pointer IS
//     the set's EXISTING pre-output receipt (receipt_ref === the set's pre_output_receipt_ref).
//   - NO DUPLICATE AUTHORITY: reading the proof stream mints nothing — the ODK receipt + set record
//     counts on disk are unchanged across repeated reads, and the projection is idempotent (the
//     odk_materialization entry count for our set stays exactly 1).
//   - The lineage surface renders the real edge (kind + existing receipt + "no receipt authority is
//     duplicated"), not the 0-edge gap.
//   - HONEST STILL: an ontology that materialized nothing contributes NO odk_materialization entry
//     and its lineage shows 0 edges.
//   - The Provenance surface (/__ioi/work-ledger) still renders (regression).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-provenance-proof-stream-threading.mjs
// Exit 2 = BLOCKED.

import http from "node:http";
import { readdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const grantFor = (ch) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const dirCount = (d) => { try { return readdirSync(path.join(DATA, d)).length; } catch { return -1; } };
const stream = async () => (await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [];

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon proof stream not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const SENTINEL = "thread-parity-bearer";

  // Build a real materialized object set (fixture) → the receipts to thread.
  const rows = [{ id: "L-1", disp: "First Loan", amt: 1250.5 }, { id: "L-2", disp: "Second Loan", amt: 90000 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "thread-parity", base_url: `http://127.0.0.1:${port}`, name: "Thread Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "thread-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "thread-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "thread-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "thread-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "thread-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "thread-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "thread-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "thread-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "thread-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const set = ex.j.materialized_object_set;
  if (set?.id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${set.id}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the fixture"); srv.close(); process.exit(2); }

  // 1. The set is threaded into the proof stream, referencing the EXISTING pre-output receipt.
  const entries = await stream();
  const mine = entries.find((e) => e.kind === "odk_materialization" && e.materialized_set_ref === set.ref);
  ok("a materialized set is threaded into the Provenance proof stream as odk_materialization", !!mine, mine ? "present" : "missing");
  ok("the entry references the full chain (set · run · session · plan)", mine && mine.materializing_run_ref === set.materializing_run_ref && mine.connector_session_ref === set.connector_session_ref && mine.capability_lease_plan_ref === set.capability_lease_plan_ref);
  ok("the proof pointer IS the set's EXISTING pre-output receipt (referenced, not re-minted)", mine && mine.receipt_ref === set.pre_output_receipt_ref && mine.pre_output_receipt_ref === set.pre_output_receipt_ref);
  ok("the entry declares its authority rule: the stream mints no receipt here", /mints no receipt/.test(mine?.authority_rule || ""));
  ok("the entry carries the outcome + object count (registered · 2)", mine?.status === "registered" && mine?.object_count === 2);

  // 2. No duplicate authority: reading the stream mints nothing; the projection is idempotent.
  const recBefore = dirCount("odk-materializing-run-receipts");
  const setBefore = dirCount("odk-materialized-object-sets");
  await stream(); await stream(); await stream();
  const recAfter = dirCount("odk-materializing-run-receipts");
  const setAfter = dirCount("odk-materialized-object-sets");
  ok("NO DUPLICATE AUTHORITY: repeated proof-stream reads mint no ODK receipt", recBefore >= 0 && recBefore === recAfter, `${recBefore} → ${recAfter}`);
  ok("NO DUPLICATE OUTPUT: repeated reads register no new object set", setBefore >= 0 && setBefore === setAfter, `${setBefore} → ${setAfter}`);
  const again = await stream();
  ok("idempotent projection: exactly ONE odk_materialization entry for our set (no accumulation)", again.filter((e) => e.kind === "odk_materialization" && e.materialized_set_ref === set.ref).length === 1);
  ok("no work-ledger/proof-stream receipt FAMILY is written (read-time projection only)", dirCount("work-ledger-receipts") === -1 && dirCount("provenance-stream-receipts") === -1);

  // 3. The lineage surface renders the real edge, not the gap.
  const lin = await page(`${SERVE}/__ioi/lineage?ontology=${encodeURIComponent(ont.id)}`);
  const t = lin.text;
  ok("lineage surface shows the real threaded edge (odk_materialization + existing receipt)", />odk_materialization</.test(t) && t.includes(set.pre_output_receipt_ref) && /no receipt authority is duplicated/.test(t));
  ok("lineage surface no longer shows the 0-edge 'not yet threaded' gap for a built chain", !/not yet threaded/.test(t) && !/0 Provenance proof-stream edges/.test(t));

  // 4. Still honest — a fresh ontology contributes no entry and shows 0 edges.
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "thread-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "A", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology;
  track("domain-ontologies", fresh?.id);
  const s2 = await stream();
  ok("a fresh (unmaterialized) ontology contributes NO odk_materialization entry", !s2.some((e) => e.kind === "odk_materialization" && e.ontology_ref === fresh.ref));

  // 5. Regression: the Provenance surface still renders with the new kind present.
  const prov = await page(`${SERVE}/__ioi/work-ledger`);
  ok("regression: the Provenance surface (/__ioi/work-ledger) still renders", prov.status === 200 && /Provenance/.test(prov.text) && !/\bPalantir\b/.test(prov.text));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`provenance-proof-stream-threading readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
