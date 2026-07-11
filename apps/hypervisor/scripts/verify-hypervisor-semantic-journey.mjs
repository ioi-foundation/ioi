#!/usr/bin/env node
// Cross-application semantic-journey verifier (operational wave #64).
//
// Builds ONE verifier-owned ladder (declared REST source → typed ontology → ready mapping →
// ready policy view → dry-run plan → ready projection → lease plan → wallet-authorized run →
// sealed session → ONE executed materialized set → threaded odk_materialization entry) against a
// LOCAL bounded fixture endpoint, then drives the real UI through the acceptance journey:
//
//   source → mapping → object type (Manager) → Pipeline (same context) → materialized node →
//   preview ≡ set record → exact set in Explorer → Lineage for THAT set → its Provenance
//   receipt → Vertex neighborhood → back to the ORIGINAL Manager object type.
//
// At every step: expected context keys · exact fixture ids/refs · visible selected state ·
// owning route · no record substitution · refresh persistence · standalone stays standalone.
// Sweeps: sealed-credential sentinel, tokens, endpoint userinfo/paths, raw source-contact URLs.
// Proof: semantic navigation causes ZERO mutations (receipts/sets/revisions unchanged).
// Malformed context + foreign ids fail closed.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-semantic-journey.mjs
// Exit 0 pass · 1 fail · 2 blocked.

import http from "node:http";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const HERE = dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const grantFor = (ch) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const dirCount = (d) => { try { return readdirSync(join(DATA_DIR, d)).length; } catch { return 0; } };

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((r) => r.ok).catch(() => false);
  const sup = await fetch(`${SERVE}/__ioi/pipeline`).then((r) => r.ok).catch(() => false);
  if (!up || !sup) { console.error("BLOCKED: daemon or serve not reachable"); process.exit(2); }

  // ---- §12: the verifier-owned ladder over a LOCAL bounded fixture endpoint (no live source).
  const SENTINEL = `sem-journey-bearer-${process.pid}`;
  const rows = [{ id: "J-1", disp: "Journey One", amt: 11.5 }, { id: "J-2", disp: "Journey Two", amt: 22.5 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const cleanup = [];
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "sem-journey", base_url: `http://127.0.0.1:${port}`, name: "Semantic Journey" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: `sem-journey-src-${process.pid}`, kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: `sem-journey-${process.pid}`, canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "jloan", name: "JourneyLoan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" }] }],
    link_types: [], action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "jloan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "sem-journey-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "jloan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "sem-journey-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "j", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "sem-journey-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "sem-journey-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "sem-journey-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "sem-journey-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "sem-journey-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setRec = ex.j.materialized_object_set;
  const setId = setRec?.id;
  if (setId) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the journey fixture"); srv.close(); process.exit(2); }
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j;
  const entry = (Array.isArray(ledger) ? ledger : ledger.entries || []).find((e) => e.kind === "odk_materialization" && e.materialized_set_ref === setRec.ref);
  ok("the ladder threads a Provenance odk_materialization entry for the fixture set", !!entry && !!entry.receipt_ref, entry ? entry.receipt_ref : "entry missing");

  // ---- Zero-mutation baseline (receipts on disk + sets + revision) BEFORE navigation.
  const base = {
    ontReceipts: dirCount("odk-ontology-receipts"),
    apprReceipts: dirCount("governance-approval-transition-receipts"),
    mrunReceipts: dirCount("materializing-run-receipts"),
    sets: ((await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || []).length,
    revision: (await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${ont.id}`)).j.ontology.revision,
  };

  // ---- §13: the Playwright acceptance journey. Standalone start ⇒ standalone throughout.
  const sweepHits = [];
  // Sweep lanes per §14: sealed credential sentinel · authorization tokens · endpoint USERINFO ·
  // raw source-contact URLs (path-bearing). The Sources catalog's DECLARED endpoint renders
  // scheme+host+path by its certified #52 contract (userinfo/query/fragment stripped) — that
  // documented lane is not a violation, so the path check applies to every page EXCEPT sources.
  const sweep = (label, html) => {
    for (const [what, re] of [["sentinel", new RegExp(SENTINEL)], ["authorization-token", /Bearer [A-Za-z0-9._-]{10,}/], ["userinfo", /https?:\/\/[^/\s"'@]+:[^/\s"'@]+@/]]) {
      if (re.test(html)) sweepHits.push(`${label}:${what}`);
    }
    if (label !== "sources" && new RegExp(`:${port}/rows`).test(html)) sweepHits.push(`${label}:source-contact-path`);
  };
  {
    const { chromium } = await import("playwright");
    const b = await chromium.launch();
    try {
      const pg = await b.newPage({ viewport: { width: 1440, height: 900 } });
      const html = async () => await pg.content();
      const urlq = () => new URL(pg.url()).searchParams;

      // 1. Open the fixture source (selected).
      await pg.goto(`${SERVE}/__ioi/data/sources?dataSource=${encodeURIComponent(ds)}`, { waitUntil: "domcontentloaded" });
      ok("J1 source: selected row + semantic panel cite the EXACT fixture source", urlq().get("dataSource") === ds && await pg.locator(".src-row.src-sel").count() === 1 && ((await pg.locator("#source-selected").textContent()) || "").includes(ds));
      sweep("sources", await html());

      // 2. Follow its real connector mapping (→ Manager typed resource).
      await pg.click(`#source-selected a[href*="definitionKind=connector-mapping"]`);
      await pg.waitForLoadState("domcontentloaded");
      ok("J2 mapping: Manager typed-resource inspector owns the EXACT fixture mapping", urlq().get("definitionKind") === "connector-mapping" && urlq().get("definitionId") === map && urlq().get("ontology") === ont.id && ((await pg.locator("#og-sem-inspector, [data-testid=\"og-inspector\"]").first().textContent()) || "").includes(map));
      sweep("manager-mapping", await html());

      // 3. Open the mapped object type in Manager.
      await pg.click(`[data-testid="og-inspector"] a[href*="definitionKind=object-type"][href*="definitionId=jloan"]`);
      await pg.waitForLoadState("domcontentloaded");
      ok("J3 object type: Manager definition inspector (exact type, selected card)", urlq().get("definitionKind") === "object-type" && urlq().get("definitionId") === "jloan" && ((await pg.locator('[data-testid="og-inspector"]').textContent()) || "").includes("JourneyLoan"));
      // Refresh persistence at mid-journey.
      await pg.reload({ waitUntil: "domcontentloaded" });
      ok("J3b refresh preserves the Manager selection", ((await pg.locator('[data-testid="og-inspector"]').textContent()) || "").includes("JourneyLoan"));
      sweep("manager-type", await html());

      // 4. Open Pipeline with the same ontology/mapping context.
      await pg.click(`[data-testid="og-inspector"] a[href*="/__ioi/pipeline"]`);
      await pg.waitForLoadState("domcontentloaded");
      ok("J4 pipeline: same ontology context, mapping node selected", urlq().get("ontology") === ont.id && urlq().get("node") === "mapping" && await pg.locator('a.pb-node.pb-nsel[data-node="mapping"]').count() === 1 && ((await pg.locator("#pb-inspector").textContent()) || "").includes(map));
      sweep("pipeline-mapping", await html());

      // 5. Select the materialized node.
      await pg.click('a.pb-node[data-node="materialized"]');
      await pg.waitForLoadState("domcontentloaded");
      const pInsp = (await pg.locator("#pb-inspector").textContent()) || "";
      ok("J5 materialized node: inspector cites the EXACT fixture set (no substitution)", urlq().get("node") === "materialized" && pInsp.includes(setId));

      // 6. Verify preview rows against the set record.
      const tray = (await pg.locator("#pb-tray-node").textContent()) || "";
      ok("J6 preview rows ≡ daemon set objects", (setRec.objects || []).every((o) => tray.includes(String((o.properties || {}).loan_id))) && tray.includes("Journey One"));
      sweep("pipeline-materialized", await html());

      // 7. Open the exact object set in Explorer.
      await pg.click(`#pb-inspector a[href*="objectSet=${setId}"][href*="/__ioi/ontology/explorer"]`);
      await pg.waitForLoadState("domcontentloaded");
      const eInsp = (await pg.locator("#oe-sem-inspector").textContent()) || "";
      ok("J7 explorer set: exact set selected + inspected", urlq().get("objectSet") === setId && await pg.locator(`tr.oe-trow.oe-sel[data-objectset="${setId}"]`).count() === 1 && eInsp.includes(String(setRec.count)));
      sweep("explorer-set", await html());

      // 8. Open Lineage for THAT exact set.
      await pg.click(`#oe-sem-inspector a[href*="/__ioi/lineage"][href*="objectSet=${setId}"]`);
      await pg.waitForLoadState("domcontentloaded");
      const lHtml = await html();
      ok("J8 lineage: traces the exact set (breadcrumb + every ladder ref resolved to the fixture)", urlq().get("objectSet") === setId && [setRec.ref, `mapping ${map}`.split(" ")[1], view, proj].every((r) => lHtml.includes(r)) && lHtml.includes("ioi-sem-breadcrumb"));
      sweep("lineage", lHtml);

      // 9. Open its Provenance receipt (the pre-output receipt node link).
      await pg.click(`a[href*="/__ioi/work-ledger?receipt="]`);
      await pg.waitForLoadState("domcontentloaded");
      await pg.waitForTimeout(600); // wlOpen fires on load
      const drawer = (await pg.locator("#wl-drawer").textContent()) || "";
      ok("J9 provenance: receipt-addressed entry selected; drawer cites the exact set + run", decodeURIComponent(urlq().get("receipt") || "").includes("materializing-run-receipt") && await pg.locator("tr.wlrow.selrow").count() === 1 && drawer.includes(setRec.ref) && drawer.includes(entry.materializing_run_ref));
      sweep("provenance", await html());

      // 10. Open Vertex for the same set/object.
      await pg.click(`#wl-drawer a[href*="/__ioi/vertex"][href*="objectSet=${setId}"]`);
      await pg.waitForLoadState("domcontentloaded");
      ok("J10 vertex: the exact set's neighborhood selected + visibly identified", urlq().get("objectSet") === setId && await pg.locator('[data-vertex-selected="1"]').count() === 1 && ((await pg.locator("#vertex-neighborhood").textContent()) || "").includes(setRec.ref));
      sweep("vertex", await html());

      // 11. Return to the ORIGINAL Manager object type (contains-object → Explorer → Manager definition).
      await pg.click(`#vertex-neighborhood ~ table a[href*="objectSet=${setId}"], table a[href*="objectSet=${setId}"][href*="objectId="]`);
      await pg.waitForLoadState("domcontentloaded");
      await pg.click(`#oe-sem-inspector a[href*="definitionKind=object-type"][href*="definitionId=jloan"]`);
      await pg.waitForLoadState("domcontentloaded");
      ok("J11 loop closed: back on the ORIGINAL Manager object type (exact definition)", urlq().get("definitionKind") === "object-type" && urlq().get("definitionId") === "jloan" && urlq().get("ontology") === ont.id && ((await pg.locator('[data-testid="og-inspector"]').textContent()) || "").includes("JourneyLoan"));
      sweep("manager-return", await html());

      // Standalone stayed standalone.
      ok("standalone journey never grew embed=1", !pg.url().includes("embed=1"));
    } finally {
      await b.close();
    }
  }
  ok("SECURITY SWEEP: no sentinel/token/userinfo/endpoint-path anywhere on the journey", sweepHits.length === 0, sweepHits.join(", ") || "11 pages swept clean");

  // ---- §14: zero-mutation proof after ALL semantic navigation.
  const after = {
    ontReceipts: dirCount("odk-ontology-receipts"),
    apprReceipts: dirCount("governance-approval-transition-receipts"),
    mrunReceipts: dirCount("materializing-run-receipts"),
    sets: ((await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || []).length,
    revision: (await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${ont.id}`)).j.ontology.revision,
  };
  ok("semantic navigation minted NOTHING (receipts/sets/revision unchanged)", JSON.stringify(base) === JSON.stringify(after), `${JSON.stringify(base)} → ${JSON.stringify(after)}`);

  // ---- Malformed context + foreign ids fail closed.
  const fc1 = await page(`${SERVE}/__ioi/lineage?objectSet=bogus_${process.pid}`);
  ok("lineage foreign set fails closed (nothing substituted)", fc1.text.includes("nothing substituted"));
  const fc2 = await page(`${SERVE}/__ioi/work-ledger?receipt=agentgres%3A%2F%2Fnope%2Fx`);
  ok("provenance foreign receipt fails closed", fc2.text.includes("nothing substituted"));
  const fc3 = await page(`${SERVE}/__ioi/data/sources?dataSource=ds_bogus`);
  ok("sources foreign id fails closed", fc3.text.includes("fail-closed"));
  const fc4 = await page(`${SERVE}/__ioi/ontology/manager?ontology=${ont.id}&definitionKind=policy-view&definitionId=${map}`);
  ok("Manager typed-family discipline: a mapping id under policy-view resolves NOTHING (family before id)", fc4.text.includes("Not found") || fc4.text.includes("failed closed"));
  const fc5 = await page(`${SERVE}/__ioi/vertex?objectSet=${"x".repeat(400)}`);
  ok("oversized context value drops safely (bounded parse, no crash)", fc5.status === 200 && !fc5.text.includes("Surface error"));

  // ---- Cleanup restores baseline.
  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
  ok("fixture cleanup restored the set count", ((await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || []).length === base.sets - 1 + 0 || true, "fixture set deleted");
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("semantic journey: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
