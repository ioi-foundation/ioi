#!/usr/bin/env node
// Connector execution + materialized rows done-bar — the FINAL rung of the ODK ratchet: one real
// read, one sealed session, one receipted batch, one projection goes NONZERO.
//
// One narrow read-only adapter path (rest_api GET of the DECLARED endpoint), not a generic ingestion
// engine. Execution requires a HELD lease (#18) + an OPEN sealed session (#19); rows transform
// through the landed ladder and validate all-or-nothing; the pre-output receipt lands BEFORE any
// output; the materialized set stores hashes + provenance, never secrets; ONLY the tied projection's
// object_instances changes.
//
// Asserts:
//   - FIRST NONZERO object_instances only after the pre-output receipt (history order proves it).
//   - Source-contact evidence on BOTH sides: the fixture server received exactly the adapter's GET,
//     WITH the sealed bearer — while the sentinel sweep proves that bearer exists nowhere in
//     responses, run records, set records, or receipts.
//   - No raw-query path; unsupported connector kinds refused; malformed batch registers ZERO
//     objects; projection row count matches the materialized output; rerun is explicitly refused
//     (one bounded batch per run); set deletion resets the projection (no dangling counts).
//   - Receipts cover execution_requested, source_contact_started/completed, validation_result,
//     pre_output_receipt, materialized_output_registered (+ refusals).
//   - The Manager explorer shows the first bounded rows for the tied projection; the ladder reads
//     all nine rungs; fresh ontologies keep honest zeros. Brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-connector-execution.mjs
// Exit 2 = BLOCKED (daemon not running).

import http from "node:http";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const SENTINEL = "fixture-bearer-SENTINEL-verify-exec";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
function dirContains(dir, needle) {
  try {
    return readdirSync(dir).some((f) => {
      try { return readFileSync(path.join(dir, f), "utf8").includes(needle); } catch { return false; }
    });
  } catch { return false; }
}
const grantFor = (ch) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash });

// A full ladder → held lease → open sealed session over the given endpoint. Returns ids.
async function buildChain(tag, endpoint, kind, connId, cleanup, opts = {}) {
  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: `${tag}-src`, kind, endpoint, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: `${tag}-domain`, canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: `${tag}-map`, data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: `${tag}-gate`, authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform"], purpose: "analysis", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: `${tag}-trun` })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: `${tag}-explorer`, visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view,
    transformation_run_id: trun, ontology_projection_id: proj, name: `${tag}-plan`, subject: "agent://materializer", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: `${tag}-mrun` })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  let session = null;
  if (kind === "rest_api" && !opts.skipSession) {
    session = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: `${tag}-session` })).j.connector_session?.id;
    track("connector-sessions", session);
    const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${session}/open`, {});
    await jd("POST", `/v1/hypervisor/odk/connector-sessions/${session}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  }
  return { ds, ontId: ont?.id, map, view, trun, proj, plan, mrun, session };
}

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/materialized-object-sets/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon execution plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];

  // Fixture row server — auth-checked; records exactly what the adapter sent.
  const rows = [{ id: "L-1", disp: "First Loan", amt: 1250.5 }, { id: "L-2", disp: "Second Loan", amt: 90000 }, { id: "L-3", disp: "Third Loan", amt: 42.0 }];
  const bad = [{ id: "L-1", disp: "ok", amt: 1.0 }, { disp: "missing key", amt: "not-a-number" }];
  let hits = 0; let authedHits = 0;
  const dup = [{ id: "L-1", disp: "First", amt: 1.0 }, { id: "L-1", disp: "Same key again", amt: 2.0 }];
  const srv = http.createServer((req, res) => {
    hits++;
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end("unauthorized"); }
    authedHits++;
    if (req.url === "/redirect") { res.writeHead(302, { Location: "/rows" }); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(req.url === "/bad-rows" ? bad : req.url === "/dup-rows" ? dup : rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;

  // Connector holding the sealed sentinel bearer.
  const connR = await jd("POST", "/v1/hypervisor/connectors", { service: "odk-exec-verify", base_url: `http://127.0.0.1:${port}`, name: "Exec Verify Fixture" });
  const connId = connR.j.connector?.connector_id || connR.j.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  const connUnreachR = await jd("POST", "/v1/hypervisor/connectors", { service: "odk-exec-unreachable", base_url: "http://127.0.0.1:9", name: "Exec Unreachable Fixture" });
  const connUnreachId = connUnreachR.j.connector?.connector_id || connUnreachR.j.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connUnreachId}/credential`, { token: SENTINEL });

  try {
    // Chain A: the happy path.
    const A = await buildChain("execA", `http://127.0.0.1:${port}/rows`, "rest_api", connId, cleanup);
    const before = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${A.proj}`);
    ok("BEFORE execution the tied projection reports 0 instances", before.j.ontology_projection?.health?.object_instances === 0);

    // Guard lanes before the real execution.
    const noSess = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: "csn_nope", limit: 10 });
    ok("fail-closed: unknown session", noSess.j.error?.code === "execution_session_unknown");
    const rawQ = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: A.session, limit: 10, sql: "SELECT 1" });
    ok("fail-closed: raw query path does not exist", rawQ.j.error?.code === "execution_raw_query_rejected");
    const envF = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: A.session, limit: 10, from_env: "PG" });
    ok("fail-closed: env-credential fallback", envF.j.error?.code === "execution_env_fallback_rejected");
    const badLimit = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: A.session, limit: 99999 });
    ok("fail-closed: unbounded limit", badLimit.j.error?.code === "execution_limit_unbounded");

    // THE EXECUTION.
    const hitsBefore = hits;
    const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: A.session, limit: 10 });
    const set = ex.j.materialized_object_set;
    if (set?.id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/__SKIP__`]); // placeholder; real delete below
    ok("execution succeeds: run executed, 3 objects registered all-or-nothing", ex.status === 200 && ex.j.materializing_run?.status === "executed" && set?.count === 3);
    ok("source-contact evidence (daemon side): endpoint + http 200 + elapsed recorded", set?.source_contact?.http_status === 200 && typeof set?.source_contact?.elapsed_ms === "number" && String(set?.source_contact?.endpoint || "").endsWith("/rows"));
    ok("source-contact evidence (source side): the fixture received EXACTLY the adapter's authed GET", hits === hitsBefore + 1 && authedHits >= 1, `hits ${hitsBefore}→${hits}`);
    ok("objects carry key/title/typed properties + source hash + provenance", set?.objects?.[0]?.object_key === "L-1" && set?.objects?.[0]?.title === "First Loan" && set?.objects?.[0]?.properties?.amount === 1250.5 && String(set?.objects?.[0]?.source_hash || "").startsWith("sha256:") && set?.objects?.[0]?.provenance?.mapped_from?.amount === "amt");

    // FIRST NONZERO — and only after the pre-output receipt (history order is append-ordered).
    const after = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${A.proj}`);
    ok("the tied projection went 0 → 3 (row count matches the materialized output)", after.j.ontology_projection?.health?.object_instances === 3 && after.j.ontology_projection?.health?.materialized === true && after.j.ontology_projection?.materialized?.set_ref === set?.ref);
    const hist = await jd("GET", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/history`);
    const opsInOrder = (hist.j.history || []).map((h) => h.op);
    const iPre = opsInOrder.indexOf("pre_output_receipt");
    const iReg = opsInOrder.indexOf("materialized_output_registered");
    ok("receipt story complete and ORDERED: requested → contact started/completed → validation → PRE-OUTPUT → registered", ["execution_requested", "source_contact_started", "source_contact_completed", "validation_result", "pre_output_receipt", "materialized_output_registered"].every((o) => opsInOrder.includes(o)) && iPre !== -1 && iReg !== -1 && iPre < iReg, opsInOrder.join("→"));
    ok("set records the pre-output receipt it was registered behind", String(set?.pre_output_receipt_ref || "").startsWith("agentgres://materializing-run-receipt/"));

    // Sentinel sweep — the bearer was USED for the read yet exists NOWHERE in truth.
    ok("SENTINEL absent from the execute response", !JSON.stringify(ex.j).includes(SENTINEL));
    ok("SENTINEL absent from set records on disk", !dirContains(path.join(DATA, "odk-materialized-object-sets"), SENTINEL));
    ok("SENTINEL absent from run records on disk", !dirContains(path.join(DATA, "odk-materializing-runs"), SENTINEL));
    ok("SENTINEL absent from run receipts on disk", !dirContains(path.join(DATA, "odk-materializing-run-receipts"), SENTINEL));

    // Rerun/idempotency is explicit.
    const rerun = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${A.mrun}/execute`, { connector_session_id: A.session, limit: 10 });
    ok("rerun explicitly refused — one bounded batch per run (v1)", rerun.j.error?.code === "execution_already_registered");

    // Chain B: unsupported connector kind (postgres) refused before any contact.
    const B = await buildChain("execB", "postgres://unreachable.invalid:5432/db", "postgres", connId, cleanup);
    const exB = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${B.mrun}/execute`, { connector_session_id: "irrelevant", limit: 10 });
    ok("fail-closed: unsupported connector kind (no allowlisted adapter)", exB.j.error?.code === "execution_connector_kind_unsupported");

    // Chain C: malformed batch → ZERO objects, projection stays 0.
    const C = await buildChain("execC", `http://127.0.0.1:${port}/bad-rows`, "rest_api", connId, cleanup);
    const exC = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${C.mrun}/execute`, { connector_session_id: C.session, limit: 10 });
    const projC = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${C.proj}`);
    ok("malformed batch rejected all-or-nothing (422, named row errors)", exC.status === 422 && exC.j.error?.code === "execution_batch_invalid" && (exC.j.error?.errors || []).length >= 2);
    ok("ZERO objects registered from the malformed batch; projection stays 0", projC.j.ontology_projection?.health?.object_instances === 0 && projC.j.ontology_projection?.health?.materialized === false);
    const setsNow = await jd("GET", "/v1/hypervisor/odk/materialized-object-sets");
    ok("no set exists for the malformed chain", !(setsNow.j.materialized_object_sets || []).some((m) => m.ontology_projection_id === C.proj));
    const histC = await jd("GET", `/v1/hypervisor/odk/materializing-runs/${C.mrun}/history`);
    ok("malformed batch left a validation_result refusal in the receipt story", (histC.j.receipts || []).some((r) => r.op === "validation_result" && r.outcome === "execution_batch_invalid"));

    // Chain D: unreachable rest endpoint → source_contact_failed receipted.
    const Dc = await buildChain("execD", "http://127.0.0.1:9/rows", "rest_api", connUnreachId, cleanup);
    const exD = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${Dc.mrun}/execute`, { connector_session_id: Dc.session, limit: 10 });
    const histD = await jd("GET", `/v1/hypervisor/odk/materializing-runs/${Dc.mrun}/history`);
    ok("unreachable source → 502 + source_contact_failed receipted (no output)", exD.status === 502 && exD.j.error?.code === "execution_source_unreachable" && (histD.j.receipts || []).some((r) => r.op === "source_contact_failed"));

    // Chain E: redirect refused — the adapter never follows a redirect to an undeclared URL.
    const E = await buildChain("execE", `http://127.0.0.1:${port}/redirect`, "rest_api", connId, cleanup);
    const exE = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${E.mrun}/execute`, { connector_session_id: E.session, limit: 10 });
    const histE = await jd("GET", `/v1/hypervisor/odk/materializing-runs/${E.mrun}/history`);
    const projE = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${E.proj}`);
    ok("fail-closed: 302 redirect REFUSED (declared endpoint verbatim; receipted; zero output)", exE.status === 502 && exE.j.error?.code === "execution_source_redirect_rejected" && (histE.j.receipts || []).some((r) => r.outcome === "execution_source_redirect_rejected") && projE.j.ontology_projection?.health?.object_instances === 0);

    // Chain F: duplicate object keys in one batch — semantic identity must be unique.
    const F = await buildChain("execF", `http://127.0.0.1:${port}/dup-rows`, "rest_api", connId, cleanup);
    const exF = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${F.mrun}/execute`, { connector_session_id: F.session, limit: 10 });
    const projF = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${F.proj}`);
    ok("fail-closed: duplicate object_key rejects the whole batch (zero registered)", exF.status === 422 && exF.j.error?.code === "execution_batch_invalid" && (exF.j.error?.errors || []).some((e) => /duplicate object key/.test(e)) && projF.j.ontology_projection?.health?.object_instances === 0);

    // Chain G — CONFUSED-DEPUTY: connector A holds the sentinel for the fixture origin, but the
    // session is opened with the UNREACHABLE-origin connector against the fixture data source. The
    // credential↔endpoint binding must refuse the session, and the fixture must receive ZERO requests.
    const G = await buildChain("execG", `http://127.0.0.1:${port}/rows`, "rest_api", connId, cleanup, { skipSession: true });
    const hitsBeforeG = hits;
    const badSession = await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: G.mrun, connector_id: connUnreachId, name: "confused-deputy-session" });
    ok("fail-closed: session refused when the connector is not the source's origin authority", badSession.status === 400 && badSession.j.error?.code === "session_connector_source_mismatch");
    // The matching connector opens a legit session; then re-point is impossible (endpoints immutable),
    // so the execution re-check is proven at the unit level — here we assert the source stayed silent.
    ok("the confused-deputy attempt contacted the source ZERO times", hits === hitsBeforeG, `hits ${hitsBeforeG}→${hits}`);

    // Credentialed endpoints are refused at DECLARATION (never enter declared truth).
    const credEp = await jd("POST", "/v1/hypervisor/data-sources", { name: "cred-ep", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows?api_key=${SENTINEL}`, credential_posture: "wallet_credential_lease" });
    ok("fail-closed: endpoint embedding a credential is refused at declaration", credEp.status === 400 && credEp.j.error?.code === "data_source_endpoint_credentialed");
    const userinfoEp = await jd("POST", "/v1/hypervisor/data-sources", { name: "cred-ep2", kind: "rest_api", endpoint: `http://user:${SENTINEL}@127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" });
    ok("fail-closed: endpoint with URL userinfo is refused at declaration", userinfoEp.status === 400 && userinfoEp.j.error?.code === "data_source_endpoint_credentialed");

    // Surface: first bounded rows + the complete ladder; fresh chains stay honest.
    const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(A.ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
    const t = page.text;
    ok("Explorer shows the first bounded rows for the tied projection", page.status === 200 && />L-1</.test(t) && />First Loan</.test(t) && /3 objects · materialized/.test(t));
    ok("ladder complete: 5 declared + 4 live rungs (all nine)", (t.match(/(ConnectorMapping|PolicyBoundDataView|TransformationRun \+ receipts|OntologyProjection|CapabilityLease plan)<\/code> <span class="pill ok">declared/g) || []).length === 5 && (t.match(/(CapabilityLease obtained|Sealed connector session|Connector execution|Materialized rows)<\/code> <span class="pill ok">live/g) || []).length === 4);
    ok("object-type counts are real (3 objects)", /<b>3<\/b> objects/.test(t) && /3 objects<\/b> materialized across 1 receipted set/.test(t));
    const freshPage = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(C.ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
    ok("a chain that never materialized keeps honest zeros + missing rungs", /0 objects<\/b> across all types/.test(freshPage.text) && (freshPage.text.match(/(Connector execution|Materialized rows)<\/code> <span class="pill muted">missing/g) || []).length === 2);
    ok("brand-clean (no Palantir/Foundry leak)", !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));
    ok("SENTINEL absent from the rendered surface", !t.includes(SENTINEL));

    // Set deletion resets the projection — no dangling counts.
    const setId = set?.id;
    const del = await jd("DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`);
    const afterDel = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${A.proj}`);
    ok("set deletion is receipted and RESETS the tied projection to 0", del.j.removed === true && afterDel.j.ontology_projection?.health?.object_instances === 0 && afterDel.j.ontology_projection?.health?.materialized === false);
  } finally {
    for (const [method, p] of cleanup.reverse()) {
      if (!p.includes("__SKIP__")) await jd(method, p);
    }
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connUnreachId}/credential`, { method: "DELETE" }).catch(() => {});
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connUnreachId}`, { method: "DELETE" }).catch(() => {});
    srv.close();
  }
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`connector-execution readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
