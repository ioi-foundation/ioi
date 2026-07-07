#!/usr/bin/env node
// Sealed connector session done-bar — the CREDENTIAL-HANDLING crossing, split from execution.
//
// A MaterializingRun that HOLDS its CapabilityLease may open a sealed connector session: a SECOND
// crossing through the SAME gateway with credential_required:true. The gateway resolves the SEALED
// credential server-side and mints the session's lease; the session PROVES resolution is authorized
// for the exact lease scope — and nothing more. No credential material is stored, logged, returned,
// or receipted; no source is contacted; no rows exist. Execution is the next cut (#20).
//
// Asserts:
//   - THE 428 LANE: without a sealed credential the gateway fails closed (verbatim, receipted)
//     BEFORE any wallet consideration.
//   - THE CROSSING: seal a SENTINEL bearer into the connector estate → 403 challenge → real
//     dcrypt-signed grant → session_obtained; the gateway audit trail grows; only non-secret labels
//     (credential_source, credential_key_source) land on the record.
//   - SENTINEL LEAK SWEEP: the raw token appears NOWHERE — response, session records dir, receipts
//     dir, run records dir.
//   - Scope discipline: scope is never restated (verbatim from the lease); TTL narrows only; scope
//     frozen; every bypass lane rejected; run must HOLD its lease; ladder drift blocks; local
//     source kinds refused.
//   - Receipts: created/session_requested/session_refused/session_obtained/session_released (+
//     patch_rejected) — the full crossing story, credential-free.
//   - object_instances stays 0; ladder shows Sealed connector session (live) with Connector
//     execution + Materialized rows still missing; brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-connector-session.mjs
// Exit 2 = BLOCKED (daemon not running).

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), ".ioi", "hypervisor", "data");
const SENTINEL = "fixture-bearer-SENTINEL-do-not-leak";

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

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/connector-sessions/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon connector-session plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (kind, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${kind}/${id}`]); };

  // Full ladder → plan → run → OBTAINED lease (the #18 crossing, exercised as a fixture).
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "csn-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "csn-verify", canonical_object_model: {
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } });
  const ontId = ontR.j.ontology?.id; const ontRef = ontR.j.ontology?.ref;
  track("domain-ontologies", ontId);
  const mapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "csn-verify-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" } });
  const mapId = mapR.j.connector_mapping?.id;
  track("connector-mappings", mapId);
  const viewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "csn-verify-gate", authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform"], purpose: "underwriting analysis", property_scope: ["loan_id", "title"], retention_posture: "bounded" });
  const viewId = viewR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", viewId);
  const trunR = await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapId, policy_view_id: viewId, name: "csn-verify-trun" });
  const trunId = trunR.j.transformation_run?.id;
  track("transformation-runs", trunId);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trunId}/dry-run`);
  const projR = await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mapId, policy_view_id: viewId, name: "csn-verify-explorer", visible_properties: ["loan_id", "title"] });
  const projId = projR.j.ontology_projection?.id;
  track("ontology-projections", projId);
  const planR = await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: dataSourceId, connector_mapping_id: mapId, policy_view_id: viewId,
    transformation_run_id: trunId, ontology_projection_id: projId, name: "csn-verify-plan", subject: "agent://materializer", ttl_seconds: 900 });
  const planId = planR.j.capability_lease_plan?.id;
  track("capability-lease-plans", planId);
  const mrunR = await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "csn-verify-mrun" });
  const mrunId = mrunR.j.materializing_run?.id;
  track("materializing-runs", mrunId);
  const ch1 = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrunId}/acquire-lease`, {});
  const g1 = mintApprovalGrant({ policyHash: ch1.j.approval?.policy_hash, requestHash: ch1.j.approval?.request_hash });
  const leased = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrunId}/acquire-lease`, { wallet_approval_grant: g1 });
  ok("fixture: the run HOLDS its lease (#18 crossing green)", leased.j.materializing_run?.status === "lease_obtained");
  // A second, lease-less run for the not-obtained lane.
  const mrun2R = await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "csn-verify-noleaserun" });
  const mrun2Id = mrun2R.j.materializing_run?.id;
  track("materializing-runs", mrun2Id);
  // Connector fixture (NO credential yet).
  const connR = await jd("POST", "/v1/hypervisor/connectors", { service: "odk-csn-fixture", base_url: "https://db.invalid", name: "ODK Session Fixture" });
  const connId = connR.j.connector?.connector_id || connR.j.connector_id;
  if (!dataSourceId || !mapId || !viewId || !trunId || !projId || !planId || !mrunId || !connId) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  // 1. Session request admitted — scope inherited VERBATIM, never restated.
  const sR = await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrunId, connector_id: connId, name: "loans-session", ttl_seconds: 300 });
  const s0 = sR.j.connector_session;
  track("connector-sessions", s0?.id);
  ok("session request admitted (201, requested) with the lease scope snapshotted verbatim", sR.status === 201 && s0?.status === "requested" && JSON.stringify(s0?.properties) === JSON.stringify(["loan_id", "title"]) && JSON.stringify(s0?.operations) === JSON.stringify(["read", "transform"]));
  ok("session TTL narrows the run's (300 ≤ 900); inert; both cuts named", s0?.ttl_seconds === 300 && s0?.execution?.object_instances === 0 && JSON.stringify(s0?.missing_authority) === JSON.stringify(["ConnectorExecution", "MaterializedRows"]));

  // 2. THE 428 LANE: no sealed credential → fail-closed before any wallet consideration.
  const r428 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${s0.id}/open`, {});
  ok("without a sealed credential the gateway fails closed 428 (verbatim, receipted)", r428.status === 428 && /credential_required/.test(r428.j.reason || ""));

  // 3. Seal the SENTINEL bearer → 403 challenge → real grant → session_obtained.
  const bind = await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
  ok("SENTINEL bearer sealed into the connector estate (token-lease:bound)", bind.j.ok === true && bind.j.auth_posture === "token-lease:bound");
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${s0.id}/open`, {});
  ok("with the credential sealed, the wallet gate challenges (403 + hashes)", ch2.status === 403 && ch2.j.reason === "odk_connector_session_authority_required" && !!ch2.j.approval?.policy_hash);
  const g2 = mintApprovalGrant({ policyHash: ch2.j.approval.policy_hash, requestHash: ch2.j.approval.request_hash });
  const before = ((await jd("GET", "/v1/hypervisor/capability-leases")).j.leases || []).length;
  const opened = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${s0.id}/open`, { wallet_approval_grant: g2 });
  const ss = opened.j.connector_session;
  ok("session obtained — the gateway resolved the sealed credential and minted the session lease", opened.status === 200 && ss?.status === "session_obtained" && String(ss?.session?.session_ref || "").startsWith("sealed-session://"));
  const after = ((await jd("GET", "/v1/hypervisor/capability-leases")).j.leases || []).length;
  ok("the session lease is REAL (gateway audit trail grew)", after === before + 1, `${before} → ${after}`);
  ok("only non-secret labels landed (credential_source/credential_key_source)", ss?.session?.credential_descriptor?.credential_source === "connector" && !!ss?.session?.credential_descriptor?.credential_key_source && ss?.session?.credential_material === false);
  ok("still inert: source_contacted false, object_instances 0", ss?.execution?.source_contacted === false && ss?.execution?.object_instances === 0);

  // 4. SENTINEL LEAK SWEEP — the raw bearer exists ONLY in the sealed store, nowhere else.
  ok("SENTINEL absent from the open response", !JSON.stringify(opened.j).includes(SENTINEL));
  ok("SENTINEL absent from session records on disk", !dirContains(path.join(DATA, "odk-connector-sessions"), SENTINEL));
  ok("SENTINEL absent from session receipts on disk", !dirContains(path.join(DATA, "odk-connector-session-receipts"), SENTINEL));
  ok("SENTINEL absent from materializing-run records on disk", !dirContains(path.join(DATA, "odk-materializing-runs"), SENTINEL));
  ok("SENTINEL absent from the gateway lease descriptors", !((await jd("GET", "/v1/hypervisor/capability-leases")).j.leases || []).some((l) => JSON.stringify(l).includes(SENTINEL)));

  // 5. Guards + fail-closed lanes.
  const reopen = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${s0.id}/open`, { wallet_approval_grant: g2 });
  ok("re-open refused (one session per request)", reopen.j.error?.code === "session_already_obtained");
  const frozen = await jd("PATCH", `/v1/hypervisor/odk/connector-sessions/${s0.id}`, { ttl_seconds: 60 });
  ok("scope frozen from birth (receipted refusal)", frozen.j.error?.code === "session_scope_frozen");
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/connector-sessions", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    track("connector-sessions", r.j?.connector_session?.id);
  };
  await reject("scope restated (verbatim binding, no restatement)", { materializing_run_id: mrunId, connector_id: connId, name: "x", requested_properties: ["loan_id"] }, "session_scope_widening_rejected");
  await reject("plaintext secret", { materializing_run_id: mrunId, connector_id: connId, name: "x", password: "h" }, "session_plaintext_secret_rejected");
  await reject("raw query body", { materializing_run_id: mrunId, connector_id: connId, name: "x", sql: "SELECT 1" }, "session_raw_query_rejected");
  await reject("env-credential fallback", { materializing_run_id: mrunId, connector_id: connId, name: "x", from_env: "PGPASSWORD" }, "session_env_fallback_rejected");
  await reject("missing name", { materializing_run_id: mrunId, connector_id: connId }, "session_name_required");
  await reject("unknown run", { materializing_run_id: "mrun_nope", connector_id: connId, name: "x" }, "session_run_unknown");
  await reject("run does not HOLD its lease", { materializing_run_id: mrun2Id, connector_id: connId, name: "x" }, "session_lease_not_obtained");
  await reject("unknown connector", { materializing_run_id: mrunId, connector_id: "conn_nope", name: "x" }, "session_connector_unknown");
  await reject("TTL widening (9999 > run's 900)", { materializing_run_id: mrunId, connector_id: connId, name: "x", ttl_seconds: 9999 }, "session_ttl_widening_rejected");

  // 6. Release + receipts tell the whole story, credential-free.
  const rel = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${s0.id}/release`);
  ok("release is receipted + terminal", rel.j.connector_session?.status === "session_released" && rel.j.connector_session?.session?.obtained === false);
  const hist = await jd("GET", `/v1/hypervisor/odk/connector-sessions/${s0.id}/history`);
  const opsSeen = (hist.j.receipts || []).map((x) => x.op);
  ok("receipts: created/session_requested/session_refused/session_obtained/session_released", ["created", "session_requested", "session_refused", "session_obtained", "session_released"].every((o) => opsSeen.includes(o)), opsSeen.join(","));
  const ov = await jd("GET", "/v1/hypervisor/odk/connector-sessions/overview");
  ok("overview: credential-handling-only governance gaps + labels-only doctrine", (ov.j.governance_gaps || []).some((g) => /never stored, logged, returned/i.test(g)) && (ov.j.governance_gaps || []).some((g) => /NEXT cut/i.test(g)));
  const allS = await jd("GET", "/v1/hypervisor/odk/connector-sessions");
  ok("no session anywhere reports contact or instances", (allS.j.connector_sessions || []).every((c) => c.execution?.source_contacted === false && c.execution?.object_instances === 0));

  // 7. UX ladder.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Manager renders sealed sessions (Resources, 'sealed · no contact')", page.status === 200 && /Sealed connector sessions \(\d+\)/.test(t) && /sealed · no contact/.test(t));
  ok("ladder rung 7: Sealed connector session (live)", /Sealed connector session<\/code> <span class="pill ok">live/.test(t));
  ok("ladder: Connector execution + Materialized rows still missing", /Connector execution<\/code> <span class="pill muted">missing/.test(t) && /Materialized rows<\/code> <span class="pill muted">missing/.test(t));
  ok("0-objects boundary preserved; brand-clean", /0 objects/.test(t) && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup — draft/test records removed; connector credential revoked; connector removed.
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`connector-session readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
