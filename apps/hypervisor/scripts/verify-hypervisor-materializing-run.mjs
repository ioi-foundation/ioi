#!/usr/bin/env node
// MaterializingRun (lease acquisition) done-bar — THE FIRST LIVE AUTHORITY CROSSING, kept small.
//
// A run cites one declared CapabilityLease plan and may obtain a REAL wallet-gated CapabilityLease
// from the EXISTING gateway. It must NOT contact the source, resolve or unwrap credential material,
// extract rows, move data, or create object instances. Connector execution and materialization are
// the next cut.
//
// Asserts:
//   - THE CROSSING IS REAL: acquire without a grant → the gateway's 403 challenge (verbatim, with
//     policy/request hashes; refusal receipted); a real dcrypt-signed grant bound to those hashes →
//     lease_obtained; the gateway audit-trail count INCREASES BY ONE and contains our lease id.
//   - NO CREDENTIAL MATERIAL: authority-only crossing (no backing credential resolved); no token/
//     secret in any response, record, or receipt; env-credential fallback rejected.
//   - Narrow-only: subject/purpose unchanged; operations/properties/TTL ⊆ the plan; every widening
//     attempt rejected. After obtaining, the scope is FROZEN.
//   - Drift discipline: a degraded ladder (deleted projection) blocks acquisition with a named code.
//   - Receipts record request, gateway decision, lease id, TTL, scope, refusals, release/cancel.
//   - object_instances stays 0; the UX ladder reads: … CapabilityLease plan ✓ · CapabilityLease
//     obtained (live) · Connector execution missing · Materialized rows missing. Brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-materializing-run.mjs
// Exit 2 = BLOCKED (daemon not running).

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const gatewayLeases = async () => (await jd("GET", "/v1/hypervisor/capability-leases")).j.leases || [];

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/materializing-runs/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon materializing-run plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (kind, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${kind}/${id}`]); };

  // Full ladder + declared plan over an UNREACHABLE source.
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "mrun-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "mrun-verify", canonical_object_model: {
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } });
  const ontId = ontR.j.ontology?.id; const ontRef = ontR.j.ontology?.ref;
  track("domain-ontologies", ontId);
  const mapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "mrun-verify-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" } });
  const mapId = mapR.j.connector_mapping?.id;
  track("connector-mappings", mapId);
  const viewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "mrun-verify-gate", authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform"], purpose: "underwriting analysis", property_scope: ["loan_id", "title"], retention_posture: "bounded" });
  const viewId = viewR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", viewId);
  const trunR = await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapId, policy_view_id: viewId, name: "mrun-verify-trun" });
  const trunId = trunR.j.transformation_run?.id;
  track("transformation-runs", trunId);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trunId}/dry-run`);
  const projR = await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mapId, policy_view_id: viewId, name: "mrun-verify-explorer", visible_properties: ["loan_id", "title"] });
  const projId = projR.j.ontology_projection?.id;
  track("ontology-projections", projId);
  const planR = await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: dataSourceId, connector_mapping_id: mapId, policy_view_id: viewId,
    transformation_run_id: trunId, ontology_projection_id: projId, name: "mrun-verify-plan", subject: "agent://materializer", ttl_seconds: 900 });
  const planId = planR.j.capability_lease_plan?.id;
  track("capability-lease-plans", planId);
  if (!dataSourceId || !ontId || !mapId || !viewId || !trunId || !projId || !planId) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  // 1. Run admitted (planned; TTL narrowed 600 ≤ 900); inert; no lease yet.
  const t0 = Date.now();
  const created = await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "materialize-loans", ttl_seconds: 600 });
  const elapsed = Date.now() - t0;
  const r0 = created.j.materializing_run;
  track("materializing-runs", r0?.id);
  ok("run admitted (201) instantly against an unreachable source — no contact", created.status === 201 && r0?.status === "planned" && elapsed < 4000, `${elapsed}ms`);
  ok("narrowed TTL accepted (600 ≤ plan's 900); lease not yet obtained", r0?.ttl_seconds === 600 && r0?.lease?.obtained === false);
  ok("inert invariants + both remaining cuts named", r0?.execution?.source_contacted === false && r0?.execution?.object_instances === 0 && JSON.stringify(r0?.missing_authority) === JSON.stringify(["ConnectorExecution", "MaterializedRows"]));

  // 2. THE CROSSING. No grant → the gateway's 403 challenge, verbatim, refusal receipted.
  const before = (await gatewayLeases()).length;
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r0.id}/acquire-lease`, {});
  ok("without a wallet grant the gateway's 403 challenge returns verbatim (hashes present)", ch.status === 403 && ch.j.reason === "odk_materialize_lease_authority_required" && !!ch.j.approval?.policy_hash && !!ch.j.approval?.request_hash);
  // Mint a REAL dcrypt-signed grant bound to the challenge hashes; retry.
  const grant = mintApprovalGrant({ policyHash: ch.j.approval.policy_hash, requestHash: ch.j.approval.request_hash });
  const got = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r0.id}/acquire-lease`, { wallet_approval_grant: grant });
  const rr = got.j.materializing_run;
  ok("with the bound grant the run obtains its lease (lease_obtained)", got.status === 200 && rr?.status === "lease_obtained" && !!rr?.lease?.lease_id, rr?.lease?.lease_id);
  const after = await gatewayLeases();
  ok("REAL MINT PROOF: the gateway audit trail grew by exactly one", after.length === before + 1, `${before} → ${after.length}`);
  ok("our lease is IN the gateway audit trail (the existing primitive, not a copy)", after.some((l) => l.lease_id === rr?.lease?.lease_id));
  ok("lease record carries safe fields only (grant_ref, hashes, expiry, tools) — credential_material false", rr?.lease?.credential_material === false && !!rr?.lease?.grant_ref && !!rr?.lease?.policy_hash && (rr?.lease?.allowed_tools || []).every((t) => String(t).startsWith("odk.materialize.")));
  ok("NO token/secret anywhere in the response", !JSON.stringify(got.j).match(/"token"|hunter2|secret_key|private_key/i));
  ok("still no execution: source_contacted false, object_instances 0", rr?.execution?.source_contacted === false && rr?.execution?.object_instances === 0);

  // 3. Post-obtain guards.
  const again = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r0.id}/acquire-lease`, { wallet_approval_grant: grant });
  ok("re-acquire refused (a run holds one lease)", again.j.error?.code === "materializing_run_lease_already_obtained");
  const frozen = await jd("PATCH", `/v1/hypervisor/odk/materializing-runs/${r0.id}`, { ttl_seconds: 300 });
  ok("scope is FROZEN after obtaining (receipted refusal)", frozen.j.error?.code === "materializing_run_scope_frozen");
  const meta = await jd("PATCH", `/v1/hypervisor/odk/materializing-runs/${r0.id}`, { description: "holds its lease" });
  ok("metadata patch still allowed (history kept)", meta.j.materializing_run?.revision === 2);

  // 4. Fail-closed lanes at create.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/materializing-runs", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    track("materializing-runs", r.j?.materializing_run?.id);
  };
  await reject("plaintext secret", { capability_lease_plan_id: planId, name: "x", password: "h" }, "materializing_run_plaintext_secret_rejected");
  await reject("raw query body", { capability_lease_plan_id: planId, name: "x", sql: "SELECT 1" }, "materializing_run_raw_query_rejected");
  await reject("env-credential fallback", { capability_lease_plan_id: planId, name: "x", from_env: "PGPASSWORD" }, "materializing_run_env_fallback_rejected");
  await reject("missing name", { capability_lease_plan_id: planId }, "materializing_run_name_required");
  await reject("unknown plan", { capability_lease_plan_id: "clp_nope", name: "x" }, "materializing_run_plan_unknown");
  await reject("subject re-assignment", { capability_lease_plan_id: planId, name: "x", subject: "agent://other" }, "materializing_run_subject_mismatch");
  await reject("purpose drift", { capability_lease_plan_id: planId, name: "x", purpose: "resale" }, "materializing_run_purpose_mismatch");
  await reject("operation widening (export not in the plan)", { capability_lease_plan_id: planId, name: "x", requested_operations: ["read", "transform", "export"] }, "materializing_run_operation_widening_rejected");
  await reject("property widening", { capability_lease_plan_id: planId, name: "x", requested_properties: ["loan_id", "ghost"] }, "materializing_run_scope_widening_rejected");
  await reject("TTL widening (3600 > plan's 900)", { capability_lease_plan_id: planId, name: "x", ttl_seconds: 3600 }, "materializing_run_ttl_widening_rejected");

  // 5. Release (terminal), then acquire is immutable.
  const rel = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r0.id}/release-lease`);
  ok("release-lease is receipted + terminal (obtained → false)", rel.j.materializing_run?.status === "lease_released" && rel.j.materializing_run?.lease?.obtained === false);
  const acq2 = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r0.id}/acquire-lease`, {});
  ok("a released run is immutable", acq2.j.error?.code === "materializing_run_terminal_immutable");

  // 6. Drift lane: a second run whose ladder degrades before acquisition.
  const r2R = await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "drift-run" });
  const r2 = r2R.j.materializing_run;
  track("materializing-runs", r2?.id);
  await jd("DELETE", `/v1/hypervisor/odk/ontology-projections/${projId}`);
  const drifted = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${r2.id}/acquire-lease`, {});
  ok("acquire after ladder drift (projection deleted) → refused with a named drift code (receipted)", drifted.status === 400 && drifted.j.error?.code === "materializing_run_plan_drift");

  // 7. History + overview honesty.
  const hist = await jd("GET", `/v1/hypervisor/odk/materializing-runs/${r0.id}/history`);
  const opsSeen = (hist.j.receipts || []).map((x) => x.op);
  ok("receipts record request, refusal, decision, release (the full crossing story)", ["created", "lease_requested", "lease_refused", "lease_obtained", "lease_released"].every((o) => opsSeen.includes(o)), opsSeen.join(","));
  ok("no credential material in any receipt", !JSON.stringify(hist.j.receipts || []).match(/"token"|hunter2|secret_key/i));
  const ov = await jd("GET", "/v1/hypervisor/odk/materializing-runs/overview");
  ok("overview: lifecycle + lease-acquisition-only governance gaps", JSON.stringify(ov.j.lifecycle_states) === JSON.stringify(["planned", "lease_obtained", "executed", "lease_released", "cancelled"]) && (ov.j.governance_gaps || []).some((g) => /never contacts the source/i.test(g)));
  const allRuns = await jd("GET", "/v1/hypervisor/odk/materializing-runs");
  ok("no non-executed run reports execution or object instances", (allRuns.j.materializing_runs || []).filter((r) => r.status !== "executed").every((r) => r.execution?.source_contacted === false && r.execution?.object_instances === 0));

  // 8. UX ladder — the crossing rendered honestly.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Manager renders materializing runs (Resources, 'no execution')", page.status === 200 && /Materializing runs \(\d+\)/.test(t) && /no execution/.test(t));
  ok("ladder rung 6: CapabilityLease obtained (live)", /CapabilityLease obtained<\/code> <span class="pill ok">live/.test(t));
  ok("ladder: Connector execution + Materialized rows missing", /Connector execution<\/code> <span class="pill muted">missing/.test(t) && /Materialized rows<\/code> <span class="pill muted">missing/.test(t));
  ok("0-objects boundary preserved; brand-clean", /0 objects/.test(t) && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup — draft/test records removed; the minted lease REMAINS in the gateway audit trail
  // (an audit trail is append-only by nature; the crossing happened and is recorded).
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`materializing-run readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
