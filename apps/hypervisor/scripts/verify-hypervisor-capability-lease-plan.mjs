#!/usr/bin/env node
// CapabilityLease PLAN done-bar — credential-authority PLANNING for ODK materialization.
//
// The first credential-crossing contract a future materializing run would have to cite: it declares
// the EXACT CapabilityLease scope such a run may ask for — and mints NOTHING. Wallet authority
// becomes explicit BEFORE execution, but nothing operational crosses. The ONLY gateway is the
// EXISTING capability-lease primitive; this plane never becomes a second lease system.
//
// Asserts:
//   - NO source contact (instant create vs unreachable source); NO lease minted (the real
//     /v1/hypervisor/capability-leases count is UNCHANGED by planning); no credential material
//     accepted or emitted; object_instances stays 0.
//   - Binds the COMPLETE landed ladder (source → mapping → view → dry_run_ready run → ready
//     projection) and rejects every mismatch/degradation.
//   - Every scope-widening attempt rejected: properties beyond policy scope, properties beyond
//     projection-visible, operations beyond the view, unauthorized subject, purpose drift,
//     posture relaxation, unbounded TTL.
//   - Bypass lanes rejected: plaintext secret, raw query, env-credential fallback.
//   - Receipts/history on create/patch/revoke and every refusal; malformed patch no rev bump;
//     revoked is immutable.
//   - The ODK Manager renders the plan honestly (Resources + ladder rung 5 declared, Materializing
//     run still missing); brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-capability-lease-plan.mjs
// Exit 2 = BLOCKED (daemon not running).

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const gatewayCount = async () => (await jd("GET", "/v1/hypervisor/capability-leases")).j.leases?.length ?? -1;

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/capability-lease-plans/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon lease-plan plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (kind, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${kind}/${id}`]); };

  // Complete-ladder fixtures over an UNREACHABLE source (+ a non-leaseable source).
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "clp-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const dsNL = await jd("POST", "/v1/hypervisor/data-sources", { name: "clp-verify-nolease", kind: "local_folder", credential_posture: "no_credentials_required" });
  const noLeaseId = dsNL.j.data_source?.source_id;
  if (noLeaseId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${noLeaseId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "clp-verify", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } });
  const ontId = ontR.j.ontology?.id; const ontRef = ontR.j.ontology?.ref;
  track("domain-ontologies", ontId);
  const mapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "clp-verify-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] });
  const mapId = mapR.j.connector_mapping?.id;
  track("connector-mappings", mapId);
  const viewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "clp-verify-gate", authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform", "export"], purpose: "underwriting analysis", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded",
    export_posture: "receipted_export_only", receipt_obligations: ["export: one receipt per exported batch"] });
  const viewId = viewR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", viewId);
  const runR = await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapId, policy_view_id: viewId, name: "clp-verify-run" });
  const runId = runR.j.transformation_run?.id;
  track("transformation-runs", runId);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${runId}/dry-run`);
  const projR = await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mapId, policy_view_id: viewId, name: "clp-verify-explorer", visible_properties: ["loan_id", "title"] });
  const projId = projR.j.ontology_projection?.id;
  track("ontology-projections", projId);
  if (!dataSourceId || !noLeaseId || !ontId || !mapId || !viewId || !runId || !projId) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  const base = (extra) => ({ data_source_id: dataSourceId, connector_mapping_id: mapId, policy_view_id: viewId, transformation_run_id: runId, ontology_projection_id: projId,
    name: "materialize-loans-lease", subject: "agent://materializer", ttl_seconds: 900, ...extra });

  // 1. NO MINTING: gateway count before/after planning is UNCHANGED.
  const before = await gatewayCount();
  const t0 = Date.now();
  const created = await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", base({}));
  const elapsed = Date.now() - t0;
  const p0 = created.j.capability_lease_plan;
  track("capability-lease-plans", p0?.id);
  const after = await gatewayCount();
  ok("plan declares (201) instantly against an unreachable source — no contact", created.status === 201 && elapsed < 4000, `${elapsed}ms`);
  ok("NO LEASE MINTED — the real capability-lease gateway count is unchanged by planning", before >= 0 && before === after, `${before} → ${after}`);
  ok("inert invariants: minted=false, credential_material=false, contacted=false, moved=false, instances=0", p0?.lease?.minted === false && p0?.lease?.credential_material === false && p0?.execution?.source_contacted === false && p0?.execution?.data_moved === false && p0?.execution?.object_instances === 0);
  ok("gateway is the EXISTING capability-lease primitive (cited, not duplicated)", p0?.gateway?.primitive === "ioi.hypervisor.capability-lease.v1" && p0?.gateway?.route === "/v1/hypervisor/capability-leases");
  ok("the plan binds the COMPLETE ladder (all five refs present)", String(p0?.data_source_ref || "").startsWith("data-source:") && ["connector_mapping_ref", "policy_view_ref", "transformation_run_ref", "ontology_projection_ref"].every((k) => typeof p0?.[k] === "string" && p0[k].includes("://")));
  ok("scope defaults are the NARROWEST (projection-visible; read+transform; view postures echoed)", JSON.stringify(p0?.requested_properties) === JSON.stringify(["loan_id", "title"]) && JSON.stringify(p0?.requested_operations) === JSON.stringify(["read", "transform"]) && p0?.retention_posture === "bounded");
  ok("bounded TTL + missing MaterializingRun named", p0?.ttl_seconds === 900 && /MaterializingRun/.test(p0?.missing_authority || ""));
  ok("no secret material anywhere on the record", !JSON.stringify(p0 || {}).match(/hunter2|password|api_key|"secret"/i));
  ok("create receipted + history", (p0?.receipt_refs || []).length === 1 && (p0?.history || []).length === 1);

  // 2. Fail-closed lanes — bypasses, ladder degradation, and every scope-widening attempt.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    track("capability-lease-plans", r.j?.capability_lease_plan?.id);
  };
  await reject("plaintext secret", base({ password: "hunter2" }), "lease_plan_plaintext_secret_rejected");
  await reject("raw query body", base({ sql: "SELECT 1" }), "lease_plan_raw_query_rejected");
  await reject("env-credential fallback (authority bypass)", base({ from_env: "PGPASSWORD" }), "lease_plan_env_fallback_rejected");
  await reject("missing name", { ...base({}), name: undefined }, "lease_plan_name_required");
  await reject("unknown data source", base({ data_source_id: "ds_nope" }), "lease_plan_data_source_unknown");
  await reject("source posture not wallet-leaseable", base({ data_source_id: noLeaseId }), "lease_plan_posture_not_leaseable");
  await reject("unknown mapping", base({ connector_mapping_id: "cmap_nope" }), "lease_plan_mapping_unknown");
  await reject("unknown policy view", base({ policy_view_id: "pbdv_nope" }), "lease_plan_policy_view_unknown");
  await reject("unknown run", base({ transformation_run_id: "trun_nope" }), "lease_plan_run_unknown");
  await reject("unknown projection", base({ ontology_projection_id: "oproj_nope" }), "lease_plan_projection_unknown");
  await reject("subject not explicitly authorized by the view", base({ subject: "agent://stranger" }), "lease_plan_subject_not_authorized");
  await reject("purpose drift from the gate", base({ purpose: "resale" }), "lease_plan_purpose_mismatch");
  await reject("operation beyond the view (publish)", base({ requested_operations: ["read", "transform", "publish"] }), "lease_plan_operation_not_authorized");
  await reject("materializing lease without transform", base({ requested_operations: ["read"] }), "lease_plan_operation_not_authorized");
  await reject("scope widening beyond POLICY scope", base({ requested_properties: ["loan_id", "ghost"] }), "lease_plan_scope_widening_rejected");
  await reject("scope widening beyond PROJECTION-visible (amount is policy-scoped but not visible)", base({ requested_properties: ["loan_id", "amount"] }), "lease_plan_scope_widening_rejected");
  await reject("posture relaxation (durable vs the gate's bounded)", base({ retention_posture: "durable" }), "lease_plan_posture_conflict");
  await reject("TTL zero (unbounded)", base({ ttl_seconds: 0 }), "lease_plan_ttl_unbounded");
  await reject("TTL over the maximum", base({ ttl_seconds: 999999 }), "lease_plan_ttl_unbounded");
  // High-risk op WITH view authorization + obligations is admitted.
  const hr = await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", base({ name: "export-lease", requested_operations: ["read", "transform", "export"] }));
  track("capability-lease-plans", hr.j.capability_lease_plan?.id);
  ok("high-risk export WITH view authorization + named obligations is admitted", hr.status === 201 && hr.j.capability_lease_plan?.status === "declared");
  // Binding mismatch: a second ready mapping the rest of the ladder does not bind.
  const map2R = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "clp-verify-map2", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" } });
  track("connector-mappings", map2R.j.connector_mapping?.id);
  await reject("mixed ladder (view/run/projection bind a different mapping)", base({ connector_mapping_id: map2R.j.connector_mapping?.id }), "lease_plan_binding_mismatch");

  // 3. Patch + revoke semantics.
  const p1 = await jd("PATCH", `/v1/hypervisor/odk/capability-lease-plans/${p0.id}`, { description: "the exact lease a run may request" });
  ok("valid patch bumps revision + receipt", p1.j.capability_lease_plan?.revision === 2 && (p1.j.capability_lease_plan?.receipt_refs || []).length === 2);
  const p2 = await jd("PATCH", `/v1/hypervisor/odk/capability-lease-plans/${p0.id}`, { ttl_seconds: 999999 });
  ok("malformed patch is a receipted refusal (no state change)", p2.j.ok === false && p2.j.error?.code === "lease_plan_ttl_unbounded");
  const afterBad = await jd("GET", `/v1/hypervisor/odk/capability-lease-plans/${p0.id}`);
  ok("rejected patch does NOT bump the revision", afterBad.j.capability_lease_plan?.revision === 2, `rev ${afterBad.j.capability_lease_plan?.revision}`);
  const revoked = await jd("POST", `/v1/hypervisor/odk/capability-lease-plans/${hr.j.capability_lease_plan.id}/revoke`);
  const pR = await jd("PATCH", `/v1/hypervisor/odk/capability-lease-plans/${hr.j.capability_lease_plan.id}`, { name: "z" });
  ok("revoke is terminal + receipted; revoked is immutable", revoked.j.capability_lease_plan?.status === "revoked" && pR.j.error?.code === "lease_plan_revoked_immutable");

  // 4. Projections + overview honesty; and STILL nothing minted after all of the above.
  const hist = await jd("GET", `/v1/hypervisor/odk/capability-lease-plans/${p0.id}/history`);
  ok("/:id/history returns bounded history + persisted receipts (incl. the refused patch)", (hist.j.history || []).length >= 2 && (hist.j.receipts || []).length >= 3);
  const ov = await jd("GET", "/v1/hypervisor/odk/capability-lease-plans/overview");
  ok("overview: gateway cited + bounded TTL + plan-only governance gaps", ov.j.gateway?.route === "/v1/hypervisor/capability-leases" && ov.j.max_ttl_seconds === 3600 && (ov.j.governance_gaps || []).some((g) => /no lease is minted/i.test(g)));
  const finalCount = await gatewayCount();
  ok("after ALL planning activity the gateway is STILL unchanged (nothing ever minted)", finalCount === before, `${before} → ${finalCount}`);

  // 5. ODK Manager UX — honest credential-authority plan.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Manager renders lease plans as daemon truth (Resources, 'not minted')", page.status === 200 && /Capability-lease plans \(\d+\)/.test(t) && /not minted/.test(t) && t.includes("materialize-loans-lease"));
  ok("ladder rung 5: CapabilityLease plan declared (nothing minted)", /CapabilityLease plan<\/code> <span class="pill ok">declared/.test(t) && /nothing minted/.test(t));
  ok("execution + rows remain the missing crossings", /Connector execution<\/code> <span class="pill muted">missing/.test(t) && /Materialized rows<\/code> <span class="pill muted">missing/.test(t));
  ok("0-objects boundary preserved; brand-clean", /0 objects/.test(t) && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup — leave no draft debris.
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`capability-lease-plan readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
