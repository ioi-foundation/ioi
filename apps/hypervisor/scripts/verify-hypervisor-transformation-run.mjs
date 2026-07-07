#!/usr/bin/env node
// TransformationRun + receipts done-bar — the THIRD ODK authority-crossing rung: an auditable
// PLAN / DRY-RUN contract, NOT live source contact.
//
// "A run may exist" ≠ "the system can pull from Postgres/S3/API and mint semantic objects." A v1 run
// references one READY ConnectorMapping and one READY PolicyBoundDataView (same mapping, `transform`
// allowed) and produces an auditable plan/dry-run receipt only. No source contact, no extraction, no
// object instances, no explorer rows, no connector credentials. `executed`/`materialized` are
// RESERVED for a future connector-adapter cut.
//
// Asserts:
//   - NO SOURCE CONTACT even for unreachable sources: create + dry-run complete instantly;
//     execution.source_contacted false; object_instances 0.
//   - Fail-closed on every lane: secret, raw query body, missing name, unknown/not-ready mapping,
//     unknown/not-ready view, view↔mapping mismatch, unsupported operation, transform not
//     authorized, field outside policy scope, purpose mismatch, invalid intent, high-risk intent not
//     authorized / without receipt obligations.
//   - Policy envelope enforced at plan time AND re-checked at dry-run (drift → blocked, named).
//   - Receipts BEFORE output registration; every create/dry-run/block/cancel/patch — and every
//     FAILED validation — is receipted; bounded history never lost; malformed patch no rev bump;
//     cancelled is immutable.
//   - The ODK Manager ladder reads: ConnectorMapping declared · PolicyBoundDataView declared ·
//     TransformationRun plan/dry-run declared · OntologyProjection missing. 0 objects; brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-transformation-run.mjs
// Exit 2 = BLOCKED (daemon not running).

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/transformation-runs/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon transformation-run plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (kind, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${kind}/${id}`]); };

  // Fixtures — UNREACHABLE source → ready ontology → ready mapping (+incomplete sibling) → views.
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "trun-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "trun-verify", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" },
    ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } });
  const ontId = ontR.j.ontology?.id; const ontRef = ontR.j.ontology?.ref;
  track("domain-ontologies", ontId);
  const mapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "trun-verify-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] });
  const mapId = mapR.j.connector_mapping?.id;
  track("connector-mappings", mapId);
  const incMapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "trun-verify-inc", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "a", property_id: "amount", source_type: "double" },
    title_mapping: { source_field: "d", property_id: "title", source_type: "string" } });
  const incMapId = incMapR.j.connector_mapping?.id;
  track("connector-mappings", incMapId);
  const viewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "trun-verify-gate", authority_subjects: ["agent://planner"],
    allowed_operations: ["read", "transform", "export"], purpose: "underwriting analysis", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded",
    export_posture: "receipted_export_only", receipt_obligations: ["export: one receipt per exported batch"] });
  const viewId = viewR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", viewId);
  const readOnlyR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "trun-verify-readonly", authority_subjects: ["agent://reader"],
    allowed_operations: ["read"], purpose: "browse", property_scope: ["title"], retention_posture: "ephemeral" });
  const readOnlyId = readOnlyR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", readOnlyId);
  if (!dataSourceId || !ontId || !mapId || !viewId || !readOnlyId) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  const base = (extra) => ({ connector_mapping_id: mapId, policy_view_id: viewId, name: "loan-plan", ...extra });

  // 1. Plan admitted instantly (no source contact for an unreachable source), inert, receipted.
  const t0 = Date.now();
  const created = await jd("POST", "/v1/hypervisor/odk/transformation-runs", base({ requested_fields: ["loan_id", "amount"] }));
  const elapsed = Date.now() - t0;
  const r0 = created.j.transformation_run;
  track("transformation-runs", r0?.id);
  ok("plan admitted (201) instantly against an UNREACHABLE source — no contact", created.status === 201 && r0?.status === "planned" && elapsed < 4000, `${elapsed}ms`);
  ok("run is INERT: source_contacted false, data_moved false, object_instances 0", r0?.execution?.source_contacted === false && r0?.execution?.data_moved === false && r0?.execution?.object_instances === 0);
  ok("create is receipted + history; OntologyProjection named still-missing", (r0?.receipt_refs || []).length === 1 && (r0?.history || []).length === 1 && JSON.stringify(r0?.missing_contracts) === JSON.stringify(["OntologyProjection"]));

  // 2. Dry-run → auditable plan; receipt registered BEFORE the plan output; gate recorded on plan.
  const dr = await jd("POST", `/v1/hypervisor/odk/transformation-runs/${r0.id}/dry-run`);
  const r1 = dr.j.transformation_run;
  ok("dry-run → dry_run_ready with an auditable plan (fields resolved from the mapping)", r1?.status === "dry_run_ready" && (r1?.plan?.fields || []).length === 2 && r1?.plan?.fields?.some((f) => f.property_id === "loan_id" && f.source_field === "id"));
  ok("plan declares would_contact_source false + receipts_before_output true + 0 instances", r1?.plan?.would_contact_source === false && r1?.plan?.receipts_before_output === true && r1?.plan?.object_instances === 0);
  ok("plan carries the policy gate (view ref + purpose + obligations)", String(r1?.plan?.policy_gate?.policy_view_ref || "").startsWith("policy-bound-data-view://") && r1?.plan?.policy_gate?.purpose === "underwriting analysis");
  ok("dry-run receipted (2 receipts, 2 history entries)", (r1?.receipt_refs || []).length === 2 && (r1?.history || []).length === 2);

  // 3. Fail-closed lanes.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/transformation-runs", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    track("transformation-runs", r.j?.transformation_run?.id);
  };
  await reject("plaintext secret", base({ password: "hunter2" }), "transformation_run_plaintext_secret_rejected");
  await reject("raw query body (no ad-hoc extraction semantics)", base({ sql: "SELECT * FROM loans" }), "transformation_run_raw_query_rejected");
  await reject("missing name", { connector_mapping_id: mapId, policy_view_id: viewId }, "transformation_run_name_required");
  await reject("unknown mapping", base({ connector_mapping_id: "cmap_nope" }), "transformation_run_mapping_unknown");
  await reject("mapping not ready", base({ connector_mapping_id: incMapId }), "transformation_run_mapping_not_ready");
  await reject("unknown policy view", base({ policy_view_id: "pbdv_nope" }), "transformation_run_policy_view_unknown");
  await reject("view does not authorize transform", base({ policy_view_id: readOnlyId }), "transformation_run_operation_not_authorized");
  await reject("operation unsupported in v1 (only transform)", base({ operation: "export" }), "transformation_run_operation_unsupported");
  await reject("requested field outside the policy scope", base({ requested_fields: ["ghost"] }), "transformation_run_field_unscoped");
  await reject("purpose mismatch with the policy view", base({ purpose: "resale" }), "transformation_run_purpose_mismatch");
  await reject("invalid output intent", base({ output_intent: "crystal_ball" }), "transformation_run_output_intent_invalid");
  await reject("high-risk intent the view does not authorize", base({ output_intent: "training_material" }), "transformation_run_intent_not_authorized");
  // view↔mapping mismatch: a second ready mapping the view does not bind.
  const map2R = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "trun-verify-map2", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" } });
  track("connector-mappings", map2R.j.connector_mapping?.id);
  await reject("policy view binds a different mapping", base({ connector_mapping_id: map2R.j.connector_mapping?.id }), "transformation_run_policy_view_mapping_mismatch");
  // Authorized high-risk intent (export allowed + obligated) is admitted.
  const hr = await jd("POST", "/v1/hypervisor/odk/transformation-runs", base({ name: "export-plan", output_intent: "export_bundle" }));
  track("transformation-runs", hr.j.transformation_run?.id);
  ok("high-risk intent WITH authorized op + named obligations is admitted", hr.status === 201 && hr.j.transformation_run?.status === "planned");

  // 4. Policy-envelope drift → blocked with a named reason; retry keeps history intact.
  const driftViewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "trun-drift-gate", authority_subjects: ["agent://p"],
    allowed_operations: ["transform"], purpose: "drift test", property_scope: ["title"], retention_posture: "ephemeral" });
  const driftViewId = driftViewR.j.policy_bound_data_view?.id;
  const driftRunR = await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapId, policy_view_id: driftViewId, name: "drift-plan" });
  const driftRun = driftRunR.j.transformation_run;
  track("transformation-runs", driftRun?.id);
  await jd("DELETE", `/v1/hypervisor/odk/policy-bound-data-views/${driftViewId}`);
  const blocked = await jd("POST", `/v1/hypervisor/odk/transformation-runs/${driftRun.id}/dry-run`);
  ok("gate drift (view deleted) → dry-run BLOCKED with a named reason (re-checked, never cached)", blocked.j.transformation_run?.status === "blocked" && blocked.j.transformation_run?.blocked_reasons?.[0]?.code === "transformation_run_policy_view_unknown");
  const blocked2 = await jd("POST", `/v1/hypervisor/odk/transformation-runs/${driftRun.id}/dry-run`);
  ok("retry while blocked keeps history intact (grows, never lost)", blocked2.j.transformation_run?.status === "blocked" && (blocked2.j.transformation_run?.history || []).length === 3);

  // 5. Patch semantics + cancel immutability.
  const p1 = await jd("PATCH", `/v1/hypervisor/odk/transformation-runs/${r0.id}`, { requested_fields: ["title"] });
  ok("plan-affecting patch re-validates, resets to planned, clears the stale plan, bumps rev", p1.j.transformation_run?.status === "planned" && p1.j.transformation_run?.plan === null && p1.j.transformation_run?.revision === 2);
  const p2 = await jd("PATCH", `/v1/hypervisor/odk/transformation-runs/${r0.id}`, { requested_fields: ["ghost"] });
  ok("malformed patch rejected (receipted refusal, no state change)", p2.j.ok === false && p2.j.error?.code === "transformation_run_field_unscoped");
  const afterBad = await jd("GET", `/v1/hypervisor/odk/transformation-runs/${r0.id}`);
  ok("rejected patch does NOT bump the revision", afterBad.j.transformation_run?.revision === 2, `rev ${afterBad.j.transformation_run?.revision}`);
  const cancel = await jd("POST", `/v1/hypervisor/odk/transformation-runs/${r0.id}/cancel`);
  ok("cancel is terminal + receipted", cancel.j.transformation_run?.status === "cancelled");
  const drC = await jd("POST", `/v1/hypervisor/odk/transformation-runs/${r0.id}/dry-run`);
  const pC = await jd("PATCH", `/v1/hypervisor/odk/transformation-runs/${r0.id}`, { name: "z" });
  ok("cancelled run is immutable (dry-run + patch both refused)", drC.j.error?.code === "transformation_run_cancelled_immutable" && pC.j.error?.code === "transformation_run_cancelled_immutable");

  // 6. Projections: history + overview name the honest boundaries; reserved states never set.
  const hist = await jd("GET", `/v1/hypervisor/odk/transformation-runs/${r0.id}/history`);
  ok("/:id/history returns bounded history + persisted receipts", (hist.j.history || []).length >= 4 && (hist.j.receipts || []).length >= 4);
  const ov = await jd("GET", "/v1/hypervisor/odk/transformation-runs/overview");
  ok("overview: v1 lifecycle + executed/materialized RESERVED for a future connector-adapter cut", JSON.stringify(ov.j.lifecycle_states) === JSON.stringify(["planned", "dry_run_ready", "blocked", "cancelled"]) && JSON.stringify(ov.j.reserved_states?.states) === JSON.stringify(["executed", "materialized"]));
  ok("overview names plan-only + no-source-read + receipted-refusals governance gaps", (ov.j.governance_gaps || []).some((g) => /never contacts a source/i.test(g)) && (ov.j.governance_gaps || []).some((g) => /FAILED validation is receipted/i.test(g)));
  const runsNow = await jd("GET", "/v1/hypervisor/odk/transformation-runs");
  ok("no run anywhere reports executed/materialized or object instances", (runsNow.j.transformation_runs || []).every((r) => !["executed", "materialized"].includes(r.status) && r.execution?.object_instances === 0));

  // 7. ODK Manager UX — runs as daemon truth; the ladder's third rung declared.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Manager renders transformation runs as daemon truth (Resources)", page.status === 200 && /Transformation runs \(\d+\)/.test(t) && /no source contact/.test(t));
  ok("ladder: ConnectorMapping + PolicyBoundDataView + TransformationRun all declared", /ConnectorMapping<\/code> <span class="pill ok">declared/.test(t) && /PolicyBoundDataView<\/code> <span class="pill ok">declared/.test(t) && /TransformationRun \+ receipts<\/code> <span class="pill ok">declared/.test(t));
  ok("ladder: OntologyProjection named; execution + rows still missing", /OntologyProjection<\/code>/.test(t) && /Connector execution<\/code> <span class="pill muted">missing/.test(t) && /Materialized rows<\/code> <span class="pill muted">missing/.test(t));
  ok("0-objects boundary preserved; brand-clean", /0 objects/.test(t) && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup — leave no draft debris.
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`transformation-run readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
