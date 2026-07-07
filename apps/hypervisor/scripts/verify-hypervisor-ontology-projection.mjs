#!/usr/bin/env node
// OntologyProjection done-bar — the FOURTH and final inert ODK authority-crossing rung, completing
// the CONTRACT-COMPLETE skeleton: source → model → mapping → policy → run plan → projection.
//
// A projection declares the explorer/search/read SHAPE: "if authorized object data existed, what
// would this surface be allowed to render, search, filter, relate, and act on?" It binds a ready
// mapping + a ready READ-authorizing policy view (+ optionally a dry_run_ready run plan) and stays
// INERT: no live connector reads, no credential use, no extraction, no materialization —
// object_instances stays 0 and materialized stays false.
//
// Asserts:
//   - No source contact (instant create vs unreachable source); no object rows; no materialized
//     explorer results (the declared shape renders with a 0-objects boundary cell).
//   - Fail-closed on every lane: secret, raw query, missing name, unknown/not-ready mapping,
//     unknown/not-ready/mismatched view, view without `read`, unknown/not-ready/mismatched run,
//     unscoped visible/facet/sort/title/key properties, invalid layout, unknown action / wrong
//     object, action ENABLED without transform authorization, link affordance ENABLED (always a
//     false promise in v1), export affordance without export authorization + obligations.
//   - Honest health/lifecycle: empty visible → draft+gap; recheck drift → blocked (named);
//     retire is terminal + immutable; malformed patch is a receipted refusal, no rev bump.
//   - Receipts + bounded history on create/patch/recheck/retire; refusals receipted.
//   - The ODK Manager ladder is CONTRACT-COMPLETE: all four rungs declared; only the live crossing
//     (materializing run under credential authority) missing. Brand-clean; 0 objects everywhere.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ontology-projection.mjs
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
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/ontology-projections/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ontology-projection plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (kind, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${kind}/${id}`]); };

  // Full-ladder fixtures over an UNREACHABLE source.
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "oproj-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "oproj-verify", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [
      { id: "loan", name: "Loan", title_property: "title", properties: [
        { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
        { id: "title", name: "Title", value_type: "string" },
        { id: "amount", name: "Amount", value_type: "money" } ] },
      { id: "borrower", name: "Borrower", title_property: "name", properties: [{ id: "name", name: "Name", value_type: "string" }] },
    ],
    link_types: [{ id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" }],
    action_types: [
      { id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" },
      { id: "audit_b", name: "Audit Borrower", kind: "modify_object", applies_to: "borrower" } ],
  } });
  const ontId = ontR.j.ontology?.id; const ontRef = ontR.j.ontology?.ref;
  track("domain-ontologies", ontId);
  const mapR = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "oproj-verify-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] });
  const mapId = mapR.j.connector_mapping?.id;
  track("connector-mappings", mapId);
  const viewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "oproj-verify-gate", authority_subjects: ["agent://planner"],
    allowed_operations: ["read", "transform", "export"], purpose: "underwriting analysis", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded",
    export_posture: "receipted_export_only", receipt_obligations: ["export: one receipt per exported batch"] });
  const viewId = viewR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", viewId);
  const readOnlyR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "oproj-verify-readonly", authority_subjects: ["agent://reader"],
    allowed_operations: ["read"], purpose: "browse", property_scope: ["loan_id", "title"], retention_posture: "ephemeral" });
  const readOnlyId = readOnlyR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", readOnlyId);
  const noReadR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "oproj-verify-noread", authority_subjects: ["agent://t"],
    allowed_operations: ["transform"], purpose: "no read", property_scope: ["title"], retention_posture: "ephemeral" });
  const noReadId = noReadR.j.policy_bound_data_view?.id;
  track("policy-bound-data-views", noReadId);
  const runR = await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapId, policy_view_id: viewId, name: "oproj-verify-plan" });
  const runId = runR.j.transformation_run?.id;
  track("transformation-runs", runId);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${runId}/dry-run`);
  if (!dataSourceId || !ontId || !mapId || !viewId || !runId) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  const base = (extra) => ({ connector_mapping_id: mapId, policy_view_id: viewId, name: "loan-explorer", ...extra });

  // 1. Ready projection with the full declared shape, citing the dry_run_ready plan.
  const t0 = Date.now();
  const created = await jd("POST", "/v1/hypervisor/odk/ontology-projections", base({
    transformation_run_id: runId,
    visible_properties: ["loan_id", "title", "amount"], facet_properties: ["amount"], sort_fields: ["title"],
    layout: "table",
    action_affordances: [{ action_type_id: "approve", enabled: true }],
    relationship_affordances: [{ link_type_id: "held_by", enabled: false }],
    export_affordance_enabled: true,
  }));
  const elapsed = Date.now() - t0;
  const p0 = created.j.ontology_projection;
  track("ontology-projections", p0?.id);
  ok("projection declares (201) instantly against an unreachable source — no contact", created.status === 201 && elapsed < 4000, `${elapsed}ms`);
  ok("projection is ready + INERT: 0 instances, not materialized, missing authority named", p0?.status === "ready" && p0?.health?.object_instances === 0 && p0?.health?.materialized === false && /credential authority/.test(p0?.health?.missing_authority || ""));
  ok("title/key display default from the mapping (mapped + scoped)", p0?.title_field === "title" && p0?.key_field === "loan_id");
  ok("declared shape carries facets/sorts/layout + the cited dry_run_ready plan", (p0?.facet_properties || [])[0] === "amount" && p0?.layout === "table" && String(p0?.transformation_run_ref || "").startsWith("transformation-run://"));
  ok("affordances validated: action enabled (transform authorized) · link declared-only · export gated", p0?.action_affordances?.[0]?.enabled === true && p0?.relationship_affordances?.[0]?.enabled === false && p0?.export_affordance_enabled === true);
  ok("create is receipted + history", (p0?.receipt_refs || []).length === 1 && (p0?.history || []).length === 1);

  // 2. Fail-closed lanes.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/ontology-projections", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    track("ontology-projections", r.j?.ontology_projection?.id);
  };
  await reject("plaintext secret", base({ password: "hunter2" }), "projection_plaintext_secret_rejected");
  await reject("raw query body", base({ sql: "SELECT 1" }), "projection_raw_query_rejected");
  await reject("missing name", { connector_mapping_id: mapId, policy_view_id: viewId }, "projection_name_required");
  await reject("unknown mapping", base({ connector_mapping_id: "cmap_nope" }), "projection_mapping_unknown");
  await reject("unknown policy view", base({ policy_view_id: "pbdv_nope" }), "projection_policy_view_unknown");
  await reject("policy view without read (a projection is a read/search shape)", base({ policy_view_id: noReadId }), "projection_read_not_authorized");
  await reject("unknown transformation run", base({ transformation_run_id: "trun_nope" }), "projection_run_unknown");
  await reject("visible property outside mapped+policy scope", base({ visible_properties: ["ghost"] }), "projection_property_unscoped");
  await reject("facet property outside scope", base({ facet_properties: ["ghost"] }), "projection_property_unscoped");
  await reject("invalid layout", base({ layout: "hologram" }), "projection_layout_invalid");
  await reject("unknown action affordance", base({ action_affordances: [{ action_type_id: "ghost" }] }), "projection_action_affordance_unknown");
  await reject("action affordance for a different object type", base({ action_affordances: [{ action_type_id: "audit_b" }] }), "projection_action_affordance_unknown");
  await reject("action ENABLED without transform authorization", { connector_mapping_id: mapId, policy_view_id: readOnlyId, name: "x", action_affordances: [{ action_type_id: "approve", enabled: true }] }, "projection_action_affordance_not_authorized");
  await reject("unknown link affordance", base({ relationship_affordances: [{ link_type_id: "ghost" }] }), "projection_link_affordance_unknown");
  await reject("link affordance ENABLED (false promise — no object plane resolves rows)", base({ relationship_affordances: [{ link_type_id: "held_by", enabled: true }] }), "projection_link_affordance_unresolved");
  await reject("export affordance without export authorization + obligations", { connector_mapping_id: mapId, policy_view_id: readOnlyId, name: "x", export_affordance_enabled: true }, "projection_export_affordance_not_authorized");

  // 3. Honest health: explicitly empty visible properties → draft + named gap (not rejected).
  const empty = await jd("POST", "/v1/hypervisor/odk/ontology-projections", base({ name: "empty-vis", visible_properties: [] }));
  track("ontology-projections", empty.j.ontology_projection?.id);
  ok("empty visible properties → honest draft/incomplete with a named gap", empty.status === 201 && empty.j.ontology_projection?.status === "draft" && (empty.j.ontology_projection?.health?.gaps || []).some((g) => /visible/.test(g)));

  // 4. Recheck drift → blocked; patch semantics; retire immutability.
  const driftViewR = await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapId, name: "oproj-drift-gate", authority_subjects: ["agent://d"],
    allowed_operations: ["read"], purpose: "drift", property_scope: ["loan_id", "title"], retention_posture: "ephemeral" });
  const driftViewId = driftViewR.j.policy_bound_data_view?.id;
  const driftProjR = await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mapId, policy_view_id: driftViewId, name: "drift-proj" });
  const driftProj = driftProjR.j.ontology_projection;
  track("ontology-projections", driftProj?.id);
  await jd("DELETE", `/v1/hypervisor/odk/policy-bound-data-views/${driftViewId}`);
  const blocked = await jd("POST", `/v1/hypervisor/odk/ontology-projections/${driftProj.id}/recheck`);
  ok("recheck after gate drift → BLOCKED with a named reason (never cached)", blocked.j.ontology_projection?.status === "blocked" && blocked.j.ontology_projection?.blocked_reasons?.[0]?.code === "projection_policy_view_unknown");
  const p1 = await jd("PATCH", `/v1/hypervisor/odk/ontology-projections/${p0.id}`, { description: "main loan explorer" });
  ok("valid patch bumps revision + receipt", p1.j.ontology_projection?.revision === 2 && (p1.j.ontology_projection?.receipt_refs || []).length === 2);
  const p2 = await jd("PATCH", `/v1/hypervisor/odk/ontology-projections/${p0.id}`, { visible_properties: ["ghost"] });
  ok("malformed patch is a receipted refusal (no state change)", p2.j.ok === false && p2.j.error?.code === "projection_property_unscoped");
  const after = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${p0.id}`);
  ok("rejected patch does NOT bump the revision", after.j.ontology_projection?.revision === 2, `rev ${after.j.ontology_projection?.revision}`);
  const retired = await jd("POST", `/v1/hypervisor/odk/ontology-projections/${driftProj.id}/retire`);
  const pR = await jd("PATCH", `/v1/hypervisor/odk/ontology-projections/${driftProj.id}`, { name: "z" });
  const rcR = await jd("POST", `/v1/hypervisor/odk/ontology-projections/${driftProj.id}/recheck`);
  ok("retire is terminal + immutable (patch + recheck refused)", retired.j.ontology_projection?.status === "retired" && pR.j.error?.code === "projection_retired_immutable" && rcR.j.error?.code === "projection_retired_immutable");

  // 5. Projections + overview honesty.
  const hist = await jd("GET", `/v1/hypervisor/odk/ontology-projections/${p0.id}/history`);
  ok("/:id/history returns bounded history + persisted receipts (incl. the refused patch)", (hist.j.history || []).length >= 2 && (hist.j.receipts || []).length >= 3);
  const ov = await jd("GET", "/v1/hypervisor/odk/ontology-projections/overview");
  ok("overview: declarative lifecycle + missing live authority + no-rows governance gaps", JSON.stringify(ov.j.lifecycle_states) === JSON.stringify(["draft", "ready", "blocked", "retired"]) && /credential authority/.test(ov.j.missing_authority || "") && (ov.j.governance_gaps || []).some((g) => /never rows|no materialized/i.test(g)));
  const all = await jd("GET", "/v1/hypervisor/odk/ontology-projections");
  ok("no projection anywhere reports instances or materialization", (all.j.ontology_projections || []).every((p) => p.health?.object_instances === 0 && p.health?.materialized === false));

  // 6. ODK Manager UX — declared explorer shape + contract-complete ladder.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Explorer pane renders the DECLARED shape (projection declared · no materialized objects)", page.status === 200 && /projection declared/.test(t) && /no materialized objects/.test(t) && t.includes("loan-explorer"));
  ok("declared shape shows columns + 0-objects boundary cell (no fabricated rows)", /0 objects — projection declared, nothing materialized/.test(t));
  ok("ladder is CONTRACT-COMPLETE: all four rungs declared", (t.match(/(ConnectorMapping|PolicyBoundDataView|TransformationRun \+ receipts|OntologyProjection)<\/code> <span class="pill ok">declared/g) || []).length === 4);
  ok("execution + materialized rows remain the missing crossings", /Connector execution<\/code> <span class="pill muted">missing/.test(t) && /Materialized rows<\/code> <span class="pill muted">missing/.test(t));
  ok("brand-clean (no Palantir/Foundry leak)", !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup.
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ontology-projection readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
