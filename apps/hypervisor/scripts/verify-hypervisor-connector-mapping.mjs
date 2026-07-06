#!/usr/bin/env node
// ConnectorMapping done-bar — the FIRST inert authority-crossing brick.
//
// A ConnectorMapping DECLARES how a registered data source's fields would bind to a typed ontology
// object's properties. It is validated, receipted, and INERT: no extraction, no source read, no
// object instances, no explorer rows, no data movement. It is rung 1 of the ladder the surface names
// honestly — PolicyBoundDataView → TransformationRun → OntologyProjection remain missing.
//
// Asserts:
//   - INERT: a mapping created against an UNREACHABLE source succeeds instantly and never reads it;
//     object_instances stays 0; ingestion is not wired; the three downstream contracts stay missing.
//   - Fail-closed on every lane: plaintext secret, missing name, unknown source/ontology/object/
//     property, invalid source type, incompatible value type, cardinality mismatch, duplicate target,
//     missing key/title mapping, title must target the object's title_property.
//   - Receipts + bounded history on create/patch; a malformed patch does NOT bump the revision.
//   - Honest health: required-property coverage → ready/incomplete; overview names the gaps.
//   - The ODK Ontology Manager UX renders the mapping as daemon truth (Resources) and the
//     authority-crossing ladder (ConnectorMapping declared; the rest missing); no object rows appear;
//     brand-clean, no reference leak.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-connector-mapping.mjs
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
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/connector-mappings/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon connector-mapping plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];

  // Fixtures: a declared data source (#10) pointing at an UNREACHABLE endpoint, and a ready typed
  // ontology (#11) whose `loan` object has a REQUIRED `loan_id`.
  const dsR = await jd("POST", "/v1/hypervisor/data-sources", { name: "cmap-verify-src", kind: "postgres", endpoint: "postgres://unreachable.invalid:5432/db", credential_posture: "wallet_credential_lease" });
  const dataSourceId = dsR.j.data_source?.source_id;
  if (dataSourceId) cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${dataSourceId}`]);
  const ontR = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "cmap-verify", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" },
    ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
  } });
  const ontRef = ontR.j.ontology?.ref;
  const ontId = ontR.j.ontology?.id;
  if (ontId) cleanup.push(["DELETE", `/v1/hypervisor/odk/domain-ontologies/${ontId}`]);
  if (!dataSourceId || !ontRef) { console.error("BLOCKED: fixtures failed"); process.exit(2); }

  const KEY = { source_field: "id", property_id: "loan_id", source_type: "string" };
  const TITLE = { source_field: "disp", property_id: "title", source_type: "string" };
  const base = (extra) => ({ name: "loan-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan", key_mapping: KEY, title_mapping: TITLE, ...extra });

  // 1. INERT valid mapping — against the UNREACHABLE source, instantly, with no read.
  const t0 = Date.now();
  const created = await jd("POST", "/v1/hypervisor/odk/connector-mappings", base({ field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] }));
  const elapsed = Date.now() - t0;
  const m = created.j.connector_mapping;
  if (m?.id) cleanup.push(["DELETE", `/v1/hypervisor/odk/connector-mappings/${m.id}`]);
  ok("valid mapping declares (201) against an unreachable source, instantly (no source read)", created.status === 201 && !!m?.ref && elapsed < 4000, `${elapsed}ms`);
  ok("mapping is INERT — ingestion not wired, no object instances", m?.ingestion?.wired === false && m?.health?.object_instances === 0);
  ok("authority is NOT crossed; the three downstream contracts stay missing", m?.health?.authority_crossed === false && JSON.stringify(m?.health?.missing_contracts) === JSON.stringify(["PolicyBoundDataView", "TransformationRun", "OntologyProjection"]));
  ok("mapping is declared + receipted + has a history entry", m?.status === "declared" && (m?.receipt_refs || []).length >= 1 && (m?.history || []).length >= 1);
  ok("receipt ref is a connector-mapping receipt", String((m?.receipt_refs || [])[0] || "").startsWith("agentgres://connector-mapping-receipt/"));
  ok("health is `ready` (required loan_id covered by the key mapping)", m?.health?.status === "ready", m?.health?.status);
  ok("no plaintext credential is stored anywhere on the record", !JSON.stringify(m || {}).match(/hunter2|password|api_key|"secret"/i));

  // 2. Honest incomplete — required property left unmapped.
  const inc = await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "inc-map", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan", key_mapping: { source_field: "a", property_id: "amount", source_type: "double" }, title_mapping: TITLE });
  if (inc.j.connector_mapping?.id) cleanup.push(["DELETE", `/v1/hypervisor/odk/connector-mappings/${inc.j.connector_mapping.id}`]);
  ok("required property left unmapped → honest `incomplete` + named gap", inc.j.connector_mapping?.health?.status === "incomplete" && (inc.j.connector_mapping?.health?.required_gaps || []).some((g) => /Loan Id/i.test(g)));

  // 3. Fail-closed lanes.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/connector-mappings", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    if (r.j?.connector_mapping?.id) cleanup.push(["DELETE", `/v1/hypervisor/odk/connector-mappings/${r.j.connector_mapping.id}`]);
  };
  await reject("plaintext secret", base({ password: "hunter2" }), "connector_mapping_plaintext_secret_rejected");
  await reject("missing name", { data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan", key_mapping: KEY, title_mapping: TITLE }, "connector_mapping_name_required");
  await reject("unknown data source", base({ data_source_id: "ds_nope" }), "connector_mapping_data_source_unknown");
  await reject("unknown ontology", base({ ontology_ref: "ontology://nope" }), "connector_mapping_ontology_unknown");
  await reject("unknown object type", base({ object_type_id: "ghost" }), "connector_mapping_object_type_unknown");
  await reject("missing key mapping", { name: "x", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan", title_mapping: TITLE }, "connector_mapping_key_mapping_required");
  await reject("missing title mapping", { name: "x", data_source_id: dataSourceId, ontology_ref: ontRef, object_type_id: "loan", key_mapping: KEY }, "connector_mapping_title_mapping_required");
  await reject("title must target the title_property", base({ title_mapping: { source_field: "d", property_id: "amount", source_type: "double" } }), "connector_mapping_title_mapping_required");
  await reject("unknown property", base({ field_mappings: [{ source_field: "z", property_id: "ghost", source_type: "string" }] }), "connector_mapping_property_unknown");
  await reject("invalid source type", base({ field_mappings: [{ source_field: "z", property_id: "amount", source_type: "blob" }] }), "connector_mapping_source_type_invalid");
  await reject("incompatible value type", base({ field_mappings: [{ source_field: "z", property_id: "amount", source_type: "string" }] }), "connector_mapping_value_type_incompatible");
  await reject("cardinality mismatch (multi → scalar)", base({ field_mappings: [{ source_field: "z", property_id: "amount", source_type: "double", source_cardinality: "many" }] }), "connector_mapping_cardinality_mismatch");
  await reject("duplicate target property", base({ field_mappings: [{ source_field: "a", property_id: "amount", source_type: "double" }, { source_field: "b", property_id: "amount", source_type: "double" }] }), "connector_mapping_duplicate_target");

  // 4. Projections + patch semantics.
  const health = await jd("GET", `/v1/hypervisor/odk/connector-mappings/${m.id}/health`);
  ok("/:id/health projects readiness (object_instances 0)", health.status === 200 && health.j.health?.status === "ready" && health.j.health?.object_instances === 0);
  const hist = await jd("GET", `/v1/hypervisor/odk/connector-mappings/${m.id}/history`);
  ok("/:id/history returns history + receipts", (hist.j.history || []).length >= 1 && (hist.j.receipts || []).length >= 1);
  const ov = await jd("GET", "/v1/hypervisor/odk/connector-mappings/overview");
  ok("overview names the inert/missing-contract governance gaps", (ov.j.governance_gaps || []).some((g) => /INERT|nothing here reads|no extraction/i.test(g)) && JSON.stringify(ov.j.missing_contracts) === JSON.stringify(["PolicyBoundDataView", "TransformationRun", "OntologyProjection"]));
  const p1 = await jd("PATCH", `/v1/hypervisor/odk/connector-mappings/${m.id}`, { description: "bound" });
  ok("valid patch bumps revision + history + receipt", p1.j.connector_mapping?.revision === 2 && (p1.j.connector_mapping?.history || []).length === 2 && (p1.j.connector_mapping?.receipt_refs || []).length === 2);
  const p2 = await jd("PATCH", `/v1/hypervisor/odk/connector-mappings/${m.id}`, { field_mappings: [{ source_field: "z", property_id: "ghost", source_type: "string" }] });
  ok("malformed patch rejected (ok:false + code)", p2.j.ok === false && p2.j.error?.code === "connector_mapping_property_unknown");
  const after = await jd("GET", `/v1/hypervisor/odk/connector-mappings/${m.id}/health`);
  ok("rejected patch does NOT bump the revision", after.j.revision === 2, `rev ${after.j.revision}`);

  // 5. ODK Manager UX renders the mapping as daemon truth; no object rows; brand-clean.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("Ontology Manager renders the mapping as daemon truth (Resources)", page.status === 200 && /Connector mappings \(\d+\)/.test(t) && t.includes(m.id.startsWith("cmap") ? "loan-map" : "loan-map"));
  ok("authority-crossing ladder shows ConnectorMapping declared", /ConnectorMapping<\/code> <span class="pill ok">declared/.test(t));
  ok("ladder keeps the three downstream contracts missing", ["PolicyBoundDataView", "TransformationRun", "OntologyProjection"].every((c) => t.includes(c)) && /pill muted">missing/.test(t));
  ok("mapping row states it is not extracting (inert)", /not extracting/.test(t));
  ok("no object/explorer rows appear (0 objects boundary preserved)", /0 objects/.test(t));
  ok("surface is brand-clean (no Palantir/Foundry leak)", !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // Cleanup — leave no draft debris.
  for (const [method, p] of cleanup.reverse()) await jd(method, p);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`connector-mapping readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
