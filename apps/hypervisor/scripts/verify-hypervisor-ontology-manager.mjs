#!/usr/bin/env node
// Ontology-manager contract done-bar — the ODK DomainOntology plane PROMOTED IN PLACE into a sharper
// schema-workbench contract (NOT a second plane). Data supplies declared source truth; Ontology is
// the semantic spine that recipes, domain apps, marketplace packs, evals and generated surfaces bind
// into — so its typed model is load-bearing and validated fail-closed.
//
// Asserts:
//   - No parallel ontology truth: /v1/hypervisor/odk/domain-ontologies is authority; the top-level
//     /v1/hypervisor/ontologies is only a GET alias over the same handler (no POST plane beside it).
//   - A typed CanonicalObjectModel (value/object/link/action types) validates and projects `ready`
//     health with object_instances 0; create is revision 1 + receipted + a history entry.
//   - Fail-closed on malformed models: missing domain, invalid type id, duplicate name, unresolved
//     link end, unresolved property value_type, bad cardinality, bad action kind, enum w/o values.
//   - Health is honest: an object with no relations/actions is `incomplete`; a legacy string-array
//     model (the pre-hardening shape) is tolerated as `empty` (no regression to older builders).
//   - PATCH bumps revision + appends history + writes a receipt; a malformed PATCH is rejected and
//     does NOT bump the revision.
//   - The Data/Ontology owner surface renders the manager as authority (typed counts + health) and
//     keeps NO object/explorer rows — the schema/explorer captures stay secondary references.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ontology-manager.mjs
// Exit 2 = BLOCKED (daemon not running).

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
// A well-formed model: typed object (property → base + declared value type), a relation, an action.
const readyModel = () => ({
  value_types: [{ id: "money", name: "Money", base: "double" }],
  object_types: [
    { id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" },
    ] },
    { id: "borrower", name: "Borrower", title_property: "name", properties: [{ id: "name", name: "Name", value_type: "string" }] },
  ],
  link_types: [{ id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" }],
  action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }],
});

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }
  const made = [];

  // 0. No parallel plane — the alias is GET-only over ODK; there is no POST truth beside it.
  const aliasGet = await jd("GET", "/v1/hypervisor/ontologies");
  ok("top-level /ontologies is a GET alias over ODK (list shape)", aliasGet.status === 200 && Array.isArray(aliasGet.j.ontologies), "alias ok");
  const aliasPost = await fetch(`${DAEMON}/v1/hypervisor/ontologies`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((r) => r.status).catch(() => 0);
  ok("no parallel write plane beside ODK (alias POST not allowed)", aliasPost === 404 || aliasPost === 405, `POST -> ${aliasPost}`);

  // 1. Typed create → ready, revision 1, receipted, history.
  const created = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-ontology-mgr", canonical_object_model: readyModel() });
  const rec = created.j.ontology;
  if (rec?.id) made.push(rec.id);
  ok("typed ontology creates (201)", created.status === 201 && !!rec?.ref, rec?.ref);
  ok("readiness health projects `ready` (required pieces present)", rec?.health?.status === "ready", rec?.health?.status);
  ok("no object instances (schema only — explorer boundary)", rec?.health?.object_instances === 0);
  ok("create is revision 1 + receipted + a history entry", rec?.revision === 1 && (rec?.receipt_refs || []).length >= 1 && (rec?.history || []).length >= 1, `rev ${rec?.revision}`);
  ok("receipt ref is an ontology receipt", String((rec?.receipt_refs || [])[0] || "").startsWith("agentgres://odk-ontology-receipt/"));

  // 2. Health + history projection routes (projections over ODK).
  const health = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${rec.id}/health`);
  ok("/:id/health projects readiness", health.status === 200 && health.j.health?.status === "ready" && health.j.revision === 1);
  const hist = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${rec.id}/history`);
  ok("/:id/history returns history + receipts", hist.status === 200 && (hist.j.history || []).length >= 1 && (hist.j.receipts || []).length >= 1);

  // 3. Fail-closed lanes — each rejected with its specific code.
  const reject = async (label, body, code) => {
    const r = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", body);
    ok(`fail-closed: ${label}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code || `status ${r.status}`);
    if (r.j?.ontology?.id) made.push(r.j.ontology.id); // safety: never leak an accidental create
  };
  await reject("missing domain", { canonical_object_model: {} }, "odk_domain_required");
  await reject("invalid type id", { domain: "x", canonical_object_model: { object_types: [{ id: "Loan!", name: "Loan" }] } }, "ontology_type_id_invalid");
  await reject("duplicate object name", { domain: "x", canonical_object_model: { object_types: [
    { id: "a", name: "Loan", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] },
    { id: "b", name: "loan", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] },
  ] } }, "ontology_duplicate_name");
  await reject("unresolved link end", { domain: "x", canonical_object_model: { object_types: [{ id: "loan", name: "Loan" }], link_types: [{ id: "l", name: "L", from: "loan", to: "ghost", cardinality: "one_to_one" }] } }, "ontology_ref_unresolved");
  await reject("unresolved property value_type", { domain: "x", canonical_object_model: { object_types: [{ id: "loan", name: "Loan", properties: [{ id: "amt", name: "Amt", value_type: "currency" }] }] } }, "ontology_ref_unresolved");
  await reject("bad cardinality", { domain: "x", canonical_object_model: { object_types: [{ id: "a", name: "A" }, { id: "b", name: "B" }], link_types: [{ id: "l", name: "L", from: "a", to: "b", cardinality: "lots" }] } }, "ontology_cardinality_invalid");
  await reject("bad action kind", { domain: "x", canonical_object_model: { object_types: [{ id: "a", name: "A" }], action_types: [{ id: "x", name: "X", kind: "teleport", applies_to: "a" }] } }, "ontology_action_kind_invalid");
  await reject("enum value type without values", { domain: "x", canonical_object_model: { value_types: [{ id: "grade", name: "Grade", base: "enum" }] } }, "ontology_enum_values_required");
  await reject("malformed model JSON (parse sentinel)", { domain: "x", canonical_object_model: { __json_parse_error: true } }, "ontology_object_model_json_invalid");

  // 4. Honest health — incomplete + legacy back-compat.
  const inc = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-incomplete", canonical_object_model: { object_types: [{ id: "loan", name: "Loan", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }] } });
  if (inc.j?.ontology?.id) made.push(inc.j.ontology.id);
  ok("object with no relations/actions is `incomplete` (honest)", inc.j.ontology?.health?.status === "incomplete" && (inc.j.ontology?.health?.gaps || []).some((g) => /relations or behaviors/.test(g)));
  const legacy = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-legacy", canonical_object_model: { objects: ["Loan", "Borrower"], actions: ["approve"], states: ["draft"], roles: [], events: [] } });
  if (legacy.j?.ontology?.id) made.push(legacy.j.ontology.id);
  ok("legacy string-array model still creates (no regression to older builders)", legacy.status === 201 && legacy.j.ontology?.health?.status === "empty", legacy.j.ontology?.health?.status);

  // 5. PATCH — revision bump + history + receipt; a bad patch is rejected without a bump.
  const p1 = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${rec.id}`, { description: "now underwritten" });
  ok("valid patch bumps revision + appends history + receipt", p1.j.ontology?.revision === 2 && (p1.j.ontology?.history || []).length === 2 && (p1.j.ontology?.receipt_refs || []).length === 2, `rev ${p1.j.ontology?.revision}`);
  const p2 = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${rec.id}`, { canonical_object_model: { object_types: [{ id: "BAD ID", name: "x" }] } });
  ok("malformed patch is rejected (ok:false + code)", p2.j.ok === false && p2.j.error?.code === "ontology_type_id_invalid", p2.j.error?.code);
  const afterBad = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${rec.id}/health`);
  ok("rejected patch does NOT bump the revision", afterBad.j.revision === 2, `rev ${afterBad.j.revision}`);

  // 6. Overview projections — model vocab + honest health rollup (over ODK, not a 2nd plane).
  const ov = await jd("GET", "/v1/hypervisor/odk/overview");
  ok("overview publishes the object-model vocab", (ov.j.object_model_vocab?.base_value_types || []).length >= 5 && (ov.j.object_model_vocab?.link_cardinalities || []).length === 3 && (ov.j.object_model_vocab?.action_kinds || []).length === 4);
  ok("overview publishes an honest health rollup", ov.j.ontology_health && typeof ov.j.ontology_health.ready === "number" && typeof ov.j.ontology_health.incomplete === "number" && typeof ov.j.ontology_health.empty === "number");

  // 7. Owner surface — the Ontology Manager reference-UX parity shell over daemon authority. Select
  //    the ready fixture so its typed panes render deterministically.
  const page = await fetch(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(rec.id)}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  const t = page.text;
  ok("owner surface serves brand-clean", page.status === 200 && !/\bPalantir\b/.test(t));
  ok("primary surface IS the Ontology Manager (reference-UX grammar)", /<h1[^>]*>Ontology Manager/.test(t));
  ok("manager renders the reference IA panes", ['pane-object-types', 'pane-properties', 'pane-link-types', 'pane-action-types', 'pane-value-types', 'pane-functions', 'pane-health-issues', 'pane-configuration'].every((p) => t.includes(`id="${p}"`)));
  ok("panes are daemon-backed (the selected ready ontology's typed model renders)", t.includes("verify-ontology-mgr") && t.includes("Loan") && t.includes("Held by"));
  ok("surface shows honest health (a `ready` pill)", /pill ok">ready/.test(t));
  ok("object-instance boundary is stated (0 objects, no explorer rows)", /0 objects/.test(t) && /Object data (&amp;|&) Explorer/.test(t));
  ok("unsupported lanes name the missing authority contracts", ["ConnectorMapping", "PolicyBoundDataView", "TransformationRun", "OntologyProjection"].every((c) => t.includes(c)));
  ok("IOI authority threaded in (daemon truth + receipts + conformance)", /daemon truth/.test(t) && /receipt/i.test(t) && /Conformance/.test(t));
  ok("schema + explorer captures kept secondary (linked references)", t.includes("/__apps/explorer") && t.includes("/__apps/schema"));
  ok("Data plane still rendered (data-source authority present)", /Data sources/.test(t) && t.includes("/__apps/sources"));

  // SHELL PIXEL CERTIFICATION (#41) — shell_pixel_certified is a layer ON TOP of daemon_wired:
  // pixel-identical SHELL (certified by the committed evidence file the harness itself wrote),
  // semantically-truthful BODY (which is what everything above just proved against the LIVE daemon —
  // typed counts, resources, health, disabled named-gap lanes). The matrix row and the committed cert
  // must agree, and the cert must be genuine measurement (non-pinned, both desktop viewports, budgets).
  {
    const { readFileSync } = await import("node:fs");
    const path = (await import("node:path")).default;
    const { fileURLToPath } = await import("node:url");
    const here = path.dirname(fileURLToPath(import.meta.url));
    const appRoot = path.resolve(here, "..");
    let row = null, cert = null;
    try { const m = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8")); row = (m.seeds || []).find((s) => s.slug === "schema"); } catch { /* */ }
    try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: schema is shell_pixel_certified (pixel-identical shell, semantically-truthful body) with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/schema.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: schema slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "schema" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" · ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated ≤ 1.25% AND raw ≤ 3.0% on every certified viewport, with real certified-shell coverage (shell not masked away)", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
  }

  // Cleanup.
  for (const id of made) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ontology-manager readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
