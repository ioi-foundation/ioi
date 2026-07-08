#!/usr/bin/env node
// PIPELINE BUILDER REFERENCE PORT — #32 done-bar (reference_ported; daemon_wired BLOCKED, honestly).
//
// /__ioi/pipeline is a ported source-neutral reference builder SHELL (left rail · header · graph
// toolbar · canvas node cards · right output panel · bottom tray) — NOT the dark automationsShell —
// fully wired to the real ODK authority ladder. It is NOT daemon_wired: every /workspace/builder/*
// route in the local mirror renders "An error occurred" (only the global platform nav renders), so
// there is NO valid builder reference to prove structural parity against. This verifier asserts the
// port is real + wired AND that the harness correctly REFUSES to grant parity against the errored
// reference (the guard works) — so parity is not falsely claimed.
//
// Asserts:
//   - MATRIX: pipeline = reference_ported → /__ioi/pipeline (port_surface) with a parity_blocked note;
//     0 daemon_wired; lineage/vertex stay substrate_bound.
//   - PORTED SHELL (not automationsShell): the page is the pb-shell with a rail + canvas; no .wrap doc.
//   - GUARD: the local builder REFERENCE errors, and the harness therefore records structural_parity
//     FALSE for pipeline (an error page can never yield a parity pass) — daemon_wired stays blocked.
//   - PORT IS REAL: the IOI candidate itself renders the builder shell regions (rail+body+…).
//   - DAEMON TRUTH INSIDE THE SHELL: a fully-built pipeline shows 7/7 stages live, the built state, the
//     real object-instance count, the datasource→transform→output node cards, and real Preview rows.
//   - UNSUPPORTED CONTROLS DISABLED IN PLACE: Build + Preview enabled; Schedule + Deploy present but
//     disabled (named gaps), not moved to a separate page.
//   - CONDITIONALLY HONEST: a fresh ontology's pipeline is "not built" (0/7 live). Brand-clean; the
//     ODK ladder (Ontology Manager) remains intact.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-pipeline.mjs
// Exit 2 = BLOCKED (daemon/capture/serve not running).

import http from "node:http";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const grantFor = (ch) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/materialized-object-sets/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ODK plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const SENTINEL = "pipeline-parity-bearer";

  // 0. Matrix — pipeline is daemon_wired (TRUE parity); siblings still substrate_bound.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies pipeline as reference_ported → /__ioi/pipeline (shell ported + wired) with a parity_blocked note", bySlug.pipeline?.parity_class === "reference_ported" && bySlug.pipeline?.port_surface === "/__ioi/pipeline" && bySlug.pipeline?.candidate_surface === "/__ioi/pipeline" && /error/i.test(bySlug.pipeline?.parity_blocked || ""));
  ok("no false parity for pipeline: NOT daemon_wired (its errored builder reference cannot certify parity); lineage/vertex stay substrate_bound", bySlug.pipeline?.parity_class !== "daemon_wired" && bySlug.lineage?.parity_class === "substrate_bound" && bySlug.vertex?.parity_class === "substrate_bound");
  ok("estate honest: reference_capture still the majority; no false 'covered'", (matrix.by_parity_class?.reference_capture || 0) >= (matrix.by_parity_class?.reference_ported || 0) && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference baseline boots the familiar builder, brand-clean.
  const ref = await page(`${SERVE}/__apps/pipeline`);
  ok("reference baseline /__apps/pipeline boots the Pipeline Builder grammar (brand-clean)", ref.status === 200 && /<title>[^<]*Pipeline Builder/.test(ref.text) && !/\bPalantir\b/.test(ref.text));

  // Fixture row server (auth-checked) → build a REAL pipeline end to end.
  const rows = [{ id: "L-1", disp: "First Loan", amt: 1250.5 }, { id: "L-2", disp: "Second Loan", amt: 90000 }, { id: "L-3", disp: "Third Loan", amt: 42.0 }];
  const srv = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "pipe-parity", base_url: `http://127.0.0.1:${port}`, name: "Pipe Parity" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });

  const track = (k, id) => { if (id) cleanup.push(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: "pipe-parity-src", kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  cleanup.push(["DELETE", `/v1/hypervisor/data-sources/${ds}`]);
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "pipe-parity", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" } ] }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "pipe-parity-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "pipe-parity-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "a", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "pipe-parity-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "pipe-parity-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "pipe-parity-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "pipe-parity-mrun" })).j.materializing_run?.id;
  track("materializing-runs", mrun);
  const ch = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grantFor(ch.j) });
  const sess = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connId, name: "pipe-parity-sess" })).j.connector_session?.id;
  track("connector-sessions", sess);
  const ch2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, { wallet_approval_grant: grantFor(ch2.j) });
  const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sess, limit: 10 });
  const setId = ex.j.materialized_object_set?.id;
  if (setId) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`]);
  if (!ont?.id || ex.j.materializing_run?.status !== "executed") { console.error("BLOCKED: could not build the pipeline fixture"); srv.close(); process.exit(2); }

  // 2. PORTED SHELL — a reference builder shell, not the dark automationsShell.
  const built = await page(`${SERVE}/__ioi/pipeline?ontology=${encodeURIComponent(ont.id)}`);
  const t = built.text;
  ok("the surface is a PORTED reference builder shell (pb-shell: rail + canvas + tray), NOT automationsShell", built.status === 200 && /class="pb-shell"/.test(t) && /class="pb-rail"/.test(t) && /id="pb-canvas"/.test(t) && !/max-width:920px/.test(t) && !/class="wrap"/.test(t));
  ok("the ported shell carries the builder regions (header title · graph toolbar · right output panel · bottom tray)", /class="pb-header"/.test(t) && /class="pb-toolbar"/.test(t) && /class="pb-right"/.test(t) && /class="pb-tray"/.test(t) && /Pipeline Builder<\/div>/.test(t));

  // 3. GUARD — the local builder reference ERRORS, so the harness must REFUSE to grant parity, and
  //    the port itself must still render the real builder shell regions (the port is legitimate).
  const artDir = path.join(appRoot, ".artifacts", "pipeline-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "pipeline", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("harness ran + captured real screenshots for the pipeline reference vs IOI port", hp && hp.evidence_ok === true, hp ? `ref ${hp.reference_screenshot_bytes}b · ioi ${hp.ioi_screenshot_bytes}b` : "harness did not run");
  ok("GUARD: the local builder REFERENCE errors, so the harness refuses parity (structural_parity FALSE, reference_valid FALSE)", hp && hp.reference_errored === true && hp.structural_parity === false && hp.reference_valid === false, hp ? `errored=${hp.reference_errored} valid=${hp.reference_valid} parity=${hp.structural_parity}` : "n/a");
  ok("the PORT itself is a real, VALID builder shell (IOI non-errored, renders rail + body + more, ready for parity once a valid reference exists)", hp && hp.ioi_valid === true && hp.ioi_errored === false && ["rail", "body"].every((r) => hp.ioi_regions.includes(r)) && hp.ioi_regions.length >= 4);

  // 4. DAEMON TRUTH inside the shell.
  ok("datasource → transform → output node cards present (the ODK ladder as the canvas graph)", ["Datasource", "Object mapping", "Policy gate", "Transform plan", "Read projection", "Lease + session", "Materialized objects"].every((n) => t.includes(`>${n}<`)));
  ok("a built pipeline shows 7/7 stages live + the built state (daemon truth)", /7\/7 stages live/.test(t) && /pb-live">built/.test(t));
  ok("the output carries the real object-instance count (3)", /3 object instances materialized/.test(t) || />3<\/div>/.test(t));
  ok("Preview (bottom tray) shows the first materialized rows — daemon truth, not a mock", /id="pb-preview"/.test(t) && />L-1</.test(t) && />First Loan</.test(t));

  // 5. Unsupported controls disabled IN PLACE (not moved to a separate page).
  ok("Build + Preview are enabled controls in the toolbar", /pb-btn primary"[^>]*>▶ Build</.test(t) && /href="#pb-preview"/.test(t));
  ok("Schedule + Deploy are present but DISABLED in place (named gaps, not hidden)", /<button[^>]*disabled[^>]*>Schedule<\/button>/.test(t) && /<button[^>]*disabled[^>]*>Deploy<\/button>/.test(t));
  ok("reference capture linked as the secondary baseline; brand/reference clean", t.includes("/__apps/pipeline") && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));

  // 6. Conditionally honest — a fresh ontology's pipeline is "not built".
  const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "pipe-parity-fresh", canonical_object_model: { object_types: [{ id: "a", name: "A", title_property: "t", properties: [{ id: "t", name: "T", value_type: "string" }] }], action_types: [{ id: "x", name: "X", kind: "modify_object", applies_to: "a" }] } })).j.ontology?.id;
  track("domain-ontologies", fresh);
  const freshPage = await page(`${SERVE}/__ioi/pipeline?ontology=${encodeURIComponent(fresh)}`);
  ok("a fresh ontology's pipeline is honestly 'not built' (0/7 stages live)", /pb-declared">not built/.test(freshPage.text) && /0\/7 stages live/.test(freshPage.text));

  // 7. The ODK ladder itself is intact + cross-links to the pipeline view.
  const odk = await page(`${SERVE}/__ioi/odk?ontology=${encodeURIComponent(ont.id)}`);
  ok("the ODK ladder is intact (Ontology Manager still renders) + links to the pipeline view", /Ontology Manager/.test(odk.text) && odk.text.includes("/__ioi/pipeline"));

  srv.close();
  for (const [method, p] of cleanup) await jd(method, p);
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
  await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`pipeline-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
