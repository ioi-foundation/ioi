#!/usr/bin/env node
// THE ADOPTED PIPELINE BUILDER LISTS THE CALLER'S DATARECIPE PIPELINES (R-241 seed depth, ADR 0056 P4).
//
// The reference Pipeline Builder is the seed: it boots from the LOCAL reference mirror (never vendored —
// the repository is public) through the /__apps/pipeline lane, and the serve answers its landing from the
// Hypervisor's planes (adopted-pipeline.mjs). A pipeline is a DataRecipe family; its Main sandbox is the
// family's admitted head, and each open change set over it is a draft sandbox. This proves, against an
// ISOLATED daemon + serve, that the landing lists exactly the caller's pipelines — a family merged through
// a change set and a family that exists only as a founding change set — each typed Batch, with no outputs
// set and never deployed (nothing borrowed from the reference), its creator named from the Hypervisor's
// principal; that the search narrows the list; that the details, sandboxes, project picker and user lookup
// the app reads answer from the Hypervisor and name nothing that is not the caller's; and that the app
// reaches the local mirror only for the reference's chrome reads and the reads named still open.
//
// Seed writes go through the daemon's change-set plane (the adopted Create is not bound yet). Exit: 0 pass
// · 1 fail · 2 blocked (no daemon binary, no local reference mirror, or the mirror server is not reachable
// — the seed cannot boot, which is not a pass).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   IOI_HARVEST_CAPTURE_URL       default http://127.0.0.1:9225 (the local mirror server)
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-pipeline.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(400);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}
const MIRROR_PAGE = path.join(ROOT, "internal-docs", "reverse-engineering", "palantir", "public", "workspace", "builder", "index.html");
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
if (!fs.existsSync(MIRROR_PAGE)) { console.error(`BLOCKED: no local reference mirror at ${MIRROR_PAGE}`); process.exit(2); }
if (!(await fetch(`${CAPTURE}/workspace/builder/`).then((r) => r.ok).catch(() => false))) { console.error(`BLOCKED: the local mirror server is not reachable at ${CAPTURE}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-pipeline-"));
let daemon = null, serve = null, DAEMON = "", SERVE = "", COOKIE = "";
const daemonReq = async (method, route, body) => {
  const r = await fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).catch(() => null);
  return { status: r?.status ?? 0, body: r ? await r.json().catch(() => ({})) : {} };
};
const serveJson = async (method, route, body) => {
  const r = await fetch(`${SERVE}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).catch(() => null);
  return { status: r?.status ?? 0, passthrough: r?.headers.get("x-ioi-mirror-passthrough") === "1", body: r ? await r.json().catch(() => null) : null };
};

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, password: "adopted-pipeline-bootstrap-v1", email: "pipeline@ioi.local" }),
  }).then((r) => r.json()).catch(() => ({})) : {};
  COOKIE = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", COOKIE.startsWith("ioi_session=ioi_sess_"), COOKIE.slice(0, 24));

  const servePort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_HARVEST_CAPTURE_URL: CAPTURE, IOI_ADOPTED_SURFACES: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/__apps/pipeline`, 30000);

  // ---- 1. two pipelines over daemon truth: a family merged through a change set (with an open successor),
  // and a family that exists only as a founding change set; plus a project for the picker ------------------
  const who = (await daemonReq("GET", "/v1/hypervisor/auth/whoami")).body;
  const OWNER = (who.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://"));
  const operatorRef = who.principal?.principal_ref || "";
  const operatorName = who.principal?.name || "";
  const POLICY = `sha256:${"3c".repeat(32)}`;
  const ont = await daemonReq("POST", "/v1/hypervisor/ontology-versions", { owner_ref: OWNER, idempotency_key: "ap-ont", namespace: "acme-clinic", name: "patient-intake", governing_scope_ref: "domain://acme-clinic/intake", policy_hash: POLICY, entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } });
  const ONT1 = ont.body?.ontology_version?.ontology_id;
  const map = await daemonReq("POST", "/v1/hypervisor/connector-mapping-revisions", { owner_ref: OWNER, idempotency_key: "ap-map", family: "acme.intake-form", name: "intake-form", connector_id: "connector://google-drive", ontology_revision_ref: ONT1, source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09", target_object_model_refs: ["object-model://om_patient_intake"], field_mappings: [{ role: "key", source_field: "record_id", target_property_ref: "object-model://om_patient_intake#intake_id", source_type: "string", source_cardinality: "one" }], action_mappings: [], authority_scopes_required: ["scope:connector.google_drive.read"], redaction_policy_ref: "policy://acme-clinic/intake-redaction", evidence_required: ["evidence-contract://acme-clinic/intake-consent"], effective_policy_hash: POLICY, registry_status: "active" });
  const MAP1 = map.body?.connector_mapping?.revision_ref;
  const draft = (extra = {}) => ({ name: "intake-normalise", ontology_revision_refs: [ONT1], input_source_types: ["connector", "document"], connector_mapping_revision_refs: [MAP1], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"], transformation_steps: ["extract", "redact", "normalize", "validate", "map"], policy_bound_data_view_refs: [], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active", ...extra });
  const w = (key, extra = {}) => ({ owner_ref: OWNER, idempotency_key: key, ...extra });
  const opened = await daemonReq("POST", "/v1/hypervisor/change-sets", w("ap-open-1", { subject: { kind: "data_recipe", family: "acme.intake-normalise" }, title: "Normalise intake", draft: draft() }));
  const cs1 = String(opened.body?.change_set?.change_set_ref || "").replace("change://", "");
  const steps = [];
  for (const step of ["validate", "propose", "merge"]) steps.push((await daemonReq("POST", `/v1/hypervisor/change-sets/${cs1}/${step}`, w(`ap-${step}-1`))).status);
  const successor = await daemonReq("POST", "/v1/hypervisor/change-sets", w("ap-open-2", { subject: { kind: "data_recipe", family: "acme.intake-normalise" }, title: "Add a dedupe step", draft: draft({ transformation_steps: ["extract", "redact", "normalize", "validate", "map", "dedupe"], succession_reason: "transformation_step_change" }) }));
  const founding = await daemonReq("POST", "/v1/hypervisor/change-sets", w("ap-open-3", { subject: { kind: "data_recipe", family: "acme.claims-triage" }, title: "Claims triage", draft: { name: "claims-triage" } }));
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: "pipeline-picker-project", initializer: { specs: [{ git: { remoteUri: "https://example.invalid/adopted/pipeline.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  ok("PRECONDITION: a DataRecipe family merged through a change set (revision 1) with an open successor, a founding-only change set, and a project exist",
    steps.join(",") === "200,200,200" && successor.status === 201 && founding.status === 201 && !!project.project?.id,
    `merge steps ${steps.join(",")} · successor ${successor.status} · founding ${founding.status} · project ${project.project?.id || "none"}`);

  // ---- 2. the adopted landing, in a browser ----------------------------------------------------------------
  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    const passthroughs = new Set();
    pg.on("response", (resp) => {
      if (resp.headers()["x-ioi-mirror-passthrough"] !== "1") return;
      passthroughs.add(`${resp.request().method()} ${new URL(resp.url()).pathname.replace(/ri\.[a-z-]+\.main\.[a-z-]+\.[0-9a-f-]{36}/gu, "<rid>")}`);
    });
    await pg.goto(`${SERVE}/__apps/pipeline`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(12000);
    const text = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const table = text.includes("LAST DEPLOYED") ? text.slice(text.indexOf("LAST DEPLOYED") + "LAST DEPLOYED".length, text.indexOf("Explore reference examples") > 0 ? text.indexOf("Explore reference examples") : undefined).trim() : "";
    // one row per pipeline: "<name> Created … ago by <who> <outputs> Batch Not yet deployed"
    const rows = table.split(/ ?Not yet deployed ?/u).filter(Boolean).map((chunk) => {
      const m = /^(\S+) Created .*? ago (?:by )?(.+) Batch$/u.exec(chunk.trim());
      if (!m) return { unparsed: chunk };
      // the creator is named by the operator's own name or not at all; what follows is the outputs cell
      const named = !!operatorName && m[2].startsWith(`${operatorName} `);
      return { name: m[1], by: named ? operatorName : "", outputs: named ? m[2].slice(operatorName.length + 1) : m[2] };
    });
    const byName = Object.fromEntries(rows.map((r) => [r.name, r]));
    ok("the adopted landing lists exactly the caller's two pipelines — the merged family and the founding-only change set — each Batch and never deployed, the merged one showing the outputs its recipe declares and the founding draft none",
      !/An error (?:has )?occurred|Unable to load pipelines|Failed to load (?!examples)/u.test(text) && rows.length === 2 && rows.every((r) => r.name)
        && byName["intake-normalise"]?.outputs === "om_patient_intake acme-clinic/patient-intake-row/v2" && byName["claims-triage"]?.outputs === "No outputs set",
      `rows ${JSON.stringify(rows)} · table "${table.slice(0, 260)}"`);
    ok("each pipeline names its creator from the Hypervisor's principal (the change set that founded it)",
      !!operatorName && rows.length === 2 && rows.every((r) => r.by === operatorName), `operator "${operatorName}" · ${rows.map((r) => `${r.name} by "${r.by}"`).join(" · ")}`);

    await pg.getByPlaceholder("Search pipelines").fill("claims");
    await pg.waitForTimeout(3000);
    const searched = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("the landing search narrows the list to the matching pipeline", /claims-triage/u.test(searched) && !/intake-normalise/u.test(searched),
      searched.slice(searched.indexOf("LAST DEPLOYED"), searched.indexOf("LAST DEPLOYED") + 160));

    // The mirror still answers the reference's CHROME reads, and the three builder reads named open in the
    // seed-depth record (the transform catalog, the AIP toggle, the editor's display settings); anything
    // else is a new lane reaching recorded tenant answers, and fails here until it is bound.
    const CHROME_PASSTHROUGHS = new Set([
      "GET /aip-assist/api/chat/checkAvailability", "GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection",
      "GET /workspace/api/lifecycleStatusByApplication", "POST /documentation/api/v2/release-notes/pagination", "POST /log-receiver/api/beacon",
      "GET /language-model-service/api/config/v1/enabled",
    ]);
    const NAMED_OPEN = new Set(["GET /eddie/api/transformations/all", "POST /eddie/api/natural-language-converter/aip-enabled", "GET /eddie/api/pipeline-builder-settings"]);
    const unexpected = [...passthroughs].filter((p) => !CHROME_PASSTHROUGHS.has(p) && !NAMED_OPEN.has(p));
    ok("the adopted landing reaches the local mirror only for the reference's chrome reads and the three builder reads named open — its pipelines, projects and users answer from the Hypervisor",
      unexpected.length === 0 && passthroughs.size > 0, unexpected.length ? `unexpected: ${unexpected.join(" · ")}` : `${passthroughs.size} chrome/named reads`);
  } finally {
    await browser.close();
  }

  // ---- 3. the wire the landing reads, directly ---------------------------------------------------------------
  const bulk = await fetch(`${SERVE}/graphql-gateway/api/bulk?q=PipelineLandingSearchQuery`, {
    method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" },
    body: JSON.stringify({ operations: { 0: "query PipelineLandingSearchQuery($text: String, $pageSize: Int!) { searchResourcesV2(pageSize: $pageSize, filter: {text: $text, types: [EDDIE_PIPELINE]}) { results { resource { rid __typename } __typename } nextPageToken __typename } __typename }" }, requests: [{ hash: "0", name: "PipelineLandingSearchQuery", variables: { text: "", pageSize: 50 } }] }),
  }).then((r) => r.text()).catch(() => "");
  const rids = [...bulk.matchAll(/"rid":"(ri\.eddie\.main\.pipeline\.[0-9a-f-]{36})"/gu)].map((m) => m[1]);
  const foreign = "ri.eddie.main.pipeline.00000000-0000-4000-8000-000000000000";
  const byRids = await serveJson("POST", "/eddie/api/pipelines-v2/get/by-rids", [...rids, foreign]);
  const names = Object.values(byRids.body?.pipelines || {}).map((p) => p.name).sort();
  const one = rids.length ? await serveJson("GET", `/eddie/api/pipelines-v2/${rids[0]}`) : { status: 0 };
  const none = await serveJson("GET", `/eddie/api/pipelines-v2/${foreign}`);
  ok("the pipeline details answer the caller's pipelines only — a rid that is not theirs is left out of a batch and refused alone",
    rids.length === 2 && names.join(",") === "claims-triage,intake-normalise" && !(foreign in (byRids.body?.pipelines || {})) && !byRids.passthrough && one.status === 200 && none.status === 404,
    `search ${rids.length} · by-rids ${names.join(",")} · one ${one.status} · foreign ${none.status}`);

  const details = Object.values(byRids.body?.pipelines || {});
  const intake = details.find((p) => p.name === "intake-normalise");
  const claims = details.find((p) => p.name === "claims-triage");
  const snaps = await serveJson("POST", "/eddie/api/pipelines-v2/get-sandboxes-with-snapshots", { requests: [intake, claims].filter(Boolean).map((p) => ({ pipelineRid: p.rid, sandboxId: p.publishedSandboxes[0] })) });
  const [mainIntake, mainClaims] = snaps.body?.sandboxes || [];
  const kinds = (s) => (s?.snapshot?.targets || []).map((t) => t.target?.type).join(",");
  ok("Main is each pipeline's published sandbox: the merged family's holds revision 1 and targets exactly its recipe's declared outputs (one object, one dataset), the founding-only one holds no revision (Root) and no target; no transform is invented",
    mainIntake?.sandbox?.name === "Main" && mainIntake.sandbox.isPublished === true && mainIntake.version?.message === "Revision 1" && mainClaims?.version?.message === "Root"
      && kinds(mainIntake) === "object,dataset" && kinds(mainClaims) === "" && [mainIntake, mainClaims].every((s) => s?.snapshot?.transforms?.length === 0) && !snaps.passthrough,
    `${mainIntake?.sandbox?.name}/${mainIntake?.version?.message} targets [${kinds(mainIntake)}] · ${mainClaims?.sandbox?.name}/${mainClaims?.version?.message} targets [${kinds(mainClaims)}]`);

  const picker = await serveJson("POST", "/foundry-search/api/compass/v0/search", { query: { includeResources: ["FILE"], filter: { isProjectPreview: true, type: "isProjectPreview" }, text: "" }, limit: 50, sort: { order: "ASC", category: "NAME" }, offset: 0 });
  const other = await serveJson("POST", "/foundry-search/api/compass/v0/search", { query: { includeResources: ["FILE"], text: "" }, limit: 50, offset: 0 });
  const pickerNames = (picker.body?.result || []).map((r) => r.indexedResource?.name);
  const ownProjects = ((await daemonReq("GET", "/v1/hypervisor/projects")).body?.projects || []).map((p) => p.name);
  ok("the project picker answers with the caller's projects and any other compass search with nothing — never the recorded tenant's index",
    pickerNames.includes("pipeline-picker-project") && pickerNames.every((n) => ownProjects.includes(n)) && (other.body?.result || []).length === 0 && !picker.passthrough && !other.passthrough,
    `picker ${JSON.stringify(pickerNames)} · other ${(other.body?.result || []).length}`);

  const operatorId = intake?.attribution?.user || "";
  const users = await serveJson("POST", "/multipass/api/users", [operatorId, "00000000-0000-4000-8000-000000000000"]);
  ok("the user lookup names the operator by the id the pipeline carries and answers nothing for an id no principal of theirs holds",
    Array.isArray(users.body) && users.body.length === 1 && users.body[0].id === operatorId && users.body[0].username === "pipeline@ioi.local" && !users.passthrough && !!operatorRef,
    `${JSON.stringify((users.body || []).map((u) => [u.id, u.username]))}`);
}

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-pipeline", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});
