#!/usr/bin/env node
// THE ADOPTED PIPELINE BUILDER LISTS THE CALLER'S DATARECIPE PIPELINES (R-241 seed depth, ADR 0056 P4).
//
// The reference Pipeline Builder is the seed: it boots from the LOCAL reference capture server (never vendored —
// the repository is public) through the /__apps/pipeline lane, and the serve answers its landing from the
// Hypervisor's planes (adopted-pipeline.mjs). A pipeline is a DataRecipe family; its Main sandbox is the
// family's admitted head, and each open change set over it is a draft sandbox. This proves, against an
// ISOLATED daemon + serve, that the landing lists exactly the caller's pipelines — a family merged through
// a change set and a family that exists only as a founding change set — each typed Batch, with no outputs
// set and never deployed (nothing taken from the reference), its creator named from the Hypervisor's
// principal; that the search narrows the list; that the details, sandboxes, project picker and user lookup
// the app reads answer from the Hypervisor and name nothing that is not the caller's; and that the app
// reaches the local capture server only for the reference's chrome reads and the reads named still open.
//
// Seed writes go through the daemon's change-set plane (the adopted Create is not bound yet). Exit: 0 pass
// · 1 fail · 2 blocked (no daemon binary, no local capture-server pages, or the capture server is not reachable
// — the seed cannot boot, which is not a pass).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   IOI_HARVEST_CAPTURE_URL       default http://127.0.0.1:9225 (the local capture server)
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
const CAPTURE_PAGE = path.join(ROOT, "internal-docs", "reverse-engineering", "palantir", "public", "workspace", "builder", "index.html");
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
if (!fs.existsSync(CAPTURE_PAGE)) { console.error(`BLOCKED: no local capture-server page at ${CAPTURE_PAGE}`); process.exit(2); }
if (!(await fetch(`${CAPTURE}/workspace/builder/`).then((r) => r.ok).catch(() => false))) { console.error(`BLOCKED: the local capture server is not reachable at ${CAPTURE}`); process.exit(2); }

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-pipeline-"));
let daemon = null, serve = null, DAEMON = "", SERVE = "", COOKIE = "";
const daemonReq = async (method, route, body) => {
  const r = await fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).catch(() => null);
  return { status: r?.status ?? 0, body: r ? await r.json().catch(() => ({})) : {} };
};
const serveJson = async (method, route, body) => {
  const r = await fetch(`${SERVE}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).catch(() => null);
  return { status: r?.status ?? 0, passthrough: r?.headers.get("x-ioi-capture-passthrough") === "1", body: r ? await r.json().catch(() => null) : null };
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
  // the successor is validated and PROPOSED — an open proposal on the Proposals tab
  const succId = String(successor.body?.change_set?.change_set_ref || "").replace("change://", "");
  for (const step of ["validate", "propose"]) steps.push((await daemonReq("POST", `/v1/hypervisor/change-sets/${succId}/${step}`, w(`ap-${step}-2`))).status);
  const founding = await daemonReq("POST", "/v1/hypervisor/change-sets", w("ap-open-3", { subject: { kind: "data_recipe", family: "acme.claims-triage" }, title: "Claims triage", draft: { name: "claims-triage" } }));
  // an Ontology Manager draft never published: the builder offers it, and a recipe cannot bind it
  const odkDraft = await daemonReq("POST", "/v1/hypervisor/odk/domain-ontologies", w("ap-odk-1", { domain: "claims-draft", description: "an unpublished draft" }));
  const project = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ name: "pipeline-picker-project", initializer: { specs: [{ git: { remoteUri: "https://example.invalid/adopted/pipeline.git" } }] } }) }).then((r) => r.json()).catch(() => ({}));
  ok("PRECONDITION: a DataRecipe family merged through a change set (revision 1) with an open successor, a founding-only change set, and a project exist",
    steps.join(",") === "200,200,200,200,200" && successor.status === 201 && founding.status === 201 && !!project.project?.id,
    `merge steps ${steps.join(",")} · successor ${successor.status} · founding ${founding.status} · project ${project.project?.id || "none"}`);

  let createBody = null; // the adopted form's own create request (its registry location is reused below)
  // ---- 2. the adopted landing, in a browser ----------------------------------------------------------------
  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    const passthroughs = new Set();
    pg.on("response", (resp) => {
      if (resp.headers()["x-ioi-capture-passthrough"] !== "1") return;
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

    // Data recipes, the canonical route, opens this adopted app; our rail stands where the reference's
    // global sidebar was.
    const canonical = await fetch(`${SERVE}/data/recipes`, { headers: { accept: "text/html", cookie: COOKIE }, redirect: "manual" });
    const referenceSidebar = await pg.evaluate(() => { const el = document.getElementById("workspace-sidebar"); return !!el && el.getBoundingClientRect().width > 0; });
    const ourRail = await pg.evaluate(() => !!document.querySelector(".og-grail a[href='/ai']"));
    ok("Data recipes (/data/recipes) opens the adopted Pipeline Builder, and our rail stands where the reference's sidebar was",
      canonical.status === 302 && /^\/workspace\/builder\/?$/u.test(canonical.headers.get("location") || "") && ourRail && !referenceSidebar,
      `/data/recipes ${canonical.status} → ${canonical.headers.get("location")} · our rail ${ourRail} · reference sidebar ${referenceSidebar}`);

    await pg.getByPlaceholder("Search pipelines").fill("claims");
    await pg.waitForTimeout(3000);
    const searched = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("the landing search narrows the list to the matching pipeline", /claims-triage/u.test(searched) && !/intake-normalise/u.test(searched),
      searched.slice(searched.indexOf("LAST DEPLOYED"), searched.indexOf("LAST DEPLOYED") + 160));

    // ---- the editor, opened from the row: editable, over the family's head (Main is protected) -------------
    await pg.getByPlaceholder("Search pipelines").fill("");
    await pg.waitForTimeout(2500);
    await pg.getByText("intake-normalise", { exact: true }).first().click();
    await pg.waitForTimeout(14000);
    await pg.getByText("Close", { exact: true }).first().click({ timeout: 3000 }).catch(() => { /* no announcement */ });
    await pg.waitForTimeout(1500);
    const editorUrl = pg.url().replace(SERVE, "");
    // the object output's name is an input's value (the pane renders it editable-looking, disabled here)
    const editor = (await pg.evaluate(() => `${document.body.innerText} ${[...document.querySelectorAll("input")].map((i) => i.value).join(" ")}`)).replace(/\s+/gu, " ");
    ok("a pipeline opens in the adopted editor on its Main sandbox, editable and PROTECTED (a change there is saved to a new branch: only a merged change set moves Main), listing the recipe's declared outputs and never deployed",
      /^\/workspace\/builder\/ri\.eddie\.main\.pipeline\.[0-9a-f-]{36}\/sandbox\/[0-9a-f-]{36}$/u.test(editorUrl) && !/An error (?:has )?occurred|Pipeline not found/u.test(editor)
        && /intake-normalise/u.test(editor) && /\bMain\b/u.test(editor) && /This branch is protected\. Changes will be saved to a new branch\./u.test(editor) && !/read-only mode/u.test(editor)
        && /acme-clinic\/patient-intake-row\/v2/u.test(editor) && /om_patient_intake/u.test(editor) && /Pipeline not yet deployed/u.test(editor),
      `${editorUrl} · ${JSON.stringify({ error: /An error (?:has )?occurred|Pipeline not found/u.test(editor), main: /\bMain\b/u.test(editor), protected: /This branch is protected/u.test(editor), readOnly: /read-only mode/u.test(editor), dataset: /acme-clinic\/patient-intake-row\/v2/u.test(editor), object: /om_patient_intake/u.test(editor), notDeployed: /Pipeline not yet deployed/u.test(editor) })}`);
    ok("the object output's target ontology is the recipe's own ontology (its declared revision's family), not \"No ontology selected\"",
      /Target ontology acme-clinic\/patient-intake/u.test(editor) && !/No ontology selected|An ontology must be specified/u.test(editor),
      `target ${/Target ontology acme-clinic\/patient-intake/u.test(editor)} · no-ontology error ${/No ontology selected|An ontology must be specified/u.test(editor)}`);
    ok("the editor's graph holds no transforms (a recipe keeps no transform graph yet, ADR 0057) and offers to add data, rather than drawing any",
      /Welcome to Pipeline Builder/u.test(editor) && /2 outputs defined/u.test(editor), /Welcome to Pipeline Builder/u.test(editor) ? "add-data welcome card" : "graph text absent");

    // ---- Proposals: a proposed change set is an open proposal; its page opens over the change set ------------
    await pg.getByText("Proposals", { exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(8000);
    const proposalsTab = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByText("Add a dedupe step", { exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(12000);
    const proposalPage = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("the editor's Proposals tab lists the proposed change set with its author, and its page opens — merging into Main, up to date with it",
      /Add a dedupe step/u.test(proposalsTab) && proposalsTab.includes(operatorName) && !/Failed to load/u.test(proposalsTab)
        && /Merging into Main from Add a dedupe step/u.test(proposalPage) && /is up to date with "Main"/u.test(proposalPage) && !/Failed to load proposal/u.test(proposalPage),
      `tab "${proposalsTab.slice(Math.max(0, proposalsTab.indexOf("Viewing")), Math.max(0, proposalsTab.indexOf("Viewing")) + 140)}" · page ${/Merging into Main/u.test(proposalPage)} · up to date ${/is up to date/u.test(proposalPage)}`);

    // ---- History: Main's timeline is the family's revisions and its TransformationRuns; a change set's, its drafts --
    // Two runs of revision 1: one queued (nothing executes a queued run, so it claims no deploy) and one completed.
    const RUNS = "/v1/hypervisor/transformation-runs";
    const rev1 = ((await daemonReq("GET", "/v1/hypervisor/data-recipe-revisions?family=acme.intake-normalise")).body?.revisions || [])[0]?.revision_ref;
    const runBody = (key, extra) => w(key, { data_recipe_revision_ref: rev1, output_intent: "ontology_objects", execution_status: "completed", input_refs: ["artifact://acme/intake-forms/batch-2026-08"], authority_grant_refs: ["grant://acme-clinic/intake-read/2026-08"], output_object_refs: ["agentgres://object/patient_intake/2026-08-batch"], receipt_refs: ["receipt://acme-clinic/transformation/2026-08-batch"], derivative_policy_ref: "policy://acme-clinic/intake-derivatives", impact_graph_ref: "agentgres://projection/intake-impact", ...extra });
    const queuedRun = await daemonReq("POST", RUNS, runBody("ap-run-queued", { execution_status: "queued" }));
    const completedRun = await daemonReq("POST", RUNS, runBody("ap-run-completed", { expected_head: (await daemonReq("GET", `${RUNS}?family=acme.intake-normalise`)).body?.head }));
    await pg.goto(`${SERVE}${editorUrl}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(12000);
    await pg.getByText("Close", { exact: true }).first().click({ timeout: 1500 }).catch(() => { /* no announcement */ });
    await pg.getByText("History", { exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(8000);
    const history = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByRole("button", { name: "Toggle collapse deployment" }).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    const historyOpen = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const deployments = (history.match(/\bDeployment\b/gu) || []).length;
    ok("the editor's History tab is the family's own timeline: the revision its change set merged (currently deployed, by its one completed run) and both runs — the completed one deployed its two declared outputs, the queued one claims no deploy",
      queuedRun.status === 201 && completedRun.status === 201 && /Viewing version history for branch: Main/u.test(history) && /Merged proposal: Normalise intake/u.test(history)
        && /Currently deployed/u.test(history) && deployments === 2 && /Deployed logic for 2 targets/u.test(historyOpen) && (historyOpen.match(/Deployed logic/gu) || []).length === 1
        && !/Failed to load|No history found|An error (?:has )?occurred/u.test(history),
      `runs ${queuedRun.status}/${completedRun.status} · ${history.slice(Math.max(0, history.indexOf("Viewing version")), Math.max(0, history.indexOf("Viewing version")) + 260)} · opened "Deployed logic" ×${(historyOpen.match(/Deployed logic/gu) || []).length}`);
    // the successor change set's history: its one draft follows the head it was opened on, and "Compare with… →
    // Previous saved version" diffs the draft against that revision (two versions of one sandbox's chain, asked
    // under two aliases of one field)
    const [, pipelineRidOfEditor] = /\/workspace\/builder\/(ri\.eddie\.main\.pipeline\.[0-9a-f-]{36})\//u.exec(editorUrl) || [];
    const sandboxesAll = await serveJson("GET", `/eddie/api/pipelines-v2/${pipelineRidOfEditor}/sandboxes/get/all`);
    const successorSandbox = (sandboxesAll.body?.sandboxes || []).find((x) => x.name === "Add a dedupe step")?.id;
    await pg.goto(`${SERVE}/workspace/builder/${pipelineRidOfEditor}/history/${successorSandbox}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(12000);
    const draftHistory = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByRole("button", { name: "Additional timeline event actions" }).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByText("Compare with", { exact: false }).first().hover({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByText("Previous saved version", { exact: false }).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(10000);
    const compare = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("a change set's History is its drafts, and comparing its draft with the previous saved version diffs it against the revision it was opened on",
      /Viewing version history for branch: Add a dedupe step/u.test(draftHistory) && !/Failed to load|No history found/u.test(draftHistory)
        && /Viewing changes for update Draft 1/u.test(compare) && /Previous saved version/u.test(compare) && /Selected version/u.test(compare) && !/Failed to load|There are no versions preceding/u.test(compare),
      `history "${draftHistory.slice(Math.max(0, draftHistory.indexOf("Viewing version")), Math.max(0, draftHistory.indexOf("Viewing version")) + 120)}" · compare "${compare.slice(Math.max(0, compare.indexOf("Viewing changes")), Math.max(0, compare.indexOf("Viewing changes")) + 160)}"`);

    // ---- Deploy (named): the panel's deployability check answers why a deploy cannot happen yet ------------------
    await pg.goto(`${SERVE}${editorUrl}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(12000);
    await pg.getByText("Close", { exact: true }).first().click({ timeout: 1500 }).catch(() => { /* no announcement */ });
    await pg.getByRole("button", { name: "Deploy", exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(6000);
    const deploySettings = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByText(/^Errors/u).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    const deployPanel = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByRole("button", { name: "Details", exact: true }).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    const deployDetails = (await pg.evaluate(() => [...document.querySelectorAll('[role="dialog"]')].map((d) => d.innerText).join(" | "))).replace(/\s+/gu, " ");
    ok("the Deploy panel opens (the editor no longer crashes on it) over the family's truth — its last deployment the completed run, its one compute profile the Hypervisor runtime — and says the pipeline cannot be deployed, with why under Details: the builder admits no TransformationRun yet and nothing executes a queued one",
      /Deploy this pipeline/u.test(deploySettings) && !/Something went wrong when rendering/u.test(deploySettings) && /Last deployment Succeeded/u.test(deploySettings) && /Hypervisor runtime/u.test(deploySettings)
        && /Pipeline cannot be deployed/u.test(deployPanel) && /does not admit runs yet/u.test(deployDetails) && /Revision 1/u.test(deployDetails),
      `panel ${/Deploy this pipeline/u.test(deploySettings)} · crashed ${/Something went wrong when rendering/u.test(deploySettings)} · last ${/Last deployment Succeeded/u.test(deploySettings)} · profile ${/Hypervisor runtime/u.test(deploySettings)} · cannot ${/Pipeline cannot be deployed/u.test(deployPanel)} · details "${deployDetails.slice(0, 240)}"`);
    await pg.keyboard.press("Escape").catch(() => {});

    // ---- Create, through the adopted form: the recipe registry is the one location; a founding change set --
    pg.on("request", (r) => { if (/\/eddie\/api\/pipelines-v2\/create/u.test(r.url())) { try { createBody = JSON.parse(r.postData() || "null"); } catch { /* not JSON */ } } });
    await pg.goto(`${SERVE}/workspace/builder/create-pipeline`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(9000);
    await pg.getByText("Select location", { exact: true }).first().click({ timeout: 8000 }).catch(() => { /* named below */ });
    for (let i = 0; i < 20 && !(await pg.getByText("Choose pipeline location").count()); i++) await pg.waitForTimeout(1000);
    await pg.waitForTimeout(3000);
    const dialog = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByText("Data recipes", { exact: true }).first().click({ timeout: 8000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    await pg.getByRole("button", { name: "Save", exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(3000);
    await pg.locator("input").first().fill("Claims normalise");
    await pg.waitForTimeout(800);
    const form = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("the create form's location dialog offers the recipe registry (Data recipes) as its one location, and the form then names it",
      /Choose pipeline location/u.test(dialog) && /Data recipes/u.test(dialog) && /\/Data recipes/u.test(form) && !/Unable to load location/u.test(form),
      `dialog "${dialog.slice(Math.max(0, dialog.indexOf("Choose pipeline location")), Math.max(0, dialog.indexOf("Choose pipeline location")) + 160)}" · form "${form.slice(form.indexOf("Name and location"), form.indexOf("Name and location") + 80)}"`);
    await pg.getByRole("button", { name: "Create pipeline", exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(15000);
    await pg.getByText("Close", { exact: true }).first().click({ timeout: 2000 }).catch(() => { /* no announcement */ });
    const createdUrl = pg.url().replace(SERVE, "");
    const createdText = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const founded = ((await daemonReq("GET", "/v1/hypervisor/change-sets?family=claims-normalise")).body?.change_sets || [])[0] || null;
    ok("Create pipeline opens a FOUNDING change set for a new DataRecipe family (no revision is admitted) and lands in the editor on its draft sandbox",
      /^\/workspace\/builder\/ri\.eddie\.main\.pipeline\.[0-9a-f-]{36}\/sandbox\/[0-9a-f-]{36}$/u.test(createdUrl) && /Claims normalise/u.test(createdText)
        && founded?.status === "open" && founded.title === "Claims normalise" && founded.subject?.base_revision_ref === null && founded.drafts?.[0]?.body?.name === "Claims normalise"
        && createBody?.createRequest?.backend === "Spark",
      `${createdUrl} · change set ${JSON.stringify(founded && [founded.status, founded.title, founded.subject?.family_ref, founded.subject?.base_revision_ref])} · backend ${createBody?.createRequest?.backend}`);

    // The capture server still answers the reference's CHROME reads, and the four builder reads named open in the
    // seed-depth record (the transform catalog and its expression examples, the AIP toggle, the editor's
    // display settings); anything else is a new lane reaching recorded tenant answers, and fails here until
    // it is bound.
    const CHROME_PASSTHROUGHS = new Set([
      "GET /aip-assist/api/chat/checkAvailability", "GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection",
      "GET /workspace/api/lifecycleStatusByApplication", "POST /documentation/api/v2/release-notes/pagination", "POST /documentation/api/v2/release-notes/paginationV2",
      "POST /log-receiver/api/beacon", "GET /language-model-service/api/config/v1/enabled", "POST /people/api/eventsink/create-events",
      "GET /compass/api/registry/actions",
    ]);
    const NAMED_OPEN = new Set(["GET /eddie/api/transformations/all", "POST /eddie/api/examples/get", "POST /eddie/api/natural-language-converter/aip-enabled", "GET /eddie/api/pipeline-builder-settings"]);
    const unexpected = [...passthroughs].filter((p) => !CHROME_PASSTHROUGHS.has(p) && !NAMED_OPEN.has(p));
    ok("the adopted landing and editor reach the local capture server only for the reference's chrome reads and the four builder reads named open — pipelines, sandboxes, projects, users, markings and permissions answer from the Hypervisor",
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
  ok("the pipeline details answer the caller's pipelines only — the one just created among them — and a rid that is not theirs is left out of a batch and refused alone",
    rids.length === 3 && names.join(",") === "Claims normalise,claims-triage,intake-normalise" && !(foreign in (byRids.body?.pipelines || {})) && !byRids.passthrough && one.status === 200 && none.status === 404,
    `search ${rids.length} · by-rids ${names.join(",")} · one ${one.status} · foreign ${none.status}`);

  const details = Object.values(byRids.body?.pipelines || {});
  // Proposals over REST: OPEN is the proposed change set; MERGED is the founding one, its version ids exact
  const intakeRid = details.find((p) => p.name === "intake-normalise")?.rid;
  const openP = await serveJson("POST", `/eddie/api/pipelines-v2/${intakeRid}/proposals/by-created-at?limit=20`, { statusKind: "OPEN", sourceSandboxIds: [] });
  const mergedP = await serveJson("POST", `/eddie/api/pipelines-v2/${intakeRid}/proposals/by-created-at?limit=20`, { statusKind: "MERGED", sourceSandboxIds: [] });
  const merged = mergedP.body?.proposals?.[0];
  const mergedInto = merged ? await serveJson("GET", `/eddie/api/pipelines-v2/${intakeRid}/versions/${merged.status.merged.mergedVersionId}/lightweight`) : { body: null };
  ok("proposals are the family's change sets by status — OPEN the proposed one, MERGED the founding one, whose merged version IS revision 1",
    openP.body?.proposals?.map((x) => x.details.name).join(",") === "Add a dedupe step" && mergedP.body?.proposals?.length === 1 && merged?.details?.name === "Normalise intake"
      && mergedInto.body?.details?.message === "Revision 1" && !openP.passthrough,
    `open ${JSON.stringify(openP.body?.proposals?.map((x) => x.details.name))} · merged ${merged?.details?.name} → ${mergedInto.body?.details?.message}`);
  // History over the wire: the timeline filters by event type; the queued run carries no status (the app then says
  // it did not run); the current deployment is the completed run's revision; the compare view's two aliases of
  // `versionHistoryV2` answer differently (the latest version, and the selected one with its predecessor).
  const bulkData = async (name, query, variables) => {
    const text = await fetch(`${SERVE}/graphql-gateway/api/bulk?q=${name}`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify({ operations: { 0: query }, requests: [{ hash: "0", name, variables }] }) }).then((r) => r.text()).catch(() => "");
    try { return JSON.parse(text.split("\n").find((l) => l.startsWith("data:")).slice(5)).data; } catch { return null; }
  };
  const HVL = "query HistoryVersionListQuery($pipelineRid: RID!, $sandboxId: String!, $filter: EddieSandboxEventTimelineFilter!, $pageSize: Int!) { eddiePipeline(rid: $pipelineRid) { sandbox(sandboxId: $sandboxId) { currentDeployment { sandboxVersion { versionId } } eventTimeline(filter: $filter, pageSize: $pageSize) { values { __typename ... on EddieSandboxDeployment { status { __typename } sandboxVersion { versionId } } ... on EddieSandboxVersion { versionId } } } } } }";
  const HVD = "query HistoryVersionDiffQuery($pipelineRid: RID!, $sandboxId: String!, $startVersionId: String) { eddiePipeline(rid: $pipelineRid) { sandbox(sandboxId: $sandboxId) { historyFromLatest: versionHistoryV2(limit: 1) { values { versionId commitMessage } } historyFromVersion: versionHistoryV2(limit: 2, startVersionId: $startVersionId) { values { versionId commitMessage } } backingBranchName } } }";
  const intakeMain = details.find((p) => p.name === "intake-normalise")?.publishedSandboxes?.[0];
  const deploys = (await bulkData("HistoryVersionListQuery", HVL, { pipelineRid: intakeRid, sandboxId: intakeMain, filter: { eventTypesToInclude: ["DEPLOYMENT"] }, pageSize: 20 }))?.eddiePipeline?.sandbox;
  const versionsOnly = (await bulkData("HistoryVersionListQuery", HVL, { pipelineRid: intakeRid, sandboxId: intakeMain, filter: { eventTypesToInclude: ["VERSION"] }, pageSize: 20 }))?.eddiePipeline?.sandbox;
  const successorBranch = ((await serveJson("GET", `/eddie/api/pipelines-v2/${intakeRid}/sandboxes/get/all`)).body?.sandboxes || []).find((x) => x.name === "Add a dedupe step");
  const diffQ = (await bulkData("HistoryVersionDiffQuery", HVD, { pipelineRid: intakeRid, sandboxId: successorBranch?.id, startVersionId: successorBranch?.version }))?.eddiePipeline?.sandbox;
  const statuses = (deploys?.eventTimeline?.values || []).map((v) => `${v.__typename}:${v.status?.__typename || "null"}`).join(",");
  const rev1Version = merged?.status?.merged?.mergedVersionId;
  const msgs = (page) => (page?.values || []).map((v) => v.commitMessage).join(",");
  ok("History over the wire: deployments alone are the two runs, newest first — the completed one Succeeded, the queued one with no status; versions alone are the one revision; Main is currently deployed at revision 1; the compare view's two aliases answer the latest draft, and that draft with the revision it follows",
    statuses === "EddieSandboxDeployment:EddieSandboxDeploymentStatus_Succeeded,EddieSandboxDeployment:null" && (deploys?.eventTimeline?.values || []).every((v) => v.sandboxVersion?.versionId === rev1Version)
      && (versionsOnly?.eventTimeline?.values || []).map((v) => `${v.__typename}:${v.versionId === rev1Version}`).join(",") === "EddieSandboxVersion:true"
      && deploys?.currentDeployment?.sandboxVersion?.versionId === rev1Version
      && msgs(diffQ?.historyFromLatest) === "Draft 1" && msgs(diffQ?.historyFromVersion) === "Draft 1,Revision 1" && /^change:\/\//u.test(diffQ?.backingBranchName || ""),
    `deployments [${statuses}] · versions ${(versionsOnly?.eventTimeline?.values || []).length} · current ${deploys?.currentDeployment?.sandboxVersion?.versionId === rev1Version} · latest [${msgs(diffQ?.historyFromLatest)}] · from version [${msgs(diffQ?.historyFromVersion)}] · branch ${diffQ?.backingBranchName}`);
  const runsBefore = ((await daemonReq("GET", "/v1/hypervisor/transformation-runs?family=acme.intake-normalise")).body?.transformation_runs || []).length;
  const deployCheck = await serveJson("POST", `/eddie/api/deployment/${intakeRid}/sandboxes/${intakeMain}/check-deployable`, { currentVersionId: rev1Version, acknowledgements: [] });
  const deployBranch = await serveJson("POST", `/eddie/api/deployment/${intakeRid}/sandboxes/${successorBranch?.id}/check-deployable`, { currentVersionId: successorBranch?.version, acknowledgements: [] });
  const deployed = await serveJson("POST", `/eddie/api/deployment/${intakeRid}/sandboxes/${intakeMain}/deploy-v2`, { currentVersionId: rev1Version, acknowledgements: [], targetBuildSelection: { type: "all", all: {} }, useOntologyRoles: false });
  const runsAfter = ((await daemonReq("GET", "/v1/hypervisor/transformation-runs?family=acme.intake-normalise")).body?.transformation_runs || []).length;
  ok("a deploy is refused by name and admits nothing: Main's check names the head revision and the missing run admission, a change set's check says its drafts are not admitted revisions, and a direct deploy fails with the same reason while the family's runs stay as they were",
    deployCheck.body?.type === "notDeployable" && /Revision 1/u.test(deployCheck.body?.notDeployable?.errors?.[0]?.message || "") && /does not admit runs yet/u.test(deployCheck.body?.notDeployable?.errors?.[0]?.message || "")
      && /drafts are not admitted revisions/u.test(deployBranch.body?.notDeployable?.errors?.[0]?.message || "")
      && deployed.body?.result?.type === "failed" && deployed.body?.versionId === rev1Version && runsBefore === 2 && runsAfter === 2 && !deployCheck.passthrough && !deployed.passthrough,
    `main ${deployCheck.body?.type} · branch ${deployBranch.body?.type} · deploy ${deployed.status} ${deployed.body?.result?.type} · runs ${runsBefore} → ${runsAfter}`);
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

  // The editor's permission and marking reads: the caller edits their own pipelines; nothing of the recorded tenant's.
  const ops = await serveJson("POST", "/multipass/api/authz/batch/operations?operations=eddie%3Aedit-pipeline", [intake?.rid, foreign]);
  const access = await serveJson("POST", "/multipass/api/authz/markings/access/principals", { markingTypes: ["MANDATORY"], principalIds: [operatorId] });
  const usable = await serveJson("GET", "/multipass/api/authz/markings/usable?markingTypes=MANDATORY");
  const opsMap = ops.body?.resourceToOperationsMap || {};
  ok("the caller may edit their own pipeline (eddie:edit-pipeline, and nothing more: no branch-protection, approval or unmarking setting is theirs to change), no other resource is named, and no principal holds a marking",
    JSON.stringify(Object.keys(opsMap)) === JSON.stringify([intake?.rid]) && JSON.stringify(opsMap[intake?.rid]) === JSON.stringify(["eddie:edit-pipeline"])
      && JSON.stringify(Object.keys(access.body?.categoryAndMarkingIds || {})) === JSON.stringify([operatorId]) && access.body.categoryAndMarkingIds[operatorId].markingIds.length === 0
      && Array.isArray(usable.body?.categories) && usable.body.categories.length === 0 && !ops.passthrough && !access.passthrough && !usable.passthrough,
    `ops ${JSON.stringify(opsMap)} · access ${JSON.stringify(Object.keys(access.body?.categoryAndMarkingIds || {}))} · usable ${usable.body?.categories?.length}`);

  // Create's refusals, each by name and each writing nothing: a project as the location, a compute with no
  // Hypervisor counterpart, a name whose family exists, and a signed-out caller.
  const registry = createBody?.createRequest?.parentFolder || "";
  const create = (req, cookie = true) => fetch(`${SERVE}/eddie/api/pipelines-v2/create-with-initial-display`, { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie: COOKIE } : {}) }, body: JSON.stringify({ createRequest: req }) }).then(async (r) => ({ status: r.status, message: (await r.json().catch(() => ({})))?.parameters?.message || "" })).catch(() => ({ status: 0, message: "" }));
  const before = ((await daemonReq("GET", "/v1/hypervisor/change-sets")).body?.change_sets || []).length;
  const inProject = await create({ name: "In a project", parentFolder: "ri.compass.main.folder.00000000-0000-4000-8000-000000000000", backend: "Spark" });
  const faster = await create({ name: "Faster one", parentFolder: registry, backend: "DataFusion" });
  const streaming = await create({ name: "Streaming one", parentFolder: registry, backend: "Flink" });
  const duplicate = await create({ name: "Claims normalise", parentFolder: registry, backend: "Spark" });
  const anonymous = await create({ name: "Anonymous", parentFolder: registry, backend: "Spark" }, false);
  const after = ((await daemonReq("GET", "/v1/hypervisor/change-sets")).body?.change_sets || []).length;
  ok("Create refuses by name a project as the location, faster and streaming compute, a name whose family exists, and a signed-out caller — and writes nothing",
    !!registry && inProject.status === 400 && /recipe registry/u.test(inProject.message) && faster.status === 400 && /DataFusion/u.test(faster.message)
      && streaming.status === 400 && /streaming/u.test(streaming.message) && duplicate.status === 400 && /already exists/u.test(duplicate.message) && anonymous.status === 401 && after === before,
    `project ${inProject.status} · faster ${faster.status} · streaming ${streaming.status} · duplicate ${duplicate.status} · anonymous ${anonymous.status} · change sets ${before} → ${after}`);

  // ---- 4. the editor's WRITES (cut 2d): a branch, a Save, a proposal and its merge, through the adopted pages ----
  // (after every read above: a merge moves the family's head, which those reads pin at revision 1)
  const writer = await chromium.launch();
  try {
    const ctx = await writer.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    const posted = [];
    pg.on("request", (r) => { if (r.method() === "POST" && /\/eddie\/api\/pipelines-v2\/[^/]+\/(?:sandboxes\/create-v3|proposals\/create|proposals\/[0-9a-f-]{36}\/merge)/u.test(r.url())) posted.push(new URL(r.url()).pathname.replace(/.*\/pipelines-v2\/[^/]+\//u, "").replace(/[0-9a-f]{8}-[0-9a-f-]{27}/gu, "<id>")); });
    await pg.goto(`${SERVE}/workspace/builder/${intake?.rid}/sandbox/${intake?.publishedSandboxes?.[0]}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(12000);
    await pg.getByText("Close", { exact: true }).first().click({ timeout: 1500 }).catch(() => { /* no announcement */ });
    // a branch: the branch picker's "Create new branch" → a Pipeline Builder branch (a change set on Main's head)
    await pg.getByRole("button", { name: "Main", exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1200);
    await pg.getByText("Create new branch", { exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1200);
    await pg.getByText("Pipeline Builder branch", { exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByRole("button", { name: "Create", exact: true }).last().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(8000);
    const onBranch = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    // propose it: the header's propose control → the create page → Create proposal
    // the propose control is an icon: known by its own tooltip ("Propose to merge changes on this branch…")
    for (const icon of await pg.locator("a[role=button], button").all()) {
      const box = await icon.boundingBox().catch(() => null);
      if (!box || box.y > 50 || (await icon.innerText().catch(() => "x")).trim()) continue;
      await icon.hover({ timeout: 1500 }).catch(() => {});
      await pg.waitForTimeout(600);
      const tip = await pg.evaluate(() => [...document.querySelectorAll('.bp6-tooltip,.bp5-tooltip,[role="tooltip"]')].map((e) => e.innerText).join(" "));
      if (/Propose to merge/u.test(tip)) { await icon.click({ timeout: 3000 }).catch(() => {}); break; }
    }
    await pg.waitForTimeout(8000);
    const createPage = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    await pg.getByRole("button", { name: /Create proposal/u }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(10000);
    const proposalPage = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    ok("a branch is created from the adopted editor (a change set opened on Main's head), and proposing it opens a proposal into Main through the builder's own create page",
      /New branch/u.test(onBranch) && /Merging New branch into Main/u.test(createPage) && /Merging New branch into Main Open/u.test(proposalPage) && posted.includes("sandboxes/create-v3") && posted.includes("proposals/create"),
      `branch ${/New branch/u.test(onBranch)} · create page ${/Merging New branch into Main/u.test(createPage)} · proposal open ${/Merging New branch into Main Open/u.test(proposalPage)} · posted ${posted.join(",")}`);
    // merge it (without the deploy after merge, which is refused by name): the family's head moves to revision 2
    const deployAfter = pg.locator('label:has-text("Deploy branch") input[type="checkbox"]').first();
    if (await deployAfter.isChecked().catch(() => false)) await pg.locator('label:has-text("Deploy branch")').first().click().catch(() => {});
    await pg.getByRole("button", { name: "Merge proposal", exact: true }).first().click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(10000);
    const mergedPage = (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const revs = ((await daemonReq("GET", "/v1/hypervisor/data-recipe-revisions?family=acme.intake-normalise")).body?.revisions || []);
    ok("merging the proposal on its page admits the branch's latest draft as the family's next revision (the builder's checkpoint gate finds no checkpoint configuration and proceeds)",
      /Merged proposal into Main/u.test(mergedPage) && posted.some((x) => /proposals\/<id>\/merge/u.test(x)) && revs.length === 2 && revs[1].succession?.predecessor_revision_ref === revs[0].revision_ref,
      `page merged ${/Merged proposal into Main/u.test(mergedPage)} · posted ${posted.join(",")} · revisions ${revs.map((r) => `${r.revision_ref.split("/").pop()}:${r.succession?.succession_reason}`).join(",")}`);
  } finally {
    await writer.close();
  }
  // The writes over the wire: a Save is a draft (or refused by name), a branch is archived by abandoning its change set,
  // a proposal is denied with its reason and never approved (no approval plane), and the autosave buffer is the caller's.
  {
    const rid = intake?.rid;
    const mainSid = intake?.publishedSandboxes?.[0];
    const headVersion = (await serveJson("GET", `/eddie/api/pipelines-v2/${rid}/all-information?sandboxId=${mainSid}`)).body?.version?.id;
    const branch = (await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/sandboxes/create-v3`, { name: "Retire the dataset output", fromVersion: headVersion, fromSandbox: mainSid, inheritFallbackBranches: true })).body?.sandbox;
    const snap = (await serveJson("POST", "/eddie/api/pipelines-v2/get-sandboxes-with-snapshots", { requests: [{ pipelineRid: rid, sandboxId: branch?.id }] })).body?.sandboxes?.[0]?.snapshot || {};
    const objectOnly = { ...snap, targets: (snap.targets || []).filter((t) => t.target?.type === "object") };
    const push = (sid, body) => serveJson("POST", `/eddie/api/pipelines-v2/${rid}/sandboxes/${sid}/push`, { display: {}, message: "Saved version from Pipeline Builder", ...body });
    const stale = await push(branch?.id, { snapshot: objectOnly, currentVersionId: headVersion });
    const withTransform = await push(branch?.id, { snapshot: { ...objectOnly, transforms: [{ id: "t" }] }, currentVersionId: branch?.version });
    const newOutput = await push(branch?.id, { snapshot: { ...objectOnly, targets: [...objectOnly.targets, { id: "n", target: { type: "dataset", dataset: { columns: [] } } }] }, currentVersionId: branch?.version });
    const onMain = await push(mainSid, { snapshot: objectOnly, currentVersionId: headVersion });
    const saved = await push(branch?.id, { snapshot: objectOnly, currentVersionId: branch?.version, backend: "Spark" });
    const savedVersion = saved.body?.newVersionId ? await serveJson("GET", `/eddie/api/pipelines-v2/${rid}/versions/${saved.body.newVersionId}/lightweight`) : { body: null };
    const draftBody = ((await daemonReq("GET", "/v1/hypervisor/change-sets?family=acme.intake-normalise")).body?.change_sets || []).find((c) => c.title === "Retire the dataset output")?.drafts?.at(-1)?.body;
    ok("a Save on a branch is the change set's next draft carrying the snapshot's outputs (the dataset output dropped, everything the editor cannot express carried); a stale version, a transform, an output with no declared contract and a Save on Main are refused by name",
      stale.status === 409 && stale.body?.errorName === "PipelineBuilder:SandboxEditConflict" && withTransform.status === 400 && withTransform.body?.errorName === "Eddie:TransformsNotKept"
        && newOutput.status === 400 && newOutput.body?.errorName === "Eddie:OutputHasNoContract" && onMain.status === 409 && onMain.body?.errorName === "PipelineBuilder:SandboxIsProtected"
        && saved.status === 200 && savedVersion.body?.details?.message === "Draft 2" && Array.isArray(draftBody?.output_dataset_contract_refs) && draftBody.output_dataset_contract_refs.length === 0
        && (draftBody?.output_object_model_refs || []).length === 1 && draftBody?.succession_reason === "output_contract_change" && (draftBody?.transformation_steps || []).length > 0,
      `stale ${stale.status} · transform ${withTransform.body?.errorName} · new output ${newOutput.body?.errorName} · main ${onMain.body?.errorName} · saved ${saved.status} ${savedVersion.body?.details?.message} · draft ${JSON.stringify({ ds: draftBody?.output_dataset_contract_refs, om: draftBody?.output_object_model_refs, why: draftBody?.succession_reason })}`);
    const ontologyMap = Object.values((await serveJson("POST", "/ontology-metadata/api/ontology/v2/load/all", {})).body?.ontologies || {});
    const draftOntology = ontologyMap.find((o) => o.displayName === "claims-draft");
    const draftRid = Object.entries((await serveJson("POST", "/ontology-metadata/api/ontology/v2/load/all", {})).body?.ontologies || {}).find(([, o]) => o.displayName === "claims-draft")?.[0];
    const onUnpublished = await push(branch?.id, { snapshot: { ...objectOnly, targetSettings: { objectTargetSettings: { ontologyRid: draftRid } } }, currentVersionId: saved.body?.newVersionId, backend: "Spark" });
    ok("the builder's ontology map offers the caller's ontologies — the published one with its head revision, the Ontology Manager draft with none — and a Save that targets the unpublished one is refused by name",
      odkDraft.status === 201 && ontologyMap.some((o) => o.displayName === "acme-clinic/patient-intake" && /\/revision\/1$/u.test(o.currentOntologyVersion || "")) && draftOntology?.currentOntologyVersion === null
        && onUnpublished.status === 400 && onUnpublished.body?.errorName === "Eddie:OntologyNotPublished",
      `odk draft ${odkDraft.status} · map ${JSON.stringify(ontologyMap.map((o) => [o.displayName, o.currentOntologyVersion]))} · unpublished save ${onUnpublished.status} ${onUnpublished.body?.errorName}`);
    const proposed = (await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/proposals/create`, { proposalDetails: { name: "Retire the dataset output into Main", description: "the row contract is retired", sourceSandbox: branch?.id, targetSandbox: mainSid } })).body?.proposal;
    const review = (decision, reason) => serveJson("POST", `/eddie/api/pipelines-v2/${rid}/proposals/${proposed?.id}/review-v2`, { checkId: null, decision: { type: decision, [decision]: {} }, reviewedSandboxVersion: null, reason, reviewCommentReferences: [] });
    const approve = await review("approve", "");
    const closeP = await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/proposals/${proposed?.id}/close`, { oldVersion: proposed?.version });
    const deny = await review("deny", "the row contract is still read downstream");
    const rejected = ((await daemonReq("GET", "/v1/hypervisor/change-sets?family=acme.intake-normalise")).body?.change_sets || []).find((c) => c.title === "Retire the dataset output into Main");
    ok("a proposal carries the name and description its dialog gave; it is denied with the reviewer's reason and never approved (there is no approval plane), and closing it is refused by name (a proposal is withdrawn by archiving its branch)",
      proposed?.details?.name === "Retire the dataset output into Main" && proposed?.details?.description === "the row contract is retired"
        && approve.status === 400 && approve.body?.errorName === "Eddie:ApprovalsNotKept" && closeP.status === 400 && closeP.body?.errorName === "Eddie:ProposalCloseIsArchive"
        && deny.status === 200 && rejected?.status === "rejected" && rejected?.decision_note === "the row contract is still read downstream",
      `proposal ${proposed?.details?.name} / ${proposed?.details?.description} · approve ${approve.body?.errorName} · close ${closeP.body?.errorName} · deny ${deny.status} → ${rejected?.status} "${rejected?.decision_note}"`);
    const scratch = (await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/sandboxes/create-v3`, { name: "Scratch", fromVersion: headVersion, fromSandbox: mainSid })).body?.sandbox;
    const rebase = await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/sandboxes/${scratch?.id}/rebase-v2`, {});
    const archived = await serveJson("POST", `/eddie/api/pipelines-v2/${rid}/sandboxes/archive`, { sandboxesToArchive: [scratch?.id] });
    const branches = ((await serveJson("GET", `/eddie/api/pipelines-v2/${rid}/sandboxes/get/all`)).body?.sandboxes || []).map((x) => x.name);
    const wsPath = `/eddie/api/work-state/${rid}/${mainSid}`;
    const ws0 = await fetch(`${SERVE}${wsPath}/v2`, { headers: { cookie: COOKIE } }).then((r) => r.status);
    const ws1 = await serveJson("POST", wsPath, { workState: { sandboxVersion: headVersion, logic: {}, display: {} } });
    const ws2 = await serveJson("GET", `${wsPath}/v2`);
    const wsStale = await serveJson("POST", wsPath, { previousStateVersion: "not-the-current-one", workState: {} });
    const wsGone = await fetch(`${SERVE}${wsPath}`, { method: "DELETE", headers: { cookie: COOKIE } }).then((r) => r.status);
    ok("a branch is archived by abandoning its change set (rebasing a pinned change set is refused by name), and the autosave buffer keeps the caller's unsaved state with a version a stale tab conflicts on",
      rebase.status === 400 && rebase.body?.errorName === "Eddie:ChangeSetsArePinned" && archived.status === 200 && !branches.includes("Scratch")
        && ws0 === 204 && ws1.status === 200 && ws2.body?.stateVersion === ws1.body?.stateVersion && wsStale.status === 409 && wsStale.body?.errorName === "PipelineBuilder:WorkStateVersionConflict" && wsGone === 204,
      `rebase ${rebase.body?.errorName} · archive ${archived.status} · branches ${JSON.stringify(branches)} · autosave ${ws0}/${ws1.status}/${ws2.status}/${wsStale.status}/${wsGone}`);
  }

  // Signed out, neither the picker nor the lookup names anything (the daemon answers some reads to an
  // anonymous loopback caller; these answers are the signed-in caller's to see).
  const anon = async (route, body) => fetch(`${SERVE}${route}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json()).catch(() => null);
  const anonPicker = await anon("/foundry-search/api/compass/v0/search", { query: { includeResources: ["FILE"], filter: { isProjectPreview: true, type: "isProjectPreview" }, text: "" }, limit: 50, offset: 0 });
  const anonUsers = await anon("/multipass/api/users", [operatorId]);
  const anonOps = await anon("/multipass/api/authz/batch/operations", [intake?.rid]);
  const anonPush = await fetch(`${SERVE}/eddie/api/pipelines-v2/${intake?.rid}/sandboxes/create-v3`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "x" }) }).then((r) => r.status).catch(() => 0);
  ok("signed out, the project picker and the user lookup answer nothing, no pipeline is editable, and a branch is refused",
    Array.isArray(anonPicker?.result) && anonPicker.result.length === 0 && Array.isArray(anonUsers) && anonUsers.length === 0
      && Object.values(anonOps?.resourceToOperationsMap || {}).every((ops) => ops.length === 0) && anonPush === 401,
    `picker ${anonPicker?.result?.length ?? "?"} · users ${Array.isArray(anonUsers) ? anonUsers.length : "?"} · ops ${JSON.stringify(anonOps?.resourceToOperationsMap)} · branch ${anonPush}`);

  // Degraded: with the daemon stopped, the landing's search and a pipeline's details answer an ERROR the app
  // shows ("Unable to load pipelines") — never an empty list that reads as "you have no pipelines".
  daemon.kill("SIGTERM");
  await sleep(1500);
  const downSearch = await fetch(`${SERVE}/graphql-gateway/api/bulk?q=PipelineLandingSearchQuery`, {
    method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" },
    body: JSON.stringify({ operations: { 0: "query PipelineLandingSearchQuery($text: String, $pageSize: Int!) { searchResourcesV2(pageSize: $pageSize, filter: {text: $text, types: [EDDIE_PIPELINE]}) { results { resource { rid __typename } __typename } nextPageToken __typename } __typename }" }, requests: [{ hash: "0", name: "PipelineLandingSearchQuery", variables: { text: "", pageSize: 50 } }] }),
  }).then((r) => r.text()).catch(() => "");
  const downDetails = await serveJson("POST", "/eddie/api/pipelines-v2/get/by-rids", rids);
  ok("with the daemon stopped, the landing's search and a pipeline's details answer an error the app shows — never an empty list",
    /"errors":\[/u.test(downSearch) && !/"results":\[\]/u.test(downSearch) && downDetails.status === 503,
    `search ${downSearch.slice(0, 160)} · details ${downDetails.status}`);
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
