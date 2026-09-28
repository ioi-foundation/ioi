#!/usr/bin/env node
// THE ADOPTED DATA CONNECTION IS THE CALLER'S DATA SOURCES, AND NOTHING RECORDED (R-241, Data Connection D1–D4).
//
// The reference Data Connection (booted by the local mirror, routed at /workspace/data-ingestion-app) answers from the
// Hypervisor's data-source plane (adopted-data-connection.mjs), in a real browser against an ISOLATED daemon + serve:
//   - the Sources list is the caller's declared data sources, each under its connection type, its syncs counted;
//   - Agents and Listeners say none — no agent or listener exists;
//   - Syncs (cut D4) over the import ladder built on the S3 bucket: a sync is its capability-lease plan (the Syncs list,
//     its filters, the bucket's Batch syncs table, the sync's Overview, Configuration and Versions); its runs are the
//     plan's materializing runs (Never ran, then Waiting when one is admitted, Canceled once cancelled); Run needs a
//     wallet-authority grant and is refused by name, as is Delete;
//   - a source's own pages: its Overview, Code imports and Webhooks (off, and nothing turns them on);
//   - New source (cut D3), driven as a person does it: pick REST API, name it, file it in a project, create — a draft
//     data source — give it its domain (the draft becomes declared, with that endpoint), and walk the remaining steps;
//   - an existing REST source's connection settings: its declarer's new domain becomes its endpoint, path kept;
//   - no read reaches the mirror but the reference's chrome, no service read gets the serve's HTML page; a type other
//     than REST API is refused by name at create, and any other write is a named gap that writes nothing;
//   - with the daemon stopped, the Sources list shows its error rather than "No sources".
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon binary, or the local mirror cannot boot the reference app).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-data-connection.mjs

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
const BIN = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
const MIRROR = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
const BASE = "/workspace/data-ingestion-app";
// the reference's chrome reads the mirror still answers (the adopted Ontology Manager's set, plus the landing's paged notes)
const CHROME = new Set(["GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection", "POST /documentation/api/v2/release-notes/pagination",
  "POST /documentation/api/v2/release-notes/paginationV2", "GET /aip-assist/api/chat/checkAvailability", "GET /workspace/api/lifecycleStatusByApplication", "POST /log-receiver/api/beacon",
  "GET /compass/api/registry/actions"]);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };

let daemon = null, serve = null;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-data-connection-"));

async function run() {
  if (!fs.existsSync(BIN)) { console.log(`BLOCKED: no daemon binary at ${BIN}`); process.exit(2); }
  if (!(await fetch(`${MIRROR}${BASE}/splash`, { signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false))) { console.log(`BLOCKED: the local mirror (${MIRROR}) does not boot ${BASE}/`); process.exit(2); }
  const daemonPort = await freePort();
  const DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => (log += c)); daemon.stderr.on("data", (c) => (log += c));
  await waitFor(`${DAEMON}/healthz`);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
  const boot = await (await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "adopted-data-connection-bootstrap-v1", email: "data@ioi.local" }) })).json();
  const COOKIE = `ioi_session=${boot.session_token}`;
  const d = (method, route, body) => fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  const servePort = await freePort();
  const SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_ADOPTED_SURFACES: "1", IOI_HARVEST_CAPTURE_URL: MIRROR },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/__ioi/login`);

  // ---- the fixture: two declared data sources of different kinds -------------------------------------------------
  const orders = await d("POST", "/v1/hypervisor/data-sources", { name: "Orders API", kind: "rest_api", endpoint: "https://api.example.test/orders", credential_posture: "wallet_credential_lease" });
  const plants = await d("POST", "/v1/hypervisor/data-sources", { name: "Plants bucket", kind: "s3", endpoint: "s3://plants-example/", credential_posture: "wallet_credential_lease" });
  const countBefore = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).length;
  // a project to file a new source in (the location picker offers the caller's projects)
  await d("POST", "/v1/hypervisor/projects", { project_name: "payments", repository_url: "https://example.local/verify/payments.git" });
  const projectRow = ((await d("GET", "/v1/hypervisor/projects")).j.projects || []).find((p) => (p.project_name || p.name) === "payments") || {};
  const project = { project_ref: projectRow.project_ref || (projectRow.project_id ? `project://${projectRow.project_id}` : null) };
  // the import ladder on the S3 bucket (cut D4): connector mapping → policy-bound view → transformation run (dry run) →
  // ontology projection → capability-lease plan. The plan is the bucket's one sync; it has no run yet.
  const owner = ((await d("GET", "/v1/hypervisor/auth/whoami")).j.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://"));
  const plantsId = plants.j.data_source?.source_id;
  const ontology = await d("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "plants", canonical_object_model: { object_types: [{ id: "plant", name: "Plant", title_property: "title",
    properties: [{ id: "plant_id", name: "Plant Id", value_type: "string", required: true }, { id: "title", name: "Title", value_type: "string" }] }], action_types: [] } });
  const mapping = await d("POST", "/v1/hypervisor/odk/connector-mappings", { owner_ref: owner, idempotency_key: "adopted-dc-plants-mapping", name: "plants-map", data_source_id: plantsId, ontology_ref: ontology.j.ontology?.ref,
    object_type_id: "plant", key_mapping: { source_field: "id", property_id: "plant_id", source_type: "string" }, title_mapping: { source_field: "name", property_id: "title", source_type: "string" } });
  const mappingId = mapping.j.connector_mapping?.id;
  const gate = await d("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mappingId, name: "plants-gate", authority_subjects: ["agent://materializer"], allowed_operations: ["read", "transform"],
    purpose: "plant catalog", property_scope: ["plant_id", "title"], retention_posture: "bounded" });
  const gateId = gate.j.policy_bound_data_view?.id;
  const transform = await d("POST", "/v1/hypervisor/odk/transformation-runs", { owner_ref: owner, idempotency_key: "adopted-dc-plants-transform", connector_mapping_id: mappingId, policy_view_id: gateId, name: "plants-transform" });
  const transformId = transform.j.transformation_run?.id;
  await d("POST", `/v1/hypervisor/odk/transformation-runs/${transformId}/dry-run`);
  const projection = await d("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mappingId, policy_view_id: gateId, name: "plants-explorer", visible_properties: ["plant_id", "title"] });
  const plan = await d("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: plantsId, connector_mapping_id: mappingId, policy_view_id: gateId, transformation_run_id: transformId,
    ontology_projection_id: projection.j.ontology_projection?.id, name: "Plants import", subject: "agent://materializer", ttl_seconds: 900 });
  const planId = plan.j.capability_lease_plan?.id;
  ok("PRECONDITION: two data sources are declared (a REST API and an S3 bucket), and a capability-lease plan binds the bucket (the import ladder, with no run)",
    orders.status < 300 && plants.status < 300 && countBefore === 2 && plan.status === 201 && !!planId, `${orders.status} · ${plants.status} · ${countBefore} declared · plan ${plan.status}${plan.j.error ? ` ${plan.j.error.code}` : ""}`);

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: boot.session_token, url: SERVE }]);
    const pg = await ctx.newPage();
    const passthrough = new Set(), fenced = new Set(), unnamed = new Set(), htmlAnswers = new Set(), gqlErrors = new Set(), pageErrors = [];
    pg.on("pageerror", (e) => pageErrors.push(String(e.message).slice(0, 160)));
    pg.on("response", async (r) => {
      const u = new URL(r.url()); const key = `${r.request().method()} ${u.pathname.replace(/ri\.[\w.-]+/gu, "<rid>")}`;
      if (r.headers()["x-ioi-mirror-passthrough"] === "1") passthrough.add(key);
      if (/^\/[a-z][a-z0-9-]*\/api\//u.test(u.pathname) && /text\/html/u.test(r.headers()["content-type"] || "")) htmlAnswers.add(key);
      if (r.status() === 501) { fenced.add(key); const j = await r.json().catch(() => ({})); if (j.errorName !== "Hypervisor:DataConnectionReadNotBound") unnamed.add(key); }
      if (/graphql/u.test(u.pathname)) { const t = await r.text().catch(() => ""); for (const m of t.matchAll(/"message":"([^"]{0,90})/gu)) gqlErrors.add(m[1]); }
    });
    const text = async () => (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const visit = async (p, until) => { await pg.goto(`${SERVE}${p}`, { waitUntil: "domcontentloaded", timeout: 60000 }); let t = ""; for (let i = 0; i < 25; i++) { await pg.waitForTimeout(800); t = await text(); if (!until || until.test(t)) break; } return t; };
    const after = (t, marker, n = 200) => (t.includes(marker) ? t.slice(t.indexOf(marker), t.indexOf(marker) + n) : `(no "${marker}")`);

    const sources = await visit(`${BASE}/sources`, /Orders API|No sources|could not|Failed/u);
    const table = after(sources, "Sources Name Connection type", 260);
    ok("the Sources list is the caller's declared data sources, each under its connection type, with its syncs counted from its lease plans",
      /Orders API REST API .{0,30}\b0 syncs/u.test(table) && /Plants bucket S3 .{0,30}\b1 sync(?!s)/u.test(table) && !/No sources/u.test(sources), table);
    // a source's own page, opened from the list the way a person opens it (cut D2)
    await pg.getByText("Orders API", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let restPage = ""; for (let i = 0; i < 25 && !/Orders API \(REST API\)|An error occurred/u.test(restPage); i++) { await pg.waitForTimeout(800); restPage = await text(); }
    const restUrl = new URL(pg.url()).pathname;
    await visit(`${BASE}/sources`, /Plants bucket/u);
    await pg.getByText("Plants bucket", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let s3Page = ""; for (let i = 0; i < 25 && !/Plants bucket \(S3\)|An error occurred/u.test(s3Page); i++) { await pg.waitForTimeout(800); s3Page = await text(); }
    ok("a source opens from the list on its own page over daemon truth: its name, its connection type and what it can do, with nothing it cannot",
      /\/sources\/ri\.magritte\.\.source\.[0-9a-f-]{36}\/overview$/u.test(restUrl) && /Orders API \(REST API\)/u.test(restPage) && /Explore source capabilities/u.test(restPage)
        && /Plants bucket \(S3\)/u.test(s3Page) && !/An error occurred/u.test(restPage + s3Page),
      `${restUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(restPage, "Orders API (", 20)} · ${after(s3Page, "Plants bucket (", 20)}`);
    // the bucket's Overview lists its syncs (cut D4): its lease plan, the plan's output dataset, Never ran and Manual
    for (let i = 0; i < 20 && !/Plants import \(Plants import objects\)|Failed to load batch syncs/u.test(s3Page); i++) { await pg.waitForTimeout(700); s3Page = await text(); }
    ok("a source's Overview lists its syncs: the bucket's Batch syncs table is its lease plan, with the plan's output dataset, Never ran and next run Manual",
      /Batch syncs 1 /u.test(s3Page) && /Plants import \(Plants import objects\) Never ran Manual/u.test(s3Page) && !/Failed to load batch syncs/u.test(s3Page),
      after(s3Page, "Batch syncs", 220));
    // the source's Code imports and Webhooks pages: both off, and nothing on them can turn either on (cut D2)
    const srcBase = restUrl.replace(/\/overview$/u, "");
    const controlsOf = () => pg.evaluate(() => [...document.querySelectorAll("input[type=checkbox], [role=switch], button, a[role=button]")]
      .map((e) => ({ label: (e.closest("label")?.innerText || e.innerText || e.getAttribute("aria-label") || "").trim().replace(/\s+/gu, " ").slice(0, 64),
        on: e.checked === true || e.getAttribute("aria-checked") === "true", off: e.disabled === true || e.getAttribute("aria-disabled") === "true" || !!e.closest("[aria-disabled=true], .bp5-disabled, .bp6-disabled") })));
    const imports = await visit(`${srcBase}/settings/code-imports`, /Enable code imports|Failed to load configuration/u);
    // every switch is disabled; the three a source's editor may set (code repositories, compute modules, pipelines for UDFs)
    // are off — the two the reference fixes on (webhooks in code repositories, virtual tables) are its own, not ours
    const importSwitches = (await controlsOf()).filter((c) => /^Allow (this source to be imported|the usage of source webhooks)/u.test(c.label));
    const configurable = importSwitches.filter((c) => /imported into (code repositories|compute modules|pipelines for UDFs)/u.test(c.label));
    const hooks = await visit(`${srcBase}/webhooks`, /No webhooks found|Failed/u);
    const newHook = (await controlsOf()).filter((c) => c.label === "New");
    ok("a source's code imports are off and cannot be enabled, and it has no webhooks and cannot create one — no code repository or webhook plane exists here",
      /Enable code imports/u.test(imports) && !/Failed to load configuration/u.test(imports) && importSwitches.every((c) => c.off) && configurable.length === 3 && configurable.every((c) => !c.on)
        && /No webhooks found/u.test(hooks) && /Webhooks 0/u.test(hooks) && newHook.length >= 1 && newHook.every((c) => c.off),
      `imports ${importSwitches.map((c) => `${c.label.replace(/^Allow (this source to be imported into|the usage of) /u, "")}:${c.on ? "on" : "off"}${c.off ? "" : "(LIVE)"}`).join(", ")} · ${after(hooks, "Webhooks 0", 40)} · New ${JSON.stringify(newHook)}`);
    const agents = await visit(`${BASE}/agents`, /No agents found|Unable to load agents/u);
    const listeners = await visit(`${BASE}/listeners`, /No listeners found|Failed to load listeners/u);
    ok("Agents and Listeners say none — no agent or listener exists",
      /No agents found/u.test(agents) && /No listeners found/u.test(listeners) && !/Unable to load agents|Failed to load listeners/u.test(agents + listeners),
      `${after(agents, "No agents", 20)} · ${after(listeners, "No listeners", 22)}`);

    // ---- Syncs (cut D4): a sync is a capability-lease plan on one of the caller's sources; its runs are the plan's
    // materializing runs, its output dataset the plan's own, and no schedule runs it
    // (waited for until the row's dataset and status have loaded)
    const SYNC_ROW = /Plants import objects \/\S+ Plants bucket (Never ran|Waiting|Running|Canceled|Failed|Succeeded)|No syncs|Could not load syncs/u;
    const syncs = await visit(`${BASE}/syncs`, SYNC_ROW);
    const row = after(syncs, "Next run Actions", 140);
    // the filters sift the list: a status the sync is not in hides it, its own keeps it, and so does a name it carries
    const statusBox = (label) => pg.locator("label").filter({ hasText: new RegExp(`^\\s*${label}\\s*$`, "u") }).first();
    await statusBox("Running").click({ timeout: 8000 }).catch(() => {}); await pg.waitForTimeout(1500);
    const hiddenByRunning = /No syncs/u.test(await text());
    await statusBox("Running").click({ timeout: 8000 }).catch(() => {}); await statusBox("Never ran").click({ timeout: 8000 }).catch(() => {}); await pg.waitForTimeout(1500);
    const keptByNeverRan = /Plants import Plants import objects/u.test(await text());
    await statusBox("Never ran").click({ timeout: 8000 }).catch(() => {});
    ok("the Syncs list is the caller's lease plans: the bucket's sync, its output dataset and source, Never ran, next run Manual — and its status filters sift it",
      /^Next run Actions Plants import Plants import objects \/\S+ Plants bucket Never ran Manual Run Delete/u.test(row) && hiddenByRunning && keptByNeverRan && !/Could not load syncs/u.test(syncs),
      `${row} · Running ${hiddenByRunning ? "hides it" : "KEEPS it"} · Never ran ${keptByNeverRan ? "keeps it" : "HIDES it"}`);
    // a sync's own pages, opened from the list the way a person opens one
    await visit(`${BASE}/syncs`, /Plants import/u);
    await pg.getByText("Plants import", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let overview = ""; for (let i = 0; i < 25 && !/Build details .{0,40}Next run|An error occurred/u.test(overview); i++) { await pg.waitForTimeout(800); overview = await text(); }
    const syncUrl = new URL(pg.url()).pathname;
    const syncBase = syncUrl.replace(/\/overview$/u, "");
    const configuration = await visit(`${syncBase}/configuration`, /type: capability-lease-plan|An error occurred/u);
    const versions = await visit(`${syncBase}/versions`, /extractName|An error occurred/u);
    ok("a sync opens from the list on its Overview, Configuration and Versions over its plan: the lease-plan adapter, its dataset and source, never run, Manual with no schedule, and the plan's lease shape as its one version",
      /\/syncs\/ri\.magritte\.\.extract\.[0-9a-f-]{36}\/overview$/u.test(syncUrl)
        && /Plants import capability-lease-plan Properties Output dataset Plants import objects Source Plants bucket Build details Never run Next run Manual/u.test(overview)
        && /Run this import Manually/u.test(configuration) && /type: capability-lease-plan/u.test(configuration) && /subject: agent:\/\/materializer/u.test(configuration)
        && /Version 1 Current/u.test(versions) && /extractName: Plants import/u.test(versions) && /purpose: plant catalog/u.test(versions) && !/An error occurred/u.test(overview + configuration + versions),
      `${syncUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(overview, "Properties", 150)} · ${after(configuration, "Run this import", 30)} · ${after(versions, "SYNC VERSIONS", 40)}`);
    // a run is the plan's materializing run: admitted, it waits for its lease; cancelled (no grant needed), it is Canceled
    const admitted = await d("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "plants-run-1" });
    const waiting = after(await visit(`${BASE}/syncs`, /Plants import objects \/\S+ Plants bucket Waiting/u), "Next run Actions", 140);
    const banner = await visit(`${syncBase}/configuration`, /waiting to run|An error occurred/u);
    const cancelled = await d("POST", `/v1/hypervisor/odk/materializing-runs/${admitted.j.materializing_run?.id}/cancel`);
    const canceled = after(await visit(`${BASE}/syncs`, /Plants import objects \/\S+ Plants bucket Canceled/u), "Next run Actions", 140);
    ok("a sync's run is its plan's materializing run, over daemon truth: an admitted run shows Waiting (for its lease) with the running banner, and once cancelled the sync shows Canceled",
      admitted.status === 201 && /Plants bucket Waiting/u.test(waiting) && /This dataset is waiting to run/u.test(banner) && cancelled.j.materializing_run?.status === "cancelled" && /Plants bucket Canceled/u.test(canceled),
      `run ${admitted.status} ${admitted.j.materializing_run?.status} · ${waiting.slice(0, 110)} · banner ${/waiting to run/u.test(banner) ? "shown" : "ABSENT"} · cancel ${cancelled.j.materializing_run?.status} · ${canceled.slice(0, 110)}`);
    // Run and Delete, as a person presses them: each refused by name — nothing runs, the plan is untouched
    const syncWrites = [];
    const onSyncWrite = async (r) => { if (/\/magritte-coordinator\/api\/build\//u.test(r.url())) syncWrites.push({ status: r.status(), j: await r.json().catch(() => ({})) }); };
    pg.on("response", onSyncWrite);
    const runsBefore = ((await d("GET", "/v1/hypervisor/odk/materializing-runs")).j.materializing_runs || []).length;
    await visit(`${BASE}/syncs`, /Plants import/u);
    await pg.getByText("Run", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let runToast = ""; for (let i = 0; i < 12 && !/wallet-authority grant/u.test(runToast); i++) { await pg.waitForTimeout(600); runToast = await text(); }
    await pg.getByText("Delete", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: "Confirm", exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    for (let i = 0; i < 12 && syncWrites.length < 2; i++) await pg.waitForTimeout(600);
    pg.off("response", onSyncWrite);
    const runsAfter = ((await d("GET", "/v1/hypervisor/odk/materializing-runs")).j.materializing_runs || []).length;
    const planAfter = (await d("GET", `/v1/hypervisor/odk/capability-lease-plans/${planId}`)).j.capability_lease_plan;
    ok("a sync's Run is refused by name, pointing at the approval flow (a run needs a wallet-authority grant), and Delete is refused by name — nothing runs and the plan is untouched",
      syncWrites.some((x) => x.status === 409 && x.j.errorName === "Hypervisor:DataConnectionRunNeedsApproval") && syncWrites.some((x) => x.status === 409 && x.j.errorName === "Hypervisor:DataConnectionSyncWriteNotBound")
        && /wallet-authority grant, issued through the Hypervisor's approval flow/u.test(runToast) && runsAfter === runsBefore && planAfter?.status === "declared" && planAfter?.revision === 1,
      `${syncWrites.map((x) => `${x.status} ${x.j.errorName}`).join(" · ") || "no write sent"} · runs ${runsBefore} → ${runsAfter} · plan ${planAfter?.status} r${planAfter?.revision}`);
    const splash = await visit(`${BASE}/splash`, /Set up new connections|An error occurred/u);
    const newSource = await pg.evaluate(() => [...document.querySelectorAll("a,button,[role=button]")].filter((e) => (e.innerText || "").trim() === "New source").map((e) => e.disabled === true || e.getAttribute("aria-disabled") === "true"));
    ok("the landing renders, and offers New source (a source is created as a data-source declaration)",
      /Set up new connections/u.test(splash) && !/An error occurred/u.test(splash) && newSource.length >= 1 && newSource.every((off) => !off),
      `${after(splash, "Data Connection Synchronize", 60)} · New source ${newSource.length ? (newSource.every((off) => !off) ? "offered" : "DISABLED") : "absent"}`);

    // ---- New source, as a person creates one (cut D3): pick REST API, name it, file it in a project, create — a draft
    // data source — then give it its domain: the draft becomes a declared source with that endpoint
    await visit(`${BASE}/sources/new`, /Select your source type|REST API/u);
    await pg.locator("[role=button], button, a, div").filter({ hasText: /^REST API\b/u }).last().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(3000);
    await pg.getByRole("button", { name: /^Continue$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(3000);
    await pg.locator("input[type=text]").first().fill("Payments API").catch(() => {});
    const createBtn = pg.getByRole("button", { name: /^Create source and continue$/u }).first();
    for (let i = 0; i < 15 && !(await createBtn.isEnabled().catch(() => false)); i++) await pg.waitForTimeout(700);
    await createBtn.click({ timeout: 8000 }).catch(() => {});
    let setupUrl = ""; for (let i = 0; i < 25 && !/\/setup\/connection-details$/u.test(setupUrl); i++) { await pg.waitForTimeout(800); setupUrl = new URL(pg.url()).pathname; }
    const drafted = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).find((x) => x.name === "Payments API");
    const hostField = pg.locator("input[placeholder='external-system.com']").first();
    await hostField.waitFor({ state: "visible", timeout: 20000 }).catch(() => {});
    await hostField.fill("payments.example.test").catch(() => {});
    await pg.getByRole("button", { name: /^Save and continue$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: /^Continue without adding$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let nextUrl = ""; for (let i = 0; i < 25 && !/\/setup\/export-configuration$/u.test(nextUrl); i++) { await pg.waitForTimeout(800); nextUrl = new URL(pg.url()).pathname; }
    const declared = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).find((x) => x.name === "Payments API");
    ok("New source creates a REST API source as a draft data source in the chosen project, and saving its connection details gives it that endpoint",
      /\/setup\/connection-details$/u.test(setupUrl) && drafted?.lifecycle?.status === "draft" && !drafted?.endpoint && drafted?.project_ref === project.project_ref && drafted?.declared_by_principal_ref
        && declared?.endpoint === "https://payments.example.test" && declared?.lifecycle?.status === "declared" && (declared?.receipt_refs || []).length === 2 && /\/setup\/export-configuration$/u.test(nextUrl),
      `${setupUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · drafted ${drafted ? `${drafted.lifecycle?.status} ${drafted.endpoint || "no endpoint"} ${drafted.project_ref || "no project"}` : "none"} · declared ${declared ? `${declared.lifecycle?.status} ${declared.endpoint} ${(declared.receipt_refs || []).length} receipts` : "none"} · ${nextUrl.replace(/ri\.[\w.-]+/u, "<rid>")}`);

    ok("no page reached the mirror beyond the reference's chrome, every read the adopted layer does not bind is a named gap (never the serve's HTML page), and no GraphQL operation on these pages is unbound",
      [...passthrough].every((p) => CHROME.has(p)) && unnamed.size === 0 && htmlAnswers.size === 0 && fenced.size === 0 && gqlErrors.size === 0 && pageErrors.length === 0,
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · fenced ${[...fenced].join(",") || "none"} · unnamed ${[...unnamed].join(",") || "none"} · html ${[...htmlAnswers].join(",") || "none"} · gql ${[...gqlErrors].slice(0, 2).join(" | ") || "none"} · page ${pageErrors.slice(0, 1).join("") || "none"}`);

    // the setup's remaining steps: exports are off and nothing here enables them, code imports are off, and the summary
    // offers the source's page
    await pg.getByRole("button", { name: /^Continue$/u }).last().click({ timeout: 8000 }).catch(() => {});
    let importsUrl = ""; for (let i = 0; i < 20 && !/\/setup\/code-imports$/u.test(importsUrl); i++) { await pg.waitForTimeout(700); importsUrl = new URL(pg.url()).pathname; }
    await pg.getByRole("button", { name: /^Continue$/u }).last().click({ timeout: 8000 }).catch(() => {});
    let summaryUrl = ""; for (let i = 0; i < 20 && !/\/setup\/summary$/u.test(summaryUrl); i++) { await pg.waitForTimeout(700); summaryUrl = new URL(pg.url()).pathname; }
    const summary = await text();
    ok("the setup's remaining steps walk through as the reference's do: export configuration, code imports, then a summary that opens the source",
      /\/setup\/code-imports$/u.test(importsUrl) && /\/setup\/summary$/u.test(summaryUrl) && /Go to Source page/u.test(summary) && /Open Source/u.test(summary),
      `${importsUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${summaryUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(summary, "What to do next", 120)}`);

    // ---- an existing REST source's connection settings: its declarer changes the domain, and the source's endpoint
    // follows, keeping its path
    await visit(`${srcBase}/settings/connection-details`, /Domain base URL|You do not have permission/u);
    const domain = pg.locator("input[placeholder='external-system.com']").first();
    await domain.waitFor({ state: "visible", timeout: 20000 }).catch(() => {});
    const shownHost = await domain.inputValue().catch(() => "");
    await domain.fill("orders.example.test").catch(() => {});
    await pg.getByRole("button", { name: /^Save$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: /^Continue without adding$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let edited = null; for (let i = 0; i < 20; i++) { await pg.waitForTimeout(700); edited = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).find((x) => x.name === "Orders API"); if (edited?.endpoint !== "https://api.example.test/orders") break; }
    ok("an existing REST source's connection settings show its domain, and its declarer's change becomes the source's endpoint, keeping its path — receipted",
      shownHost === "api.example.test" && edited?.endpoint === "https://orders.example.test/orders" && (edited?.receipt_refs || []).length === 2,
      `shown ${shownHost || "(none)"} · endpoint ${edited?.endpoint} · ${(edited?.receipt_refs || []).length} receipts`);

    // ---- refused by name: a type this plane cannot create, and a write the app would send that is not bound ----------
    const H = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}${BASE}/sources/new` };
    const countMid = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).length;
    const s3 = await fetch(`${SERVE}/magritte-coordinator/api/source-store/source/v3`, { method: "POST", headers: H, body: JSON.stringify({ description: { name: "Should not exist", description: "", apiName: null }, config: { source: { type: "s3-direct", config: { url: "s3://x/" } } } }) }).then(async (r) => ({ status: r.status, pass: r.headers.get("x-ioi-mirror-passthrough"), j: await r.json().catch(() => ({})) }));
    const exp = await fetch(`${SERVE}/magritte-coordinator/api/export-store/exports`, { method: "POST", headers: H, body: "{}" }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
    const countAfter = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).length;
    ok("a type other than REST API is refused by name at create, and any other Data Connection write is a named gap — neither writes anything, and neither is the recorded tenant's answer",
      s3.status === 400 && s3.j.errorName === "Hypervisor:DataConnectionTypeNotCreatable" && !s3.pass && exp.status === 501 && exp.j.errorName === "Hypervisor:DataConnectionReadNotBound" && countAfter === countMid,
      `S3 ${s3.status} ${s3.j.errorName} · other write ${exp.status} ${exp.j.errorName} · data sources ${countMid} → ${countAfter}`);

    // ---- degraded: the daemon stopped ---------------------------------------------------------------------------------
    daemon.kill("SIGTERM");
    for (let i = 0; i < 30 && daemon.exitCode === null && daemon.signalCode === null; i++) await sleep(200);
    const down = await visit(`${BASE}/sources`, /Orders API|No sources|could not|Failed|error/iu);
    ok("with the daemon stopped, the Sources list shows its error — never \"No sources\"",
      !/Orders API/u.test(down) && !/No sources Either no sources exist/u.test(down) && /error|failed|could not|unable/iu.test(after(down, "Sources Name", 300)),
      after(down, "Sources Name", 160));
    const syncsDown = await visit(`${BASE}/syncs`, /Plants import|No syncs|Could not load syncs/u);
    ok("with the daemon stopped, the Syncs list shows its error — never \"No syncs\"",
      !/Plants import/u.test(syncsDown) && !/No syncs Please create/u.test(syncsDown) && /Syncs Could not load syncs/u.test(syncsDown),
      after(syncsDown, "Syncs Could", 80));
  } finally {
    await browser.close();
  }
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
  emitVerifierCensus({ verifierId: "adopted-data-connection", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => { console.error(e); cleanup(); process.exit(1); });
