#!/usr/bin/env node
// THE ADOPTED DATA CONNECTION IS THE CALLER'S DATA SOURCES, AND NOTHING RECORDED (R-241, Data Connection D1–D8).
//
// The reference Data Connection (booted by the local mirror, routed at /workspace/data-ingestion-app) answers from the
// Hypervisor's data-source plane (adopted-data-connection.mjs), in a real browser against an ISOLATED daemon + serve:
//   - the Sources list is the caller's declared data sources, each under its connection type, its syncs counted;
//   - Agents and Listeners say none — no agent or listener exists;
//   - Syncs (cut D4) over the import ladder built on the S3 bucket: a sync is its capability-lease plan (the Syncs list,
//     its filters, the bucket's Batch syncs table, the sync's Overview, Configuration and Versions); its runs are the
//     plan's materializing runs (Never ran, then Waiting when one is admitted, Canceled once cancelled); Run needs a
//     wallet-authority grant and is refused by name, as is Delete;
//   - a source's own pages: its Overview, Code imports and Webhooks (off, and nothing turns them on); its Virtual tables
//     (none, and none can be) and Explore source (nothing browses a source), each saying why in words made true here
//     (cut D5 — the reference's advice to contact a representative, switch runtime or configure a catalog is gone); its
//     Logs, which are the receipts of its syncs' runs (a refused execute shows as an ERROR, with the daemon's reason);
//   - Duplicate sync opens over the original's plan (cut D5); a sync's writes are driven as a person does them (cut D6 —
//     the reference's checkpoint prompt chunks are in the mirror now): Save after a real edit of the configuration
//     re-declares the plan (the daemon's revision), Duplicate's Create sync and New from a source's Batch syncs (the
//     reference's own YAML editor, the plan's ladder written into it) each declare a plan, landing on the new sync; the
//     checkpoint read before each is the daemon's justification-checkpoint plane (none can apply: its catalog gates no
//     lease-plan write); a new sync's output folder is its source's project folder, else the owner's organization folder
//     — answered, never created — and its dataset's build policy (always) and branch (master) are what is already true;
//     New on a bucket (the reference's file-sync form) is refused by name, and nothing is declared;
//   - a source's Edit syncs (cut D7), opened from its Overview's sync count: its lease plans, each configured in the
//     reference's own panel (Save re-declares the plan), Bulk edit and Run N syncs — what a plan cannot hold (another
//     transaction type, a build policy but Always, a maximum duration, a run) refused by name; and a source sits in the
//     folder it is filed in (its project's, else the owner's organization folder) on its Overview and output-folder page;
//   - "On a schedule" (cut D8): the reference's schedule editor renders, each cron expression it composes checked by the
//     daemon's own cron parser; a save on a schedule — in Edit syncs, on a sync's Configuration, after Duplicate's Create
//     sync — is refused by name (no schedule runs a sync: each run takes its own wallet-authority grant), nothing written;
//     a REST source's Edit syncs, reached by URL, lists its lease plans and its New (Create webhook) says truly why it is off;
//   - New source (cut D3), driven as a person does it: pick REST API, name it, file it in a project, create — a draft
//     data source — give it its domain (the draft becomes declared, with that endpoint), and walk the remaining steps;
//   - an existing REST source's connection settings: its declarer's new domain becomes its endpoint, path kept;
//   - no read reaches the mirror but the reference's chrome, no service read gets the serve's HTML page; a type other
//     than REST API is refused by name at create, and any other write is a named gap that writes nothing;
//   - with the daemon stopped, the Sources list, the Syncs list and a source's Edit syncs show their error rather than
//     none, and the checkpoint read fails rather than answering none.
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
// (a sync's dataset rid is named from its plan's id — the daemon's plan ids are what the Run N syncs selection is checked against)
import { syncDatasetRidOf } from "./adopted-data-connection.mjs";

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

    // (waited for until both rows' sync counts have loaded — they load after the names)
    const sources = await visit(`${BASE}/sources`, /(?=[\s\S]*Orders API REST API .{0,30}?\b\d+ syncs?\b)(?=[\s\S]*Plants bucket S3 .{0,30}?\b\d+ syncs?\b)|No sources|could not|Failed/u);
    const table = after(sources, "Sources Name Connection type", 260);
    ok("the Sources list is the caller's declared data sources, each under its connection type, with its syncs counted from its lease plans",
      /Orders API REST API .{0,30}\b0 syncs/u.test(table) && /Plants bucket S3 .{0,30}\b1 sync(?!s)/u.test(table) && !/No sources/u.test(sources), table);
    // a source's own page, opened from the list the way a person opens it (cut D2)
    await pg.getByText("Orders API", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    // (waited for until the page's sections have loaded — the header renders first)
    let restPage = ""; for (let i = 0; i < 25 && !/Orders API \(REST API\)[\s\S]*Explore source capabilities|An error occurred/u.test(restPage); i++) { await pg.waitForTimeout(800); restPage = await text(); }
    const restUrl = new URL(pg.url()).pathname;
    await visit(`${BASE}/sources`, /Plants bucket/u);
    await pg.getByText("Plants bucket", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let s3Page = ""; for (let i = 0; i < 25 && !/Plants bucket \(S3\)|An error occurred/u.test(s3Page); i++) { await pg.waitForTimeout(800); s3Page = await text(); }
    const s3Base = new URL(pg.url()).pathname.replace(/\/overview$/u, "");
    ok("a source opens from the list on its own page over daemon truth: its name, its connection type and what it can do, with nothing it cannot",
      /\/sources\/ri\.magritte\.\.source\.[0-9a-f-]{36}\/overview$/u.test(restUrl) && /Orders API \(REST API\)/u.test(restPage) && /Explore source capabilities/u.test(restPage)
        && /Plants bucket \(S3\)/u.test(s3Page) && !/An error occurred/u.test(restPage + s3Page),
      `${restUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(restPage, "Orders API (", 20)} · ${after(s3Page, "Plants bucket (", 20)}`);
    // the bucket's Overview lists its syncs (cut D4): its lease plan, the plan's output dataset, Never ran and Manual
    for (let i = 0; i < 25 && !/Plants import \(Plants import objects\) .{0,60}?Manual|Failed to load batch syncs/u.test(s3Page); i++) { await pg.waitForTimeout(700); s3Page = await text(); }
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
    ok("a source's Webhooks callout says why there are none — the Hypervisor has no webhook plane and no other runtime — never the reference's advice to contact a representative or switch runtime",
      /Webhooks are not supported here: the Hypervisor has no webhook plane/u.test(hooks) && !/representative|switch to a different runtime|when connecting via direct connection/u.test(hooks),
      after(hooks, "Webhooks are not", 180));
    // (cut D5) the bucket's Virtual tables and Explore source: nothing is registered, queried in place or browsed here
    const vt = await visit(`${s3Base}/virtual-tables`, /No virtual tables found on this source|Failed loading|An error occurred/u);
    const vtControls = (await controlsOf()).filter((c) => /^(Create virtual table|Enable)$/u.test(c.label));
    ok("a source's Virtual tables are none — none is registered and none can be — and the page says why in words that are true here (nothing queries a source in place, no table catalog exists)",
      /No virtual tables found on this source/u.test(vt) && /Virtual tables are not supported here: the Hypervisor never queries a source in place/u.test(vt) && /no table catalog exists for a source here/u.test(vt)
        && !/Go to Connection settings to enable these|No catalog is configured in Connection settings|Failed loading|An error occurred/u.test(vt) && vtControls.length >= 3 && vtControls.every((c) => c.off),
      `${after(vt, "Virtual tables are", 100)} · ${vtControls.map((c) => `${c.label}${c.off ? "" : "(LIVE)"}`).join(", ")}`);
    const explore = await visit(`${s3Base}/explore`, /Source exploration is unavailable|An error occurred/u);
    ok("a source's Explore source says nothing browses it — the Hypervisor reads a source only in a sync run — never that this instance lacks a worker",
      /Source exploration is unavailable\. The Hypervisor never browses a source: it reads one only in a sync run/u.test(explore) && !/This instance of|Foundry Worker|An error occurred/u.test(explore),
      after(explore, "Source exploration", 190));
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
    // (waited for until its dataset and source have loaded, not only its build details)
    let overview = ""; for (let i = 0; i < 25 && !/Output dataset (?!Loading)[\s\S]*Source (?!Loading)[\s\S]*Build details .{0,40}Next run|An error occurred/u.test(overview); i++) { await pg.waitForTimeout(800); overview = await text(); }
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
    // (cut D5) Duplicate sync, from the sync's Configuration as a person opens it: the new sync starts as the plan's exact
    // duplicate — its configuration naming the plan's ladder and lease shape — and naming it enables Create sync
    await visit(`${syncBase}/configuration`, /Duplicate sync/u);
    await pg.getByText("Duplicate sync", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let dup = ""; for (let i = 0; i < 25 && !/exact duplicate of Plants import[\s\S]*leaseTtlSeconds|An error occurred/u.test(dup); i++) { await pg.waitForTimeout(800); dup = await text(); }
    const dupUrl = new URL(pg.url()).pathname;
    const createSync = pg.getByRole("button", { name: /^Create sync$/u }).first();
    await pg.locator("input[placeholder='Dataset name']").first().fill("Plants copy").catch(() => {});
    let named = "", createAfter = false;
    for (let i = 0; i < 15 && !(createAfter && /Plants copy Syncing data from Plants bucket/u.test(named)); i++) { await pg.waitForTimeout(500); named = await text(); createAfter = await createSync.isEnabled().catch(() => false); }
    ok("Duplicate sync opens over the original's plan: the new sync starts as its exact duplicate, its configuration naming the plan's ladder and lease shape, its dataset in the owner's folder — and naming it names the new sync, with Create sync offered",
      /\/extracts\/duplicate\/ri\.magritte\.\.extract\.[0-9a-f-]{36}$/u.test(dupUrl) && /This sync is an exact duplicate of Plants import/u.test(dup) && dup.includes(`connectorMapping: ${mappingId}`) && dup.includes(`transformationRun: ${transformId}`)
        && /subject: agent:\/\/materializer/u.test(dup) && /Syncing data from Plants bucket/u.test(dup) && /Plants copy Syncing data from Plants bucket/u.test(named) && createAfter === true && !/An error occurred/u.test(dup + named),
      `${dupUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(dup, "This sync is", 60)} · ${dup.includes(`connectorMapping: ${mappingId}`) ? "ladder named" : "LADDER ABSENT"} · ${after(named, "Plants copy", 50)} · Create sync ${createAfter ? "offered" : "NOT OFFERED"}`);
    // a run is the plan's materializing run: admitted, it waits for its lease; cancelled (no grant needed), it is Canceled
    const admitted = await d("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "plants-run-1" });
    // (and an execute of it, which the daemon refuses: the run holds no lease — a receipt the source's Logs show)
    const refusedExecute = await d("POST", `/v1/hypervisor/odk/materializing-runs/${admitted.j.materializing_run?.id}/execute`, {});
    const waiting = after(await visit(`${BASE}/syncs`, /Plants import objects \/\S+ Plants bucket Waiting/u), "Next run Actions", 140);
    const banner = await visit(`${syncBase}/configuration`, /waiting to run|An error occurred/u);
    const cancelled = await d("POST", `/v1/hypervisor/odk/materializing-runs/${admitted.j.materializing_run?.id}/cancel`);
    const canceled = after(await visit(`${BASE}/syncs`, /Plants import objects \/\S+ Plants bucket Canceled/u), "Next run Actions", 140);
    ok("a sync's run is its plan's materializing run, over daemon truth: an admitted run shows Waiting (for its lease) with the running banner, and once cancelled the sync shows Canceled",
      admitted.status === 201 && /Plants bucket Waiting/u.test(waiting) && /This dataset is waiting to run/u.test(banner) && cancelled.j.materializing_run?.status === "cancelled" && /Plants bucket Canceled/u.test(canceled),
      `run ${admitted.status} ${admitted.j.materializing_run?.status} · ${waiting.slice(0, 110)} · banner ${/waiting to run/u.test(banner) ? "shown" : "ABSENT"} · cancel ${cancelled.j.materializing_run?.status} · ${canceled.slice(0, 110)}`);
    // (cut D5) the bucket's Logs: its syncs' run receipts in the reference's own log viewer — by default (INFO hidden) the
    // refused execute, with the daemon's reason and outcome; with the level filter cleared, the admission and the cancel too
    const receipts = (await d("GET", `/v1/hypervisor/odk/materializing-runs/${admitted.j.materializing_run?.id}/history`)).j.receipts || [];
    const refusalReceipt = receipts.find((r) => r.op === "execution_refused");
    const logs = await visit(`${s3Base}/logs`, /execution requires a HELD lease|No logs|Failed to load logs|Unable to load/u);
    await pg.getByRole("button", { name: "Clear all", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let allLogs = ""; for (let i = 0; i < 15 && !/MaterializingRun admitted/u.test(allLogs); i++) { await pg.waitForTimeout(700); allLogs = await text(); }
    ok("a source's Logs are its syncs' run receipts: the daemon's refusal of an execute shows as an ERROR with its reason and outcome (INFO hidden by default), and with the level filter cleared the admission and the cancel show too",
      refusedExecute.status === 400 && refusedExecute.j.error?.code === "execution_lease_not_obtained" && !!refusalReceipt
        && logs.includes(`ERROR`) && logs.includes(String(refusalReceipt?.summary)) && /"outcome": "execution_lease_not_obtained"/u.test(logs) && /"sync": "Plants import"/u.test(logs) && !/MaterializingRun admitted/u.test(logs)
        && /MaterializingRun admitted/u.test(allLogs) && /cancel/iu.test(after(allLogs, "level time message", 2000)) && !/Failed to load logs|Unable to load/u.test(logs + allLogs),
      `execute ${refusedExecute.status} ${refusedExecute.j.error?.code} · ${after(logs, "ERROR", 120)} · cleared: ${/MaterializingRun admitted/u.test(allLogs) ? "admission shown" : "admission ABSENT"}`);
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

    // ---- (cut D6) a sync's writes, driven as a person does them. The reference first asks which checkpoints apply (its
    // prompt's chunks are in the mirror now), then writes; every answer on the way is captured here.
    const writes = [];
    const WRITE_ROUTE = /getConfigsV5|\/build\/add-extract|\/extract-store\/extract\/ri\.|\/set-policies|\/branchesUnrestricted2\/|\/createDataset2|\/hierarchy\/projects\/decorated/u;
    const onWrite = async (r) => {
      const u = new URL(r.url()); const req = r.request().postData() || "";
      if (WRITE_ROUTE.test(u.pathname) || (/graphql/u.test(u.pathname) && /GetOrCreateSourceOutputFolder/u.test(req))) writes.push({ p: u.pathname, m: r.request().method(), s: r.status(), req, body: await r.text().catch(() => "") });
    };
    pg.on("response", onWrite);
    const fencedBefore = fenced.size, pageErrorsBefore = pageErrors.length, gqlBefore = gqlErrors.size;
    const jsonOf = (s) => { try { return JSON.parse(s); } catch { return null; } };
    const plans = async () => (await d("GET", "/v1/hypervisor/odk/capability-lease-plans")).j.capability_lease_plans || [];
    const folderAnswered = (sourceRid) => (writes.filter((w) => /graphql/u.test(w.p) && w.req.includes(sourceRid)).map((w) => /"outputFolder":\{"rid":"([^"]+)"/u.exec(w.body)?.[1]).filter(Boolean)).at(-1) || null;
    const s3Rid = s3Base.split("/").pop();

    // Save, after a real edit of the configuration: the plan's lease TTL, 900 → 600, typed into the reference's editor
    await visit(`${syncBase}/configuration`, /leaseTtlSeconds: 900/u);
    await pg.locator("pre.CodeMirror-line").filter({ hasText: /leaseTtlSeconds: 900/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.keyboard.press("End");
    for (let i = 0; i < 3; i++) await pg.keyboard.press("Backspace");
    await pg.keyboard.type("600");
    const saveBtn = pg.getByRole("button", { name: /^Save$/u }).first();
    let saveOffered = false; for (let i = 0; i < 12 && !saveOffered; i++) { await pg.waitForTimeout(400); saveOffered = await saveBtn.isVisible().catch(() => false); }
    await saveBtn.click({ timeout: 8000 }).catch(() => {});
    let savedPage = ""; for (let i = 0; i < 20 && !/Sync saved/u.test(savedPage); i++) { await pg.waitForTimeout(600); savedPage = await text(); }
    const planSaved = (await d("GET", `/v1/hypervisor/odk/capability-lease-plans/${planId}`)).j.capability_lease_plan || {};
    const editGate = writes.find((w) => /getConfigsV5/u.test(w.p) && /DATA_CONNECTION_SYNC_EDIT/u.test(w.req));
    const put = writes.find((w) => w.m === "PUT" && /\/extract-store\/extract\//u.test(w.p));
    ok("a sync's Save, pressed after a real edit of its configuration, re-declares its plan: the checkpoint read keyed on its source answers none, the PUT carries the whole configuration, and the daemon's plan is revision 2 with the new lease TTL, receipted — the page says Sync saved",
      saveOffered && editGate?.s === 200 && jsonOf(editGate.body)?.checkpointConfigs?.length === 0 && editGate.req.includes(s3Rid) && put?.s === 200 && jsonOf(put.req)?.extractConfig?.sourceAdapter?.leaseTtlSeconds === 600
        && planSaved.revision === 2 && planSaved.ttl_seconds === 600 && (planSaved.history || []).at(-1)?.op === "patched" && !!(planSaved.history || []).at(-1)?.receipt_ref && /Sync saved/u.test(savedPage),
      `Save ${saveOffered ? "offered" : "NOT OFFERED"} · checkpoint read ${editGate ? `${editGate.s} ${editGate.body.slice(0, 40)}` : "NOT SENT"} · PUT ${put?.s ?? "NOT SENT"} · plan r${planSaved.revision} ttl ${planSaved.ttl_seconds} ${(planSaved.history || []).at(-1)?.op} · ${/Sync saved/u.test(savedPage) ? "Sync saved" : "NO TOAST"}`);

    // the checkpoint read is the daemon's plane: its catalog names no lease-plan write, and it refuses to configure one
    const checkpointPlane = (await d("GET", "/v1/hypervisor/justification-checkpoints")).j;
    const offCatalog = await d("POST", "/v1/hypervisor/justification-checkpoints", { owner_ref: owner, idempotency_key: "adopted-dc-sync-edit-checkpoint", display_name: "Sync edits need a reason",
      interaction_kinds: ["capability_lease_plan.patch"], prompt: { title: "Why change this sync?", body: "Say why." }, justification: { kind: "response" } });
    ok("the checkpoint read before a sync's writes is the daemon's justification-checkpoint plane: its catalog gates no lease-plan write and the daemon refuses to configure a checkpoint for one, so none can apply — and the page's read says so (never the recorded tenant's configurations)",
      Array.isArray(checkpointPlane.catalog) && checkpointPlane.catalog.length > 0 && !checkpointPlane.catalog.some((k) => /capability_lease_plan/u.test(k))
        && offCatalog.status === 400 && offCatalog.j.error?.code === "justification_checkpoint_interaction_invalid"
        && jsonOf(editGate?.body)?.classificationInferabilityStatus?.uninferableClassifcation === "CBAC_NOT_ENABLED",
      `catalog ${JSON.stringify(checkpointPlane.catalog)} · configure for a sync edit ${offCatalog.status} ${offCatalog.j.error?.code}`);

    // Duplicate sync → Create sync: a new plan on the original's ladder, its dataset in the bucket's output folder (the
    // owner's organization folder: the bucket is filed in no project)
    await visit(`${syncBase}/configuration`, /Duplicate sync/u);
    await pg.getByText("Duplicate sync", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let dupForm = ""; for (let i = 0; i < 25 && !/exact duplicate of Plants import[\s\S]*leaseTtlSeconds: 600/u.test(dupForm); i++) { await pg.waitForTimeout(800); dupForm = await text(); }
    await pg.locator("input[placeholder='Dataset name']").first().fill("Plants copy").catch(() => {});
    await pg.waitForTimeout(1200);
    const dupDestination = after(await text(), "Confirm destination for output dataset", 90);
    await pg.getByRole("button", { name: /^Create sync$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let dupLanded = ""; for (let i = 0; i < 25 && !/Sync created/u.test(dupLanded); i++) { await pg.waitForTimeout(700); dupLanded = await text(); }
    const dupUrlNow = new URL(pg.url()).pathname;
    const copy = (await plans()).find((x) => x.name === "Plants copy");
    const dupFolder = folderAnswered(s3Rid);
    const dupCreate = writes.find((w) => /createDataset2/u.test(w.p) && /Plants copy/u.test(w.req));
    const createGate = writes.find((w) => /getConfigsV5/u.test(w.p) && /DATA_CONNECTION_SYNC_CREATE/u.test(w.req) && w.req.includes(s3Rid));
    const dupAdd = writes.find((w) => /add-extract/u.test(w.p) && /Plants copy/u.test(w.req));
    const dupPolicy = writes.find((w) => /set-policies/u.test(w.p) && w.req.includes(String(jsonOf(dupCreate?.body)?.rid)));
    const dupBranch = writes.find((w) => /branchesUnrestricted2/u.test(w.p) && w.p.includes(String(jsonOf(dupCreate?.body)?.rid)));
    ok("Duplicate sync's Create sync declares a new plan on the original's ladder and lands on the new sync: its output folder is the bucket's (the owner's organization folder — answered, nothing created), the checkpoint read answers none, and the dataset's build policy (always) and branch (master) are what is already true",
      copy?.status === "declared" && copy?.data_source_id === plantsId && copy?.connector_mapping_id === mappingId && copy?.ttl_seconds === 600 && dupUrlNow === `${BASE}/syncs/${String(jsonOf(dupAdd?.body))}/overview` && /Sync created/u.test(dupLanded)
        && !!dupFolder && jsonOf(dupCreate?.req)?.requestWithName?.parentRid === dupFolder && /master Error local/u.test(dupDestination)
        && createGate?.s === 200 && jsonOf(createGate.body)?.checkpointConfigs?.length === 0 && dupAdd?.s === 200 && dupPolicy?.s === 204 && dupBranch?.s === 200 && jsonOf(dupBranch.body)?.id === "master",
      `plan ${copy ? `${copy.status} on ${copy.connector_mapping_id} ttl ${copy.ttl_seconds}` : "NONE"} · ${dupUrlNow.replace(/ri\.[\w.-]+/u, "<rid>")} · destination "${dupDestination.slice(39)}" · checkpoint ${createGate?.s} · add-extract ${dupAdd?.s} · policy ${dupPolicy?.s} · branch ${dupBranch?.s}`);

    // New, from a source's Batch syncs: a feed filed in the project, with its own import ladder and no sync. The reference
    // opens its YAML editor for a custom source; the plan's ladder is written into it, the dataset named, Create sync pressed.
    const meter = await d("POST", "/v1/hypervisor/data-sources", { name: "Meter feed", kind: "http_feed", endpoint: "https://feed.example.test/meters", credential_posture: "wallet_credential_lease", project_ref: project.project_ref });
    const meterId = meter.j.data_source?.source_id;
    const meterOntology = await d("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "meters", canonical_object_model: { object_types: [{ id: "meter", name: "Meter", title_property: "title",
      properties: [{ id: "meter_id", name: "Meter Id", value_type: "string", required: true }, { id: "title", name: "Title", value_type: "string" }] }], action_types: [] } });
    const meterMapping = (await d("POST", "/v1/hypervisor/odk/connector-mappings", { owner_ref: owner, idempotency_key: "adopted-dc-meters-mapping", name: "meters-map", data_source_id: meterId, ontology_ref: meterOntology.j.ontology?.ref,
      object_type_id: "meter", key_mapping: { source_field: "id", property_id: "meter_id", source_type: "string" }, title_mapping: { source_field: "name", property_id: "title", source_type: "string" } })).j.connector_mapping?.id;
    const meterGate = (await d("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: meterMapping, name: "meters-gate", authority_subjects: ["agent://materializer"], allowed_operations: ["read", "transform"],
      purpose: "meter catalog", property_scope: ["meter_id", "title"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
    const meterTransform = (await d("POST", "/v1/hypervisor/odk/transformation-runs", { owner_ref: owner, idempotency_key: "adopted-dc-meters-transform", connector_mapping_id: meterMapping, policy_view_id: meterGate, name: "meters-transform" })).j.transformation_run?.id;
    await d("POST", `/v1/hypervisor/odk/transformation-runs/${meterTransform}/dry-run`);
    const meterProjection = (await d("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: meterMapping, policy_view_id: meterGate, name: "meters-explorer", visible_properties: ["meter_id", "title"] })).j.ontology_projection?.id;
    await visit(`${BASE}/sources`, /Meter feed/u);
    await pg.getByText("Meter feed", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let meterPage = ""; for (let i = 0; i < 25 && !/Batch syncs/u.test(meterPage); i++) { await pg.waitForTimeout(700); meterPage = await text(); }
    const meterRid = new URL(pg.url()).pathname.split("/").at(-2);
    await pg.getByRole("button", { name: /^New$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let newForm = ""; for (let i = 0; i < 25 && !/type: custom/u.test(newForm); i++) { await pg.waitForTimeout(700); newForm = await text(); }
    const newUrl = new URL(pg.url()).pathname;
    await pg.locator("pre.CodeMirror-line").first().click({ timeout: 8000 }).catch(() => {});
    await pg.keyboard.press("Control+A");
    await pg.keyboard.type(`type: capability-lease-plan\nconnectorMapping: ${meterMapping}\npolicyView: ${meterGate}\ntransformationRun: ${meterTransform}\nontologyProjection: ${meterProjection}\nsubject: agent://materializer\nleaseTtlSeconds: 900\n`);
    await pg.locator("input[placeholder='Dataset name']").first().fill("Meter readings").catch(() => {});
    await pg.waitForTimeout(1500);
    const newDestination = after(await text(), "Confirm destination for output dataset", 80);
    await pg.getByRole("button", { name: /^Create sync$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let newLanded = ""; for (let i = 0; i < 25 && !/Sync created/u.test(newLanded); i++) { await pg.waitForTimeout(700); newLanded = await text(); }
    const readings = (await plans()).find((x) => x.name === "Meter readings");
    const newAdd = writes.find((w) => /add-extract/u.test(w.p) && /Meter readings/u.test(w.req));
    const newCreate = writes.find((w) => /createDataset2/u.test(w.p) && /Meter readings/u.test(w.req));
    const meterFolder = folderAnswered(meterRid);
    const meterRow = after(await visit(`${BASE}/syncs`, /Meter readings objects \/\S+ Meter feed/u), "Meter readings Meter readings objects", 80);
    ok("New, from a feed's Batch syncs, opens the reference's editor for a custom source; the plan's ladder written into it and Create sync pressed declare the plan on the feed and land on it — its output folder is the project the feed is filed in (the destination names it; nothing created), and the new sync's dataset sits there",
      meter.status === 201 && /\/sources\/ri\.magritte\.\.source\.[0-9a-f-]{36}\/extracts\/new$/u.test(newUrl) && /type: custom/u.test(newForm)
        && readings?.status === "declared" && readings?.data_source_id === meterId && readings?.connector_mapping_id === meterMapping && readings?.ontology_projection_id === meterProjection && newAdd?.s === 200 && /Sync created/u.test(newLanded)
        && !!meterFolder && meterFolder !== dupFolder && jsonOf(newCreate?.req)?.requestWithName?.parentRid === meterFolder && /master payments New/u.test(newDestination) && /^Meter readings Meter readings objects \/payments Meter feed/u.test(meterRow),
      `${newUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · editor ${/type: custom/u.test(newForm) ? "custom" : "ABSENT"} · plan ${readings ? `${readings.status} on ${readings.connector_mapping_id}` : "NONE"} · destination "${newDestination.slice(39)}" · row ${meterRow}`);

    // New on the bucket: the reference's file-sync form — a sync of a bucket's files — refused by name, nothing declared
    const plansBeforeFiles = (await plans()).length;
    await visit(`${s3Base}/overview`, /Create batch sync/u);
    await pg.getByRole("button", { name: /^Create batch sync$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let filesForm = ""; for (let i = 0; i < 25 && !/Subfolder/u.test(filesForm); i++) { await pg.waitForTimeout(700); filesForm = await text(); }
    await pg.locator("input[placeholder='Dataset name']").first().fill("Plants files").catch(() => {});
    await pg.waitForTimeout(1000);
    await pg.getByRole("button", { name: /^Create sync$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let filesToast = ""; for (let i = 0; i < 15 && !/A sync here is a capability-lease plan/u.test(filesToast); i++) { await pg.waitForTimeout(600); filesToast = await text(); }
    const filesAdd = writes.find((w) => /add-extract/u.test(w.p) && /Plants files/u.test(w.req));
    ok("New on a bucket opens the reference's file-sync form, and its Create sync is refused by name — a sync here is a lease plan, and the Hypervisor never lists or copies a source's files — with nothing declared",
      /Subfolder/u.test(filesForm) && filesAdd?.s === 409 && jsonOf(filesAdd.body)?.errorName === "Hypervisor:DataConnectionSyncAdapterFixed" && /never lists or copies a source's files/u.test(filesToast)
        && (await plans()).length === plansBeforeFiles && /\/extracts\/new$/u.test(new URL(pg.url()).pathname),
      `form ${/Subfolder/u.test(filesForm) ? "file sync" : "ABSENT"} · add-extract ${filesAdd?.s} ${jsonOf(filesAdd?.body)?.errorName} · plans ${plansBeforeFiles} → ${(await plans()).length}`);
    pg.off("response", onWrite);

    // what a plan cannot hold, sent with the page's own bodies: the daemon's refusal carries its own code
    const SH = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}${syncBase}/configuration` };
    const serveJ = (method, p, body) => fetch(`${SERVE}${p}`, { method, headers: SH, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => null) }));
    const syncRid = syncBase.split("/").pop();
    const stored = (await serveJ("POST", "/magritte-coordinator/api/extract-store/extracts/bulk", [syncRid])).j?.[syncRid] || {};
    const withAdapter = (a, extra = {}) => ({ ...stored, ...extra, extractConfig: { ...stored.extractConfig, sourceAdapter: { ...stored.extractConfig?.sourceAdapter, ...a } } });
    const wrongPurpose = await serveJ("PUT", `/magritte-coordinator/api/extract-store/extract/${syncRid}`, withAdapter({ purpose: "anything else" }));
    const planKept = (await d("GET", `/v1/hypervisor/odk/capability-lease-plans/${planId}`)).j.capability_lease_plan || {};
    const noLadder = await serveJ("POST", "/magritte-coordinator/api/build/add-extract?branchName=master", withAdapter({ connectorMapping: null }, { extractName: "Plants orphan", datasetId: undefined }));
    const intoExisting = await serveJ("POST", "/magritte-coordinator/api/build/add-extract?branchName=master", { ...stored, extractName: "Plants twin" });
    const otherBranch = await serveJ("POST", `/foundry-catalog/api/catalog/datasets/${stored.datasetId}/branchesUnrestricted2/develop`, {});
    const plansNow = await plans();
    ok("what a plan cannot hold is refused by name and changes nothing: a purpose its policy view does not grant (the daemon's own refusal), a new sync naming no ladder, one syncing into an existing dataset, and another branch",
      wrongPurpose.status === 409 && wrongPurpose.j?.errorName === "Hypervisor:lease_plan_purpose_mismatch" && planKept.revision === 2 && planKept.purpose === "plant catalog"
        && noLadder.status === 409 && noLadder.j?.errorName === "Hypervisor:DataConnectionSyncLadderRequired" && intoExisting.status === 409 && intoExisting.j?.errorName === "Hypervisor:DataConnectionSyncDatasetNotBound"
        && otherBranch.status === 409 && otherBranch.j?.errorName === "Hypervisor:DataConnectionBranchNotBound" && !plansNow.some((x) => ["Plants orphan", "Plants twin"].includes(x.name)),
      `purpose ${wrongPurpose.status} ${wrongPurpose.j?.errorName} (plan r${planKept.revision}) · no ladder ${noLadder.status} ${noLadder.j?.errorName} · existing dataset ${intoExisting.status} ${intoExisting.j?.errorName} · branch ${otherBranch.status} ${otherBranch.j?.errorName}`);
    ok("no write flow met a fenced read, a page error or an unbound GraphQL operation",
      fenced.size === fencedBefore && pageErrors.length === pageErrorsBefore && gqlErrors.size === gqlBefore && unnamed.size === 0 && htmlAnswers.size === 0,
      `fenced ${[...fenced].slice(fencedBefore).join(",") || "none"} · page ${pageErrors.slice(pageErrorsBefore, pageErrorsBefore + 1).join("") || "none"} · gql ${[...gqlErrors].slice(gqlBefore, gqlBefore + 2).join(" | ") || "none"}`);

    // ---- (cut D7) a source's Edit syncs, reached from its Overview's sync count: its syncs are its lease plans, each
    // configured in the reference's own panel and saved through the plan's PATCH; what a plan cannot hold is refused by
    // name. And a source sits in the folder it is filed in — its project's, else the owner's organization folder — on its
    // own pages as its syncs' datasets do.
    const d7 = [];
    const D7_ROUTE = /getConfigsV5|\/extract-store\/extract\/ri\.|\/set-policies|\/submitBuild|\/build\/trigger\/|\/scheduler\/api\/(?!scheduler\/get-)/u;
    const onD7 = async (r) => { const u = new URL(r.url()); if (D7_ROUTE.test(u.pathname) && r.request().method() !== "GET") d7.push({ p: u.pathname, m: r.request().method(), s: r.status(), req: r.request().postData() || "", body: await r.text().catch(() => "") }); };
    pg.on("response", onD7);
    const fencedBeforeD7 = fenced.size, pageErrorsBeforeD7 = pageErrors.length, gqlBeforeD7 = gqlErrors.size;
    const planOf = async (id) => (await d("GET", `/v1/hypervisor/odk/capability-lease-plans/${id}`)).j.capability_lease_plan || {};
    const bucketPlans = async () => (await plans()).filter((x) => x.data_source_id === plantsId && x.status !== "revoked").sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
    const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const saveButton = () => pg.locator("a,button").filter({ hasText: /^Save$/u }).first();
    const toastOf = (t, re) => (t.match(new RegExp(`.{0,40}${re.source}.{0,120}`, "u")) || [""])[0];

    // the bucket's Overview names where it is filed, and its sync count opens Edit syncs
    const s3Overview = await visit(`${s3Base}/overview`, /Parent folder local \/[\s\S]*Output folder \(local\)|An error occurred/u);
    const bucketNow = await bucketPlans();
    await pg.getByText(/^\d+ syncs?$/u).first().click({ timeout: 8000 }).catch(() => {});
    const SYNC_LIST = new RegExp(`Syncs\\s*\\(${bucketNow.length}\\) ${bucketNow.map((p) => `\\(${esc(p.name)} objects\\) \\/local`).join(" ")} `, "u");
    let editSyncs = ""; for (let i = 0; i < 25 && !SYNC_LIST.test(editSyncs) && !/Failed to load syncs|An error occurred/u.test(editSyncs); i++) { await pg.waitForTimeout(800); editSyncs = await text(); }
    const editUrl = new URL(pg.url()).pathname;
    ok("Edit syncs, opened from a source's Overview sync count, lists the source's lease plans newest first, each its plan's dataset in the source's folder (the owner's organization folder: the bucket is filed in no project) — and the Overview's Parent folder and Output folder name that folder",
      editUrl === `${s3Base}/edit-syncs` && bucketNow.length === 2 && SYNC_LIST.test(editSyncs) && !/Failed to load syncs|An error occurred/u.test(editSyncs)
        && /Batch syncs 2 syncs/u.test(s3Overview) && /Parent folder local \//u.test(s3Overview) && /Output folder \(local\)/u.test(s3Overview),
      `${editUrl.replace(/ri\.[\w.-]+/u, "<rid>")} · daemon ${bucketNow.map((p) => p.name).join(", ")} · ${after(editSyncs, "Syncs(", 90)} · ${after(s3Overview, "Parent folder", 22)} · ${after(s3Overview, "Output folder", 24)}`);

    // a sync's panel is its plan: schedule Manually (no schedule runs one), build policy Always, the plan's configuration
    const importBefore = await planOf(planId);
    await pg.getByText("(Plants import objects)", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let syncPanel = ""; for (let i = 0; i < 25 && !(/Configure Plants import[\s\S]*Build policy/u.test(syncPanel) && syncPanel.includes(`leaseTtlSeconds: ${importBefore.ttl_seconds}`)); i++) { await pg.waitForTimeout(700); syncPanel = await text(); }
    await pg.locator("pre.CodeMirror-line").filter({ hasText: new RegExp(`leaseTtlSeconds: ${importBefore.ttl_seconds}`, "u") }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.keyboard.press("End");
    for (let i = 0; i < String(importBefore.ttl_seconds).length; i++) await pg.keyboard.press("Backspace");
    await pg.keyboard.type("450");
    await pg.waitForTimeout(600);
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let panelSaved = ""; for (let i = 0; i < 20 && !/Sync saved!/u.test(panelSaved); i++) { await pg.waitForTimeout(600); panelSaved = await text(); }
    const importSaved = await planOf(planId);
    const panelGate = d7.find((w) => /getConfigsV5/u.test(w.p) && /DATA_CONNECTION_SYNC_EDIT/u.test(w.req));
    const panelPut = d7.find((w) => w.m === "PUT" && w.s === 200);
    ok("a sync's panel in Edit syncs is its plan (schedule Manually, build policy Always, the plan's lease shape), and its Save after a real edit re-declares the plan: the checkpoint read answers none, and the daemon's plan moves one revision with the new lease TTL, receipted — the page says Sync saved",
      /Run this import Manually/u.test(syncPanel) && /Build policy .{0,60}Always/u.test(syncPanel) && syncPanel.includes(`connectorMapping: ${mappingId}`) && /View sync details/u.test(syncPanel)
        && panelGate?.s === 200 && jsonOf(panelGate.body)?.checkpointConfigs?.length === 0 && jsonOf(panelPut?.req)?.extractConfig?.sourceAdapter?.leaseTtlSeconds === 450
        && importSaved.revision === importBefore.revision + 1 && importSaved.ttl_seconds === 450 && (importSaved.history || []).at(-1)?.op === "patched" && !!(importSaved.history || []).at(-1)?.receipt_ref && /Sync saved!/u.test(panelSaved),
      `panel ${/Run this import Manually/u.test(syncPanel) ? "Manually" : "NO SCHEDULE LINE"} · checkpoint ${panelGate?.s ?? "NOT SENT"} · PUT ${panelPut?.s ?? "NOT SENT"} · plan r${importBefore.revision} → r${importSaved.revision} ttl ${importSaved.ttl_seconds} · ${/Sync saved!/u.test(panelSaved) ? "Sync saved" : "NO TOAST"}`);

    // what a plan cannot hold, pressed in the panel: another transaction type, a build policy other than Always, a Run
    const runsBeforeD7 = ((await d("GET", "/v1/hypervisor/odk/materializing-runs")).j.materializing_runs || []).length;
    await pg.getByText("Append", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(500);
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let appendToast = ""; for (let i = 0; i < 15 && !/holds none of the APPEND transaction type/u.test(appendToast); i++) { await pg.waitForTimeout(600); appendToast = await text(); }
    await pg.getByText("Snapshot", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: /^Edit$/u }).last().click({ timeout: 8000 }).catch(() => {});
    const policyDialog = pg.locator(".bp5-dialog, .bp6-dialog, [role=dialog]").last();
    await policyDialog.locator("pre.CodeMirror-line").first().click({ timeout: 8000 }).catch(() => {});
    await pg.keyboard.press("Control+A");
    await pg.keyboard.type("type: never\nnever: {}\n");
    await policyDialog.getByRole("button", { name: /^Done$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(600);
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let policyToast = ""; for (let i = 0; i < 15 && !/keeps no build policy/u.test(policyToast); i++) { await pg.waitForTimeout(600); policyToast = await text(); }
    // (a compute profile, from View 3 more settings: the reference's default profile, then Save)
    await pg.getByRole("button", { name: /^View 3 more settings$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByText(/^Compute profile se/u).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(600);
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let profileToast = ""; for (let i = 0; i < 15 && !/holds none of Spark profiles/u.test(profileToast); i++) { await pg.waitForTimeout(600); profileToast = await text(); }
    await pg.locator("a,button").filter({ hasText: /^Run$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let runToastD7 = ""; for (let i = 0; i < 15 && !/wallet-authority grant/u.test(runToastD7); i++) { await pg.waitForTimeout(600); runToastD7 = await text(); }
    const importKept = await planOf(planId);
    const appendPut = d7.find((w) => w.m === "PUT" && w.s === 409);
    const policySet = d7.find((w) => /set-policies/u.test(w.p));
    const panelRun = d7.find((w) => /build\/trigger/u.test(w.p));
    const profilePut = d7.find((w) => w.m === "PUT" && (jsonOf(w.req)?.sparkProfiles || []).length);
    ok("in Edit syncs, what a plan cannot hold is refused by name and changes nothing: another transaction type (the plan's PATCH is never sent), a build policy other than Always, a compute profile, and a Run (a wallet-authority grant) — each toast says why",
      appendPut && jsonOf(appendPut.body)?.errorName === "Hypervisor:DataConnectionSyncFieldNotBound" && /holds none of the APPEND transaction type/u.test(appendToast)
        && policySet?.s === 409 && jsonOf(policySet.body)?.errorName === "Hypervisor:DataConnectionBuildPolicyNotBound" && jsonOf(policySet.req)?.[0]?.buildPolicy?.type === "never" && /keeps no build policy/u.test(policyToast)
        && profilePut?.s === 409 && jsonOf(profilePut.body)?.errorName === "Hypervisor:DataConnectionSyncFieldNotBound" && /holds none of Spark profiles/u.test(profileToast)
        && panelRun?.s === 409 && jsonOf(panelRun.body)?.errorName === "Hypervisor:DataConnectionRunNeedsApproval" && /wallet-authority grant/u.test(runToastD7)
        && importKept.revision === importSaved.revision && importKept.ttl_seconds === 450,
      `append ${appendPut?.s ?? "NOT SENT"} · policy ${policySet?.s ?? "NOT SENT"} ${jsonOf(policySet?.body)?.errorName || ""} "${toastOf(policyToast, /keeps no build policy/u).slice(0, 80)}" · profile ${profilePut?.s ?? "NOT SENT"} · run ${panelRun?.s ?? "NOT SENT"} · plan r${importKept.revision}`);

    // Bulk edit: a maximum duration is refused by name for every selected sync; the schedule Manually is what is already
    // true, so its Save writes nothing
    const revsBefore = (await bucketPlans()).map((p) => `${p.id}:${p.revision}`).join(",");
    const d7Mark = d7.length;
    await visit(editUrl, SYNC_LIST);
    await pg.locator("input[type=checkbox]").first().check({ force: true, timeout: 8000 }).catch(() => {});
    await pg.getByText(/^Bulk edit 2 syncs$/u).first().click({ timeout: 8000 }).catch(() => {});
    let bulk = ""; for (let i = 0; i < 15 && !/Bulk configure 2 syncs[\s\S]*Maximum duration/u.test(bulk); i++) { await pg.waitForTimeout(600); bulk = await text(); }
    await pg.getByRole("button", { name: /^Edit$/u }).nth(1).click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(600);
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let durationToast = ""; for (let i = 0; i < 15 && !/holds none of a maximum duration/u.test(durationToast); i++) { await pg.waitForTimeout(600); durationToast = await text(); }
    // (each selected sync's PUT is its own request: the first refusal's toast can land before the second is answered)
    for (let i = 0; i < 15 && d7.slice(d7Mark).filter((w) => w.m === "PUT").length < 2; i++) await pg.waitForTimeout(600);
    const durationPuts = d7.slice(d7Mark).filter((w) => w.m === "PUT");
    await pg.getByRole("button", { name: /^Remove$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: /^Edit$/u }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(800);
    const manualForm = await text();
    const manualMark = d7.length;
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let bulkSaved = ""; for (let i = 0; i < 15 && !/2 syncs saved!/u.test(bulkSaved); i++) { await pg.waitForTimeout(600); bulkSaved = await text(); }
    const revsAfter = (await bucketPlans()).map((p) => `${p.id}:${p.revision}`).join(",");
    ok("Bulk edit in Edit syncs: a maximum duration is refused by name for each selected sync, and the bulk schedule Manually — what is already true, no schedule runs a sync — saves without writing anything; every plan keeps its revision",
      durationPuts.length === 2 && durationPuts.every((w) => w.s === 409 && jsonOf(w.body)?.errorName === "Hypervisor:DataConnectionSyncFieldNotBound" && jsonOf(w.req)?.maxAllowedDuration) && /holds none of a maximum duration/u.test(durationToast)
        && /Bulk schedule .{0,20}Run imports Manually/u.test(manualForm) && /2 syncs saved!/u.test(bulkSaved) && d7.length === manualMark && revsAfter === revsBefore,
      `duration ${durationPuts.map((w) => `${w.s} ${jsonOf(w.body)?.errorName}`).join(" · ") || "NOT SENT"} "${toastOf(durationToast, /holds none of a maximum duration/u).slice(0, 60)}" · ${after(manualForm, "Bulk schedule", 50)} · Manually saved ${/2 syncs saved!/u.test(bulkSaved) ? "yes" : "NO"} with ${d7.length - manualMark} writes · revisions ${revsBefore === revsAfter ? "kept" : `${revsBefore} → ${revsAfter}`}`);

    // Run N syncs builds the selection's datasets: refused by name, nothing runs
    await visit(editUrl, SYNC_LIST);
    await pg.locator("input[type=checkbox]").first().check({ force: true, timeout: 8000 }).catch(() => {});
    await pg.getByText(/^Run 2 syncs$/u).first().click({ timeout: 8000 }).catch(() => {});
    let runAllToast = ""; for (let i = 0; i < 15 && !/wallet-authority grant/u.test(runAllToast); i++) { await pg.waitForTimeout(600); runAllToast = await text(); }
    const submit = d7.find((w) => /submitBuild/u.test(w.p));
    const runsAfterD7 = ((await d("GET", "/v1/hypervisor/odk/materializing-runs")).j.materializing_runs || []).length;
    // (the selection is the bucket's plans: each plan's dataset rid, named from the daemon's plan id)
    const bucketDatasets = bucketNow.map((p) => syncDatasetRidOf(p.id)).sort();
    ok("Run N syncs in Edit syncs asks to build the selection's datasets, and is refused by name as a sync's Run is — a sync's dataset is built only by its plan's materializing run, under a wallet-authority grant — and nothing runs",
      submit?.s === 409 && jsonOf(submit.body)?.errorName === "Hypervisor:DataConnectionRunNeedsApproval" && JSON.stringify([...(jsonOf(submit.req)?.jobSpecSelections?.[0]?.datasets?.datasetRids || [])].sort()) === JSON.stringify(bucketDatasets)
        && /wallet-authority grant/u.test(runAllToast) && runsAfterD7 === runsBeforeD7,
      `submitBuild ${submit?.s ?? "NOT SENT"} ${jsonOf(submit?.body)?.errorName || ""} over ${(jsonOf(submit?.req)?.jobSpecSelections?.[0]?.datasets?.datasetRids || []).length} datasets · runs ${runsBeforeD7} → ${runsAfterD7}`);

    // a source filed in a project sits in that project on its own pages: Parent folder, Output folder and its settings
    // page, and its Edit syncs' datasets (the daemon's source names the project; the project names the folder)
    const meterSource = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).find((x) => x.source_id === meterId) || {};
    const projectName = projectRow.project_name || projectRow.name;
    const meterOverview = await visit(`${BASE}/sources/${meterRid}/overview`, new RegExp(`Parent folder ${esc(projectName)} \\/[\\s\\S]*Output folder \\(${esc(projectName)}\\)|Parent folder local|An error occurred`, "u"));
    await pg.locator("[aria-label='Navigate to output folder configuration']").first().click({ timeout: 8000 }).catch(() => {});
    let folderPage = ""; for (let i = 0; i < 20 && !/Default output folder for syncs .{0,40}(Change default output folder|Unable to load)/u.test(folderPage); i++) { await pg.waitForTimeout(700); folderPage = await text(); }
    const folderUrl = new URL(pg.url()).pathname;
    const changeOff = await pg.getByRole("button", { name: /^Change default output folder$/u }).first().isDisabled().catch(() => null);
    await pg.getByRole("button", { name: /^Change default output folder$/u }).first().hover({ force: true, timeout: 5000 }).catch(() => {});
    let changeWhy = ""; for (let i = 0; i < 8 && !/the folder it is filed in/u.test(changeWhy); i++) { await pg.waitForTimeout(400); changeWhy = await text(); }
    const meterEdit = await visit(`${BASE}/sources/${meterRid}/edit-syncs`, /Meter readings objects\) \/\S+|Failed to load syncs|An error occurred/u);
    ok("a source filed in a project sits in that project on its own pages — Parent folder, Output folder and its settings page (Change default output folder off, saying why: it is the folder the source is filed in), and its Edit syncs' datasets — never the organization folder",
      meterSource.project_ref === project.project_ref && new RegExp(`Parent folder ${esc(projectName)} \\/`, "u").test(meterOverview) && new RegExp(`Output folder \\(${esc(projectName)}\\)`, "u").test(meterOverview)
        && /\/settings\/output-folder$/u.test(folderUrl) && new RegExp(`Default output folder for syncs \\(${esc(projectName)}\\)`, "u").test(folderPage) && changeOff === true && /the folder it is filed in/u.test(changeWhy)
        && new RegExp(`\\(Meter readings objects\\) \\/${esc(projectName)}\\b`, "u").test(meterEdit) && !/Parent folder local/u.test(meterOverview),
      `daemon ${meterSource.project_ref || "no project"} · ${after(meterOverview, "Parent folder", 26)} · ${after(meterOverview, "Output folder", 26)} · ${folderUrl.replace(/ri\.[\w.-]+/u, "<rid>")} "${after(folderPage, "Default output folder for syncs", 52)}" · Change ${changeOff === true ? "off" : "OFFERED"} ${/the folder it is filed in/u.test(changeWhy) ? "says why" : "NO REASON"} · ${after(meterEdit, "(Meter readings objects)", 36)}`);
    pg.off("response", onD7);
    ok("no Edit syncs or folder flow met a fenced read, a page error or an unbound GraphQL operation",
      fenced.size === fencedBeforeD7 && pageErrors.length === pageErrorsBeforeD7 && gqlErrors.size === gqlBeforeD7 && unnamed.size === 0 && htmlAnswers.size === 0,
      `fenced ${[...fenced].slice(fencedBeforeD7).join(",") || "none"} · page ${pageErrors.slice(pageErrorsBeforeD7, pageErrorsBeforeD7 + 1).join("") || "none"} · gql ${[...gqlErrors].slice(gqlBeforeD7, gqlBeforeD7 + 2).join(" | ") || "none"}`);

    // ---- (cut D8) "On a schedule": the reference's schedule editor (its chunk is in the mirror now) renders, and each cron
    // expression it composes is checked by the daemon's own cron parser; but no schedule runs a sync — each run takes its
    // own wallet-authority grant, and the Hypervisor's scheduler fires automation steps, none of which admits a
    // materializing run — so a save on a schedule is refused by name, before anything is written
    const d8 = [];
    const D8_ROUTE = /\/scheduler\/api\/|getConfigsV5|\/extract-store\/extract\/ri\.|\/set-policies|\/add-extract|\/build\/trigger\/|\/createDataset2/u;
    const onD8 = async (r) => { const u = new URL(r.url()); if (D8_ROUTE.test(u.pathname) && r.request().method() !== "GET") d8.push({ p: u.pathname, m: r.request().method(), s: r.status(), req: r.request().postData() || "", body: await r.text().catch(() => "") }); };
    pg.on("response", onD8);
    const fencedBeforeD8 = fenced.size, pageErrorsBeforeD8 = pageErrors.length, gqlBeforeD8 = gqlErrors.size;
    const automations = async () => ((await d("GET", "/v1/hypervisor/automations")).j.automations || []).length;
    const runCount = async () => ((await d("GET", "/v1/hypervisor/odk/materializing-runs")).j.materializing_runs || []).length;
    const chooseSchedule = async () => {
      await pg.locator("[class*=popover-button]").filter({ hasText: /Manually/u }).first().click({ timeout: 8000 }).catch(() => {});
      await pg.getByRole("menuitem", { name: "On a schedule" }).first().click({ timeout: 8000 }).catch(() => {});
      let t = ""; for (let i = 0; i < 20 && !/Schedule Details Run every/u.test(t); i++) { await pg.waitForTimeout(600); t = await text(); }
      // (Save waits for the cron check)
      for (let i = 0; i < 15 && (await saveButton().getAttribute("aria-disabled").catch(() => "true")) === "true"; i++) await pg.waitForTimeout(500);
      return t;
    };
    const SCHEDULE_TOAST = /No schedule runs a sync here: each run is its plan's materializing run/u;
    const importBeforeD8 = await planOf(planId);
    const automationsBefore = await automations(), runsBeforeD8 = await runCount();

    // in Edit syncs, a sync's panel
    await visit(editUrl, /\(Plants import objects\)/u);
    await pg.getByText("(Plants import objects)", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let schedPanel = ""; for (let i = 0; i < 20 && !/Configure Plants import[\s\S]*Build policy/u.test(schedPanel); i++) { await pg.waitForTimeout(700); schedPanel = await text(); }
    const editorShown = await chooseSchedule();
    const checkMark = d8.length;
    const cronCheck = d8.find((w) => /validate-cron-expression/u.test(w.p));
    const cronAsked = jsonOf(cronCheck?.req);
    const daemonCron = await d("GET", `/v1/hypervisor/cron-preview?cron=${encodeURIComponent(String(cronAsked ?? ""))}&tz=UTC&n=1`);
    const badCron = await serveJ("POST", "/scheduler/api/scheduler/validate-cron-expression", "61 * * * *");
    const daemonBad = await d("GET", `/v1/hypervisor/cron-preview?cron=${encodeURIComponent("61 * * * *")}&tz=UTC&n=1`);
    ok("choosing On a schedule renders the reference's schedule editor (Schedule Details, Run every), and each cron expression it composes is checked by the daemon's own cron parser — the one its automation scheduler fires by: the editor's expression passes because the daemon finds its next fire, an out-of-range minute fails with the daemon's own reason",
      /Run this import On a schedule Schedule Details Run every/u.test(editorShown) && cronCheck?.s === 200 && typeof cronAsked === "string" && cronAsked.split(" ").length === 5
        && daemonCron.j.ok === true && (daemonCron.j.runs || []).length === 1 && jsonOf(cronCheck.body)?.error === null
        && badCron.status === 200 && daemonBad.j.ok === false && typeof daemonBad.j.error === "string" && badCron.j?.error === daemonBad.j.error,
      `${after(editorShown, "Run this import", 60)} · check ${cronCheck?.s ?? "NOT SENT"} "${cronAsked}" → ${cronCheck?.body || ""} (daemon next ${(daemonCron.j.runs || [])[0] || daemonCron.j.error}) · "61 * * * *" → ${JSON.stringify(badCron.j)} (daemon "${daemonBad.j.error}")`);

    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let schedToast = ""; for (let i = 0; i < 15 && !SCHEDULE_TOAST.test(schedToast); i++) { await pg.waitForTimeout(600); schedToast = await text(); }
    const editSave = d8.slice(checkMark);
    const importAfterEdit = await planOf(planId);
    // …and on the sync's own Configuration page
    await visit(`${syncBase}/configuration`, /Run this import Manually/u);
    await chooseSchedule();
    const configMark = d8.length;
    await saveButton().click({ timeout: 8000 }).catch(() => {});
    let configToast = ""; for (let i = 0; i < 15 && !SCHEDULE_TOAST.test(configToast); i++) { await pg.waitForTimeout(600); configToast = await text(); }
    const configSave = d8.slice(configMark);
    const importAfterConfig = await planOf(planId);
    const automationsAfter = await automations(), runsAfterD8 = await runCount();
    const refusedSave = (ws) => {
      const byDataset = ws.find((w) => /get-schedules-by-run-build-dataset/u.test(w.p));
      const gate = ws.find((w) => /getConfigsV5/u.test(w.p) && /SCHEDULE_CREATE/u.test(w.req));
      const create = ws.find((w) => /create-schedules/u.test(w.p));
      return byDataset?.s === 200 && JSON.stringify(jsonOf(byDataset.body)) === "[]" && (jsonOf(byDataset.req)?.datasetRids || []).includes(syncDatasetRidOf(planId))
        && gate?.s === 409 && jsonOf(gate.body)?.errorName === "Hypervisor:DataConnectionScheduleNotBound"
        && create?.s === 409 && jsonOf(create.body)?.errorName === "Hypervisor:DataConnectionScheduleNotBound" && jsonOf(create.req)?.[0]?.trigger?.type === "time"
        && jsonOf(create.req)?.[0]?.action?.runBuild?.jobSpecSelections?.[0]?.single?.datasetRid === syncDatasetRidOf(planId)
        && !ws.some((w) => /extract-store\/extract\/ri\.|set-policies|add-extract|build\/trigger/u.test(w.p));
    };
    const saveTrail = (ws) => ws.map((w) => `${w.p.split("/").pop()} ${w.s}${/getConfigsV5/u.test(w.p) ? ` ${jsonOf(w.req)?.checkpointType}` : ""}`).join(", ") || "NOTHING SENT";
    ok("a sync saved on a schedule — in Edit syncs and on its own Configuration page — is refused by name before anything is written: no schedule builds its dataset, creating one is refused at its checkpoint read and at its create (each run takes its own wallet-authority grant; the scheduler fires automation steps, none of which admits a materializing run), the toast says why, and the plan keeps its revision — no automation, no run",
      refusedSave(editSave) && refusedSave(configSave) && SCHEDULE_TOAST.test(schedToast) && SCHEDULE_TOAST.test(configToast)
        && importAfterEdit.revision === importBeforeD8.revision && importAfterConfig.revision === importBeforeD8.revision && importAfterConfig.ttl_seconds === importBeforeD8.ttl_seconds
        && automationsAfter === automationsBefore && runsAfterD8 === runsBeforeD8,
      `edit syncs: ${saveTrail(editSave)} "${toastOf(schedToast, SCHEDULE_TOAST).slice(0, 70)}" · configuration: ${saveTrail(configSave)} · plan r${importBeforeD8.revision} → r${importAfterEdit.revision} → r${importAfterConfig.revision} · automations ${automationsBefore} → ${automationsAfter} · runs ${runsBeforeD8} → ${runsAfterD8}`);

    // Duplicate sync on a schedule: the new sync is Duplicate's declaration (bound, cut D6) and lands on it; the schedule
    // the reference asks for after it — for the dataset the page was answered — is refused by name, so it runs Manually
    await visit(`${syncBase}/configuration`, /Duplicate sync/u);
    await pg.getByText("Duplicate sync", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let dupSched = ""; for (let i = 0; i < 25 && !/exact duplicate of Plants import[\s\S]*leaseTtlSeconds/u.test(dupSched); i++) { await pg.waitForTimeout(800); dupSched = await text(); }
    await pg.locator("input[placeholder='Dataset name']").first().fill("Plants nightly").catch(() => {});
    await chooseSchedule();
    const dupMark = d8.length;
    await pg.getByRole("button", { name: /^Create sync$/u }).first().click({ timeout: 8000 }).catch(() => {});
    let dupSchedLanded = ""; for (let i = 0; i < 25 && !(/Sync created/u.test(dupSchedLanded) && SCHEDULE_TOAST.test(dupSchedLanded)); i++) { await pg.waitForTimeout(700); dupSchedLanded = await text(); }
    const dupSchedWrites = d8.slice(dupMark);
    const nightly = (await plans()).find((x) => x.name === "Plants nightly");
    const nightlyAdd = dupSchedWrites.find((w) => /add-extract/u.test(w.p));
    const nightlyCreate = dupSchedWrites.find((w) => /create-schedules/u.test(w.p));
    const nightlyAsked = jsonOf(nightlyCreate?.req)?.[0]?.action?.runBuild?.jobSpecSelections?.[0]?.single?.datasetRid;
    const nightlySyncs = await serveJ("POST", "/magritte-coordinator/api/extract-store/extracts/bulk", [String(jsonOf(nightlyAdd?.body))]);
    ok("Duplicate sync on a schedule declares the new sync and lands on it (Sync created), and the schedule the reference asks for after it — for the dataset its page was answered — is refused by name, so the new plan runs Manually; no automation appears",
      nightly?.status === "declared" && nightly?.revision === 1 && nightlyAdd?.s === 200 && new URL(pg.url()).pathname === `${BASE}/syncs/${String(jsonOf(nightlyAdd?.body))}/overview`
        && nightlyCreate?.s === 409 && jsonOf(nightlyCreate.body)?.errorName === "Hypervisor:DataConnectionScheduleNotBound" && nightlyAsked === jsonOf(dupSchedWrites.find((w) => /createDataset2/u.test(w.p))?.body)?.rid
        && /Sync created/u.test(dupSchedLanded) && SCHEDULE_TOAST.test(dupSchedLanded) && !!nightlySyncs.j?.[String(jsonOf(nightlyAdd?.body))] && (await automations()) === automationsBefore,
      `plan ${nightly ? `${nightly.status} r${nightly.revision}` : "NONE"} · add-extract ${nightlyAdd?.s ?? "NOT SENT"} · create-schedules ${nightlyCreate?.s ?? "NOT SENT"} ${jsonOf(nightlyCreate?.body)?.errorName || ""} · ${new URL(pg.url()).pathname.replace(/ri\.[\w.-]+/u, "<rid>")} · ${/Sync created/u.test(dupSchedLanded) ? "Sync created" : "NOT CREATED"} + ${SCHEDULE_TOAST.test(dupSchedLanded) ? "refusal toast" : "NO REFUSAL TOAST"}`);

    // a REST source's Edit syncs, reached by URL (the reference offers a REST source no such tab): its syncs are its lease
    // plans (none), and its New is the source's primary action — Create webhook — off, saying why in words true here
    const ordersId = orders.j.data_source?.source_id;
    const restPlans = (await plans()).filter((x) => x.data_source_id === ordersId && x.status !== "revoked");
    const restEdit = await visit(`${srcBase}/edit-syncs`, /No syncs for source|Failed to load syncs|An error occurred/u);
    const restNew = await pg.evaluate(() => [...document.querySelectorAll("a,button,[role=button]")].filter((e) => (e.innerText || "").trim() === "New").map((e) => e.disabled === true || e.getAttribute("aria-disabled") === "true" || /bp[56]-disabled/u.test(e.className)));
    await pg.getByText("New", { exact: true }).first().hover({ force: true, timeout: 5000 }).catch(() => {});
    let restWhy = []; for (let i = 0; i < 10 && !restWhy.length; i++) { await pg.waitForTimeout(400); restWhy = await pg.evaluate(() => [...document.querySelectorAll(".bp5-tooltip, .bp6-tooltip, [role=tooltip]")].map((e) => e.innerText.trim()).filter(Boolean)); }
    ok("a REST source's Edit syncs, reached by URL, lists its lease plans — none — and its New (the source's Create webhook, not a sync) is off, saying why in words true here (no webhook plane, no other runtime), never that the person lacks permission",
      restPlans.length === 0 && /No syncs No syncs for source/u.test(restEdit) && !/Failed to load syncs|An error occurred/u.test(restEdit) && restNew.length === 1 && restNew[0] === true
        && restWhy.some((w) => /^Webhooks are not supported here: the Hypervisor has no webhook plane/u.test(w)) && !restWhy.some((w) => /permission|representative|switch to a different runtime/iu.test(w)),
      `daemon ${restPlans.length} plans · ${after(restEdit, "No syncs", 32)} · New ${restNew.length ? (restNew.every(Boolean) ? "off" : "OFFERED") : "ABSENT"} · "${(restWhy[0] || "NO TOOLTIP").slice(0, 80)}"`);
    pg.off("response", onD8);
    ok("no On a schedule or REST Edit syncs flow met a fenced read, a page error or an unbound GraphQL operation",
      fenced.size === fencedBeforeD8 && pageErrors.length === pageErrorsBeforeD8 && gqlErrors.size === gqlBeforeD8 && unnamed.size === 0 && htmlAnswers.size === 0,
      `fenced ${[...fenced].slice(fencedBeforeD8).join(",") || "none"} · page ${pageErrors.slice(pageErrorsBeforeD8, pageErrorsBeforeD8 + 1).join("") || "none"} · gql ${[...gqlErrors].slice(gqlBeforeD8, gqlBeforeD8 + 2).join(" | ") || "none"}`);

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
    // (cut D7) …and a source's Edit syncs says it failed to load them, never that the source has none
    const editDown = await visit(editUrl, /Plants import objects|No syncs|Failed to load syncs|An error occurred/u);
    ok("with the daemon stopped, a source's Edit syncs shows it failed to load its syncs — never \"No syncs\"",
      /Failed to load syncs/u.test(editDown) && !/Plants import objects|No syncs for source/u.test(editDown),
      after(editDown, "Failed to load syncs", 40));
    // (cut D6) …and the checkpoint read before a sync's write fails rather than answering none (which would let the
    // write skip an obligation the daemon might keep)
    const gateDown = await serveJ("POST", "/checkpoints/api/checkpoints/configuration/getConfigsV5", { checkpointedItems: [{ checkpointedItemId: { checkpointedResourceRid: s3Rid, type: "checkpointedResourceRid" }, branches: [] }], checkpointType: "DATA_CONNECTION_SYNC_EDIT" });
    ok("with the daemon stopped, the checkpoint read before a sync's write fails — never \"no checkpoint applies\"",
      gateDown.status >= 500 && !Array.isArray(gateDown.j?.checkpointConfigs), `${gateDown.status} ${JSON.stringify(gateDown.j).slice(0, 120)}`);
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
