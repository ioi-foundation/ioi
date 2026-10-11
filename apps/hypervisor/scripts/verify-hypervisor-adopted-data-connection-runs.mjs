#!/usr/bin/env node
// A SYNC WHOSE RUN FAILED READS FAILED, OVER DAEMON TRUTH (R-241, Data Connection D5).
//
// The adopted Data Connection maps a sync's builds onto its lease plan's materializing runs (adopted-data-connection.mjs,
// cut D4). A run can fail only once it holds its lease and an open sealed session — both of which need the deployment
// authority — so this verifier stands up the whole crossing on an ISOLATED stack, as check:adopted-approvals does:
//   - a sealed local authority node (fresh keys, sealed under a per-run operator passphrase), a daemon pointed at it and
//     a serve with the adopted surfaces on (the serve names no authority binary or state dir: it holds no key);
//   - a REST API source, its import ladder and lease plan (the sync), and a connector holding a sealed credential for the
//     source's origin;
//   - the run obtains its lease and opens its sealed session, each through the daemon's parked challenge and the
//     operator's decision (the passphrase goes to the daemon, which runs the authority's `approve`); then an execute
//     that carries no grant for the source contact is refused by the daemon (execution_authority_required) — the run
//     keeps its lease, and its last act is the refusal;
//   - in a real browser: the Syncs list and the sync's Overview read Failed; the build's status detail is the refusal;
//     the source's Logs show the refused execute as an ERROR with the daemon's reason (a REST API source's page lists
//     only Overview, Connection settings and Webhooks, as the reference's does, so its Logs are opened by their URL);
//     nothing reaches the capture server but the reference's chrome, and nothing is fenced.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon or authority binary, or the local capture server cannot boot the reference app).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon (the authority: IOI_WALLET_AUTHORITY_BINARY)
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-data-connection-runs.mjs   (about ten minutes: the authority starts a chain)

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { startLocalAuthority, DEFAULT_BINARY as AUTHORITY_BINARY, OPERATOR_PASS_ENV } from "./lib/wallet-network-local-authority.mjs";
import { sanitizedVerifierBaseEnv } from "./lib/isolated-daemon.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const BIN = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
const BASE = "/workspace/data-ingestion-app";
// the reference's chrome reads the capture server still answers (check:adopted-data-connection's set)
const CHROME = new Set(["GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection", "POST /documentation/api/v2/release-notes/pagination",
  "POST /documentation/api/v2/release-notes/paginationV2", "GET /aip-assist/api/chat/checkAvailability", "GET /workspace/api/lifecycleStatusByApplication", "POST /log-receiver/api/beacon",
  "GET /compass/api/registry/actions"]);
// unique per run: the passphrase seals this run's authority keys and appears nowhere the adopted app can reach
const OPERATOR_PASS = `adopted-dc-runs-${randomBytes(12).toString("hex")}`;

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };

let authority = null, daemon = null, serve = null;
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-dc-runs-authority-"));
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-dc-runs-"));

async function run() {
  if (!fs.existsSync(BIN) || !fs.existsSync(process.env.IOI_WALLET_AUTHORITY_BINARY || AUTHORITY_BINARY)) { console.log(`BLOCKED: no daemon (${BIN}) or authority binary`); process.exit(2); }
  if (!(await fetch(`${CAPTURE}${BASE}/splash`, { signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false))) { console.log(`BLOCKED: the local capture server (${CAPTURE}) does not boot ${BASE}/`); process.exit(2); }
  delete process.env[OPERATOR_PASS_ENV];
  authority = await startLocalAuthority({ stateDir, principalRef: "domain://adopted-dc-runs", operatorPass: OPERATOR_PASS, log: () => {} });
  const daemonPort = await freePort();
  const DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(BIN, [], { cwd: ROOT, env: { ...sanitizedVerifierBaseEnv(process.env), ...authority.daemonEnv, IOI_WALLET_TEST_SIGNER: "", IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1" }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => (log = (log + c).slice(-200000))); daemon.stderr.on("data", (c) => (log = (log + c).slice(-200000)));
  if (!(await waitFor(`${DAEMON}/healthz`))) { console.log("BLOCKED: the isolated daemon did not start"); process.exit(2); }
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
  const boot = await (await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "adopted-dc-runs-bootstrap-v1", email: "runs@ioi.local" }) })).json();
  const COOKIE = `ioi_session=${boot.session_token}`;
  const d = (method, route, body) => fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(900000) })
    .then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  // the serve names no authority binary or state dir: it holds no key
  const servePort = await freePort();
  const SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_ADOPTED_SURFACES: "1", IOI_HARVEST_CAPTURE_URL: CAPTURE },
    stdio: ["ignore", "pipe", "pipe"],
  });
  serve.stdout.on("data", () => {}); serve.stderr.on("data", () => {});
  await waitFor(`${SERVE}/__ioi/login`);

  // ---- the fixture: a REST API source (its origin never answers — nothing reaches it), its ladder and plan, and a
  // connector holding a sealed credential for that origin
  const origin = `http://127.0.0.1:${await freePort()}`;
  const owner = ((await d("GET", "/v1/hypervisor/auth/whoami")).j.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://"));
  const source = await d("POST", "/v1/hypervisor/data-sources", { name: "Orders API", kind: "rest_api", endpoint: `${origin}/orders`, credential_posture: "wallet_credential_lease" });
  const sourceId = source.j.data_source?.source_id;
  const ontology = await d("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "orders", canonical_object_model: { object_types: [{ id: "order", name: "Order", title_property: "title",
    properties: [{ id: "order_id", name: "Order Id", value_type: "string", required: true }, { id: "title", name: "Title", value_type: "string" }] }], action_types: [] } });
  const mapping = await d("POST", "/v1/hypervisor/odk/connector-mappings", { owner_ref: owner, idempotency_key: "adopted-dc-runs-mapping", name: "orders-map", data_source_id: sourceId, ontology_ref: ontology.j.ontology?.ref,
    object_type_id: "order", key_mapping: { source_field: "id", property_id: "order_id", source_type: "string" }, title_mapping: { source_field: "name", property_id: "title", source_type: "string" } });
  const mappingId = mapping.j.connector_mapping?.id;
  const view = await d("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mappingId, name: "orders-gate", authority_subjects: ["agent://materializer"], allowed_operations: ["read", "transform"],
    purpose: "order book", property_scope: ["order_id", "title"], retention_posture: "bounded" });
  const viewId = view.j.policy_bound_data_view?.id;
  const transform = await d("POST", "/v1/hypervisor/odk/transformation-runs", { owner_ref: owner, idempotency_key: "adopted-dc-runs-transform", connector_mapping_id: mappingId, policy_view_id: viewId, name: "orders-transform" });
  const transformId = transform.j.transformation_run?.id;
  await d("POST", `/v1/hypervisor/odk/transformation-runs/${transformId}/dry-run`);
  const projection = await d("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mappingId, policy_view_id: viewId, name: "orders-explorer", visible_properties: ["order_id", "title"] });
  const plan = await d("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: sourceId, connector_mapping_id: mappingId, policy_view_id: viewId, transformation_run_id: transformId,
    ontology_projection_id: projection.j.ontology_projection?.id, name: "Orders import", subject: "agent://materializer", ttl_seconds: 900 });
  const planId = plan.j.capability_lease_plan?.id;
  const connector = await d("POST", "/v1/hypervisor/connectors", { service: "adopted-dc-runs", base_url: origin, name: "Orders connector" });
  const connectorId = connector.j.connector?.connector_id || connector.j.connector_id;
  const credential = await d("POST", `/v1/hypervisor/connectors/${connectorId}/credential`, { token: `adopted-dc-runs-${randomBytes(8).toString("hex")}` });

  // ---- the run: its lease and its sealed session, each through the daemon's parked challenge and the operator's decision
  // (the passphrase goes to the daemon, never the serve), then an execute with no grant for the source contact
  const decided = [];
  const throughTheOperator = async (first, retry) => {
    const challenge = first.j.approval_challenge?.challenge_id;
    if (first.status !== 403 || !challenge) return { first, decision: null, again: first };
    const decision = await d("POST", `/v1/hypervisor/authority/challenges/${challenge}/decision`, { decision: "approve", reason: "adopted Data Connection run verifier", operator_passphrase: OPERATOR_PASS });
    decided.push(decision.status);
    return { first, decision, again: await retry(decision.j.approval_ref) };
  };
  const admitted = await d("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: planId, name: "orders-run-1" });
  const runId = admitted.j.materializing_run?.id;
  const lease = await throughTheOperator(await d("POST", `/v1/hypervisor/odk/materializing-runs/${runId}/acquire-lease`, {}),
    (ref) => d("POST", `/v1/hypervisor/odk/materializing-runs/${runId}/acquire-lease`, { wallet_approval_grant: { approval_ref: ref } }));
  const session = await d("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: runId, connector_id: connectorId, name: "orders-session" });
  const sessionId = session.j.connector_session?.id;
  const opened = await throughTheOperator(await d("POST", `/v1/hypervisor/odk/connector-sessions/${sessionId}/open`, {}),
    (ref) => d("POST", `/v1/hypervisor/odk/connector-sessions/${sessionId}/open`, { wallet_approval_grant: { approval_ref: ref } }));
  const executed = await d("POST", `/v1/hypervisor/odk/materializing-runs/${runId}/execute`, { connector_session_id: sessionId, limit: 10 });
  const failedRun = (await d("GET", `/v1/hypervisor/odk/materializing-runs/${runId}`)).j.materializing_run || {};
  const lastAct = (failedRun.history || []).at(-1) || {};
  ok("PRECONDITION: the run obtained its lease and opened its sealed session through the sealed authority (two parked challenges, each approved with the operator's passphrase through the daemon), and its execute with no grant for the source contact was refused by the daemon — the run keeps its lease, its last act the refusal",
    source.status < 300 && plan.status === 201 && credential.status === 200 && lease.first.status === 403 && lease.again.status === 200 && lease.again.j.materializing_run?.status === "lease_obtained"
      && opened.first.status === 403 && opened.again.status === 200 && decided.length === 2 && decided.every((s) => s === 200)
      && executed.status === 403 && executed.j.error?.code === "execution_authority_required" && failedRun.status === "lease_obtained" && lastAct.op === "execution_refused",
    `plan ${plan.status} · lease ${lease.first.status} → ${lease.again.status} ${lease.again.j.materializing_run?.status || lease.again.j.reason || ""} · session ${opened.first.status} → ${opened.again.status} · decisions ${decided.join(",")} · execute ${executed.status} ${executed.j.error?.code} · run ${failedRun.status}, last ${lastAct.op} "${lastAct.summary}"`);

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: boot.session_token, url: SERVE }]);
    const pg = await ctx.newPage();
    const passthrough = new Set(), fenced = new Set(), htmlAnswers = new Set(), pageErrors = [], builds = [];
    pg.on("pageerror", (e) => pageErrors.push(String(e.message).slice(0, 160)));
    pg.on("response", async (r) => {
      const u = new URL(r.url()); const key = `${r.request().method()} ${u.pathname.replace(/ri\.[\w.-]+/gu, "<rid>")}`;
      if (r.headers()["x-ioi-capture-passthrough"] === "1") passthrough.add(key);
      if (/^\/[a-z][a-z0-9-]*\/api\//u.test(u.pathname) && /text\/html/u.test(r.headers()["content-type"] || "")) htmlAnswers.add(key);
      if (r.status() === 501) fenced.add(key);
      if (/^\/job-tracker\/api\/builds\/bulk(V2)?$/u.test(u.pathname)) { const j = await r.json().catch(() => null); for (const q of Array.isArray(j) ? j : []) builds.push(...(q.buildDetails || [])); }
    });
    const text = async () => (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const visit = async (p, until) => { await pg.goto(`${SERVE}${p}`, { waitUntil: "domcontentloaded", timeout: 60000 }); let t = ""; for (let i = 0; i < 25; i++) { await pg.waitForTimeout(800); t = await text(); if (!until || until.test(t)) break; } return t; };
    const after = (t, marker, n = 200) => (t.includes(marker) ? t.slice(t.indexOf(marker), t.indexOf(marker) + n) : `(no "${marker}")`);

    // the Syncs list, then the sync's Overview, opened the way a person opens them
    const syncs = await visit(`${BASE}/syncs`, /Orders import objects \/\S+ Orders API (Never ran|Waiting|Running|Canceled|Failed|Succeeded)|No syncs|Could not load syncs/u);
    const row = after(syncs, "Next run Actions", 160);
    await pg.getByText("Orders import", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let overview = ""; for (let i = 0; i < 25 && !/Build details .{0,60}Next run|An error occurred/u.test(overview); i++) { await pg.waitForTimeout(800); overview = await text(); }
    const failedBuild = builds.find((b) => b.buildStatus === "FAILED");
    await visit(`${BASE}/sources`, /Orders API/u);
    await pg.getByText("Orders API", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let sourcePage = ""; for (let i = 0; i < 25 && !/Orders API \(REST API\)|An error occurred/u.test(sourcePage); i++) { await pg.waitForTimeout(800); sourcePage = await text(); }
    const sourceBase = new URL(pg.url()).pathname.replace(/\/overview$/u, "");
    ok("a sync whose run's execute was refused reads Failed over daemon truth — on the Syncs list and the sync's Overview (Build details) — and the build's status detail is the refusal",
      /Orders import Orders import objects \/\S+ Orders API Failed/u.test(row) && /Build details Failed/u.test(overview) && /Orders API \(REST API\)/u.test(sourcePage)
        && failedBuild?.jobs?.[0]?.jobStatus === "FAILED" && failedBuild?.jobs?.[0]?.securedProperties?.statusDetails?.message === lastAct.summary,
      `${row.slice(0, 130)} · ${after(overview, "Build details", 50)} · build ${failedBuild?.buildStatus || "none"} "${failedBuild?.jobs?.[0]?.securedProperties?.statusDetails?.message || ""}"`);

    // the source's Logs: the refused execute as an ERROR, with the daemon's reason and outcome, in the reference's viewer
    const receipts = (await d("GET", `/v1/hypervisor/odk/materializing-runs/${runId}/history`)).j.receipts || [];
    const refusal = receipts.find((r) => r.op === "execution_refused" && r.outcome === "execution_authority_required");
    const logs = await visit(`${sourceBase}/logs`, /independently resolved|No logs|Failed to load logs|Unable to load/u);
    ok("the source's Logs show the refused execute as an ERROR with the daemon's own reason and outcome (its syncs' run receipts), and the lease and session that preceded it",
      !!refusal && logs.includes("ERROR") && logs.includes(String(refusal.summary)) && /"outcome": "execution_authority_required"/u.test(logs) && /"sync": "Orders import"/u.test(logs) && !/Failed to load logs|Unable to load/u.test(logs),
      `${refusal ? `receipt "${refusal.summary}"` : "NO REFUSAL RECEIPT"} · ${after(logs, "ERROR", 160)}`);

    ok("no page reached the capture server beyond the reference's chrome, nothing was fenced, and no service read got the serve's HTML page",
      [...passthrough].every((p) => CHROME.has(p)) && fenced.size === 0 && htmlAnswers.size === 0 && pageErrors.length === 0,
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · fenced ${[...fenced].join(",") || "none"} · html ${[...htmlAnswers].join(",") || "none"} · page ${pageErrors.slice(0, 1).join("") || "none"}`);
  } finally {
    await browser.close();
  }
}

async function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { await authority?.stop(); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
  try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(async () => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-data-connection-runs", sourceUrl: import.meta.url, results });
  await cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
