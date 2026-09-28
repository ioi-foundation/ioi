#!/usr/bin/env node
// THE ADOPTED DATA CONNECTION LISTS THE CALLER'S DATA SOURCES, AND NOTHING RECORDED (R-241, Data Connection D1).
//
// The reference Data Connection (booted by the local mirror, routed at /workspace/data-ingestion-app) answers from the
// Hypervisor's data-source plane (adopted-data-connection.mjs), in a real browser against an ISOLATED daemon + serve:
//   - the Sources list is the caller's declared data sources, each under its connection type, with no syncs;
//   - Syncs, Agents and Listeners say none — a declared source ingests nothing yet, and no agent or listener exists;
//   - the landing renders, and offers no create it would refuse (creating a source is not bound yet);
//   - no read reaches the mirror but the reference's chrome, no service read gets the serve's HTML page, and a write the
//     app would send (creating a source) is a named gap that writes nothing;
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
  ok("PRECONDITION: two data sources are declared (a REST API and an S3 bucket)", orders.status < 300 && plants.status < 300 && countBefore === 2, `${orders.status} · ${plants.status} · ${countBefore} declared`);

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
    ok("the Sources list is the caller's declared data sources, each under its connection type, with no syncs",
      /Orders API REST API/u.test(table) && /Plants bucket S3/u.test(table) && (table.match(/0 syncs/gu) || []).length === 2 && !/No sources/u.test(sources), table);
    const syncs = await visit(`${BASE}/syncs`, /No syncs|Could not load syncs/u);
    const agents = await visit(`${BASE}/agents`, /No agents found|Unable to load agents/u);
    const listeners = await visit(`${BASE}/listeners`, /No listeners found|Failed to load listeners/u);
    ok("Syncs, Agents and Listeners say none — a declared source ingests nothing yet, and no agent or listener exists",
      /No syncs/u.test(syncs) && /No agents found/u.test(agents) && /No listeners found/u.test(listeners) && !/Could not load syncs|Unable to load agents|Failed to load listeners/u.test(syncs + agents + listeners),
      `${after(syncs, "No syncs", 20)} · ${after(agents, "No agents", 20)} · ${after(listeners, "No listeners", 22)}`);
    const splash = await visit(`${BASE}/splash`, /Set up new connections|An error occurred/u);
    ok("the landing renders, and offers no create it would refuse (creating a source is not bound yet)",
      /Set up new connections/u.test(splash) && !/An error occurred/u.test(splash) && !(await pg.getByRole("button", { name: /^New source$/u }).count()),
      after(splash, "Data Connection Synchronize", 90));

    ok("no page reached the mirror beyond the reference's chrome, every read the adopted layer does not bind is a named gap (never the serve's HTML page), and no GraphQL operation on these pages is unbound",
      [...passthrough].every((p) => CHROME.has(p)) && unnamed.size === 0 && htmlAnswers.size === 0 && fenced.size === 0 && gqlErrors.size === 0 && pageErrors.length === 0,
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · fenced ${[...fenced].join(",") || "none"} · unnamed ${[...unnamed].join(",") || "none"} · html ${[...htmlAnswers].join(",") || "none"} · gql ${[...gqlErrors].slice(0, 2).join(" | ") || "none"} · page ${pageErrors.slice(0, 1).join("") || "none"}`);

    // ---- the fence: the app's create (a write) is a named gap and writes nothing ---------------------------------
    const H = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}${BASE}/sources/new` };
    const create = await fetch(`${SERVE}/magritte-coordinator/api/source-store/source/v3`, { method: "POST", headers: H, body: JSON.stringify({ description: { name: "Should not exist", description: "", apiName: "ShouldNotExist" } }) }).then(async (r) => ({ status: r.status, pass: r.headers.get("x-ioi-mirror-passthrough"), j: await r.json().catch(() => ({})) }));
    const countAfter = ((await d("GET", "/v1/hypervisor/data-sources")).j.data_sources || []).length;
    ok("on the Data Connection surface the app's create is a named gap that writes nothing — never the recorded tenant's answer",
      create.status === 501 && create.j.errorName === "Hypervisor:DataConnectionReadNotBound" && !create.pass && countAfter === countBefore,
      `create ${create.status} ${create.j.errorName} · data sources ${countBefore} → ${countAfter}`);

    // ---- degraded: the daemon stopped ---------------------------------------------------------------------------------
    daemon.kill("SIGTERM");
    for (let i = 0; i < 30 && daemon.exitCode === null && daemon.signalCode === null; i++) await sleep(200);
    const down = await visit(`${BASE}/sources`, /Orders API|No sources|could not|Failed|error/iu);
    ok("with the daemon stopped, the Sources list shows its error — never \"No sources\"",
      !/Orders API/u.test(down) && !/No sources Either no sources exist/u.test(down) && /error|failed|could not|unable/iu.test(after(down, "Sources Name", 300)),
      after(down, "Sources Name", 160));
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
