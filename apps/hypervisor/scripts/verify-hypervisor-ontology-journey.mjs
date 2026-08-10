#!/usr/bin/env node
// SURF-ontology primary journey verifier (next-legs Leg 3a).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev
// processes), the brief §5 acceptance that #219/#222 left open: create /
// version-discipline / read / search-filter / denial / CAS-conflict-and-
// recovery / receipt / reload / restart-survival journeys, plus the typed
// named-gap assertions for the daemon families that do not exist (proposals,
// saved-set authoring) — absence is asserted, never papered over.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary or product bundle missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-ontology-journey.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ontology-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Ontology writes are identity-first (rule E — the W1.1/G-2 finding is CLOSED): every
// authoring crossing carries the bootstrap operator's session; the daemon refuses an
// anonymous write typed-401 BEFORE any record load. Reads stay ungated.
let SESSION = "";
const sessionCookie = () => (SESSION ? { cookie: `ioi_session=${SESSION}` } : {});

const jd = (p, init) => fetch(`${DAEMON}${p}`, init ? { headers: { "content-type": "application/json", ...sessionCookie() }, ...init } : undefined)
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const MANAGER_ACTIONS = `${"/__ioi/ontology/manager"}/actions`;
async function act(id, data, { anonymous = false } = {}) {
  const r = await fetch(`${SERVE}${MANAGER_ACTIONS}/${id}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(anonymous ? {} : sessionCookie()) },
    body: new URLSearchParams(data).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "");
  return { status: r?.status ?? 0, location, q };
}

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();

  // Operator bootstrap mirrors scripts/smoke-product-surfaces.mjs; the yielded session is
  // now the AUTHORING identity every write below carries (identity-first ontology writes).
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "ontology-journey-bootstrap-v1", email: "ontology-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/ontology/schema`, 30000);

  // -- canonical mounts render the preserved grammar -------------------------
  const schemaPage = await pageText("/ontology/schema");
  ok("canonical /ontology/schema renders the Manager", schemaPage.status === 200 && schemaPage.text.includes("og-inspector"), `status ${schemaPage.status}`);
  const explorePage = await pageText("/ontology/explore");
  ok("canonical /ontology/explore renders the Explorer", explorePage.status === 200 && explorePage.text.includes("oe-inspector"), `status ${explorePage.status}`);

  // -- create ---------------------------------------------------------------
  const domain = `journey-${Date.now().toString(36)}`;
  const created = await act("create-ontology", { domain, version: "1.0.0", description: "journey ontology" });
  const ontId = created.q.get("record") || "";
  ok("create-ontology crosses with a receipt", created.status === 303 && created.q.get("acted") === "create-ontology" && (created.q.get("receipt") || "").length > 0, created.location.slice(0, 140));
  const afterCreate = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("created ontology reads back at revision 1", afterCreate.status === 200 && afterCreate.body?.ontology?.revision === 1 && afterCreate.body?.ontology?.domain === domain, `rev ${afterCreate.body?.ontology?.revision}`);

  // -- version discipline: five upserts + metadata, each a receipted revision -
  const steps = [
    ["upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", description: "typed object" }],
    ["upsert-property", { ontology: ontId, object_type_id: "obj_journey", def_id: "prop_name", name: "name", value_type: "string", required: "on" }],
    ["upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", description: "typed object", title_property: "prop_name" }],
    ["upsert-value-type", { ontology: ontId, def_id: "vt_stage", name: "Stage", base: "enum", enum_values: "draft,active" }],
    ["upsert-link-type", { ontology: ontId, def_id: "lnk_owner", name: "owns", from: "obj_journey", to: "obj_journey", cardinality: "one_to_many" }],
    ["upsert-action-type", { ontology: ontId, def_id: "act_review", name: "review", kind: "modify_object", applies_to: "obj_journey" }],
    ["update-metadata", { ontology: ontId, domain, version: "1.1.0", description: "journey ontology amended" }],
  ];
  let expectedRev = 1;
  for (const [actionId, fields] of steps) {
    const res = await act(actionId, fields);
    expectedRev += 1;
    ok(`${actionId} crosses with a receipt`, res.status === 303 && res.q.get("acted") === actionId && (res.q.get("receipt") || "").length > 0, res.location.slice(0, 140));
  }
  const afterSteps = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const com = afterSteps.body?.ontology?.canonical_object_model ?? {};
  ok("revision advanced once per mutation", afterSteps.body?.ontology?.revision === expectedRev, `rev ${afterSteps.body?.ontology?.revision}, expected ${expectedRev}`);
  ok("canonical object model holds the authored definitions",
    JSON.stringify(com).includes("obj_journey") && JSON.stringify(com).includes("vt_stage") && JSON.stringify(com).includes("lnk_owner"),
    Object.keys(com).join(","));

  // -- receipts are durable objects -----------------------------------------
  let receiptCount = 0;
  try {
    receiptCount = fs.readdirSync(path.join(dataDir, "odk-ontology-receipts")).length;
  } catch { receiptCount = -1; }
  ok("every mutation left a durable receipt", receiptCount >= expectedRev, `${receiptCount} receipts on disk`);

  // -- CAS conflict and recovery --------------------------------------------
  const stale = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`, {
    method: "PATCH",
    body: JSON.stringify({ expected_revision: 1, description: "stale write" }),
  });
  ok("stale expected_revision refuses with the typed conflict", stale.status === 409 && JSON.stringify(stale.body).includes("odk_revision_conflict"), `status ${stale.status}`);
  const recovered = await act("upsert-object-type", { ontology: ontId, def_id: "obj_recovered", name: "Recovered", description: "post-conflict" });
  expectedRev += 1;
  ok("a fresh read-and-write recovers after the conflict", recovered.status === 303 && (recovered.q.get("receipt") || "").length > 0, recovered.location.slice(0, 120));

  // -- typed refusal surfaces its REAL code through the UI lane ---------------
  const masked = await act("upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", title_property: "prop_missing" });
  ok("a plane refusal keeps its typed code through the UI (never receipt_missing)",
    masked.status === 303 && masked.q.get("refused") === "ontology_ref_unresolved",
    masked.location.slice(0, 130));

  // -- denial ----------------------------------------------------------------
  const denied = await act("upsert-object-type", { ontology: "ont-does-not-exist", def_id: "x", name: "X" });
  ok("missing ontology denies with the typed refusal", denied.status === 303 && denied.q.get("refused") === "odk_ontology_not_found", denied.location.slice(0, 120));

  // -- read / search-filter / health / history -------------------------------
  const filtered = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}&section=object-types`);
  ok("Manager reads back the authored type through the canonical mount", filtered.status === 200 && filtered.text.includes("JourneyObject"), "");
  const scoped = await pageText(`/ontology/explore?ontology=${encodeURIComponent(ontId)}`);
  ok("Explorer scope selector resolves the ontology", scoped.status === 200 && scoped.text.includes(domain), "");
  const history = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}/history`);
  ok("history records the mutation trail", history.status === 200 && JSON.stringify(history.body).length > 2, `status ${history.status}`);
  const historyReceipts = Array.isArray(history.body?.receipts) ? history.body.receipts : [];
  ok("receipts bind the resolved acting principal (INV-37)",
    historyReceipts.length > 0 && historyReceipts.every((r) => typeof r.acting_principal_ref === "string" && r.acting_principal_ref.startsWith("user://")),
    historyReceipts[0]?.acting_principal_ref ?? "no receipts");
  const health = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}/health`);
  ok("health answers for the authored ontology", health.status === 200, `status ${health.status}`);

  // -- named gaps stay typed, never faked ------------------------------------
  const proposals = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}/proposals`);
  ok("proposal family absent — named gap typed, not simulated", proposals.status === 404 || proposals.status === 405, `status ${proposals.status}`);
  const savedSet = await jd("/v1/hypervisor/odk/materialized-object-sets", { method: "POST", body: JSON.stringify({ name: "x" }) });
  ok("saved-set authoring absent — named gap typed, not simulated", savedSet.status === 404 || savedSet.status === 405, `status ${savedSet.status}`);

  // -- identity gate (W1.1/G-2 finding CLOSED): anonymous authoring refuses typed ----
  // Rule E — the refusal is owed BEFORE any record load: the serve action lane without a
  // session and a direct daemon write without identity both answer the typed
  // request_principal_required, never a silent success and never a 404 existence oracle.
  const anonAct = await act("upsert-object-type", { ontology: ontId, def_id: "obj_anon", name: "Anon" }, { anonymous: true });
  ok("anonymous serve action refuses typed (request_principal_required, no receipt)",
    anonAct.status === 303 && anonAct.q.get("refused") === "request_principal_required" && !anonAct.q.get("acted") && !anonAct.q.get("receipt"),
    anonAct.location.slice(0, 130));
  const anonCreate = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: "anon-domain" }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  ok("anonymous direct daemon create answers typed 401 request_principal_required",
    anonCreate.status === 401 && anonCreate.body?.ok === false && anonCreate.body?.code === "request_principal_required",
    `status ${anonCreate.status} code ${anonCreate.body?.code}`);
  const anonPatch = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${ontId}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ description: "anon write" }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  ok("anonymous direct daemon patch answers typed 401 before the record load (rule E)",
    anonPatch.status === 401 && anonPatch.body?.code === "request_principal_required",
    `status ${anonPatch.status} code ${anonPatch.body?.code}`);
  const unchanged = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("anonymous attempts changed nothing", unchanged.status === 200 && unchanged.body?.ontology?.revision === expectedRev, `rev ${unchanged.body?.ontology?.revision}`);

  // -- restart survival -------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const afterRestart = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("ontology survives a daemon restart at the same revision",
    afterRestart.status === 200 && afterRestart.body?.ontology?.revision === expectedRev,
    `rev ${afterRestart.body?.ontology?.revision}, expected ${expectedRev}`);
  let receiptsAfter = 0;
  try { receiptsAfter = fs.readdirSync(path.join(dataDir, "odk-ontology-receipts")).length; } catch { receiptsAfter = -1; }
  ok("receipts survive the restart", receiptsAfter >= receiptCount && receiptCount > 0, `${receiptsAfter} receipts`);
  const reload = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}`);
  ok("canonical mount re-renders the authored ontology after restart", reload.status === 200 && reload.text.includes(domain), "");

  // -- G-8 posture matrix (browser) ------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}/ontology/schema?ontology=${encodeURIComponent(ontId)}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.includes(domain) && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
