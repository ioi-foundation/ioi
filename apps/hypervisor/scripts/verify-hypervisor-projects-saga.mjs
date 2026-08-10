#!/usr/bin/env node
// SURF-projects saga verifier (next-legs Leg 4, OQ-5 ruling).
//
// Proves, against an ISOLATED real daemon + serve lane, that project creation is
// an explicit resumable saga: step 1 (CreateProject) commits durably; step 2
// (UpdateProjectEnvironmentClasses) is a receipted, CAS-guarded, idempotent
// durable step with identity-first refusals; every refusal names the exact
// preserved partial state; and the audit's observed journey — CreateProject 200
// → binding 501 → stuck form — is REPRODUCIBLY DEAD at the RPC seam.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-projects-saga-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

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

const jd = (p, init, cookie = false) => fetch(`${DAEMON}${p}`, {
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

// The SPA seam: RPCs against the serve lane's /api adapter, with the browser's
// session cookie so the adapter's identity forwarding is exercised end-to-end.
const rpc = (op, body) => fetch(`${SERVE}/api/ioi.v1.ProjectService/${op}`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "projects-saga-bootstrap-v1", email: "projects-saga@ioi.local" }),
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
  await waitFor(`${SERVE}/projects`, 30000);

  // -- saga step 1: create commits durably -----------------------------------
  const created = await rpc("CreateProject", {
    name: "saga-journey",
    initializer: { specs: [{ git: { remoteUri: "https://example.invalid/saga/journey.git" } }] },
  });
  const projectId = created.body?.project?.id || created.body?.project?.projectId || "";
  ok("saga step 1: CreateProject commits", created.status === 200 && projectId.length > 0, `status ${created.status} id ${projectId}`);
  const durable = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`);
  ok("step 1 is durable daemon truth", durable.status === 200 && durable.body?.ok === true, "");

  // -- the audit's dead journey: binding no longer 501s ----------------------
  const bind = await rpc("UpdateProjectEnvironmentClasses", {
    projectId,
    environmentClassIds: ["local-workspace-v0"],
  });
  ok("saga step 2: binding crosses with a receipt (the 501 journey is DEAD)",
    bind.status === 200 && (bind.body?.receiptRef || "").startsWith("agentgres://project-receipts/"),
    `status ${bind.status} receipt ${bind.body?.receiptRef ?? ""} ${JSON.stringify(bind.body).slice(0, 120)}`);
  const bound = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`);
  const rec = bound.body?.project ?? {};
  ok("binding reads back: classes, revision 2, saga state, receipted history",
    JSON.stringify(rec.environment_class_ids) === JSON.stringify(["local-workspace-v0"]) &&
      rec.revision === 2 && rec.saga_state === "environment_classes_bound" &&
      (rec.history ?? []).some((h) => String(h.receipt_ref ?? "").includes("project-receipts")),
    `rev ${rec.revision} state ${rec.saga_state}`);

  // -- idempotent replay ------------------------------------------------------
  const replay = await rpc("UpdateProjectEnvironmentClasses", { projectId, environmentClassIds: ["local-workspace-v0"] });
  const after = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`);
  ok("an identical re-bind replays the stored receipt (no second truth)",
    replay.status === 200 && replay.body?.receiptRef === bind.body?.receiptRef && after.body?.project?.revision === 2,
    `receipt ${replay.body?.receiptRef ?? ""} rev ${after.body?.project?.revision}`);

  // -- typed refusal preserves the exact partial state ------------------------
  const refused = await rpc("UpdateProjectEnvironmentClasses", { projectId, environmentClassIds: ["not-a-class"] });
  const preserved = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`);
  ok("an unknown class refuses typed and preserves the durable partial state",
    refused.status === 422 && refused.body?.code === "environment_class_unknown" &&
      preserved.body?.project?.revision === 2 &&
      JSON.stringify(preserved.body?.project?.environment_class_ids) === JSON.stringify(["local-workspace-v0"]),
    `status ${refused.status} code ${refused.body?.code}`);

  // -- CAS guards the step ----------------------------------------------------
  const stale = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}/environment-classes`, {
    method: "PATCH",
    body: JSON.stringify({ expected_revision: 1, environment_class_ids: ["devcontainer"] }),
  }, true);
  ok("a stale expected_revision refuses with the typed conflict",
    stale.status === 409 && stale.body?.code === "project_revision_conflict" && stale.body?.current_revision === 2,
    `status ${stale.status}`);

  // -- identity-first (rule E): no session -> refusal BEFORE the 404 oracle ---
  const anon = await jd(`/v1/hypervisor/projects/does-not-exist/environment-classes`, {
    method: "PATCH",
    body: JSON.stringify({ environment_class_ids: ["local-workspace-v0"] }),
  }, false);
  ok("an unauthenticated binding refuses identity-first (never a 404 oracle)",
    (anon.status === 401 || anon.status === 403) && anon.body?.ok === false,
    `status ${anon.status} code ${anon.body?.code ?? ""}`);

  // -- restart survival -------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const revived = await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`);
  ok("the bound saga state survives a daemon restart",
    revived.body?.project?.revision === 2 &&
      JSON.stringify(revived.body?.project?.environment_class_ids) === JSON.stringify(["local-workspace-v0"]),
    `rev ${revived.body?.project?.revision}`);
  const receipts = await (async () => {
    try { return fs.readdirSync(path.join(dataDir, "project-receipts")).length; } catch { return -1; }
  })();
  ok("the binding receipt is a durable record", receipts >= 1, `${receipts} receipts`);
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
