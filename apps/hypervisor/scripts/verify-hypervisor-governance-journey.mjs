#!/usr/bin/env node
// SURF-governance primary journey verifier (next-legs Leg 3b).
//
// Proves, against an ISOLATED real daemon + serve lane, the decision journey the
// 2026-08-09 audit found unproven: submit exact request → deny/approve with a
// daemon-resolved reviewer (P-IDENT-1A: the UI sends NO fields on transitions) →
// decision receipt → readback → stale/withdrawn/terminal refusals typed → restart
// survival → no generic approval ever authorizes a substituted effect. Plus the
// #223 unified cross-plane inbox band and the G-8 posture matrix.
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-governance-journey-"));
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

const jd = (p, init) => fetch(`${DAEMON}${p}`, init ? { headers: { "content-type": "application/json" }, ...init } : undefined)
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

// The approvals module dispatches transitions on the legacy action lane; the UI
// posts NO reviewer fields — identity is daemon-derived from the forwarded
// session cookie (P-IDENT-1A + rule E: 401 before any effect), and confirm=1 is
// the explicit-confirmation contract for destructive transitions.
let SESSION = "";
async function transition(id, verb) {
  const r = await fetch(`${SERVE}/__ioi/governance/approvals/${id}/transition`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: new URLSearchParams({ transition: verb, confirm: "1" }).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "");
  return { status: r?.status ?? 0, location, q };
}

const submit = (subject, kind, reason) => jd("/v1/hypervisor/governance/approval-requests", {
  method: "POST",
  body: JSON.stringify({ subject_ref: subject, request_kind: kind, reason }),
});

const statusOf = async (id) => {
  const r = await jd(`/v1/hypervisor/governance/approval-requests/${id}`);
  return r.body?.approval_request?.status ?? r.body?.status ?? "";
};

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "governance-journey-bootstrap-v1", email: "governance-journey@ioi.local" }),
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
  await waitFor(`${SERVE}/governance/approvals`, 30000);

  // -- submit exact requests -------------------------------------------------
  const a = await submit("system:journey-alpha", "deployment_change", "approve-path fixture");
  const b = await submit("system:journey-beta", "deployment_change", "reject-path fixture");
  const c = await submit("system:journey-gamma", "deployment_change", "withdrawn-path fixture");
  const idA = a.body?.approval_request?.id ?? "";
  const idB = b.body?.approval_request?.id ?? "";
  const idC = c.body?.approval_request?.id ?? "";
  ok("three exact approval requests submit", idA && idB && idC, `${idA} ${idB} ${idC}`);

  // -- inbox projection + canonical render ----------------------------------
  const inbox = await jd("/v1/hypervisor/governance/approvals-inbox");
  const pendingTotal = inbox.body?.pending_total ?? inbox.body?.inbox?.pending_total ?? 0;
  ok("unified approvals-inbox counts the pending requests", inbox.status === 200 && pendingTotal >= 3, `pending_total ${pendingTotal}`);
  const canonical = await pageText("/governance/approvals");
  ok("canonical /governance/approvals renders rows + the cross-plane band",
    canonical.status === 200 && canonical.text.includes("ap-crossplane") && canonical.text.includes(idA),
    `status ${canonical.status}`);

  // -- approve: daemon-resolved reviewer, receipt, readback -------------------
  const approved = await transition(idA, "approve");
  ok("approve crosses with a decision receipt", approved.status === 303 && approved.q.get("acted") === "approve" && (approved.q.get("receipt") || "").length > 0, approved.location.slice(0, 130));
  ok("approved request reads back approved", (await statusOf(idA)) === "approved");
  const recA = await jd(`/v1/hypervisor/governance/approval-requests/${idA}`);
  const receipts = JSON.stringify(recA.body);
  ok("the decision is receipted on the record itself", receipts.includes("receipt"), "");

  // -- reject with readback ---------------------------------------------------
  const rejected = await transition(idB, "reject");
  ok("reject crosses with a decision receipt", rejected.status === 303 && rejected.q.get("acted") === "reject" && (rejected.q.get("receipt") || "").length > 0, rejected.location.slice(0, 130));
  ok("rejected request reads back rejected", (await statusOf(idB)) === "rejected");

  // -- terminal/stale transitions refuse typed --------------------------------
  const dblApprove = await transition(idB, "approve");
  ok("approving a terminal request refuses typed", dblApprove.status === 303 && (dblApprove.q.get("refused") || "").length > 0, dblApprove.location.slice(0, 130));

  // -- revoke an approved decision -------------------------------------------
  const revoked = await transition(idA, "revoke");
  ok("revoke crosses with a decision receipt", revoked.status === 303 && revoked.q.get("acted") === "revoke" && (revoked.q.get("receipt") || "").length > 0, revoked.location.slice(0, 130));
  ok("revoked request reads back revoked", (await statusOf(idA)) === "revoked");

  // -- withdrawn: decided elsewhere/deleted → typed refusal -------------------
  await jd(`/v1/hypervisor/governance/approval-requests/${idC}`, { method: "DELETE" });
  const stale = await transition(idC, "approve");
  ok("a withdrawn request refuses typed, never fabricates a decision", stale.status === 303 && (stale.q.get("refused") || "").length > 0, stale.location.slice(0, 130));

  // -- no generic approval: the decision bound exactly one subject ------------
  ok("no substituted effect: B stayed rejected and C stayed gone while A moved",
    (await statusOf(idB)) === "rejected" && (await statusOf(idC)) === "",
    "");

  // -- restart survival -------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  ok("decisions survive a daemon restart", (await statusOf(idA)) === "revoked" && (await statusOf(idB)) === "rejected", "");
  // The surface is an inbox: the default view is pending, decided rows live
  // under their status views (?status=...). Terminal rows render without
  // transition forms, so the subject + terminal marker is the render proof.
  let reload = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    await new Promise((r) => setTimeout(r, 1500));
    reload = await pageText("/governance/approvals?status=all");
    if (reload.status === 200 && reload.text.includes("journey-alpha")) break;
  }
  ok("canonical mount re-renders decided state after restart (status=all view)",
    reload.status === 200 && reload.text.includes("journey-alpha") && reload.text.includes("journey-beta"),
    `status ${reload.status}`);
  const revokedView = await pageText("/governance/approvals?status=revoked");
  ok("the revoked status view lists exactly the revoked decision",
    revokedView.status === 200 && revokedView.text.includes("journey-alpha") && !revokedView.text.includes("journey-beta"),
    "");

  // -- G-8 posture matrix -----------------------------------------------------
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
      const resp = await page.goto(`${SERVE}/governance/approvals`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
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
