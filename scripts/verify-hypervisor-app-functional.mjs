#!/usr/bin/env node
// Functional-app done-bar: drives the SERVED reference UX (:4173) end-to-end via Playwright and
// proves the real loop the product promises —
//   compose a task on /ai → spin up a (local) environment → the agent performs the task over the
//   designated harness (writes real files into the env workspace) → open the visual code editor
//   (real openvscode-server bound to that workspace).
//
// Every assertion is a REAL effect (daemon truth on disk + a live editor HTTP 200), not a UI mock.
// Requires: serve-live-reference (:4173), hypervisor-daemon (:8765), and a local model
// (Ollama on :11434 with IOI_HYPERVISOR_MODEL). Missing model ⇒ BLOCKED (named host gap), not fail.
//
// Usage: node scripts/verify-hypervisor-app-functional.mjs [--json]
import fs from "node:fs";
import os from "node:os";

const JSON_OUT = process.argv.includes("--json");
const REF = process.env.IOI_REFERENCE_URL || "http://127.0.0.1:4173";
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const MODEL_UPSTREAM = process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "http://127.0.0.1:11434/v1";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${os.homedir()}/.ioi/hypervisor/data`;
// Deterministic single-file task: the done-bar proves the agent writes a REAL file via the harness,
// not the local model's website-generation quality (a multi-file prompt is model-timing-flaky).
const TASK = "Create an index.html file with a short heading about post-quantum computers.";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "app-functional", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };

if (!JSON_OUT) console.log("App-functional e2e — compose → environment → agent harness → editor");

// ---- preflight ----
const up = async (url) => { try { const r = await fetch(url, { signal: AbortSignal.timeout(3000) }); return r.ok; } catch { return false; } };
if (!(await up(`${REF}/__ioi/fallthrough`))) blocked("serve-live-reference (:4173) not running — `npm run serve:reference --workspace=@ioi/hypervisor-app`");
if (!(await up(`${DAEMON}/v1/hypervisor/providers`))) blocked("hypervisor-daemon (:8765) not running");
let modelOk = false;
try {
  const r = await fetch(`${MODEL_UPSTREAM.replace(/\/v1\/?$/, "")}/api/tags`, { signal: AbortSignal.timeout(3000) });
  modelOk = r.ok && (((await r.json()).models || []).length > 0);
} catch { modelOk = false; }
if (!modelOk) blocked(`local model not reachable at ${MODEL_UPSTREAM} — start Ollama and pull a model (e.g. \`ollama pull qwen2.5:7b\`); set IOI_HYPERVISOR_MODEL`);

let chromium;
try { ({ chromium } = await import("playwright")); } catch { blocked("playwright not installed"); }

const b = await chromium.launch({ headless: true });
let envId = null;
try {
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  // JS/page errors (real bugs) vs failing request URLs (network). Network "Failed to load resource"
  // lines carry no URL, so attribute network failures by URL. The reference may probe optional
  // supervisor files before they exist; those 404s are normal empty states.
  const errs = [];
  p.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource|WebSocket connection/i.test(m.text())) errs.push(m.text()); });
  p.on("pageerror", (e) => errs.push("pageerror: " + e.message));
  const failedUrls = [];
  p.on("response", (r) => { if (r.status() >= 400) failedUrls.push(r.url()); });
  p.on("requestfailed", (r) => failedUrls.push(r.url()));
  const cdn = new Set();
  p.on("request", (r) => { try { if (new URL(r.url()).host === "app.gitpod.io") cdn.add(r.url()); } catch { /* ignore */ } });
  const isErrorBoundary = async () => /Something went wrong|ran into a hiccup/i.test(await p.evaluate(() => document.body?.innerText || ""));

  // 1) Compose a task on /ai, choose the local env class, submit.
  await p.goto(`${REF}/ai`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await p.waitForTimeout(4000);
  await p.locator('textarea,[contenteditable="true"]').first().fill(TASK).catch(() => {});
  await p.waitForTimeout(300);
  await p.getByText("Work in a project", { exact: false }).first().click({ timeout: 5000 }).catch(() => {});
  await p.waitForTimeout(600);
  await p.getByText(/Start from scratch/i).first().click({ timeout: 4000 }).catch(() => {});
  await p.waitForTimeout(1200);
  await p.getByText(/Local Workspace \(v0\)/).first().click({ timeout: 4000, force: true }).catch(() => {});
  await p.waitForTimeout(800);
  const submitEnabled = (await p.locator('[data-testid="prompt-input-submit-button"]').isDisabled().catch(() => true)) === false;
  ok(submitEnabled, "composer: env class is selectable and submit enables (no 'Unsupported' gate)");
  await p.locator('[data-testid="prompt-input-submit-button"]').click({ timeout: 4000 }).catch(() => {});
  await p.waitForURL(/\/details\//, { timeout: 90000 }).catch(() => {});

  // 2) Navigated to the environment workbench, not an error boundary.
  envId = (p.url().match(/details\/([^/?#]+)/) || [])[1] || null;
  ok(!!envId, "compose navigates to the environment workbench /details/:envId", p.url());
  ok(!(await isErrorBoundary()), "workbench renders (not the 'Something went wrong' error boundary)");

  // 3) REAL EFFECT: the agent harness writes a real file into the env workspace (daemon truth on disk).
  const ws = envId ? `${DATA_DIR}/environments/${envId}/workspace` : null;
  let fileSeen = false;
  for (let i = 0; i < 90 && ws; i++) {
    if (fs.existsSync(`${ws}/index.html`)) { fileSeen = true; break; }
    await new Promise((r) => setTimeout(r, 2000));
  }
  ok(fileSeen, "REAL EFFECT: the agent harness produced index.html in the env workspace", ws ? (fs.existsSync(ws) ? fs.readdirSync(ws).join(",") : "no workspace") : "");

  // 3b) REAL EFFECT: the env was scaffolded with the default Dev Container baseline.
  ok(ws && fs.existsSync(`${ws}/.devcontainer/devcontainer.json`) && fs.existsSync(`${ws}/.devcontainer/Dockerfile`),
    "REAL EFFECT: env scaffolded with .devcontainer/{devcontainer.json,Dockerfile}");

  // 3c) UX EFFECT: the workbench conversation surface is now Hypervisor's OWNED Run Timeline (the
  // borrowed chat pane is replaced in-pane by an iframe to /__ioi/run-timeline). Read the owned
  // timeline's content for the conversation assertions — it must resolve the run into a completed
  // response (no stuck 'Thinking', no retry loop).
  let convText = "";
  for (let i = 0; i < 12; i++) {
    await p.waitForTimeout(1500);
    const frame = p.frames().find((f) => /\/__ioi\/run-timeline\//.test(f.url()));
    if (frame) { try { convText = await frame.evaluate(() => document.body?.innerText || ""); } catch { /* iframe navigating */ } }
    if (/Generated|Created|Wrote|Run complete|Changed files/i.test(convText)) break;
  }
  ok(!/Retrying in|Stream closed unexpectedly/i.test(convText),
    "owned Run Timeline: no retry/stream-closed error");
  ok(!/Thinking/i.test(convText),
    "owned Run Timeline: no stuck 'Thinking' placeholder");
  ok(/Generated|Created|Wrote|Run complete|Changed files/i.test(convText),
    "owned Run Timeline renders the completed agent response", convText.replace(/\s+/g, " ").slice(0, 160));

  // 4) The visual code editor opens AND RENDERS against that workspace (real openvscode-server) —
  // load it in a real browser and assert the Monaco workbench mounts + shows the scaffolded files
  // (not just that the HTML shell is served).
  if (envId) {
    const r = await fetch(`${REF}/__ioi/editor/open?environmentId=${envId}`, { redirect: "manual" });
    const loc = r.headers.get("location");
    let rendered = false, treeOk = false;
    if (loc) {
      try {
        const ep = await b.newPage({ viewport: { width: 1440, height: 900 } });
        await ep.goto(loc, { waitUntil: "domcontentloaded", timeout: 30000 });
        await ep.waitForFunction(() => !!document.querySelector(".monaco-workbench"), { timeout: 30000 }).catch(() => {});
        rendered = await ep.evaluate(() => !!document.querySelector(".monaco-workbench"));
        // The explorer tree populates after the workbench mounts — wait for the scaffolded file label.
        await ep.waitForFunction(() => /devcontainer/i.test(document.body?.innerText || ""), { timeout: 25000 }).catch(() => {});
        treeOk = await ep.evaluate(() => /devcontainer|Dockerfile/i.test(document.body?.innerText || ""));
        await ep.close();
      } catch { /* ignore */ }
    }
    ok(rendered, "editor Open-in renders a live VS Code Browser workbench (openvscode-server)", loc || `status ${r.status}`);
    ok(treeOk, "editor shows the env workspace files (.devcontainer in the explorer)");
  }

  // 4c) The conversation transcript serves the agent's REAL work (not an empty pane). The SPA's v1
  // conversation pane fetches the bare conversationUrl as finite NDJSON (text/todoGroup entries); we
  // build it from the run, so it shows the agent's summary + the files it wrote.
  if (envId) {
    const list = await fetch(`${REF}/api/gitpod.v1.AgentService/ListAgentExecutions`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((r) => r.json()).catch(() => ({}));
    const mine = (list.agentExecutions || list.executions || []).find((x) => (x.status?.usedEnvironments || []).some((u) => u.environmentId === envId));
    const convoUrl = mine?.status?.conversationUrl;
    // The conversation is a long-lived NDJSON stream (held open so the SPA's reader never sees an
    // unexpected EOF → no "Retrying" loop). Read a bounded prefix, then abort.
    let convo = "";
    if (convoUrl) {
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 4000);
        const r = await fetch(`${REF}${convoUrl}`, { signal: ctrl.signal });
        const reader = r.body.getReader();
        const dec = new TextDecoder();
        const deadline = Date.now() + 4000;
        while (Date.now() < deadline) {
          const { done, value } = await reader.read();
          if (done) break;
          convo += dec.decode(value, { stream: true });
          if (convo.includes("\"userInput\"")) break;
        }
        clearTimeout(t); ctrl.abort();
      } catch { /* aborted — expected for a held-open stream */ }
    }
    ok(convoUrl && /"userInput"|"text"|"content"/.test(convo), "conversation transcript serves the agent's real work (not an empty pane)", convo.slice(0, 60).replace(/\n/g, " "));
  }

  // 5) No console/page errors; app stays self-contained (no external CDN).
  ok(errs.length === 0, "zero JS/page errors across the flow", errs.slice(0, 2).join("; "));
  const unexpectedFailures = failedUrls.filter((u) => !/supervisor\/.*\/ReadFile/i.test(u));
  ok(unexpectedFailures.length === 0, "no failing requests beyond optional supervisor file probes", unexpectedFailures.slice(0, 3).join(" | "));
  ok(cdn.size === 0, "app is self-contained (zero external app.gitpod.io CDN requests)", [...cdn].slice(0, 2).join(", "));
} finally {
  await b.close();
}

const verdict = failures > 0 ? "FAIL" : "PASS";
const report = { workstream: "app-functional", verdict, failures, checks: checks.length, envId };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
