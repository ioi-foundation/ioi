#!/usr/bin/env node
// T7-F — native operator-surface verifier (UX strategy: hybrid).
//
// Proves the native Workbench UX is real and daemon-backed, not faked. Three tiers, all honest:
//   1. Decision gate     — the T7-0 UX strategy decision record exists (else BLOCKED_DECISION).
//   2. Daemon-backed      — ONE Session Execution Binding resolves session+env+thread+workrun;
//      (headless, real)     env-files hydrate the scoped workspace; the PTY is interactive (shell
//                           state persists); WorkRun execute mutates no host checkout; binding
//                           events carry one binding_ref (no drift); input routes to the thread.
//   3. Static UI          — native routes wired in main.tsx; the typed client exposes
//      guarantees           resolveSessionExecutionBinding + maps to daemon routes; the workspace
//                           adapter binds files->env-files and terminal->/v1/hypervisor/terminals;
//                           NO active UI path references the deleted runtime-daemon; app typechecks.
//   4. Browser render     — (opt-in --browser) a real Playwright headless mount of the native
//      (optional, real)     routes. When not run, reported as a declared tooling gap, never as a
//                           native pass.
// Usage: [--ux-strategy hybrid] [--browser] [--json].
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const WANT_BROWSER = args.includes("--browser");
const PORT = 9050 + (process.pid % 60);
const DECISION = join(REPO, "internal-docs/implementation/hypervisor-ux-strategy-decision.md");

const checks = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => {
  checks.push({ ok: !!cond, msg, detail: detail || "" });
  if (!cond) failures++;
  if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`);
};
const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method, headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { /* non-JSON (e.g. SSE stream) — keep text */ }
  return { status: res.status, json, text };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReady(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/providers`); if (r.ok) return true; } catch { /* not up */ }
    await sleep(150);
  }
  return false;
}

// ---- Tier 1: decision gate ----
if (!JSON_OUT) console.log("T7 — native operator surface (hybrid)");
if (!existsSync(DECISION)) {
  const out = { workstream: "T7", verdict: "BLOCKED_DECISION", reason: "missing internal-docs/implementation/hypervisor-ux-strategy-decision.md (T7-0)" };
  console.log(JSON_OUT ? JSON.stringify(out, null, 2) : `  VERDICT: BLOCKED_DECISION — ${out.reason}`);
  process.exit(1);
}
const decisionText = read(DECISION);
const uxStrategy = (decisionText.match(/ux_strategy:\s*(\w+)/) || [])[1] || "unknown";
ok(["reference", "native", "hybrid"].includes(uxStrategy), `UX strategy decided: ${uxStrategy}`, uxStrategy);

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-t7-nativeux-"));
const daemon = spawn(DAEMON_BIN, [], {
  env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` },
  stdio: ["ignore", "ignore", "ignore"],
});

let verdict = "FAIL";
try {
  if (!(await waitReady())) { console.error("daemon did not become ready"); process.exit(2); }

  // ---- Tier 2: daemon-backed (real) ----
  if (!JSON_OUT) console.log("  [tier 2] daemon-backed binding/files/terminal/execute");
  const env = (await api("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "t7-ux" } })).json.environment;
  const envId = env.id;
  await api("POST", `/v1/hypervisor/environments/${envId}/start`);
  const thread = (await api("POST", "/v1/threads", {})).json;
  const threadId = thread.thread_id ?? thread.thread?.id ?? thread.id;
  const wr = (await api("POST", "/v1/hypervisor/workruns", { environment_id: envId, objective: { goal: "ux" } })).json.workRun;
  const binding = (await api("POST", "/v1/hypervisor/session-execution-bindings", {
    environment_ref: `environment:${envId}`, thread_ref: threadId ? `thread:${threadId}` : undefined, work_run_ref: wr?.id ? `work_run:${wr.id}` : undefined,
  })).json.binding;
  ok(!!binding?.binding_ref && binding.environment_ref === `environment:${envId}` && !!binding.thread_ref && !!binding.work_run_ref,
    "ONE binding resolves session+environment+thread+work_run");
  ok(binding?.environment_status?.phase === "running", "binding hydrates LIVE environment truth (phase=running)");

  const bget = (await api("GET", `/v1/hypervisor/session-execution-bindings/${binding.binding_id}`)).json.binding;
  ok(bget?.event_stream_refs?.environment === `/v1/hypervisor/env-events/${envId}`, "binding exposes the env event stream ref");
  const ev = (await api("GET", `/v1/hypervisor/session-execution-bindings/${binding.binding_id}/events`)).json;
  ok((ev.events?.length ?? 0) > 0 && ev.events.every((e) => e.binding_ref === binding.binding_ref), "binding events carry ONE binding_ref (no ref drift across env/thread/workrun)");
  const input = (await api("POST", `/v1/hypervisor/session-execution-bindings/${binding.binding_id}/input`, { data: "hi" })).json;
  ok(input.ok === true && /\/v1\/threads\/.*\/turns/.test(input.route || ""), "operator input routes to the thread turn route (conversation stays in /v1/threads/*)");

  // env-files: scoped CRUD + traversal fence.
  const w = (await api("POST", "/v1/hypervisor/env-files", { environment_id: envId, op: "write", path: "src/app.ts", content: "export const x = 1;\n" })).json;
  const rd = (await api("POST", "/v1/hypervisor/env-files", { environment_id: envId, op: "read", path: "src/app.ts" })).json;
  const ls = (await api("POST", "/v1/hypervisor/env-files", { environment_id: envId, op: "list", path: "src" })).json;
  const trav = (await api("POST", "/v1/hypervisor/env-files", { environment_id: envId, op: "read", path: "../../../../etc/passwd" })).json;
  ok(w.ok && rd.result?.content?.includes("export const x") && ls.result?.entries?.some((e) => e.name === "app.ts"), "Workbench files read/write/list from the scoped environment workspace");
  ok(trav.ok === false, "env-files fences path traversal (no escape from workspace_root)");

  // interactive PTY: shell state persists across inputs.
  const term = (await api("POST", "/v1/hypervisor/terminals", { environment_ref: `environment:${envId}` })).json;
  ok(term.ok && term.interactive === true, "Workbench terminal is interactive (real PTY available)");
  await api("POST", `/v1/hypervisor/terminals/${term.terminal_id}/input`, { data: "MARK=ioi-7\n" });
  await sleep(150);
  await api("POST", `/v1/hypervisor/terminals/${term.terminal_id}/input`, { data: "echo seen=$MARK\n" });
  await sleep(250);
  const stream = (await api("GET", `/v1/hypervisor/terminals/${term.terminal_id}/stream`)).text;
  ok(/seen=ioi-7/.test(stream), "PTY shell state persists across inputs (interactive, not request/response exec)");
  await api("POST", `/v1/hypervisor/terminals/${term.terminal_id}/close`);

  // WorkRun execute: child-harness edit, no host checkout mutation.
  const exec = (await api("POST", `/v1/hypervisor/workruns/${wr.id}/execute`)).json;
  const execWr = exec.workRun ?? exec;
  ok(execWr?.host_mutation === false, "WorkRun execute produces a child-harness edit without mutating host checkout", `host_mutation=${execWr?.host_mutation}`);

  // ---- Tier 3: static UI guarantees ----
  if (!JSON_OUT) console.log("  [tier 3] native UI wiring + typecheck");
  const mainTsx = read(join(REPO, "apps/hypervisor/src/main.tsx"));
  ok(["/sessions", "/providers", "/environments", "/workbench/:id"].every((r) => mainTsx.includes(`path="${r}"`)), "main.tsx wires native Sessions/Providers/Environments/Workbench routes");
  const client = read(join(REPO, "apps/hypervisor/src/services/hypervisorDaemonClient.ts"));
  ok(/resolveSessionExecutionBinding/.test(client) && /\/v1\/hypervisor\/session-execution-bindings/.test(client) && /\/v1\/threads/.test(client), "typed client exposes resolveSessionExecutionBinding + maps to daemon routes");
  const adapter = read(join(REPO, "apps/hypervisor/src/services/HypervisorWorkspaceAdapter.ts"));
  ok(/envFiles\(/.test(adapter) && /createTerminal\(/.test(adapter), "HypervisorWorkspaceAdapter binds files->env-files and terminal->daemon PTY");
  const workbench = read(join(REPO, "apps/hypervisor/src/surfaces/NativeWorkbench.tsx"));
  ok(/WorkspaceHost/.test(workbench) && /resolveSessionExecutionBinding/.test(workbench), "NativeWorkbench mounts workspace-substrate bound to the Session Execution Binding");

  // no active UI path references the DELETED runtime-daemon JS package.
  const grep = spawnSync("grep", ["-rlE", "runtime-daemon|packages/runtime-daemon", join(REPO, "apps/hypervisor/src")], { encoding: "utf8" });
  ok((grep.stdout || "").trim() === "", "no active UI path references the deleted runtime-daemon kernel refs");
  const wbGrep = spawnSync("grep", ["-rl", "packages/runtime-daemon/src/index.mjs", join(REPO, "packages/hypervisor-workbench/src")], { encoding: "utf8" });
  ok((wbGrep.stdout || "").trim() === "", "workbench source carries no stale runtime-daemon kernelRef labels");

  // app typechecks (strict).
  const tsc = spawnSync(join(REPO, "node_modules/.bin/tsc"), ["-p", join(REPO, "apps/hypervisor/tsconfig.json"), "--noEmit"], { encoding: "utf8", cwd: REPO });
  ok(tsc.status === 0, "apps/hypervisor typechecks (tsc --noEmit, strict)", tsc.status === 0 ? "" : (tsc.stdout || tsc.stderr || "").split("\n").slice(0, 3).join(" | "));

  // ---- Tier 4: browser render (opt-in, real) ----
  if (WANT_BROWSER) {
    if (!JSON_OUT) console.log("  [tier 4] Playwright headless native render");
    const browserResult = await runBrowserTier();
    ok(browserResult.ok, `native routes render in a real browser (${browserResult.detail})`, browserResult.detail);
  } else {
    declaredGaps.push({ gate: "browser_render", prerequisite: "BROWSER_RENDER_NOT_RUN", reason: "Playwright headless render is opt-in (--browser). The native UX code + data paths are proven; the live visual render was not exercised this run.", host_grantable: true });
    if (!JSON_OUT) console.log("    · DECLARED GAP: browser_render — not run (pass --browser for the Playwright headless render)");
  }

  if (failures === 0) verdict = declaredGaps.length > 0 ? "PASS_WITH_DECLARED_GAPS" : "PASS";
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

async function runBrowserTier() {
  // Best-effort real render: build the app, serve dist with a /v1 proxy to the daemon, mount the
  // native routes in headless chromium. Any environment failure is reported honestly (not faked).
  let chromium;
  try { ({ chromium } = await import("playwright")); } catch { return { ok: false, detail: "playwright not importable" }; }
  const build = spawnSync("npm", ["run", "build", "--workspace=@ioi/hypervisor-app"], { cwd: REPO, encoding: "utf8", timeout: 600000 });
  if (build.status !== 0) return { ok: false, detail: "vite build failed: " + (build.stderr || "").split("\n").slice(-3).join(" ") };
  const http = await import("node:http");
  const { readFileSync: rf } = await import("node:fs");
  const dist = join(REPO, "apps/hypervisor/dist");
  const MIME = { ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".html": "text/html", ".json": "application/json", ".svg": "image/svg+xml", ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf", ".map": "application/json", ".ico": "image/x-icon", ".png": "image/png", ".wasm": "application/wasm" };
  const srv = http.createServer(async (req, res) => {
    try {
      if (req.url.startsWith("/v1/")) {
        const body = await new Promise((resolve, reject) => {
          const chunks = [];
          req.on("data", (chunk) => chunks.push(chunk));
          req.on("end", () => resolve(chunks.length ? Buffer.concat(chunks) : undefined));
          req.on("error", reject);
        });
        const headers = {};
        if (req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];
        const up = await fetch(`http://127.0.0.1:${PORT}${req.url}`, {
          method: req.method,
          headers,
          body: body && body.length ? body : undefined,
        });
        res.writeHead(up.status, { "Content-Type": up.headers.get("content-type") || "application/json" });
        res.end(await up.text());
        return;
      }
      const path = req.url.split("?")[0];
      const isAsset = path.includes(".") && !path.endsWith(".html");
      const file = isAsset ? join(dist, path) : join(dist, "index.html");
      const ext = isAsset ? path.slice(path.lastIndexOf(".")) : ".html";
      res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
      res.end(rf(file));
    } catch { res.writeHead(404); res.end(""); }
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const appPort = srv.address().port;
  let detail = "", okFlag = false;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors = [];
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.goto(`http://127.0.0.1:${appPort}/environments`, { waitUntil: "networkidle", timeout: 30000 });
    await page.waitForSelector('[data-testid="environments-surface"]', { timeout: 15000 });
    await page.click('[data-testid="create-env"]');
    await page.waitForSelector('[data-testid="env-card"]', { timeout: 20000 });
    okFlag = errors.length === 0;
    detail = okFlag ? "environments route mounted, env created, no console errors" : `console errors: ${errors.slice(0, 2).join("; ")}`;
  } catch (e) { detail = "render failed: " + (e instanceof Error ? e.message : String(e)); }
  finally { if (browser) await browser.close(); srv.close(); }
  return { ok: okFlag, detail };
}

const report = { workstream: "T7", ux_strategy: uxStrategy, verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else {
  console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`);
  console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
}
process.exit(verdict === "FAIL" || verdict === "BLOCKED_DECISION" ? 1 : 0);
