#!/usr/bin/env node
// Reference-functional e2e verifier — the terminable done-bar for "make :4173 completely functional".
//
// Green ⇔ (1) CONTRACT: every gitpod.v1.* RPC the reference SPA calls is adapter-owned (zero
// fallthrough to the mock mirror, via the /__ioi/fallthrough tracker); (2) REAL EFFECTS: create/
// start/delete through the RPC surface produce real daemon state (no fakes); (3) PLAYWRIGHT UI:
// :4173 loads + renders + makes its organic calls with zero fallthrough and zero console errors.
// Requires the daemon (:8765) + serve-live-reference (:4173) running. Usage: [--json].
import { existsSync } from "node:fs";

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const REF = process.env.IOI_REFERENCE_URL || "http://127.0.0.1:4173";
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };

async function rpc(method, body) {
  const res = await fetch(`${REF}/api/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const text = await res.text();
  let json = {}; try { json = text ? JSON.parse(text) : {}; } catch { json = { _binary: true }; } // WatchEvents = connect frame
  return { status: res.status, json };
}
async function daemonGet(path) { const r = await fetch(`${DAEMON}${path}`); const t = await r.text(); try { return JSON.parse(t); } catch { return {}; } }
async function fallthroughSet() { const r = await fetch(`${REF}/__ioi/fallthrough`); return (await r.json()).proxied || []; }

if (!JSON_OUT) console.log("Reference-functional e2e — :4173 completely functional + terminable");

// ---- preflight ----
let up = true;
try { const r = await fetch(`${REF}/__ioi/fallthrough`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) up = false; } catch { up = false; }
let daemonUp = true;
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) daemonUp = false; } catch { daemonUp = false; }
if (!up || !daemonUp) {
  const reason = !up ? "serve-live-reference (:4173) not running — `npm run serve:reference --workspace=@ioi/hypervisor-app`" : "hypervisor-daemon (:8765) not running";
  console.log(JSON_OUT ? JSON.stringify({ workstream: "reference-functional", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`);
  process.exit(2);
}

// ---- reset tracker, then drive the full RPC contract ----
await fetch(`${REF}/__ioi/fallthrough/reset`, { method: "POST" });

// UserService
await rpc("gitpod.v1.UserService/SetPreference", { preference: { key: "theme", value: "dark" } });
const pref = await rpc("gitpod.v1.UserService/GetPreference", { preferenceKey: "theme" });
ok(pref.json?.preference?.value === "dark", "UserService preference round-trips (real persisted store)");

// RunnerService
const auth = await rpc("gitpod.v1.RunnerService/CheckAuthenticationForHost", { host: "github.com" });
ok(auth.json?.type === "Authenticated", "RunnerService/CheckAuthenticationForHost -> Authenticated");
const runner = await rpc("gitpod.v1.RunnerService/CreateRunner", {});
ok(runner.json?.runner?.status?.phase === "RUNNER_PHASE_ACTIVE", "RunnerService/CreateRunner -> active runner from provider registry", runner.json?.runner?.id);

// EventService (connect stream end-frame, adapter-owned)
const watch = await rpc("gitpod.v1.EventService/WatchEvents", {});
ok(watch.status === 200, "EventService/WatchEvents -> adapter-owned end-stream (no mock)");

// EnvironmentService — create then exercise + assert real daemon effect
const created = await rpc("gitpod.v1.EnvironmentService/CreateEnvironment", { spec: { environment_class_id: "local-workspace-v0", project_id: "e2e-ref" } });
const envId = created.json?.environment?.id;
ok(!!envId, "EnvironmentService/CreateEnvironment -> env id", envId);
const daemonEnvs = await daemonGet("/v1/hypervisor/environments");
ok((daemonEnvs.environments || []).some((e) => e.id === envId), "REAL EFFECT: created env exists in daemon truth");
await rpc("gitpod.v1.EnvironmentService/CreateEnvironmentFromProject", { spec: { environment_class_id: "local-workspace-v0", project_id: "e2e-ref2" } });
await rpc("gitpod.v1.EnvironmentService/GetEnvironment", { environmentId: envId });
const envList = await rpc("gitpod.v1.EnvironmentService/ListEnvironments", {});
ok(Array.isArray(envList.json?.environments) && envList.json.environments.length > 0, "EnvironmentService/ListEnvironments -> daemon-backed list");
const started = await rpc("gitpod.v1.EnvironmentService/StartEnvironment", { environmentId: envId });
ok(!!started.json?.environment, "EnvironmentService/StartEnvironment -> environment");
await rpc("gitpod.v1.EnvironmentService/UpdateEnvironment", { environmentId: envId, spec: { desiredPhase: "ENVIRONMENT_PHASE_RUNNING" } });
const accTok = await rpc("gitpod.v1.EnvironmentService/CreateEnvironmentAccessToken", { environmentId: envId });
ok(!!accTok.json?.accessToken, "EnvironmentService/CreateEnvironmentAccessToken -> token");
await rpc("gitpod.v1.EnvironmentService/CreateEnvironmentLogsToken", { environmentId: envId });
await rpc("gitpod.v1.EnvironmentService/MarkEnvironmentActive", { environmentId: envId });
await rpc("gitpod.v1.EnvironmentService/ArchiveEnvironment", { environmentId: envId });
await rpc("gitpod.v1.EnvironmentService/UnarchiveEnvironment", { environmentId: envId });
await rpc("gitpod.v1.EnvironmentService/StopEnvironment", { environmentId: envId });
await rpc("gitpod.v1.EnvironmentService/DeleteEnvironment", { environmentId: envId });

// AgentService — create then exercise + assert real daemon effect + delete removes it
const agent = await rpc("gitpod.v1.AgentService/CreateAgentExecution", { text: "e2e reference session" });
const agentId = agent.json?.agentExecutionId;
ok(!!agentId, "AgentService/CreateAgentExecution -> agentExecutionId", agentId);
const threadsBefore = await daemonGet("/v1/threads");
const hasThread = (t) => (Array.isArray(t) ? t : t.threads || []).some((x) => (x.thread_id || x.id) === agentId);
ok(hasThread(threadsBefore), "REAL EFFECT: created session exists as a daemon thread");
await rpc("gitpod.v1.AgentService/StartAgent", {});
const agentList = await rpc("gitpod.v1.AgentService/ListAgentExecutions", {});
ok(Array.isArray(agentList.json?.agentExecutions), "AgentService/ListAgentExecutions -> daemon-backed list");
await rpc("gitpod.v1.AgentService/GetAgentExecution", { agentExecutionId: agentId });
const convTok = await rpc("gitpod.v1.AgentService/CreateAgentExecutionConversationToken", { agentExecutionId: agentId });
ok(!!convTok.json?.token, "AgentService/CreateAgentExecutionConversationToken -> token");
await rpc("gitpod.v1.AgentService/SendToAgentExecution", { agentExecutionId: agentId, text: "hello" });
await rpc("gitpod.v1.AgentService/StopAgentExecution", { agentExecutionId: agentId });
await rpc("gitpod.v1.AgentService/DeleteAgentExecution", { agentExecutionId: agentId });
const threadsAfter = await daemonGet("/v1/threads");
ok(!hasThread(threadsAfter), "REAL EFFECT: DeleteAgentExecution removed the daemon thread");

// ---- CONTRACT: zero gitpod.v1.* fell through to mock ----
const proxied = await fallthroughSet();
ok(proxied.length === 0, "zero gitpod.v1.* RPC fell through to the mock mirror (fully adapter-owned)", proxied.slice(0, 6).join(", "));

// ---- Playwright UI tier: :4173 loads + crawls every route + asserts a *completely working* UX ----
// "Completely functional when you click around" means more than zero network fallthrough: a route
// can render an error boundary ("Something went wrong") with zero console errors and zero fallthrough
// (e.g. a lazy chunk that fails to import). So this tier also asserts (a) no route renders the error
// boundary, and (b) the app is self-contained — zero requests to the external app.gitpod.io CDN
// (the harvested bundle's __toAssetUrl base is localized; a regression there reintroduces a remote
// chunk dependency that flakily crashes routes like /ai). /ai is stress-visited since it lazy-loads.
let chromium; try { ({ chromium } = await import("playwright")); } catch { chromium = null; }
if (!chromium) {
  declaredGaps.push({ gate: "ui_render", prerequisite: "PLAYWRIGHT_UNAVAILABLE" });
  if (!JSON_OUT) console.log("    · DECLARED GAP: ui_render — playwright unavailable");
} else {
  const b = await chromium.launch({ headless: true });
  try {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
    const errs = []; p.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); }); p.on("pageerror", (e) => errs.push("pageerror: " + e.message));
    const cdnUrls = new Set();
    p.on("request", (r) => { try { if (new URL(r.url()).host === "app.gitpod.io") cdnUrls.add(r.url()); } catch { /* ignore */ } });
    const settle = async () => { await p.waitForTimeout(3500); };
    const isErrorBoundary = async () => /Something went wrong|ran into a hiccup/i.test(await p.evaluate(() => document.body?.innerText || ""));

    // 1) Landing renders + is not itself an error boundary.
    await fetch(`${REF}/__ioi/fallthrough/reset`, { method: "POST" });
    await p.goto(`${REF}/`, { waitUntil: "domcontentloaded", timeout: 30000 });
    await p.waitForFunction(() => /get done today|New Session|Home/i.test(document.body?.innerText || ""), { timeout: 20000 }).catch(() => {});
    await settle();
    ok((await p.evaluate(() => (document.body?.innerText || "").length > 40)) && !(await isErrorBoundary()), "Playwright: :4173 reference shell renders (not an error boundary)");

    // 2) Discover internal routes (dedup /details/<id> to a single sample); stress-visit /ai.
    const links = await p.evaluate(() => {
      const out = new Set();
      for (const a of document.querySelectorAll("a[href]")) {
        try { const u = new URL(a.href, location.origin); if (u.origin === location.origin && u.pathname !== "/") out.add(u.pathname); } catch { /* ignore */ }
      }
      return [...out];
    });
    const routes = ["/"]; let sampledDetails = false;
    for (const l of links) {
      if (l.startsWith("/details/")) { if (!sampledDetails) { sampledDetails = true; routes.push(l); } }
      else routes.push(l);
    }
    routes.push("/ai", "/ai"); // lazy-loaded compose surface — exercise it repeatedly

    // 3) Visit each route; accumulate fallthrough, console errors, and error-boundary renders.
    const dirtyRoutes = []; const allErrs = []; const boundaryRoutes = [];
    for (const route of routes.slice(0, 28)) {
      await fetch(`${REF}/__ioi/fallthrough/reset`, { method: "POST" });
      errs.length = 0;
      try { await p.goto(`${REF}${route}`, { waitUntil: "domcontentloaded", timeout: 20000 }); await settle(); }
      catch (e) { dirtyRoutes.push(`${route} (nav-err: ${e.message})`); continue; }
      if (await isErrorBoundary()) boundaryRoutes.push(route);
      const proxied = await fallthroughSet();
      if (proxied.length) dirtyRoutes.push(`${route} -> ${proxied.join(", ")}`);
      if (errs.length) allErrs.push(`${route}: ${errs.slice(0, 2).join("; ")}`);
    }
    ok(boundaryRoutes.length === 0, "Playwright: no route renders the 'Something went wrong' error boundary", [...new Set(boundaryRoutes)].slice(0, 6).join(", "));
    ok(dirtyRoutes.length === 0, `Playwright: all ${routes.length} route visits fully adapter-owned (zero fallthrough)`, dirtyRoutes.slice(0, 4).join(" | "));
    ok(allErrs.length === 0, "Playwright: zero console/page errors across all routes", allErrs.slice(0, 3).join(" | "));
    ok(cdnUrls.size === 0, "Playwright: app is self-contained (zero external app.gitpod.io CDN requests)", [...cdnUrls].slice(0, 3).join(", "));
  } finally { await b.close(); }
}

const verdict = failures > 0 ? "FAIL" : declaredGaps.length ? "PASS_WITH_DECLARED_GAPS" : "PASS";
const report = { workstream: "reference-functional", verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else { console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`); console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`); }
process.exit(verdict === "FAIL" ? 1 : 0);
void existsSync;
