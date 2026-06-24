// IOI-owned API adapter for the live reference's Gitpod Connect-RPC surface.
//
// "Working backwards" from the live reference: endpoints here are backed by real IOI —
// the hypervisor-daemon (governed objects), an IOI-persisted store (preferences), and the
// EnvironmentProvider (lifecycle). handle() returns a response for endpoints we own and
// null for the rest, so the serve layer transparently proxies anything not-yet-ported to
// the live reference; if the daemon is unreachable we also return null (graceful fallback).
//
// Boundary discipline: daemon EXECUTES · wallet AUTHORIZES (crossings only) · agentgres
// RECORDS. Projections live in ioi-projection.mjs and must not inflate any plane.
//
// Daemon: IOI_HYPERVISOR_DAEMON_URL (default http://127.0.0.1:8765).
// Plan: apps/hypervisor/docs/reference-api-integration.md
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { threadToAgentExecution, daemonEnvToGitpod } from "./ioi-projection.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
// UserService preferences are app/client config (not daemon runtime truth), so they live
// in the app-local dir, NOT the daemon data dir (.ioi/hypervisor/data stays daemon-owned).
// If the daemon later owns user preferences, this projects to it (no JS ownership).
const APP_LOCAL = join(REPO_ROOT, ".ioi", "hypervisor-app-local");
const PREF_STORE = join(APP_LOCAL, "app-preferences.json");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const json = (payload) => ({ contentType: "application/json", body: JSON.stringify(payload) });

async function daemon(method, path, body) {
  const res = await fetch(DAEMON + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`daemon ${method} ${path} -> ${res.status}`);
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

// ---- preferences (real IOI-persisted storage) ----
function loadStore() {
  try {
    return JSON.parse(readFileSync(PREF_STORE, "utf8"));
  } catch {
    return {};
  }
}
function saveStore(store) {
  mkdirSync(dirname(PREF_STORE), { recursive: true });
  writeFileSync(PREF_STORE, JSON.stringify(store, null, 2));
}
function makePreference(key, value, entry) {
  const stableId = Buffer.from(key).toString("hex").slice(0, 24).padEnd(24, "0");
  return { key, value, id: `ioi-${stableId}`, createdAt: entry.createdAt, updatedAt: entry.updatedAt };
}

const textFromBody = (b) => b.text || b.message || b.prompt || b.input || b.content || "";
const envIdFromBody = (b) =>
  b.environmentId || b.req?.environmentId || b.spec?.environmentId || b.projectId || "default-environment";

export async function handle(pathname, bodyText) {
  let body = {};
  try {
    body = JSON.parse(bodyText || "{}");
  } catch {
    /* keep {} */
  }

  // ---- IOI-native passthrough (WS-I: injected surfaces; daemon projections) ----
  if (pathname.startsWith("/api/ioi/")) {
    const sub = pathname.slice("/api/ioi/".length);
    // Writes the IOI panel owns: the scoped terminal + the model-driven WorkRun turn.
    if (sub === "exec") {
      try {
        return json(await daemon("POST", "/v1/hypervisor/exec", body));
      } catch (e) {
        return json({ error: e.message, daemon: "unreachable" });
      }
    }
    const execTurn = sub.match(/^workruns\/([^/]+)\/execute$/);
    if (execTurn) {
      try {
        return json(await daemon("POST", `/v1/hypervisor/workruns/${encodeURIComponent(execTurn[1])}/execute`));
      } catch (e) {
        return json({ error: e.message, daemon: "unreachable" });
      }
    }
    if (sub === "workruns" && bodyText && body.environment_id) {
      try {
        return json(await daemon("POST", "/v1/hypervisor/workruns", body));
      } catch (e) {
        return json({ error: e.message, daemon: "unreachable" });
      }
    }
    // Reads (GET): daemon projections.
    const map = {
      "authority/posture": "/v1/hypervisor/authority/posture",
      "environment-classes": "/v1/hypervisor/environment-classes",
      "environments": "/v1/hypervisor/environments",
      "workruns": "/v1/hypervisor/workruns",
      "receipts": "/v1/model-mount/receipts",
      // WS-12 — Phase 1 surfaces the panel projects.
      "recipes": "/v1/hypervisor/recipes",
      "snapshots": "/v1/hypervisor/snapshots",
      "incidents": "/v1/hypervisor/incidents",
      "recovery-attempts": "/v1/hypervisor/recovery-attempts",
    };
    if (!map[sub]) return json({ error: "unknown ioi endpoint" });
    try {
      return json(await daemon("GET", map[sub]));
    } catch (e) {
      return json({ error: e.message, daemon: "unreachable" });
    }
  }

  // ---- UserService: real IOI-persisted preferences ----
  if (pathname === "/api/gitpod.v1.UserService/GetPreference") {
    const key = body.preferenceKey || body.preference?.value || body.preference?.preferenceKey;
    if (!key) return json({ preference: null });
    const entry = loadStore()[key];
    return json({ preference: entry ? makePreference(key, entry.value, entry) : null });
  }
  if (pathname === "/api/gitpod.v1.UserService/SetPreference") {
    const key = body.preference?.key || body.key || body.preferenceKey || "DEFAULT_PREFERENCE";
    const value = body.preference?.value ?? body.value ?? "";
    const store = loadStore();
    const now = new Date().toISOString();
    store[key] = { value, createdAt: store[key]?.createdAt || now, updatedAt: now };
    saveStore(store);
    return json({ preference: makePreference(key, value, store[key]) });
  }

  // ---- EnvironmentService: real IOI daemon environments (WS-A/WS-B) ----
  // Env truth is daemon-owned (/v1/hypervisor/environments); the JS simulator is gone.
  try {
    const env = (path) => daemon("GET", path).then((r) => r.environment);
    const act = (id, action) =>
      daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/${action}`).then((r) => r.environment);
    switch (pathname) {
      case "/api/gitpod.v1.EnvironmentService/GetEnvironment":
        return json({ environment: daemonEnvToGitpod(await env(`/v1/hypervisor/environments/${encodeURIComponent(envIdFromBody(body))}`)) });
      case "/api/gitpod.v1.EnvironmentService/ListEnvironments": {
        const r = await daemon("GET", "/v1/hypervisor/environments");
        return json({ pagination: {}, environments: (r.environments || []).map(daemonEnvToGitpod) });
      }
      case "/api/gitpod.v1.EnvironmentService/StartEnvironment":
        return json({ environment: daemonEnvToGitpod(await act(envIdFromBody(body), "start")) });
      case "/api/gitpod.v1.EnvironmentService/StopEnvironment":
        return json({ environment: daemonEnvToGitpod(await act(envIdFromBody(body), "stop")) });
      case "/api/gitpod.v1.EnvironmentService/DeleteEnvironment":
        return json({ environment: daemonEnvToGitpod(await act(envIdFromBody(body), "delete")) });
      case "/api/gitpod.v1.EnvironmentService/UpdateEnvironment": {
        const id = envIdFromBody(body);
        const desired = body.spec?.desiredPhase || body.req?.spec?.desiredPhase;
        if (desired === "ENVIRONMENT_PHASE_RUNNING") return json({ environment: daemonEnvToGitpod(await act(id, "start")) });
        if (desired === "ENVIRONMENT_PHASE_STOPPED") return json({ environment: daemonEnvToGitpod(await act(id, "stop")) });
        return json({ environment: daemonEnvToGitpod(await env(`/v1/hypervisor/environments/${encodeURIComponent(id)}`)) });
      }
      case "/api/gitpod.v1.EnvironmentService/CreateEnvironment":
      case "/api/gitpod.v1.EnvironmentService/CreateEnvironmentFromProject": {
        const created = await daemon("POST", "/v1/hypervisor/environments", { spec: body.spec || body });
        return json({ environment: daemonEnvToGitpod(created.environment) });
      }
      case "/api/gitpod.v1.EnvironmentService/CreateEnvironmentAccessToken":
      case "/api/gitpod.v1.EnvironmentService/CreateEnvironmentLogsToken":
        return json({ accessToken: `ioi-env-token-${envIdFromBody(body)}` });
      case "/api/gitpod.v1.EnvironmentService/MarkEnvironmentActive":
        return json({});
      case "/api/gitpod.v1.EnvironmentService/ArchiveEnvironment":
        return json({ environment: daemonEnvToGitpod(await act(envIdFromBody(body), "archive")) });
      case "/api/gitpod.v1.EnvironmentService/UnarchiveEnvironment":
        return json({ environment: daemonEnvToGitpod(await act(envIdFromBody(body), "restore")) });
      default:
        break;
    }
  } catch (e) {
    console.error("[ioi-api-adapter] daemon env call failed, proxying:", e.message);
    return null;
  }

  // ---- AgentService: real IOI daemon threads/turns (Session) ----
  try {
    if (pathname === "/api/gitpod.v1.AgentService/ListAgentExecutions") {
      const threads = await daemon("GET", "/v1/threads");
      const list = Array.isArray(threads) ? threads : threads.threads || [];
      return json({ pagination: {}, agentExecutions: list.map(threadToAgentExecution) });
    }
    if (pathname === "/api/gitpod.v1.AgentService/GetAgentExecution") {
      const id = body.agentExecutionId;
      const t = await daemon("GET", `/v1/threads/${encodeURIComponent(id)}`);
      return json({ agentExecution: threadToAgentExecution(t) });
    }
    if (
      pathname === "/api/gitpod.v1.AgentService/CreateAgentExecution" ||
      pathname === "/api/gitpod.v1.AgentService/StartAgent"
    ) {
      const created = await daemon("POST", "/v1/threads", { title: textFromBody(body).slice(0, 80) || undefined });
      return json({ agentExecutionId: created.thread_id || created.id });
    }
    if (pathname === "/api/gitpod.v1.AgentService/SendToAgentExecution") {
      const id = body.agentExecutionId;
      const text = textFromBody(body);
      if (id && text) await daemon("POST", `/v1/threads/${encodeURIComponent(id)}/turns`, { text });
      return json({});
    }
  } catch (e) {
    console.error("[ioi-api-adapter] daemon call failed, proxying:", e.message);
    return null;
  }

  // Not yet IOI-backed -> proxy to the live reference. Remaining (see reference-api-
  // integration.md): ProjectService (daemon needs a project-list GET), EventService
  // streaming bridge, Account/Org/Billing (bare daemon stub), approvals/reviews surfacing.
  return null;
}
