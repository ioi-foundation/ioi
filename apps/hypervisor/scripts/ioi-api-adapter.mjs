// IOI-owned API adapter for the live reference's Gitpod Connect-RPC surface.
//
// "Working backwards" from the live reference: endpoints implemented here are backed by
// the real IOI hypervisor-daemon (/v1/*) instead of the reference's mocks. handle()
// returns a response for endpoints we own and null for the rest, so the serve layer
// transparently proxies anything not-yet-ported to the live reference — and if the daemon
// is unreachable we also return null (fall back to the reference) so the app never breaks.
//
// Daemon: IOI_HYPERVISOR_DAEMON_URL (default http://127.0.0.1:8765).
// Plan: apps/hypervisor/docs/reference-api-integration.md
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RAW_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || ".ioi/hypervisor/data";
const DATA_DIR = isAbsolute(RAW_DATA_DIR) ? RAW_DATA_DIR : join(REPO_ROOT, RAW_DATA_DIR);
const PREF_STORE = join(DATA_DIR, "hypervisor-app-preferences.json");
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

// ---- map a real daemon thread -> the frontend's Gitpod agentExecution shape ----
function threadToAgentExecution(t) {
  const id = t.thread_id || t.id;
  const running = (t.status || "active") === "active";
  const phase = running ? "AGENT_EXECUTION_PHASE_RUNNING" : "AGENT_EXECUTION_PHASE_STOPPED";
  const session = t.session_id || id;
  const title = t.title && t.title.trim() && t.title.trim() !== "." ? t.title.trim() : "Untitled session";
  return {
    id,
    metadata: {
      name: title,
      creator: { id: "local-operator", principal: "PRINCIPAL_USER" },
      createdAt: t.created_at,
      updatedAt: t.updated_at || t.created_at,
      role: "AGENT_EXECUTION_ROLE_DEFAULT",
    },
    spec: {
      specVersion: "2",
      session,
      desiredPhase: running ? "PHASE_RUNNING" : "PHASE_STOPPED",
      agentId: t.agent_id || "00000000-0000-0000-0000-000000007800",
      limits: {},
    },
    status: {
      statusVersion: String(t.latest_seq || 1),
      session,
      phase,
    },
  };
}

const textFromBody = (b) => b.text || b.message || b.prompt || b.input || b.content || "";

export async function handle(pathname, bodyText) {
  let body = {};
  try {
    body = JSON.parse(bodyText || "{}");
  } catch {
    /* keep {} */
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

  // ---- AgentService: real IOI daemon threads/turns ----
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
    // Daemon unreachable / shape mismatch -> fall back to the live reference (proxy).
    console.error("[ioi-api-adapter] daemon call failed, proxying:", e.message);
    return null;
  }

  // Not yet IOI-backed -> proxy to the live reference. Next per the plan:
  //   EnvironmentService/* -> daemon runtime nodes / preview API
  //   EventService/Watch   -> daemon event stream (/v1/threads/:id events) as Connect frames
  return null;
}
