// IOI-owned API adapter for the product-ui bundle's IOI Connect-RPC surface.
//
// "Working backwards" from the product-ui bundle: endpoints here are backed by real IOI —
// the hypervisor-daemon (governed objects), an IOI-persisted store (preferences), and the
// EnvironmentProvider (lifecycle). Since W0.5 (identity truth) every `/api/ioi.v1.*` RPC is
// adapter-owned: it is daemon-backed where a route exists at the bytes, and otherwise refuses
// with a typed unavailable/named-gap error. handle() returns null only for non-RPC paths; the
// fixture/wildcard-mock lane is no longer reachable through the RPC surface, and daemon
// unreachability surfaces as a typed refusal — never fixture data presented as live.
//
// Boundary discipline: daemon EXECUTES · wallet AUTHORIZES (crossings only) · agentgres
// RECORDS. Projections live in ioi-projection.mjs and must not inflate any plane.
//
// Daemon: IOI_HYPERVISOR_DAEMON_URL (default http://127.0.0.1:8765).
// Plan: apps/hypervisor/docs/product-ui-api-integration.md
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AsyncLocalStorage } from "node:async_hooks";
import { threadToAgentExecution, daemonEnvToIOI, daemonProjectToIOI } from "./ioi-projection.mjs";
import {
  startAgentRun,
  registerAgentRun,
  sendToAgentRun,
  getRun,
  listRuns,
  runToAgentExecution,
  extractPrompt,
  extractEnvClass,
  extractAuthorityProfile,
  extractModelRouteRef,
} from "./ioi-agent-runs.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
// UserService preferences are app/client config (not daemon runtime truth), so they live
// in the app-local dir, NOT the daemon data dir (.ioi/hypervisor/data stays daemon-owned).
// If the daemon later owns user preferences, this projects to it (no JS ownership).
const APP_LOCAL = join(REPO_ROOT, ".ioi", "hypervisor-app-local");
const PREF_STORE = join(APP_LOCAL, "app-preferences.json");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
// Per-request context carries the complete bounded identity envelope. Dropping Authorization or
// x-ioi-forwarded here silently turns a managed caller into a loopback local operator at the
// daemon, so every owned adapter path must reuse this exact envelope.
const reqCtx = new AsyncLocalStorage();
const DAEMON_IDENTITY_HEADERS = [
  "authorization",
  "cookie",
  "x-ioi-forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
];

function daemonIdentityHeaders(reqHeaders = {}) {
  const normalized = {};
  for (const name of DAEMON_IDENTITY_HEADERS) {
    const value = reqHeaders[name] ?? reqHeaders[name.toLowerCase()];
    if (typeof value === "string" && value.length > 0) normalized[name] = value;
  }
  return normalized;
}

function currentDaemonHeaders({ includeContentType = false } = {}) {
  const headers = { ...(reqCtx.getStore()?.daemonHeaders || {}) };
  if (includeContentType) headers["content-type"] = "application/json";
  return headers;
}

const json = (payload) => ({ contentType: "application/json", body: JSON.stringify(payload) });
// Connect-protocol error: non-2xx HTTP + {code,message} so the SPA's client rejects (e.g. a
// rejected GitHub token surfaces as a real connect failure, not a silent success).
const jsonStatus = (status, payload) => ({ contentType: "application/json", body: JSON.stringify(payload), status });
// W0.5 identity truth — the typed refusal for an RPC whose backing daemon route does not exist
// (or did not answer). The Connect client rejects with the named gap and the pane renders a
// degraded state; nothing fabricates rows, names, or silent successes in its place.
const unavailableRpc = (gap, message, status = 503) =>
  jsonStatus(status, { code: "unavailable", message: `${gap}: ${message}` });
// A daemon that ANSWERED with a refusal did answer. Seven catch sites below reported every daemon
// error as "the daemon … did not answer" (503 unavailable) — including a 401. Unavailable is a
// RETRYABLE code, so a signed-out browser watched the rail's Sessions skeleton spin forever while
// the daemon kept saying, correctly, "sign in" (R-240). A 401 is `unauthenticated` and a 403 is
// `permission_denied` — both terminal, both naming the real reason; only no answer at all is
// `unavailable`.
const daemonRefusalRpc = (gap, e, unavailableMessage) => {
  const m = String(e?.message || "");
  if (/-> 401$/.test(m)) return jsonStatus(401, { code: "unauthenticated", message: `${gap}: the daemon refused this read — sign in (/__ioi/login) to see it` });
  if (/-> 403$/.test(m)) return jsonStatus(403, { code: "permission_denied", message: `${gap}: the daemon refused this read for the signed-in principal` });
  return unavailableRpc(gap, unavailableMessage);
};
// Connect *streaming* refusal: HTTP 200 + an end-stream frame carrying the typed error (the
// streaming protocol conveys errors in-band; a bare non-2xx JSON body would surface as a parse
// failure instead of the named gap).
function connectStreamError(code, message) {
  const payload = Buffer.from(JSON.stringify({ error: { code, message } }), "utf8");
  const frame = Buffer.alloc(5 + payload.length);
  frame.writeUInt8(0x02, 0);
  frame.writeUInt32BE(payload.length, 1);
  payload.copy(frame, 5);
  return { contentType: "application/connect+json", body: frame, status: 200 };
}

// Structural local-scope identifiers — opaque ids the Connect schemas require plus the app-local
// seed timestamp. These are NOT display truth: display identity (names, emails, organization
// name, tier) comes from the daemon (whoami/principals/organization reads) or not at all. The
// former local-constant operator identity ("John Doe" / "IOI Workspace") and the serve layer's
// IDENTITY_REWRITES were deleted at W0.5.
const LOCAL_SCOPE = {
  userId: "00000000-0000-4000-8000-000000000001",
  orgId: "00000000-0000-4000-8000-0000000000a1",
  groupId: "00000000-0000-4000-8000-0000000000a2",
  seedTime: "2026-01-01T00:00:00.000Z",
};

// The organization's name as the daemon knows it: the display name an administrator set, else the
// name segment of its own ref (`org://local` → "local") — an identifier, never an invented label.
function orgDisplayName(org) {
  const set = typeof org.display_name === "string" ? org.display_name.trim() : "";
  if (set) return set;
  return String(org.org_ref || "").replace(/^[a-z]+:\/\//u, "");
}

async function daemon(method, path, body) {
  const headers = currentDaemonHeaders({ includeContentType: Boolean(body) });
  const res = await fetch(DAEMON + path, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) {
    // The message format is matched elsewhere (`/-> 401$/`), so it stays; the daemon's typed code
    // rides on the error instead — "-> 503" alone told an admin nothing (R-240).
    const err = new Error(`daemon ${method} ${path} -> ${res.status}`);
    err.status = res.status;
    try { const b = JSON.parse(await res.text()); err.code = b.code || b.error?.code || b.reason || ""; err.daemonMessage = b.message || b.error?.message || ""; } catch { /* untyped body */ }
    throw err;
  }
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

// The legacy agent-run cache has no durable principal/owner coordinate. Until that family is
// replaced by an owner-scoped daemon projection, it is admissible only in the selected
// local-development profile. This preflight runs before listRuns/getRun/register/send/start.
async function agentRunCacheAccessDecision() {
  let response;
  let payload = {};
  try {
    response = await fetch(`${DAEMON}/v1/hypervisor/auth/policy`, {
      headers: currentDaemonHeaders(),
      signal: AbortSignal.timeout(8000),
    });
    const text = await response.text();
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = {}; }
  } catch {
    return {
      allowed: false,
      status: 503,
      code: "agent_run_cache_authority_unavailable",
      message: "Agent-run authority could not be adjudicated; no run identity or state was resolved.",
    };
  }
  if (!response.ok) {
    return {
      allowed: false,
      status: response.status >= 400 ? response.status : 503,
      code:
        payload?.error?.code ||
        payload?.code ||
        payload?.reason ||
        "agent_run_cache_authentication_required",
      message: "Agent-run authority was refused; no run identity or state was resolved.",
    };
  }
  if (payload?.deployment_auth_posture !== "local_development") {
    return {
      allowed: false,
      status: 403,
      code: "agent_run_cache_principal_scope_unavailable",
      message:
        "The retained agent-run cache has no principal ownership coordinates and is unavailable on a managed deployment.",
    };
  }
  return { allowed: true, status: 200 };
}

// Project the daemon's MCP connectors (kind: mcp) into the native IntegrationService shape so they
// render on the org/user Integrations surfaces. Mirrors the captured ListIntegrations fixture
// (capabilities.mcp.url + auth + categories). Bearer/oauth HTTP connectors are intentionally NOT
// projected here — that surface is MCP-shaped; mixing models would blur it.
async function mcpConnectorsAsIntegrations() {
  try {
    const r = await daemon("GET", "/v1/hypervisor/connectors");
    return (r.connectors || [])
      .filter((c) => c.kind === "mcp")
      .map((c) => {
        let host = ""; try { host = new URL(c.base_url).host; } catch { /* */ }
        return {
          id: c.connector_id,
          organizationId: LOCAL_SCOPE.orgId,
          integrationDefinitionId: c.connector_id,
          enabled: true,
          capabilities: { mcp: { url: c.base_url } },
          auth: { requiresAuth: c.requires_credential !== false },
          host,
          name: c.name || c.service || "MCP integration",
          description: c.description || `MCP server · ${host}`,
          iconUrl: c.icon_url || "",
          categories: ["INTEGRATION_CATEGORY_MCP"],
          connected: c.auth_posture === "token-lease:bound",
        };
      });
  } catch {
    return [];
  }
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
const parseGitHubContextUrl = (contextUrl) => {
  let url;
  try {
    url = new URL(String(contextUrl || "").trim());
  } catch {
    return null;
  }
  const host = url.host.toLowerCase();
  const parts = url.pathname.split("/").filter(Boolean);
  if (!host.endsWith("github.com") || parts.length < 2) return null;
  const owner = parts[0];
  const repo = (parts[1] || "").replace(/\.git$/, "");
  if (!owner || !repo) return null;
  const cloneUrl = `https://${host}/${owner}/${repo}.git`;
  return {
    originalContextUrl: url.toString(),
    git: {
      cloneUrl,
      branch: "",
      commit: "",
      host,
      owner,
      repo,
      upstreamRemoteUrl: cloneUrl,
      tag: "",
    },
    projectIds: [],
    scmId: "github",
  };
};
// Project a daemon provider record into the SPA's runner vocabulary. Every field either carries
// a daemon record value or is a documented enum translation; the former dressing constants
// (version "ioi-local", release channel, variant, unconditional capability ints) were deleted at
// W0.5 — absence is honest. status.capabilities gates env-class selectability and the Git-auth
// connect action: an AVAILABLE daemon provider factually hosts environment + agent execution
// (the daemon's own env/agent lanes run on it), so the SPA capability ints are advertised only
// while the provider reports available — an unavailable provider advertises nothing.
const runnerFromProvider = (p = {}) => {
  const id = p.provider_ref || p.runnerId || "local-microvm";
  const active = !p.status || p.status === "available";
  const phase = active ? "RUNNER_PHASE_ACTIVE" : "RUNNER_PHASE_INACTIVE";
  const label = p.reason || p.display_name || id;
  return {
    id,
    runnerId: id,
    name: label,
    spec: {
      desiredPhase: phase,
      configuration: { region: p.capabilities?.locality || "local" },
    },
    status: {
      phase,
      message: label,
      capabilities: active ? [3, 4, 5] : [],
    },
    kind: "RUNNER_KIND_REMOTE",
  };
};
async function listProjectedRunners() {
  const r = await daemon("GET", "/v1/hypervisor/providers");
  return (r.providers || []).map(runnerFromProvider);
}
// EnvironmentClass projection shared by EnvironmentService/ListEnvironmentClasses,
// ProjectService/ListProjectEnvironmentClasses and RunnerConfigurationService/GetEnvironmentClass
// — all three read the ONE daemon substrate catalog (/v1/hypervisor/environment-classes).
const daemonClassToIOI = (c) => ({
  id: c.id,
  displayName: c.display_name || c.id,
  description: [c.substrate_class, c.minimum_isolation || c.isolation_claim || c.note].filter(Boolean).join(" • "),
  configuration: [{ key: "substrateClass", value: c.substrate_class || "" }],
  runnerId: "local-microvm",
  enabled: c.enabled !== false,
});
const portsFromBody = (b) => {
  const candidates = [b.spec?.ports, b.req?.spec?.ports, b.ports, b.req?.ports];
  return candidates.find((ports) => Array.isArray(ports)) || [];
};
const portAdmissionValue = (port) => port?.admission ?? port?.access ?? port?.admissionLevel;
const isPortUnexpose = (port) => {
  const admission = portAdmissionValue(port);
  return admission === 0 || admission === "0" || admission === "ADMISSION_LEVEL_UNSPECIFIED" || admission === "UNSPECIFIED";
};

// WHAT AN ENVIRONMENT UPDATE CAN CARRY, AND WHAT THE DAEMON CAN APPLY (Sessions cut 1). The daemon's
// environment record has no update route — only GET /v1/hypervisor/environments/:id and the lifecycle
// actions (start / stop / archive / restore / delete) plus the port routes. So an update applies
// `spec.desiredPhase` (as start/stop) and `spec.ports` (narrowing only), and every other member it
// carries is REFUSED BY NAME: it used to answer 200 having done nothing, which the page read as
// "Environment renamed" / "Successfully updated auto-stop". The bundle sends a rename as
// `metadata.name` (the row menu's Rename and the ▾ Rename beside the conversation tab both open the
// same EnvironmentRenameOverlay), and auto-stop as `spec.timeout.disconnected`.
const plainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function environmentUpdateRefusal(body) {
  const metadata = [body.metadata, body.req?.metadata].find(plainObject);
  const spec = [body.spec, body.req?.spec].find(plainObject) || {};
  // A name cleared to "" may serialize as an empty `metadata: {}`; either way it is a rename.
  if (metadata && ("name" in metadata || Object.keys(metadata).length === 0)) {
    return jsonStatus(501, { code: "unimplemented", message: "environment_rename_not_supported: the daemon's environment record carries no name and has no update route, so the environment was not renamed" });
  }
  if (spec.timeout !== undefined && spec.timeout !== null) {
    return jsonStatus(501, { code: "unimplemented", message: "environment_auto_stop_not_supported: the daemon sets an environment's stop policy (idle timeout) only when it is created and has no route to change it, so auto-stop was not changed" });
  }
  const unsupported = [
    ...Object.keys(metadata || {}).map((k) => `metadata.${k}`),
    ...Object.keys(spec).filter((k) => k !== "desiredPhase" && k !== "ports" && k !== "environmentId").map((k) => `spec.${k}`),
  ];
  if (unsupported.length) {
    return jsonStatus(501, { code: "unimplemented", message: `environment_update_field_not_supported: the daemon has no environment update route for ${unsupported.join(", ")}; nothing was changed` });
  }
  return null;
}

// GOAL MODE IS NOT A HYPERVISOR FEATURE (owner rule: goal pursuit is an ioi.ai composition over thread
// primitives; GoalRun never returns to the Hypervisor). The composer marks a Goal turn three ways, all
// read from the vendored bundle: `turnOptions.modes: ["AGENT_MODE_GOAL"]` (on CreateAgentSession's
// `agent`, StartAgent, and SendToAgentExecution), the prompt prefix `/ioi:goal ` it prepends in Goal
// mode, and `controlInput.goal.{set,pause,resume,complete,clear}`. `/goal` in the composer only toggles
// the mode client-side; typed as the head of a prompt it is the same command. Plan (`AGENT_MODE_SPEC`,
// `/ioi:spec `) and Agent turns are untouched.
const GOAL_MODES = new Set(["AGENT_MODE_GOAL", "GOAL", 5, "5"]);
function goalModeMarker(body) {
  const modeLists = [
    body?.turnOptions?.modes,
    body?.agent?.turnOptions?.modes,
    body?.userInput?.metadata?.modes,
    body?.initialInput?.metadata?.modes,
  ];
  if (modeLists.some((modes) => Array.isArray(modes) && modes.some((m) => GOAL_MODES.has(m)))) return "turnOptions.modes AGENT_MODE_GOAL";
  if (plainObject(body?.controlInput?.goal)) return "controlInput.goal";
  if (/^\/(?:ioi:)?goal(?:\s|$)/u.test(extractPrompt(body))) return "a /goal prompt";
  return null;
}
const goalModeRefusal = (marker) =>
  jsonStatus(501, { code: "unimplemented", message: `goal_mode_not_in_hypervisor: Goal mode (${marker}) is not a Hypervisor feature — goal pursuit is an ioi.ai composition over thread primitives. Use Agent or Plan mode here; nothing was started or sent` });

// LOGS (Sessions cut 1). The Logs pane mints a token (CreateEnvironmentLogsToken → a real env-scoped
// lease, the same one CreateEnvironmentAccessToken mints), then GETs `status.environmentUrls.logs`
// (`/api/ioi/environments/<id>/logs`, ioi-projection) with `Authorization: Bearer <token>` and parses
// the reply as the reference's log text: `[section-create]{…}`, then `[id:<section>] [<ts>] LEVEL msg`
// per line. The bearer is the logs token, never the caller's identity — the daemon read travels on the
// session cookie with the Authorization header removed.
const textPlain = (text) => ({ contentType: "text/plain; charset=utf-8", body: text });
const oneLine = (v) => String(v ?? "").replace(/[\r\n]+/gu, " ↵ ");
function sessionLogLine(entry) {
  const at = typeof entry?.at === "string" ? entry.at : typeof entry?.timestamp === "string" ? entry.timestamp : "";
  const level = typeof entry?.level === "string" && /^[A-Za-z]+$/u.test(entry.level)
    ? entry.level.toUpperCase()
    : typeof entry?.exit_code === "number" && entry.exit_code !== 0 ? "ERROR" : "INFO";
  const message = typeof entry?.message === "string"
    ? oneLine(entry.message)
    : entry?.command !== undefined
      ? `$ ${oneLine(entry.command)} (exit ${entry.exit_code ?? "?"}; stdout ${entry.stdout_bytes ?? 0} B, stderr ${entry.stderr_bytes ?? 0} B)`
      : oneLine(JSON.stringify(entry));
  return `[id:session] ${at ? `[${at}] ` : ""}${level} ${message}`;
}
function sessionLogText(entries) {
  const lines = [`[section-create]${JSON.stringify({ id: "session", title: "Session commands", continuous: true })}`];
  for (const entry of entries) lines.push(sessionLogLine(entry));
  return `${lines.join("\n")}\n`;
}
async function environmentLogsText(envId) {
  const auth = String(reqCtx.getStore()?.daemonHeaders?.authorization || "");
  const token = /^Bearer\s+(\S+)\s*$/iu.exec(auth)?.[1] || "";
  if (!token) {
    return jsonStatus(401, { code: "unauthenticated", message: "environment_logs_token_required: a logs token (CreateEnvironmentLogsToken) is required as the Bearer; no logs were read" });
  }
  const identity = currentDaemonHeaders();
  delete identity.authorization;
  const read = async (path) => {
    const res = await fetch(DAEMON + path, { headers: identity, signal: AbortSignal.timeout(8000) });
    const text = await res.text();
    let payload = {};
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = {}; }
    return { status: res.status, ok: res.ok, payload };
  };
  let lease;
  try {
    lease = await read(`/v1/hypervisor/ops-lease/${encodeURIComponent(token)}`);
  } catch (e) {
    return unavailableRpc("environment_logs_token_unverified", `the daemon did not answer the lease read (${e.message}); no logs were read`);
  }
  if (!lease.ok || lease.payload?.active !== true || lease.payload?.environment_id !== envId) {
    const why = !lease.ok || lease.payload?.active !== true ? "not active (unknown, expired or revoked)" : "bound to a different environment";
    return jsonStatus(403, { code: "permission_denied", message: `environment_logs_token_invalid: the logs token is ${why}; no logs were read` });
  }
  let logs;
  try {
    logs = await read(`/v1/hypervisor/environments/${encodeURIComponent(envId)}/logs?kind=session`);
  } catch (e) {
    return unavailableRpc("environment_logs_unavailable", `the daemon did not answer the logs read (${e.message}); no logs are served`);
  }
  if (logs.status === 401) return jsonStatus(401, { code: "unauthenticated", message: "environment_logs_unavailable: the daemon refused this read — sign in (/__ioi/login) to see it" });
  if (logs.status === 403) return jsonStatus(403, { code: "permission_denied", message: "environment_logs_unavailable: the daemon refused this read for the signed-in principal" });
  if (logs.status === 404) return jsonStatus(404, { code: "not_found", message: "environment_logs_unavailable: the daemon has no such environment" });
  if (!logs.ok || logs.payload?.ok === false || !Array.isArray(logs.payload?.entries)) {
    return unavailableRpc("environment_logs_unavailable", `the daemon's logs read did not answer with entries (${logs.status}${logs.payload?.reason ? `: ${logs.payload.reason}` : ""}); no logs are served`);
  }
  return textPlain(sessionLogText(logs.payload.entries));
}

async function waitForRunTerminal(runId, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const run = getRun(runId);
    if (!run || run.status === "done" || run.status === "failed") return run;
    await new Promise((resolve) => setTimeout(resolve, 350));
  }
  return getRun(runId);
}

export async function handle(pathname, bodyText, reqHeaders = {}) {
  const daemonHeaders = daemonIdentityHeaders(reqHeaders);
  const contentType = String(reqHeaders["content-type"] || reqHeaders["Content-Type"] || "");
  return reqCtx.run({ daemonHeaders, contentType }, () => handleImpl(pathname, bodyText));
}

async function handleImpl(pathname, bodyText) {
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
    // The Logs pane's `environmentUrls.logs` (Sessions cut 1): lease-validated, text/plain.
    const logsRead = /^environments\/([^/]+)\/logs$/u.exec(sub);
    if (logsRead) {
      let envId = "";
      try { envId = decodeURIComponent(logsRead[1]); } catch { return jsonStatus(400, { code: "invalid_argument", message: "environment_logs_bad_id: the environment id in the logs URL is not decodable" }); }
      return environmentLogsText(envId);
    }
    // Reads (GET): daemon projections.
    const map = {
      "authority/posture": "/v1/hypervisor/authority/posture",
      "environment-classes": "/v1/hypervisor/environment-classes",
      "environments": "/v1/hypervisor/environments",
      "workruns": "/v1/hypervisor/workruns",
      "receipts": "/v1/model-mount/receipts",
      // WS-12 — Phase 1 surfaces the panel projects.
      // M05.7 — the owner-qualified route name. `recipes` is this panel's key, not the daemon's
      // family: it reads the DEVELOPMENT-ENVIRONMENT recipe family, and the generic
      // `/v1/hypervisor/recipes` path it used to call is now a read-only compatibility alias.
      "recipes": "/v1/hypervisor/environment-recipes",
      "snapshots": "/v1/hypervisor/snapshots",
      "incidents": "/v1/hypervisor/incidents",
      "recovery-attempts": "/v1/hypervisor/recovery-attempts",
      // Model-route registry — daemon truth for model routes + availability posture.
      "model-routes": "/v1/hypervisor/model-routes",
      "model-routes-overview": "/v1/hypervisor/model-routes/overview",
      // Harness-profile registry — daemon truth for selectable harnesses + probed runnability.
      "harness-profiles": "/v1/hypervisor/harness-profiles",
      "harness-profiles-overview": "/v1/hypervisor/harness-profiles/overview",
    };
    if (!map[sub]) return json({ error: "unknown ioi endpoint" });
    try {
      return json(await daemon("GET", map[sub]));
    } catch (e) {
      return json({ error: e.message, daemon: "unreachable" });
    }
  }

  // ---- UserService: real IOI-persisted preferences ----
  if (pathname === "/api/ioi.v1.UserService/GetPreference") {
    const key = body.preferenceKey || body.preference?.value || body.preference?.preferenceKey;
    if (!key) return json({ preference: null });
    const entry = loadStore()[key];
    return json({ preference: entry ? makePreference(key, entry.value, entry) : null });
  }
  if (pathname === "/api/ioi.v1.UserService/SetPreference") {
    const key = body.preference?.key || body.key || body.preferenceKey || "DEFAULT_PREFERENCE";
    const value = body.preference?.value ?? body.value ?? "";
    const store = loadStore();
    const now = new Date().toISOString();
    store[key] = { value, createdAt: store[key]?.createdAt || now, updatedAt: now };
    saveStore(store);
    return json({ preference: makePreference(key, value, store[key]) });
  }
  if (pathname === "/api/ioi.v1.UserService/ListPreferences") {
    const store = loadStore();
    // App-local preference defaults (config, not truth). The seeded shell's onboarding gate is
    // already satisfied by our org/user identity state, so no upstream onboarding flag is seeded.
    const seedTime = { createdAt: LOCAL_SCOPE.seedTime, updatedAt: LOCAL_SCOPE.seedTime };
    const merged = {};
    for (const [k, v] of Object.entries(store)) merged[k] = v.value;
    const preferences = Object.entries(merged).map(([key, value]) => makePreference(key, value, store[key] || seedTime));
    return json({ pagination: {}, preferences });
  }

  // ---- Identity: UserService / AccountService / OrganizationService (daemon truth or refusal) ----
  // W0.5: display identity comes from the daemon whoami/principals planes or not at all. The old
  // local-constant operator identity is gone; RPCs whose backing record has no daemon route
  // (organization record, ToS, org policy defaults — byte-verified absent from the daemon router)
  // refuse typed until the backend build adds the route.
  // A SIGNED-OUT CALLER IS NOBODY (R-240). whoami answers an unauthenticated browser with the
  // deployment's local-operator DISPLAY principal and `authenticated: false`; on a daemon nobody has
  // bootstrapped that record is the seeded placeholder "John Doe", and the shell greeted every
  // signed-out visitor as him ("Welcome back, John", the account button). The shell still needs the
  // principal's id to boot, so the id stays; the name and email a person reads as "you" do not.
  const whoamiPrincipal = async () => {
    const w = await daemon("GET", "/v1/hypervisor/auth/whoami");
    if (!(w.principal && w.principal.principal_id)) return null;
    return w.authenticated === true ? w.principal : { ...w.principal, name: "", email: "" };
  };
  const identityRefusal = (e) =>
    /-> 401$/.test(String(e?.message || ""))
      ? jsonStatus(401, { code: "unauthenticated", message: "authentication_required: sign in to resolve the session principal" })
      : unavailableRpc("identity_daemon_unavailable", "the daemon did not answer whoami; no local-constant identity is served");
  if (pathname === "/api/ioi.v1.UserService/GetAuthenticatedUser") {
    try {
      const p = await whoamiPrincipal();
      if (!p) return unavailableRpc("identity_principal_unresolved", "whoami returned no principal; no local-constant identity is served");
      return json({ user: { id: p.principal_id, organizationId: LOCAL_SCOPE.orgId, name: p.name || "", avatarUrl: "", createdAt: p.created_at || "", status: p.status === "active" ? "USER_STATUS_ACTIVE" : "USER_STATUS_SUSPENDED", email: p.email || "" } });
    } catch (e) {
      return identityRefusal(e);
    }
  }
  if (pathname === "/api/ioi.v1.AccountService/GetAccount") {
    // Account = the whoami principal. The membership row names its organization the way
    // GetOrganization does (orgDisplayName) — the org switcher and account menu read the name from
    // HERE, not from GetOrganization, so an omitted name drew every one of them as a blank "?" and
    // "Personal workspace" even after the organization was named (R-240). Tier stays omitted.
    try {
      const p = await whoamiPrincipal();
      if (!p) return unavailableRpc("identity_principal_unresolved", "whoami returned no principal; no local-constant account is served");
      const org = await daemon("GET", "/v1/hypervisor/organization").then((r) => r.organization || {}).catch(() => ({}));
      return json({ account: { id: p.principal_id, name: p.name || "", avatarUrl: "", email: p.email || "", createdAt: p.created_at || "", updatedAt: p.updated_at || p.created_at || "", memberships: [{ userId: p.principal_id, userRole: p.role === "admin" ? "ORGANIZATION_ROLE_ADMIN" : "ORGANIZATION_ROLE_MEMBER", organizationId: LOCAL_SCOPE.orgId, organizationName: orgDisplayName(org) }], publicEmailProvider: false } });
    } catch (e) {
      return identityRefusal(e);
    }
  }
  if (pathname === "/api/ioi.v1.AccountService/GetChatIdentityToken") {
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganization") {
    // Daemon-backed (W0.6 landed GET /v1/hypervisor/organization): projects only what the daemon
    // persists about the org scope — never the former "IOI Workspace"/tier constant. The name is the
    // display name an administrator set (PATCH /v1/hypervisor/organization); until one is set it is
    // the organization's own ref name (`org://local` → "local"). An empty name drew every account
    // menu and org chip as a blank "?" avatar beside a checkmark (R-240). tier/createdAt/inviteDomains
    // are omitted (nothing backs them).
    try {
      const r = await daemon("GET", "/v1/hypervisor/organization");
      const org = r.organization || {};
      return json({ organization: { id: LOCAL_SCOPE.orgId, name: orgDisplayName(org) } });
    } catch (e) {
      return daemonRefusalRpc("org_identity_daemon_unavailable", e, `the daemon organization read did not answer (${e.message}); no fabricated organization is served`);
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateOrganization") {
    // Settings → Organization renames the organization through this call; it had no lane at all, so
    // "Save" failed for everyone (R-240). Only the display name has a record — invite domains are
    // managed through domain verification, so a request carrying them is refused by name rather than
    // having the name saved and the domains silently dropped.
    if (body.inviteDomains !== undefined && body.inviteDomains !== null) {
      return jsonStatus(412, { code: "failed_precondition", message: "Not saved: invite domains are managed under Settings → Domain verification, not here." });
    }
    try {
      const r = await daemon("PATCH", "/v1/hypervisor/organization", { display_name: String(body.name || "") });
      return json({ organization: { id: LOCAL_SCOPE.orgId, name: orgDisplayName(r.organization || {}) } });
    } catch (e) {
      if (e.status >= 400 && e.status < 500) return jsonStatus(e.status === 401 ? 401 : e.status === 403 ? 403 : 412, { code: e.status === 401 ? "unauthenticated" : e.status === 403 ? "permission_denied" : "failed_precondition", message: `Not saved: ${e.daemonMessage || e.code || `the daemon refused (${e.status})`}` });
      return jsonStatus(502, { code: "unavailable", message: `failed to rename the organization: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetTermsOfService") {
    // TYPED ABSENCE (ORG-1) — served as the service's well-formed EMPTY record, not a refusal.
    // Byte-verified against the daemon route index (GET /v1/hypervisor -> 753 routes): NO route
    // matching /terms/ exists, and no canonical owner defines a Terms-of-Service record
    // (settings.md §2). Nothing real backs any field, so every field is OMITTED and the message
    // carries its proto defaults: enabled=false, currentVersion absent, currentUserAcceptance
    // absent. That is the truth ("this deployment has no terms-of-service record to accept"), and
    // it is exactly what the bundle's acceptance gate reads (`!enabled || !currentVersion` => no
    // gate), so no ToS content, version, or acceptance is invented. The former 503 refusal made
    // the bundle's `throwOnError` boot query log a console error on every app open.
    return json({ termsOfService: {} });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganizationPolicies") {
    // TYPED ABSENCE (ORG-1) — served as the service's well-formed EMPTY policy message, not a
    // refusal. The org-policy defaults family (env quotas, archive windows, sharing/veto/agent
    // policy) is a Wave 3 daemon build: byte-verified absent from the daemon route index (GET
    // /v1/hypervisor -> 753 routes; the only /polic/ routes are auth/policy, branch-policy,
    // connectors/:id/policy, placement/venue-policy, odk/policy-bound-data-views and the
    // ioi-agent launch-policies — none is an organization-policy-defaults record family).
    // EVERY field is omitted, so the message carries proto defaults only: nothing is fabricated
    // and no policy is asserted. This is behaviour-neutral by construction — the bundle's only
    // load-bearing read is the environment-start gate's
    // `policies?.maximumEnvironmentLifetime?.seconds`, which with the field absent computes 0 =
    // "no maximum lifetime", i.e. the same non-gating outcome the 503 produced, minus the thrown
    // error that also aborted the start mutation and logged on every app open.
    return json({ policies: {} });
  }

  // ---- EnvironmentService: real IOI daemon environments (WS-A/WS-B) ----
  // Env truth is daemon-owned (/v1/hypervisor/environments); the JS simulator is gone.
  try {
    const env = (path) => daemon("GET", path).then((r) => r.environment);
    const act = (id, action) =>
      daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/${action}`).then((r) => r.environment);
    switch (pathname) {
      case "/api/ioi.v1.EnvironmentService/GetEnvironment":
        return json({ environment: daemonEnvToIOI(await env(`/v1/hypervisor/environments/${encodeURIComponent(envIdFromBody(body))}`)) });
      case "/api/ioi.v1.EnvironmentService/ListEnvironments": {
        const r = await daemon("GET", "/v1/hypervisor/environments");
        // Deleted envs stay in the daemon as an audit record (status.deleted / phase "deleted"),
        // but a deleted env is not a live lifecycle entry — exclude it from the UI list.
        let live = (r.environments || []).filter((e) => !e.status?.deleted && e.status?.phase !== "deleted");
        // Project-scoped sessions: honor the SPA's project filter against the env's origin project
        // (daemon stores it at spec.project_id; see new_env / EnvironmentService.CreateEnvironment).
        const wantProjects = body.filter?.projectIds || body.filter?.project_ids || null;
        if (Array.isArray(wantProjects) && wantProjects.length) {
          live = live.filter((e) => {
            const pid = e.spec?.project_id ?? e.spec?.projectId;
            return pid && wantProjects.includes(pid);
          });
        }
        // THE ARCHIVAL FILTER IS HONORED (R-240 Arm A): the Archived view asks ARCHIVAL_STATUS_ARCHIVED and its "Delete
        // all" deletes every environment that answer lists. Answered with every live environment, that button deleted
        // running and stopped environments too. Archived = the daemon's "archived" phase; ACTIVE excludes it; ALL and an
        // unspecified filter keep every live environment (as before).
        const archival = body.filter?.archivalStatus ?? body.filter?.archival_status ?? null;
        const archivedEnv = (e) => e.status?.phase === "archived";
        if (archival === "ARCHIVAL_STATUS_ARCHIVED" || archival === 2) live = live.filter(archivedEnv);
        else if (archival === "ARCHIVAL_STATUS_ACTIVE" || archival === 1) live = live.filter((e) => !archivedEnv(e));
        return json({ pagination: {}, environments: live.map(daemonEnvToIOI) });
      }
      case "/api/ioi.v1.EnvironmentService/ListEnvironmentClasses": {
        const r = await daemon("GET", "/v1/hypervisor/environment-classes");
        return json({ pagination: {}, environmentClasses: (r.environmentClasses || []).map(daemonClassToIOI) });
      }
      case "/api/ioi.v1.EnvironmentService/StartEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "start")) });
      case "/api/ioi.v1.EnvironmentService/StopEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "stop")) });
      case "/api/ioi.v1.EnvironmentService/DeleteEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "delete")) });
      case "/api/ioi.v1.EnvironmentService/UpdateEnvironment": {
        const id = envIdFromBody(body);
        // Refused before anything applies: a rename / auto-stop / other member the daemon cannot store is
        // named, never answered 200 with nothing done (and never half-applied beside a port change).
        const refused = environmentUpdateRefusal(body);
        if (refused) return refused;
        const desired = body.spec?.desiredPhase || body.req?.spec?.desiredPhase;
        if (desired === "ENVIRONMENT_PHASE_RUNNING") return json({ environment: daemonEnvToIOI(await act(id, "start")) });
        if (desired === "ENVIRONMENT_PHASE_STOPPED") return json({ environment: daemonEnvToIOI(await act(id, "stop")) });
        // AN UPDATE NARROWS EXPOSURE; IT NEVER WIDENS IT (R-240 Arm B: the session page sends
        // `spec.ports:[{…, admission: EVERYONE}]` by itself every time a session's detail opens — before this,
        // merely LOOKING at a session exposed its port). Un-exposing a port applies; exposing one through an
        // environment update is refused by name, so nothing widens as a side effect of a view.
        const widening = [];
        for (const port of portsFromBody(body)) {
          const portNo = Number(port?.port || 0);
          if (!Number.isFinite(portNo) || portNo <= 0) continue;
          if (isPortUnexpose(port)) await daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/ports/${portNo}/unexpose`, {});
          else widening.push(portNo);
        }
        if (widening.length) {
          return jsonStatus(403, { code: "permission_denied", message: `port_exposure_not_by_update: exposing port ${widening.join(", ")} through an environment update is refused — an update may only narrow who reaches a port; nothing was exposed` });
        }
        return json({ environment: daemonEnvToIOI(await env(`/v1/hypervisor/environments/${encodeURIComponent(id)}`)) });
      }
      case "/api/ioi.v1.EnvironmentService/CreateEnvironment":
      case "/api/ioi.v1.EnvironmentService/CreateEnvironmentFromProject": {
        // Normalize the project link to the daemon's snake_case spec.project_id so the env is
        // project-scoped (ListEnvironments filters on it). The SPA sends camelCase / top-level projectId.
        const spec = { ...(body.spec || body) };
        const pid = spec.project_id ?? spec.projectId ?? body.projectId ?? body.project_id;
        if (pid) spec.project_id = pid;
        const created = await daemon("POST", "/v1/hypervisor/environments", { spec });
        let envRecord = created.environment;
        // The compose flow asks for desiredPhase RUNNING — actually start it so it has a real
        // workspace (the daemon create leaves it stopped). This is what makes the agent + editor work.
        const desired = body.spec?.desiredPhase || body.desiredPhase;
        if (desired === "ENVIRONMENT_PHASE_RUNNING" && envRecord?.id) {
          try { envRecord = await act(envRecord.id, "start"); } catch (e) { console.error("[ioi-api-adapter] env auto-start failed:", e.message); }
        }
        return json({ environment: daemonEnvToIOI(envRecord) });
      }
      case "/api/ioi.v1.EnvironmentService/CreateEnvironmentAccessToken": {
        // Mint a real env-scoped capability lease (Cut A): the SPA uses this as the Bearer for the
        // EnvironmentOpsService gateway, which fails closed on revoke/expire.
        const id = envIdFromBody(body);
        const lease = await daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/ops-lease`);
        return json({ accessToken: lease.accessToken || lease.lease_id });
      }
      case "/api/ioi.v1.EnvironmentService/CreateEnvironmentLogsToken": {
        // Sessions cut 1: the logs token is a real env-scoped capability lease (the same ops-lease
        // CreateEnvironmentAccessToken mints — no second token plane). The logs GET
        // (`/api/ioi/environments/:id/logs`) accepts it only while the daemon reports it active AND bound
        // to that environment, then reads GET /v1/hypervisor/environments/:id/logs as the caller.
        const id = envIdFromBody(body);
        const lease = await daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/ops-lease`);
        const accessToken = lease.accessToken || lease.lease_id;
        if (!accessToken) return unavailableRpc("environment_logs_token_unissued", "the daemon answered the lease request without a lease id; no token is fabricated");
        return json({ accessToken });
      }
      case "/api/ioi.v1.EnvironmentService/MarkEnvironmentActive":
        // Canon names mark_active as an environment-ops verb (providers-and-environments.md:528)
        // but no daemon route exists — the former handler returned success without doing anything.
        return unavailableRpc("environment_mark_active_route_missing", "the daemon has no mark-active route; nothing was marked active");
      case "/api/ioi.v1.EnvironmentService/ArchiveEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "archive")) });
      case "/api/ioi.v1.EnvironmentService/UnarchiveEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "restore")) });
      default:
        break;
    }
  } catch (e) {
    // W0.5: a failed daemon env call refuses typed — the fixture lane must never answer for the
    // live environment plane (fixture rows presented as environments would be placeholder data).
    console.error("[ioi-api-adapter] daemon env call failed closed:", e.message);
    if (/-> 404$/.test(e.message)) return jsonStatus(404, { code: "not_found", message: "the daemon has no such environment" });
    return daemonRefusalRpc("environment_daemon_unavailable", e, `the daemon environment plane did not answer (${e.message}); no fixture environments are served`);
  }

  // ---- AgentService: real IOI daemon threads/turns (Session) ----
  // Goal mode is refused before any run, environment or thread is touched (see goalModeMarker).
  if (
    pathname === "/api/ioi.v1.AgentService/CreateAgentSession" ||
    pathname === "/api/ioi.v1.AgentService/StartAgent" ||
    pathname === "/api/ioi.v1.AgentService/CreateAgentExecution" ||
    pathname === "/api/ioi.v1.AgentService/SendToAgentExecution"
  ) {
    const marker = goalModeMarker(body);
    if (marker) return goalModeRefusal(marker);
  }
  try {
    if (pathname.startsWith("/api/ioi.v1.AgentService/")) {
      const decision = await agentRunCacheAccessDecision();
      if (!decision.allowed) {
        return jsonStatus(decision.status, {
          error: { code: decision.code, message: decision.message },
        });
      }
    }
    // CreateAgentSession is the /ai composer's submit: spin up a real env + run the agent over
    // the harness (create env → start → bound session → mint grant → execute). Returns once the
    // env exists; the harness runs async (tracked in the run registry). The SPA then navigates to
    // /details/:environmentId and polls GetAgentExecution.
    if (pathname === "/api/ioi.v1.AgentService/CreateAgentSession") {
      const prompt = extractPrompt(body) || "Work in this environment.";
      const environmentClassId = extractEnvClass(body) || "local-workspace-v0";
      if (process.env.IOI_HYPERVISOR_DEBUG) console.error("[ioi-api-adapter] CreateAgentSession body:", bodyText.slice(0, 800));
      let started;
      try {
        started = await startAgentRun({
          daemonBase: DAEMON,
          prompt,
          environmentClassId,
          daemonHeaders: currentDaemonHeaders(),
          authorityProfile: extractAuthorityProfile(body),
          modelRouteRef: extractModelRouteRef(body),
        });
      } catch (error) {
        // Every failure to create a run ANSWERS. A thrown error here used to escape the handler and
        // drop the socket, which reaches the caller as a transport failure — indistinguishable from
        // a dead serve, and a client cannot act on it. The daemon's typed refusal (an UNBOUNDED
        // connection in the composer's authority profile, say) keeps its own status; anything else
        // is reported as an honest 500 naming what threw.
        const typed = Boolean(error?.code && error?.status);
        // A daemon 401 on the environment create is "sign in", not a failure: reported as a 500
        // `agent_session_create_failed` it hid the composer's sign-in path (R-240).
        if (!typed && /\(401\)/.test(String(error?.message || ""))) {
          return jsonStatus(401, { error: { code: "request_principal_required", message: "an authenticated session is required to start a Session — sign in first" } });
        }
        return {
          status: typed ? error.status : 500,
          contentType: "application/json",
          body: JSON.stringify({
            error: {
              code: typed ? error.code : "agent_session_create_failed",
              message: String(error?.message || error),
              widening_path: error?.body?.error?.widening_path || null,
            },
          }),
        };
      }
      const { agentExecutionId, environment, userInputBlockId } = started;
      return json({ environment, agentExecutionId, userInputBlockId });
    }
    if (pathname === "/api/ioi.v1.AgentService/ListAgentExecutions") {
      const wanted = body.filter?.environmentIds || body.filter?.environment_ids || null;
      const runList = listRuns()
        .filter((run) => !wanted || wanted.includes(run.envId))
        .map(runToAgentExecution);
      const threads = await daemon("GET", "/v1/threads");
      const list = Array.isArray(threads) ? threads : threads.threads || [];
      return json({ pagination: {}, agentExecutions: [...runList, ...list.map(threadToAgentExecution)] });
    }
    if (pathname === "/api/ioi.v1.AgentService/GetAgentExecution") {
      const id = body.agentExecutionId;
      const run = getRun(id);
      if (run) return json({ agentExecution: runToAgentExecution(run) });
      const t = await daemon("GET", `/v1/threads/${encodeURIComponent(id)}`);
      return json({ agentExecution: threadToAgentExecution(t) });
    }
    if (
      pathname === "/api/ioi.v1.AgentService/CreateAgentExecution" ||
      pathname === "/api/ioi.v1.AgentService/StartAgent"
    ) {
      // Compose flow: StartAgent binds the agent to a just-created (running) env via
      // codeContext.environmentId. Register a real run against that env; the harness fires on
      // the subsequent SendToAgentExecution (which carries the prompt).
      const envId = body.codeContext?.environmentId || body.code_context?.environmentId;
      if (envId) {
        const run = registerAgentRun({
          envId,
          daemonHeaders: currentDaemonHeaders(),
        });
        return json({ agentExecutionId: run.id });
      }
      const created = await daemon("POST", "/v1/threads", { title: textFromBody(body).slice(0, 80) || undefined });
      return json({ agentExecutionId: created.thread_id || created.id });
    }
    if (pathname === "/api/ioi.v1.AgentService/SendToAgentExecution") {
      const id = body.agentExecutionId;
      const prompt = extractPrompt(body) || textFromBody(body);
      if (getRun(id)) {
        // The SPA generates the userInput block id client-side and sends it here; it uses the SAME
        // id as its optimistic pending message (pendingMessageId). Echo THIS id in the conversation
        // stream so the pending turn reconciles (no duplicate prompt, "Thinking…" resolves).
        const clientBlockId = body.userInput?.id || body.input?.value?.id || body.input?.userInput?.id;
        const userInputBlockId = await sendToAgentRun({
          daemonBase: DAEMON,
          runId: id,
          prompt,
          userInputBlockId: clientBlockId,
          daemonHeaders: currentDaemonHeaders(),
        });
        // The product-ui bundle invalidates/refetches the execution immediately after this RPC
        // completes. If we return while the local harness is still RUNNING, the conversation pane
        // keeps its optimistic "Thinking…" row even though the files and final reply arrive in our
        // run registry a moment later. Hold this local compose RPC until the run reaches a terminal
        // state (bounded timeout) so the normal refetch hydrates STOPPED + completed conversation
        // chunks without teaching the bundle a bespoke execution-status channel.
        await waitForRunTerminal(id);
        return json({ userInputBlockId });
      }
      if (id && prompt) await daemon("POST", `/v1/threads/${encodeURIComponent(id)}/turns`, { text: prompt });
      return json({});
    }
    if (pathname === "/api/ioi.v1.AgentService/StopAgentExecution") {
      const id = body.agentExecutionId;
      if (id) await daemon("POST", `/v1/threads/${encodeURIComponent(id)}/cancel`);
      return json({});
    }
    if (pathname === "/api/ioi.v1.AgentService/DeleteAgentExecution") {
      const id = body.agentExecutionId;
      if (id) await daemon("DELETE", `/v1/threads/${encodeURIComponent(id)}`);
      return json({});
    }
    if (pathname === "/api/ioi.v1.AgentService/CreateAgentExecutionConversationToken") {
      return json({ token: `ioi-agent-conv-${body.agentExecutionId || "anon"}` });
    }
  } catch (e) {
    if (pathname.startsWith("/api/ioi.v1.AgentService/")) {
      console.error("[ioi-api-adapter] owned AgentService call failed closed:", e.message);
      return jsonStatus(503, {
        error: {
          code: "agent_service_owned_path_unavailable",
          message:
            "The owned AgentService path is unavailable; no harvested or mock substitute is admissible.",
        },
      });
    }
    console.error("[ioi-api-adapter] daemon call failed, proxying:", e.message);
    return null;
  }

  // ---- RunnerService: runners backed by the EnvironmentProvider registry (local authority) ----
  if (pathname === "/api/ioi.v1.RunnerService/CheckAuthenticationForHost") {
    // The native Git-authentications flow asks whether the host (github.com) is authenticated, and
    // whether PAT is supported. We support PAT (CreateHostAuthenticationToken → daemon connect);
    // authenticated reflects whether a host credential is sealed in the daemon.
    const host = body.host || body.host_name || "github.com";
    let authenticated = false;
    try {
      const r = await daemon("GET", "/v1/hypervisor/scm-connectors");
      authenticated = (r.connectors || []).some((c) => c.host === host && c.auth_posture === "token-lease:bound");
    } catch { /* daemon transient */ }
    // CheckAuthenticationForHostResponse has both an older boolean (`pat_supported`) and the
    // current PAT method object (`supports_pat`). The settings row reads `supportsPat`, but the
    // generated decoder still expects the message shape — returning a boolean makes the hook retry
    // forever and leaves the row on "Checking...".
    const supportsPat = {
      createUrl: "https://github.com/settings/tokens/new?scopes=repo,workflow",
      docsUrl: "https://docs.github.com/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
      example: "ghp_...",
      requiredScopes: ["repo", "workflow"],
    };
    return json({ authenticated, authenticationUrl: "", patSupported: true, supportsPat, scmId: "github", scmName: "GitHub" });
  }
  if (pathname === "/api/ioi.v1.RunnerService/ListRunners") {
    // The compose flow filters runners to RUNNER_KIND_REMOTE (environments run on a remote-shaped
    // host). Our local provider IS that host for the served app, so present it as a REMOTE runner —
    // otherwise the env class has no supported runner and shows "Unsupported" (unselectable).
    // Daemon down => typed refusal, not an empty list masquerading as "no runners".
    try {
      return json({ pagination: {}, runners: await listProjectedRunners() });
    } catch (e) {
      return daemonRefusalRpc("runner_daemon_unavailable", e, `the daemon provider plane did not answer (${e.message}); runner availability is unknown, not empty`);
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/GetRunner") {
    // W0.5: an unknown runner id refuses 404 — the former handler fabricated an "available"
    // runner for ANY requested id.
    const runnerId = body.runnerId || body.runner_id || "local-microvm";
    try {
      const runner = (await listProjectedRunners()).find((r) => r.runnerId === runnerId);
      if (!runner) return jsonStatus(404, { code: "not_found", message: `runner ${runnerId} is not a daemon provider` });
      return json({ runner });
    } catch (e) {
      return daemonRefusalRpc("runner_daemon_unavailable", e, `the daemon provider plane did not answer (${e.message})`);
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/CreateRunner") {
    // A local deployment does not create runners; the SPA's setup flow resolves to the already-
    // registered active daemon provider. Daemon down / no active provider => typed refusal (the
    // former handler fabricated an active runner from nothing).
    try {
      const runner = (await listProjectedRunners()).find((x) => x.status?.phase === "RUNNER_PHASE_ACTIVE");
      if (!runner) return unavailableRpc("runner_provider_unavailable", "no daemon provider reports available; no runner is fabricated");
      return json({ runner });
    } catch (e) {
      return daemonRefusalRpc("runner_daemon_unavailable", e, `the daemon provider plane did not answer (${e.message})`);
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/ParseContextURL") {
    const parsed = parseGitHubContextUrl(body.contextUrl || body.context_url || "");
    if (!parsed) return jsonStatus(400, { code: "invalid_argument", message: "Only GitHub repository URLs are supported by the local Hypervisor Git auth bridge." });
    return json(parsed);
  }
  if (pathname === "/api/ioi.v1.RunnerManagerService/ListAvailableRunnerManagers") {
    // No runner-manager family exists in the daemon (byte-verified: no route). The former
    // handler returned a hand-written "IOI Local (microVM)" manager row; the single-node truth
    // already lives on the runners list itself.
    return unavailableRpc("runner_manager_route_missing", "the daemon has no runner-manager family; no hand-written manager row is served");
  }
  if (pathname === "/api/ioi.v1.RunnerService/CreateRunnerLogsToken") {
    // No daemon runner-logs-token route exists (byte-verified); the former handler minted a
    // local constant token that unlocked nothing.
    return unavailableRpc("runner_logs_token_route_missing", "the daemon has no runner-logs-token route; no fabricated token is minted");
  }

  // ---- EditorService: real daemon editor targets (vscode / insiders / browser) ----
  if (pathname === "/api/ioi.v1.EditorService/ListEditors") {
    // vscode-browser is the proven end-to-end target: its urlTemplate points at the serve layer's
    // /__ioi/editor/open, which drives the daemon editor chain and redirects to the live editor.
    // Desktop targets carry their native deep-link scheme (best-effort on the host).
    const URL_TEMPLATES = {
      "vscode-browser": "/__ioi/editor/open?environmentId={{.EnvironmentId}}",
      vscode: "vscode://ioi.ioi-flex/connect?environmentId={{.EnvironmentId}}",
      "vscode-insiders": "vscode-insiders://ioi.ioi-flex/connect?environmentId={{.EnvironmentId}}",
      // Cursor is a VS Code-family host running the SAME adapter extension, and the daemon states its
      // open route in those terms ("deep link into the local cursor host (adapter extension)").
      cursor: "cursor://ioi.ioi-flex/connect?environmentId={{.EnvironmentId}}",
    };
    const labels = { vscode: "VS Code", "vscode-insiders": "VS Code Insiders", "vscode-browser": "VS Code (Browser)" };
    try {
      const r = await daemon("GET", "/v1/hypervisor/editor-targets");
      // Offer ONLY targets whose PROBED open posture passed (openable_targets) — a listed editor
      // that cannot actually open is a dropdown lie. The owned Workbench panel shows the full
      // registry with disabled-with-reason rows.
      const openable = r.openable_targets || r.active_targets || [];
      let active = openable.filter((t) => t !== "workbench-native"); // the SPA console IS the native surface
      active = ["vscode-browser", ...active.filter((t) => t !== "vscode-browser")].filter((t) => openable.includes(t));
      // An editor with no open route is a dead option: picking it opens nothing. Cursor and SSH were
      // both offered with an empty urlTemplate (R-240); SSH stays out until the daemon publishes the
      // host and port an ssh:// link needs. Names come from the daemon profile, not the raw target id.
      const byId = Object.fromEntries((r.targets || []).map((t) => [t.target_id, t]));
      const editors = active.filter((t) => URL_TEMPLATES[t]).map((t) => ({ id: t, name: labels[t] || byId[t]?.profile?.displayName || t, alias: t, urlTemplate: URL_TEMPLATES[t], installationInstructions: "" }));
      return json({ editors });
    } catch {
      return json({ editors: [{ id: "vscode-browser", name: "VS Code (Browser)", alias: "vscode-browser", urlTemplate: URL_TEMPLATES["vscode-browser"], installationInstructions: "" }] });
    }
  }

  // ---- ProjectService: real daemon projects (WS-C). A project is the durable repository-backed
  // container the agent-automations plane will hang from; List/Create/Get/Delete are daemon-backed
  // (/v1/hypervisor/projects + /:id). The IOI automation-ready hooks (automation_refs /
  // *_policy_ref) live on the daemon record (daemon-side truth), NOT in the SPA projection. ----
  if (pathname.startsWith("/api/ioi.v1.ProjectService/")) {
    const op = pathname.slice("/api/ioi.v1.ProjectService/".length);
    const PROJECT_OPS = new Set(["ListProjects", "GetProject", "CreateProject", "DeleteProject"]);
    const projectIdFromBody = (b) =>
      b.projectId || b.project_id || b.id || (b.req && (b.req.projectId || b.req.id)) || "";
    if (PROJECT_OPS.has(op)) {
      try {
        if (op === "ListProjects") {
          const r = await daemon("GET", "/v1/hypervisor/projects");
          let records = r.projects || [];
          const search = (body.filter?.search || body.search || "").trim().toLowerCase();
          if (search) {
            records = records.filter(
              (p) =>
                (p.name || "").toLowerCase().includes(search) ||
                (p.repository_url || "").toLowerCase().includes(search),
            );
          }
          return json({ pagination: {}, projects: records.map((p) => daemonProjectToIOI(p, LOCAL_SCOPE.orgId)) });
        }
        if (op === "GetProject") {
          const id = projectIdFromBody(body);
          const r = await daemon("GET", `/v1/hypervisor/projects/${encodeURIComponent(id)}`);
          if (!r.ok || !r.project) return jsonStatus(404, { code: "not_found", message: `project ${id} not found` });
          return json({ project: daemonProjectToIOI(r.project, LOCAL_SCOPE.orgId) });
        }
        if (op === "CreateProject") {
          // Translate the SPA's create request (camelCase initializer.specs[].git) to the
          // daemon's repository-backed create body (snake_case repository_url + project_name).
          const spec = body.initializer?.specs?.[0] || {};
          const git = spec.git || {};
          const repoUrl =
            git.remoteUri || git.remote_uri || spec.contextUrl?.url || spec.context_url?.url ||
            body.cloneUrl || body.repositoryUrl || "";
          const name = (body.name || git.remoteUri || git.remote_uri || "Untitled project").toString();
          const envClassRefs = Array.isArray(body.environmentClasses)
            ? body.environmentClasses.map((c) => c.environmentClassId || c.environment_class_id).filter(Boolean)
            : body.environmentClassIds || [];
          const createBody = { repository_url: repoUrl, project_name: name, source: "manual_url" };
          if (envClassRefs.length) createBody.environment_class_refs = envClassRefs;
          const created = await daemon("POST", "/v1/hypervisor/projects", createBody);
          const records = created.records || [];
          const record =
            records.find((p) => p.project_id === created.selected_project_id) ||
            records[records.length - 1] ||
            created.record ||
            createBody;
          return json({ project: daemonProjectToIOI(record, LOCAL_SCOPE.orgId) });
        }
        if (op === "DeleteProject") {
          const id = projectIdFromBody(body);
          await daemon("DELETE", `/v1/hypervisor/projects/${encodeURIComponent(id)}`);
          return json({});
        }
      } catch (e) {
        console.error("[ioi-api-adapter] daemon project call failed:", e.message);
        // Honest local truth on daemon-down: empty list / connect error — never the mock's rows.
        if (op === "ListProjects") return json({ pagination: {}, projects: [] });
        return jsonStatus(502, { code: "unavailable", message: "daemon project plane unavailable" });
      }
    }
    if (op === "ListProjectEnvironmentClasses") {
      // The env classes a project can launch into (the create-environment dialog's "Session Class"
      // and the detail page's class list). R-240: this answered the WRONG MESSAGE — full
      // EnvironmentClass objects under `environmentClasses` — while the bundle reads
      // `projectEnvironmentClasses`, each a oneof `{ environmentClassId, order }` that it resolves
      // against the enabled catalog. Every project's picker was therefore empty ("No available
      // environment classes"), and the create went out with class "(unspecified)", which the daemon
      // refused. Daemon truth, per project: the classes bound on the record (`environment_class_refs`);
      // when none are bound, every catalog class — the daemon admits an environment against its
      // catalog, never against a per-project list, so an unbound project can launch into any of them.
      try {
        const id = projectIdFromBody(body);
        const [proj, cat] = await Promise.all([
          daemon("GET", `/v1/hypervisor/projects/${encodeURIComponent(id)}`).catch(() => ({})),
          daemon("GET", "/v1/hypervisor/environment-classes"),
        ]);
        // The record carries the binding in TWO fields: `environment_class_ids` is what the receipted
        // binding write (PATCH …/environment-classes, receipt `environment_classes_bound`) stores, and
        // `environment_class_refs` is what project create seeded. The receipted write is the truth of
        // what is bound now; the seed answers only when nothing has been bound since. Measured: a bind
        // persisted in `environment_class_ids` while a read of `environment_class_refs` stayed empty.
        const pick = (v) => (Array.isArray(v) ? v.filter(Boolean) : []);
        const bound = pick(proj.project?.environment_class_ids).length ? pick(proj.project.environment_class_ids) : pick(proj.project?.environment_class_refs);
        const ids = bound.length ? bound : (cat.environmentClasses || []).map((c) => c.id);
        return json({ pagination: {}, projectEnvironmentClasses: ids.map((environmentClassId, order) => ({ environmentClassId, order })) });
      } catch {
        return json({ pagination: {}, projectEnvironmentClasses: [] });
      }
    }
    if (op === "UpdateProjectEnvironmentClasses") {
      // OQ-5 saga step 2 — the write plane exists now (PATCH :id/environment-classes). The
      // response always names the exact durable state; a refusal never claims rollback.
      const id = projectIdFromBody(body);
      // The bundle sends `projectEnvironmentClasses: [{ environmentClassId, order }]` (a oneof,
      // flattened in Connect JSON). This read only the three older spellings, so every binding the
      // setup flow made was PATCHed as an empty list and silently dropped (R-240).
      const pec = Array.isArray(body.projectEnvironmentClasses) ? body.projectEnvironmentClasses : [];
      const ids = (pec.length
        ? [...pec].sort((a, b) => (a?.order || 0) - (b?.order || 0)).map((c) => c?.environmentClassId || c?.environmentClass?.value)
        : (body.environmentClassIds || body.environment_class_ids ||
          (Array.isArray(body.environmentClasses) ? body.environmentClasses.map((c) => c?.id || c) : []) || []))
        .filter((x) => typeof x === "string" && x.trim());
      try {
        // Status-tolerant call: a typed refusal (401/404/409/422) is saga truth to surface
        // verbatim, never rebranded daemon-down (daemon() throws on any non-2xx).
        const res = await fetch(`${DAEMON}/v1/hypervisor/projects/${encodeURIComponent(id)}/environment-classes`, {
          method: "PATCH",
          headers: currentDaemonHeaders({ includeContentType: true }),
          body: JSON.stringify({ environment_class_ids: ids }),
          signal: AbortSignal.timeout(8000),
        });
        const r = await res.json().catch(() => ({}));
        if (res.ok && r?.ok === true) {
          return json({ project: daemonProjectToIOI(r.project, LOCAL_SCOPE.orgId), receiptRef: r.receipt?.receipt_ref || "" });
        }
        return jsonStatus(res.ok ? 409 : res.status, { code: r?.code || "project_environment_classes_refused",
          message: `${r?.message || "the binding was refused"} — the created project keeps its exact durable partial state` });
      } catch (e) {
        return jsonStatus(502, { code: "project_environment_classes_unavailable",
          message: `the daemon did not answer the binding step (${e.message}); the created project keeps its exact durable partial state` });
      }
    }
    if (op === "UpdateProject") {
      // R-240: the settings page saves each field on blur through this RPC, and it had no daemon
      // lane — the edit stayed in the field, no error showed, and a reload put the old value back.
      // Display name and Branch are fields the project record holds, so they go to the receipted
      // PATCH /v1/hypervisor/projects/:id. Everything else the form can send has no field or no
      // runner behind it and is REFUSED BY NAME, so the form's own error toast says why nothing
      // saved instead of the edit silently evaporating.
      const id = projectIdFromBody(body);
      const git = body.initializer?.specs?.[0]?.git || null;
      const patch = {};
      if (typeof body.name === "string") patch.name = body.name;
      if (git && typeof git.cloneTarget === "string") patch.repository_branch = git.cloneTarget;
      const refused = [];
      if (body.devcontainerFilePath !== undefined) refused.push("the dev container file path (the project record has no such field)");
      if (body.automationsFilePath !== undefined) refused.push("the automations file path (the project record has no such field)");
      if (body.prebuildConfiguration !== undefined) refused.push("prebuilds (no prebuild runner exists in this deployment)");
      if (git && git.remoteUri) {
        try {
          const cur = await daemon("GET", `/v1/hypervisor/projects/${encodeURIComponent(id)}`);
          if (cur.project?.repository_url && git.remoteUri !== cur.project.repository_url) refused.push("the repository URL (changing it is a different project, not an edit)");
        } catch { /* the PATCH below answers for the project's existence */ }
      }
      if (refused.length) return jsonStatus(412, { code: "failed_precondition", message: `Not saved: ${refused.join("; ")}.` });
      if (!Object.keys(patch).length) return jsonStatus(412, { code: "failed_precondition", message: "Not saved: this edit names no field the project record holds." });
      try {
        const res = await fetch(`${DAEMON}/v1/hypervisor/projects/${encodeURIComponent(id)}`, {
          method: "PATCH",
          headers: currentDaemonHeaders({ includeContentType: true }),
          body: JSON.stringify(patch),
          signal: AbortSignal.timeout(8000),
        });
        const r = await res.json().catch(() => ({}));
        if (res.ok && r?.ok === true) return json({ project: daemonProjectToIOI(r.project, LOCAL_SCOPE.orgId) });
        if (res.status === 401) return jsonStatus(401, { code: "unauthenticated", message: "Not saved: sign in (/__ioi/login) to edit projects." });
        return jsonStatus(res.status >= 400 ? res.status : 409, { code: r?.code === "project_revision_conflict" ? "aborted" : "failed_precondition", message: `Not saved: ${r?.message || "the daemon refused the edit"}` });
      } catch (e) {
        return unavailableRpc("project_metadata_unavailable", `the daemon did not answer the edit (${e.message}); nothing was saved`);
      }
    }
  }

  // ---- Local-deployment projections: honest local posture for planes the daemon does not yet
  // own (groups / workflows / per-env automation / SCM). These are deferred data planes — empty is
  // the honest local truth (NOT the mock's fabricated rows). Identity-derived surfaces (members,
  // org-members group) reflect the single local operator. ----
  if (pathname === "/api/ioi.v1.ServiceAccountService/ListServiceAccounts") {
    // No service-account family exists in the daemon (byte-verified: no route). The former
    // handler returned one hardcoded "IOI Hypervisor" system row — placeholder data. If the
    // identity plane grows a service-account kind on principals, this projects it instead.
    return unavailableRpc("service_account_family_route_missing", "the daemon has no service-account family; no hardcoded system account is served");
  }
  if (pathname === "/api/ioi.v1.UserService/GetDotfilesConfiguration") {
    return json({ dotfilesConfiguration: { repository: "" } });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/ListMembers") {
    // Real multi-user roster — projected from the daemon principals plane (active members only).
    // W0.5: the constant single-operator fallback row is gone; nothing here invents a member.
    const wantsCount = body?.count?.include === true || body?.count?.include === "true";
    try {
      const r = await daemon("GET", "/v1/hypervisor/principals");
      const members = (r.principals || []).filter((p) => p.status === "active").map((p) => ({
        userId: p.principal_id, role: p.role === "admin" ? "ORGANIZATION_ROLE_ADMIN" : "ORGANIZATION_ROLE_MEMBER",
        memberSince: p.created_at, avatarUrl: "", fullName: p.name, email: p.email, status: "USER_STATUS_ACTIVE", loginProvider: p.source || "local",
      }));
      // Count is the roster the daemon actually disclosed — never a separately-sourced number.
      return json({ pagination: {}, members, ...(wantsCount ? { count: { value: members.length } } : {}) });
    } catch {
      // TYPED ABSENCE (ORG-1). The roster route EXISTS (GET /v1/hypervisor/principals, probed) but
      // the daemon adjudicates it org-admin-only: an unauthenticated local session gets 401
      // "hypervisor.authentication_required — an authenticated session or API token is required
      // even on loopback" (handle_principal_list -> require_authenticated_org_admin). The adapter
      // must NOT escalate the caller's authority to read it and must not invent rows, so it serves
      // the service's well-formed EMPTY roster rather than the 4xx/5xx the bundle's batched
      // member-by-ids loader logged on every app open. Empty here means "no member record was
      // disclosed to this caller", not "this organization has no members".
      // To keep that distinction from reading as a false zero, the membership CARDINALITY the
      // daemon does disclose unauthenticated (GET /v1/hypervisor/organization ->
      // organization.members.principals_total, 200 ok) is carried through when — and only when —
      // the caller asked for an unfiltered count; a filtered count has no undisclosed-roster
      // truth behind it, so it is omitted rather than approximated.
      const filtered = Boolean(body?.filter && Object.keys(body.filter).length > 0);
      let count;
      if (wantsCount && !filtered) {
        try {
          const org = await daemon("GET", "/v1/hypervisor/organization");
          const total = org?.organization?.members?.principals_total;
          if (typeof total === "number" && Number.isFinite(total)) count = { value: total };
        } catch {
          /* the org read did not answer either — no cardinality is claimed */
        }
      }
      return json({ pagination: {}, members: [], ...(count ? { count } : {}) });
    }
  }
  if (pathname === "/api/ioi.v1.GroupService/GetGroup") {
    return json({ group: { id: LOCAL_SCOPE.groupId, organizationId: LOCAL_SCOPE.orgId, name: "org-members", systemManaged: true, createdAt: LOCAL_SCOPE.seedTime, updatedAt: LOCAL_SCOPE.seedTime, memberCount: 1 } });
  }
  if (pathname === "/api/ioi.v1.GroupService/ListGroups") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/ioi.v1.GroupService/ListRoleAssignments") {
    return json({ pagination: {}, assignments: [] });
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/ListSCMIntegrations") {
    // The github.com SCM integration row, projected from the daemon SCM connector plane instead
    // of the former hand-written constant. GitHub PAT connect is a real daemon capability (POST
    // /v1/hypervisor/scm-connect/github); the row's identity carries the bound daemon connector
    // when one exists. Daemon down => typed refusal, never a hand-written row.
    try {
      const r = await daemon("GET", "/v1/hypervisor/scm-connectors");
      const gh = (r.connectors || []).find((c) => c.kind === "github" && c.host_level);
      const host = gh?.host || "github.com";
      return json({ pagination: {}, integrations: [{
        id: gh?.connector_id || "scm-github", runnerId: "local-microvm", scmId: "github", host,
        issuerUrl: `https://${host}`, oauthClientId: "", pat: true,
      }] });
    } catch (e) {
      return daemonRefusalRpc("scm_connector_daemon_unavailable", e, `the daemon SCM connector plane did not answer (${e.message}); no hand-written integration row is served`);
    }
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/GetEnvironmentClass") {
    // W0.5: formerly fixture-only. The one daemon substrate catalog answers by id — same
    // projection as the two List RPCs; unknown id refuses 404, never the fixture "Small" class.
    const classId = body.environmentClassId || body.environment_class_id || body.id || "";
    try {
      const r = await daemon("GET", "/v1/hypervisor/environment-classes");
      const c = (r.environmentClasses || []).find((x) => x.id === classId);
      if (!c) return jsonStatus(404, { code: "not_found", message: `environment class ${classId || "(unspecified)"} is not in the daemon catalog` });
      return json({ environmentClass: daemonClassToIOI(c) });
    } catch (e) {
      return daemonRefusalRpc("environment_class_daemon_unavailable", e, `the daemon substrate catalog did not answer (${e.message}); no fixture class is served`);
    }
  }
  if (pathname.startsWith("/api/ioi.v1.InsightsService/")) {
    // W0.5: formerly the mock fallthrough (fixture body `{}` for GetProjectInsightsStatus).
    // Insights has no daemon family at all (byte-verified: no route) — named gap, honest refusal.
    return unavailableRpc("insights_family_route_missing", "the daemon has no insights family; the pane renders a named gap instead of fixture data");
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/CreateHostAuthenticationToken") {
    // The native "Connect GitHub" PAT submit. Validate + SEAL the token via the daemon connect
    // (host-level), then reflect it as a host authentication token. Fail closed if GitHub rejects.
    const t = body.token || body || {};
    const pat = t.token || body.token || body.pat || "";
    const host = t.host || body.host || "github.com";
    if (!pat) return jsonStatus(400, { code: "invalid_argument", message: "a personal access token is required" });
    // Raw fetch (not the throwing daemon() helper) so a 401 from GitHub validation surfaces as a
    // fail-closed connect error instead of being swallowed into a proxy fallthrough.
    let r = {};
    try {
      const resp = await fetch(`${DAEMON}/v1/hypervisor/scm-connect/github`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: pat }), signal: AbortSignal.timeout(25000) });
      r = await resp.json().catch(() => ({}));
    } catch (e) { return jsonStatus(502, { code: "unavailable", message: `github connect failed: ${e.message}` }); }
    if (!r.ok) return jsonStatus(401, { code: "unauthenticated", message: r.reason || "github rejected the token" });
    return json({ token: { id: r.connector_id || "scm_host_github", runnerId: "local-microvm", host, scmId: "github", userId: LOCAL_SCOPE.userId, source: "HOST_AUTHENTICATION_TOKEN_SOURCE_PAT", expiresAt: undefined } });
  }
  if (pathname === "/api/ioi.v1.PrebuildService/ListPrebuilds") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/ioi.v1.PrebuildService/ListWarmPools") {
    // Prebuild warm pools (a managed-runner prebuild optimization). The local single-operator
    // substrate keeps no SPA-shaped warm pools — honest empty, not the mock's fabricated rows.
    return json({ pagination: {}, warmPools: [] });
  }
  if (pathname === "/api/ioi.v1.WorkflowService/ListWorkflows") {
    return json({ pagination: {}, workflows: [] });
  }
  if (pathname === "/api/ioi.v1.WorkflowService/ListWorkflowExecutions") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/ioi.v1.WorkflowService/GetWorkflowExecutionSummary") {
    return json({ totalWorkflowsInOrganization: "0" });
  }
  // An environment's services, tasks and task runs have no daemon plane: no route lists them (the
  // daemon's `env-config apply_automations` records an observation, and `environments/:id/logs?kind=tasks`
  // reads task log files — neither is a task or service record). An empty list presented that absence as
  // "No tasks defined in this environment" (Sessions cut 1), so each list refuses naming the absent plane.
  // `unimplemented` is terminal: the bundle's query retry stops on it, and the Services section renders
  // the error in place. (The Tasks tab reads only `data`, so it still says "No tasks defined" — a bundle
  // limit the adapter cannot reach.)
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListServices") {
    return jsonStatus(501, { code: "unimplemented", message: "environment_services_plane_absent: the daemon has no environment services plane (no route lists an environment's services); nothing is listed rather than an empty list that reads as \"no services\"" });
  }
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListTasks") {
    return jsonStatus(501, { code: "unimplemented", message: "environment_tasks_plane_absent: the daemon has no environment tasks plane (no route lists an environment's tasks); nothing is listed rather than an empty list that reads as \"no tasks defined\"" });
  }
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListTaskExecutions") {
    return jsonStatus(501, { code: "unimplemented", message: "environment_task_executions_plane_absent: the daemon has no environment task-run plane (no route lists an environment's task executions); nothing is listed rather than an empty list" });
  }
  // ---- BillingService: REAL metering & cost plane (OCU = Hypervisor Compute Units derived from
  // actual receipts in the daemon) + a wallet-backed budget. Not SaaS billing — the daemon's own
  // economic plane: agentgres RECORDS → metered; wallet.network FUNDS the budget. ----
  if (pathname === "/api/ioi.v1.BillingService/GetBillingInfo") {
    // Metered balance from the daemon budget (used/available from real OCU consumption). creditStatus
    // never gates a self-hosted deployment.
    try {
      const r = await daemon("GET", "/v1/hypervisor/budget");
      const b = r.budget || {};
      return json({ totalCredits: b.budget_ocu ?? 0, availableCredits: b.available_ocu ?? 0, usedCredits: b.used_ocu ?? 0, paymentMethodStatus: "PAYMENT_METHOD_STATUS_VERIFIED", creditStatus: "CREDIT_STATUS_HAS_CREDITS", autoTopupSettings: { enabled: !!b.auto_fund_enabled }, monthlyCommitmentCents: "0" });
    } catch {
      return json({ totalCredits: 0, availableCredits: 0, usedCredits: 0, paymentMethodStatus: "PAYMENT_METHOD_STATUS_VERIFIED", creditStatus: "CREDIT_STATUS_HAS_CREDITS", autoTopupSettings: {}, monthlyCommitmentCents: "0" });
    }
  }
  if (pathname === "/api/ioi.v1.BillingService/GetCreditConsumptionTimeSeries") {
    // Real per-day OCU consumption by metric kind, aggregated by the daemon from the receipts it
    // already records for every execution. Empty/low is the honest truth for a fresh deployment.
    const dr = body.dateRange || {};
    const qs = new URLSearchParams();
    if (dr.startTime) qs.set("from", dr.startTime);
    if (dr.endTime) qs.set("to", dr.endTime);
    try {
      const r = await daemon("GET", `/v1/hypervisor/usage/consumption?${qs.toString()}`);
      return json({ metrics: (r.metrics || []).map((m) => ({ displayName: m.display_name, kind: m.kind, series: m.series })) });
    } catch {
      return json({ metrics: [] });
    }
  }
  if (pathname === "/api/ioi.v1.BillingService/GetAutoTopupSettings") {
    // Wallet auto-funding policy (the wallet-native reframe of SaaS auto top-up).
    try {
      const r = await daemon("GET", "/v1/hypervisor/budget");
      const b = r.budget || {};
      return json({ settings: { enabled: !!b.auto_fund_enabled, ...(b.threshold_ocu != null ? { thresholdBalance: b.threshold_ocu } : {}), ...(b.target_ocu != null ? { targetBalance: b.target_ocu } : {}) } });
    } catch {
      return json({ settings: {} });
    }
  }
  if (pathname === "/api/ioi.v1.BillingService/ReconcileBilling") {
    // Reconcile real usage vs the budget; applies wallet auto-funding if below threshold.
    try { await daemon("POST", "/v1/hypervisor/budget/reconcile"); } catch { /* best-effort */ }
    return json({});
  }
  if (pathname === "/api/ioi.v1.BillingService/ListSubscriptions") {
    // A self-hosted deployment holds no SaaS subscriptions — empty is the honest truth (W0.5:
    // the fabricated non-expiring "sovereign contract" row is gone; the settings build replaces
    // this pane with a deployment-posture line from /v1/hypervisor/auth/policy).
    return json({ subscriptions: [] });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetAnnouncementBanner") {
    return json({ banner: { organizationId: LOCAL_SCOPE.orgId } });
  }
  // ---- OrganizationService: OIDC login config (real CRUD, client_secret sealed in the daemon) +
  // honest-local team-identity surfaces. SSO/SCIM/custom-domain/domain-verification/invite presuppose
  // a multi-user federated-login layer the single-operator daemon doesn't run yet → honest empty
  // posture (owned, not mock). OIDC config is management-real (login enforcement is a separate plane). ----
  if (pathname === "/api/ioi.v1.OrganizationService/GetOIDCConfig") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/oidc-config");
      const c = r.config || {};
      return json({ oidcConfig: { v3: { issuerUrl: c.issuer_url || "", clientId: c.client_id || "", emailDomain: c.email_domain || "", active: !!c.enabled } } });
    } catch {
      return json({ oidcConfig: { v3: {} } });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateOIDCConfig") {
    const cfg = body.oidcConfig?.v3 || body.oidcConfig || body.config || {};
    try {
      await daemon("PUT", "/v1/hypervisor/oidc-config", { issuer_url: cfg.issuerUrl, client_id: cfg.clientId, client_secret: cfg.clientSecret, email_domain: cfg.emailDomain, enabled: cfg.active ?? cfg.enabled ?? false });
      const r = await daemon("GET", "/v1/hypervisor/oidc-config");
      const c = r.config || {};
      return json({ oidcConfig: { v3: { issuerUrl: c.issuer_url || "", clientId: c.client_id || "", emailDomain: c.email_domain || "", active: !!c.enabled } } });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to update OIDC config: ${e.message}` });
    }
  }
  // An SSO connection an administrator configured is ProviderType CUSTOM (UNSPECIFIED=0, BUILTIN=1,
  // CUSTOM=2). The adapter answered "PROVIDER_TYPE_OIDC", which is no value of that enum, and Login
  // Configuration lists only CUSTOM — so a connection the daemon held and the sign-in page offered
  // read as "No custom SSO configurations yet" (R-240). Sent as its number: the value names live only
  // in the bundle's encoded descriptor, and protobuf JSON accepts the integer.
  const SSO_PROVIDER_TYPE_CUSTOM = 2;
  if (pathname === "/api/ioi.v1.OrganizationService/ListSSOConfigurations") {
    // Real SSO/OIDC login connections, projected from the daemon (no secrets surface here).
    try {
      const r = await daemon("GET", "/v1/hypervisor/sso-configurations");
      const cfgs = (r.sso_configurations || []).map((c) => ({
        id: c.sso_id, organizationId: LOCAL_SCOPE.orgId, issuerUrl: c.issuer_url, clientId: c.client_id || "",
        state: c.state === "active" ? "SSO_CONFIGURATION_STATE_ACTIVE" : "SSO_CONFIGURATION_STATE_INACTIVE",
        providerType: SSO_PROVIDER_TYPE_CUSTOM, displayName: c.display_name, emailDomain: c.email_domain || "",
      }));
      return json({ pagination: {}, ssoConfigurations: cfgs });
    } catch {
      return json({ pagination: {}, ssoConfigurations: [] });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/CreateSSOConfiguration") {
    const issuerUrl = body.issuerUrl || body.issuer_url || "";
    const clientId = body.clientId || body.client_id || "";
    if (!issuerUrl || !clientId) return jsonStatus(400, { code: "invalid_argument", message: "issuerUrl and clientId are required" });
    // A CLAIMS EXPRESSION IS AN ACCESS RESTRICTION, AND THE DAEMON HOLDS NONE (R-240). Its SSO record
    // carries issuer, client, secret, display name and email domain — no scopes, no claims. This used
    // to drop both silently, so an admin who wrote `claims.email.endsWith("@acme.com")` got a
    // connection that admits anyone the IdP vouches for. They refuse by name instead.
    const scopes = Array.isArray(body.additionalScopes) ? body.additionalScopes.filter((x) => String(x).trim()) : [];
    const claims = typeof body.claimsExpression === "string" ? body.claimsExpression.trim() : "";
    if (scopes.length || claims) {
      const named = [claims && "a claims expression (sign-in would NOT be restricted as written)", scopes.length && "additional scopes"].filter(Boolean).join(" and ");
      return jsonStatus(412, { code: "failed_precondition", message: `Not saved: this deployment cannot apply ${named} yet. Leave ${claims && scopes.length ? "them" : "it"} empty to create the connection.` });
    }
    try {
      const r = await daemon("POST", "/v1/hypervisor/sso-configurations", { issuer_url: issuerUrl, client_id: clientId, client_secret: body.clientSecret || body.client_secret || "", email_domain: body.emailDomain || body.email_domain || "", display_name: body.displayName || body.display_name || issuerUrl });
      const c = r.sso_configuration || {};
      return json({ ssoConfiguration: { id: c.sso_id, organizationId: LOCAL_SCOPE.orgId, issuerUrl: c.issuer_url, clientId: c.client_id || "", state: "SSO_CONFIGURATION_STATE_ACTIVE", providerType: SSO_PROVIDER_TYPE_CUSTOM, displayName: c.display_name, emailDomain: c.email_domain || "" } });
    } catch (e) {
      if (e.code === "hypervisor.sso_client_secret_seal_failed") return jsonStatus(412, { code: "failed_precondition", message: "Not saved: the daemon cannot seal the client secret — no custody key is configured for this deployment, and a secret is never stored in the clear." });
      if (e.status === 401 || e.status === 403) return jsonStatus(e.status, { code: e.status === 401 ? "unauthenticated" : "permission_denied", message: `Not saved: ${e.daemonMessage || e.code || "an organization administrator must be signed in"}` });
      return jsonStatus(502, { code: "unavailable", message: `failed to create SSO configuration: ${e.message}${e.code ? ` (${e.code})` : ""}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateSSOConfiguration") {
    // The daemon holds no SSO update (list, create and delete only); say so in the form's own error.
    return jsonStatus(412, { code: "failed_precondition", message: "Not saved: this deployment cannot edit an SSO connection in place — delete it and create it again." });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/DeleteSSOConfiguration") {
    const id = body.ssoConfigurationId || body.id;
    if (!id) return jsonStatus(400, { code: "invalid_argument", message: "ssoConfigurationId is required" });
    try { await daemon("DELETE", `/v1/hypervisor/sso-configurations/${encodeURIComponent(id)}`); } catch { /* idempotent */ }
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/ListSCIMConfigurations") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/scim-configurations");
      const cfgs = (r.scim_configurations || []).map((c) => ({ id: c.scim_id, organizationId: LOCAL_SCOPE.orgId, name: c.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: c.enabled !== false, ssoConfigurationId: c.sso_configuration_id || "" }));
      return json({ pagination: {}, scimConfigurations: cfgs });
    } catch {
      return json({ pagination: {} });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/CreateSCIMConfiguration") {
    // Provision a SCIM connection + mint the bearer token (returned ONCE for the admin to paste into
    // their IdP). The IdP then calls <host>/scim/v2/* with it to manage users/groups.
    try {
      const r = await daemon("POST", "/v1/hypervisor/scim-configurations", { scim_id: "scim-config", name: body.name || "SCIM provisioning", sso_configuration_id: body.ssoConfigurationId || "" });
      const c = r.scim_configuration || {};
      // The one-time token is the response's own `token` (the page reads `response.token`). It was
      // nested as an invented `bearerToken` field, which the bundle's decoder rejects — so every
      // successful create read as "Failed to create SCIM configuration" and the token was lost (R-240).
      return json({ scimConfiguration: { id: c.scim_id, organizationId: LOCAL_SCOPE.orgId, name: c.name || body.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: true, ssoConfigurationId: c.sso_configuration_id || body.ssoConfigurationId || "" }, token: r.token });
    } catch (e) {
      if (e.status >= 400 && e.status < 500) return jsonStatus(e.status === 401 ? 401 : e.status === 403 ? 403 : 412, { code: e.status === 401 ? "unauthenticated" : e.status === 403 ? "permission_denied" : "failed_precondition", message: `Not saved: ${e.daemonMessage || e.code || `the daemon refused (${e.status})`}` });
      return jsonStatus(502, { code: "unavailable", message: `failed to create SCIM configuration: ${e.message}${e.code ? ` (${e.code})` : ""}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateSCIMConfiguration") {
    // The daemon holds no SCIM update (its routes are list, create and delete). This used to read the
    // record and echo the requested `enabled` back as if saved — a success that persisted nothing
    // (R-240). It refuses by name, so the page's error says what to do instead.
    return jsonStatus(412, { code: "failed_precondition", message: "Not saved: this deployment cannot edit a SCIM configuration in place — delete it and set it up again." });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/RegenerateSCIMToken") {
    // "Regenerate Token" had no lane (a typed 501). The daemon's create re-issues a configuration
    // under the same id with a fresh token hash, so re-issuing it with the stored name and SSO link
    // IS the rotation: the old token stops working the moment this returns (R-240).
    try {
      const r0 = await daemon("GET", "/v1/hypervisor/scim-configurations");
      const id = body.scimConfigurationId || body.id || "scim-config";
      const cur = (r0.scim_configurations || []).find((c) => c.scim_id === id);
      if (!cur) return jsonStatus(404, { code: "not_found", message: "no SCIM configuration to rotate a token for" });
      const r = await daemon("POST", "/v1/hypervisor/scim-configurations", { scim_id: cur.scim_id, base_url: cur.base_url || "/scim/v2", name: cur.name || "SCIM provisioning", sso_configuration_id: cur.sso_configuration_id || "" });
      return json({ token: r.token });
    } catch (e) {
      return jsonStatus(e.status >= 400 && e.status < 500 ? 412 : 502, { code: e.status >= 400 && e.status < 500 ? "failed_precondition" : "unavailable", message: `Token not rotated: ${e.daemonMessage || e.code || e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/DeleteSCIMConfiguration") {
    const id = body.scimConfigurationId || body.id || "scim-config";
    try { await daemon("DELETE", `/v1/hypervisor/scim-configurations/${encodeURIComponent(id)}`); } catch { /* idempotent */ }
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetCustomDomain") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/custom-domain");
      return json(r.custom_domain ? { customDomain: r.custom_domain } : {});
    } catch { return json({}); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/SetCustomDomain" || pathname === "/api/ioi.v1.OrganizationService/UpdateCustomDomain") {
    const domain = body.domain || body.domainName || "";
    try { const r = await daemon("PUT", "/v1/hypervisor/custom-domain", { domain }); return json(r.custom_domain ? { customDomain: r.custom_domain } : {}); }
    catch (e) { return jsonStatus(502, { code: "unavailable", message: e.message }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/DeleteCustomDomain") {
    try { await daemon("PUT", "/v1/hypervisor/custom-domain", { domain: "" }); } catch { /* idempotent */ }
    return json({});
  }
  const dvToIOI = (d) => ({ id: d.id, organizationId: LOCAL_SCOPE.orgId, domain: d.domain, verified: !!d.verified, state: d.verified ? "DOMAIN_VERIFICATION_STATE_VERIFIED" : "DOMAIN_VERIFICATION_STATE_PENDING", recordName: d.record_name || "@", recordType: d.record_type || "TXT", recordValue: d.verification_token, verificationToken: d.verification_token });
  if (pathname === "/api/ioi.v1.OrganizationService/ListDomainVerifications") {
    try { const r = await daemon("GET", "/v1/hypervisor/domain-verifications"); return json({ pagination: {}, domainVerifications: (r.domain_verifications || []).map(dvToIOI) }); }
    catch { return json({ pagination: {} }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/CreateDomainVerification") {
    const domain = body.domain || "";
    if (!domain) return jsonStatus(400, { code: "invalid_argument", message: "domain is required" });
    try { const r = await daemon("POST", "/v1/hypervisor/domain-verifications", { domain }); return json({ domainVerification: dvToIOI(r.domain_verification || {}) }); }
    catch (e) { return jsonStatus(502, { code: "unavailable", message: e.message }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/VerifyDomainVerification") {
    const id = body.domainVerificationId || body.id;
    try { const r = await daemon("POST", `/v1/hypervisor/domain-verifications/${encodeURIComponent(id)}/verify`); return json({ domainVerification: dvToIOI(r.domain_verification || {}), verified: !!r.verified }); }
    catch (e) { return jsonStatus(502, { code: "unavailable", message: e.message }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/DeleteDomainVerification") {
    const id = body.domainVerificationId || body.id;
    try { await daemon("DELETE", `/v1/hypervisor/domain-verifications/${encodeURIComponent(id)}`); } catch { /* idempotent */ }
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganizationInvite") {
    // The org's standing invite link (real). Accepting it provisions a member (serve /__ioi/invite/:id).
    try { const r = await daemon("GET", "/v1/hypervisor/org-invite"); return json({ invite: { inviteId: r.invite?.invite_id, organizationId: LOCAL_SCOPE.orgId } }); }
    catch { return json({}); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/CreateOrganizationInvite" || pathname === "/api/ioi.v1.OrganizationService/ResetOrganizationInvite") {
    try { const r = await daemon("POST", "/v1/hypervisor/org-invite"); return json({ invite: { inviteId: r.invite?.invite_id, organizationId: LOCAL_SCOPE.orgId } }); }
    catch (e) { return jsonStatus(502, { code: "unavailable", message: e.message }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/JoinOrganization") {
    // An already-authenticated principal is already a member in this single-org deployment → ack.
    return json({ member: { userId: LOCAL_SCOPE.userId, organizationId: LOCAL_SCOPE.orgId } });
  }
  if (pathname === "/api/ioi.v1.IntegrationService/ListIntegrations") {
    // Project the daemon's MCP connectors (kind: mcp) onto the native Integrations surface. Only MCP
    // connectors land here — this surface is MCP+OAuth-shaped; bearer connectors (Slack) stay in the
    // estate to avoid conflating the two models. capabilities.mcp.url is the server the agent reaches.
    return json({ pagination: {}, integrations: await mcpConnectorsAsIntegrations() });
  }
  if (pathname === "/api/ioi.v1.IntegrationService/CreateIntegration") {
    // Native "Add MCP integration" (name + MCP URL, auth "discovered if blank") OR enabling an
    // existing definition. We register a REAL MCP connector; with no BYOA OAuth client we auto-
    // discover + DCR (RFC 9728→8414→7591) so the daemon self-configures — no per-service app.
    const mcpUrl = body.mcpUrl || body.integration?.mcpUrl || body.integration?.capabilities?.mcp?.url || "";
    const defId = body.integrationDefinitionId || body.integration?.integrationDefinitionId;
    if (!mcpUrl && defId) {
      // Enable-an-existing-definition: the projection already lists it enabled → honest ack.
      const existing = (await mcpConnectorsAsIntegrations()).find((i) => i.id === defId) || { id: defId, integrationDefinitionId: defId, enabled: true };
      return json({ integration: { ...existing, enabled: true } });
    }
    if (!mcpUrl) return jsonStatus(400, { code: "invalid_argument", message: "mcpUrl is required" });
    const name = body.name || body.integration?.name || "MCP integration";
    const authUrl = body.authUrl || body.integration?.authUrl || "";
    const tokenUrl = body.tokenUrl || body.integration?.tokenUrl || "";
    const clientId = body.clientId || body.integration?.clientId || "";
    const clientSecret = body.clientSecret || body.integration?.clientSecret || "";
    const rawScopes = body.scopes || body.integration?.scopes || [];
    const scopes = Array.isArray(rawScopes) ? rawScopes : String(rawScopes).split(/[\s,]+/).filter(Boolean);
    // A BYOA OAuth client (authUrl+tokenUrl+clientId); client_secret (if given) makes it confidential
    // (e.g. Slack) — the daemon seals it. Blank auth → auto-discovery + DCR on Connect.
    const auth_profile = authUrl && tokenUrl && clientId
      ? { type: "oauth_authcode_pkce", authorization_endpoint: authUrl, token_endpoint: tokenUrl, client_id: clientId, ...(clientSecret ? { client_secret: clientSecret } : {}), scopes }
      : null;
    let connector;
    try {
      const reg = await daemon("POST", "/v1/hypervisor/connectors", { service: "mcp", kind: "mcp", name, base_url: mcpUrl, ...(auth_profile ? { auth_profile } : {}) });
      connector = reg.connector;
      if (!auth_profile && connector?.connector_id) {
        // best-effort auto-discovery + Dynamic Client Registration (no BYOA app supplied)
        await daemon("POST", `/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/oauth/discover`, {}).catch(() => {});
      }
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to register MCP integration: ${e.message}` });
    }
    const integ = (await mcpConnectorsAsIntegrations()).find((i) => i.id === connector.connector_id) || { id: connector.connector_id, integrationDefinitionId: connector.connector_id, name, enabled: true, capabilities: { mcp: { url: mcpUrl } } };
    return json({ integration: integ });
  }
  if (pathname === "/api/ioi.v1.IntegrationService/UpdateIntegration") {
    // The switch beside each integration had no lane (a generic unmatched-RPC 501). A daemon
    // connector has no enabled flag — its org policy narrows TOOLS, which is not the same promise as
    // "off" — so this refuses by name and says where the connector is actually managed (R-240).
    return jsonStatus(412, { code: "failed_precondition", message: "Not saved: this deployment cannot switch an integration off for the organization. Narrow its tools or remove it under Connections (/__ioi/connections)." });
  }
  if (pathname === "/api/ioi.v1.IntegrationService/ValidateIntegration") {
    // Validate an integration = confirm it resolves to a real registered connector (our MCP
    // integrations ARE daemon connectors). Unknown id → invalid; daemon transient → lenient (valid).
    const id = body.integrationId || body.integration_id || body.id;
    if (!id) return json({ valid: false });
    try {
      const r = await daemon("GET", "/v1/hypervisor/connectors");
      return json({ valid: (r.connectors || []).some((c) => c.connector_id === id) });
    } catch {
      return json({ valid: true });
    }
  }
  if (pathname === "/api/ioi.v1.IntegrationService/ListIntegrationDefinitions") {
    // The org catalog of available MCP integration definitions (same projection, definition shape).
    const defs = (await mcpConnectorsAsIntegrations()).map((i) => ({
      id: i.integrationDefinitionId, name: i.name, host: i.host, description: i.description,
      iconUrl: i.iconUrl, categories: i.categories, capabilities: i.capabilities, auth: i.auth,
    }));
    return json({ pagination: {}, definitions: defs });
  }
  // ---- SecretService: real daemon-SEALED secrets (the value never leaves the daemon) ----
  // Org/User/Project secrets are credentials → sealed at rest in the daemon; we project only the
  // METADATA onto the native shape. scope is a connect-JSON oneof ({organizationId|userId|projectId});
  // ListSecrets is filtered by the requested scope so the org page and the user page each show only
  // their own secrets (single-operator local, but the scoping is honest and ready for multi-scope).
  const secretScopeKey = (scope = {}) => {
    if (!scope || typeof scope !== "object") return "global";
    if (scope.organizationId) return `organizationId:${scope.organizationId}`;
    if (scope.userId) return `userId:${scope.userId}`;
    if (scope.projectId) return `projectId:${scope.projectId}`;
    return "global";
  };
  // `scope` is a NESTED message ({userId|organizationId|projectId}); `mount` is a TOP-LEVEL oneof
  // that connect-JSON flattens to `environmentVariable:{}` | `filePath:"..."`. We store the mount as a
  // structured object and re-flatten it onto the Secret so the row's Type column renders on reload.
  const mountFromBody = (b) =>
    b.filePath !== undefined ? { filePath: b.filePath }
      : b.environmentVariable !== undefined ? { environmentVariable: b.environmentVariable || {} }
        : b.mount && typeof b.mount === "object" ? b.mount
          : null;
  const daemonSecretToIOI = (s) => ({
    id: s.secret_id,
    name: s.name,
    scope: s.scope || {},
    ...(s.mount && typeof s.mount === "object" ? s.mount : {}),
    ...(s.credential_proxy ? { credentialProxy: s.credential_proxy } : {}),
    createdAt: s.created_at,
  });
  if (pathname === "/api/ioi.v1.SecretService/ListSecrets") {
    const wantKey = secretScopeKey(body.filter?.scope || body.scope || {});
    try {
      const r = await daemon("GET", "/v1/hypervisor/secrets");
      const secrets = (r.secrets || [])
        .filter((s) => wantKey === "global" || s.scope_key === wantKey)
        .map(daemonSecretToIOI);
      return json({ pagination: {}, secrets });
    } catch {
      return json({ pagination: {}, secrets: [] });
    }
  }
  if (pathname === "/api/ioi.v1.SecretService/CreateSecret") {
    const name = (body.name || "").trim();
    if (!name) return jsonStatus(400, { code: "invalid_argument", message: "secret name is required" });
    const value = body.value || "";
    if (!value) return jsonStatus(400, { code: "invalid_argument", message: "secret value is required" });
    try {
      const r = await daemon("POST", "/v1/hypervisor/secrets", { name, value, scope: body.scope || {}, mount: mountFromBody(body), credentialProxy: body.credentialProxy || null });
      if (!r.ok) return jsonStatus(502, { code: "unavailable", message: r.reason || "failed to create secret" });
      return json({ secret: daemonSecretToIOI(r.secret) });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to create secret: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.SecretService/UpdateSecretValue") {
    const id = body.secretId || body.id;
    const value = body.value || "";
    if (!id || !value) return jsonStatus(400, { code: "invalid_argument", message: "secretId and value are required" });
    try {
      const r = await daemon("POST", `/v1/hypervisor/secrets/${encodeURIComponent(id)}/value`, { value });
      if (!r.ok) return jsonStatus(404, { code: "not_found", message: r.reason || "unknown secret" });
      return json({});
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to update secret: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.SecretService/DeleteSecret") {
    const id = body.secretId || body.id;
    if (!id) return jsonStatus(400, { code: "invalid_argument", message: "secretId is required" });
    try {
      await daemon("DELETE", `/v1/hypervisor/secrets/${encodeURIComponent(id)}`);
    } catch {
      /* idempotent: already gone -> still report removed */
    }
    return json({});
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/ListHostAuthenticationTokens") {
    // The user's connected git authentications — projected from the daemon's sealed host connectors
    // (a bound github host credential = one git authentication). Tokens themselves never surface.
    try {
      const r = await daemon("GET", "/v1/hypervisor/scm-connectors");
      const tokens = (r.connectors || [])
        .filter((c) => c.kind === "github" && c.host_level && c.auth_posture === "token-lease:bound")
        .map((c) => ({ id: c.connector_id, runnerId: "local-microvm", host: c.host || "github.com", scmId: "github", userId: LOCAL_SCOPE.userId, source: "HOST_AUTHENTICATION_TOKEN_SOURCE_PAT" }));
      return json({ pagination: {}, tokens });
    } catch {
      return json({ pagination: {}, tokens: [] });
    }
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/DeleteHostAuthenticationToken") {
    // Disconnect a git authentication = REAL revoke. Deletes the sealed credential in the daemon
    // and flips the connector to unbound; after this the publish crossing fails closed. The token
    // id projected by ListHostAuthenticationTokens is the daemon connector_id.
    const id = (body && (body.id || body.tokenId)) || "scm_host_github";
    try {
      await daemon("DELETE", `/v1/hypervisor/scm-connectors/${encodeURIComponent(id)}/credential`);
    } catch {
      /* idempotent: already gone -> still report removed */
    }
    return json({});
  }
  // ---- UserService: real API access tokens (inbound) — hash + metadata in the daemon, plaintext
  // returned ONCE on create. The native "API access tokens" surface (renamed from "Personal access
  // tokens"). The token value is never listed or recoverable after creation. ----
  const daemonTokenToIOI = (t) => ({
    id: t.token_id,
    userId: t.user_id || LOCAL_SCOPE.userId,
    description: t.description,
    readOnly: !!t.read_only,
    createdAt: t.created_at,
    expiresAt: t.expires_at,
    ...(t.last_used_at ? { lastUsedAt: t.last_used_at } : {}),
  });
  if (pathname === "/api/ioi.v1.UserService/ListPersonalAccessTokens") {
    const wantUsers = body.filter?.userIds || body.userIds || [];
    try {
      const r = await daemon("GET", "/v1/hypervisor/api-tokens");
      let tokens = (r.tokens || []);
      if (wantUsers.length) tokens = tokens.filter((t) => wantUsers.includes(t.user_id || LOCAL_SCOPE.userId));
      return json({ pagination: {}, personalAccessTokens: tokens.map(daemonTokenToIOI) });
    } catch {
      return json({ pagination: {}, personalAccessTokens: [] });
    }
  }
  if (pathname === "/api/ioi.v1.UserService/CreatePersonalAccessToken") {
    const description = (body.description || "").trim();
    if (!description) return jsonStatus(400, { code: "invalid_argument", message: "a description is required" });
    try {
      const r = await daemon("POST", "/v1/hypervisor/api-tokens", {
        description,
        user_id: body.userId || body.user_id || LOCAL_SCOPE.userId,
        read_only: body.readOnly ?? body.read_only ?? false,
        valid_for: body.validFor ?? body.valid_for ?? "2592000s",
      });
      if (!r.ok) return jsonStatus(502, { code: "unavailable", message: r.reason || "failed to create token" });
      // CreatePersonalAccessTokenResponse.token is the plaintext STRING (the SPA reveals it once,
      // then refetches the list for the row metadata). Surfaced exactly once, here.
      return json({ token: r.token.value });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to create token: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.UserService/DeletePersonalAccessToken") {
    const id = body.personalAccessTokenId || body.id || body.tokenId;
    if (!id) return jsonStatus(400, { code: "invalid_argument", message: "personalAccessTokenId is required" });
    try {
      await daemon("DELETE", `/v1/hypervisor/api-tokens/${encodeURIComponent(id)}`);
    } catch {
      /* idempotent */
    }
    return json({});
  }
  if (pathname === "/api/ioi.v1.AgentService/ListPrompts") {
    return json({ pagination: {} });
  }
  // The reference's org Agent-policies page has a "Goal mode" toggle; the vendored bundle's AgentPolicy
  // carries no goal member, so the name is unknown here. Any agentPolicy member named for goals is
  // refused by name; every other UpdateOrganizationPolicies still falls to adapter_unmatched_rpc below.
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateOrganizationPolicies") {
    const goalKeys = Object.keys(plainObject(body.agentPolicy) ? body.agentPolicy : {}).filter((k) => /goal/iu.test(k));
    if (goalKeys.length) return goalModeRefusal(`agentPolicy.${goalKeys.join(", agentPolicy.")}`);
  }

  // W0.5 — no mock fallthrough. Every `/api/ioi.v1.*` RPC the adapter does not own above refuses
  // typed: the wildcard `{}` mock was a silent-success lie and the fixture files are placeholder
  // data; neither is reachable through the RPC surface any more. Streaming calls get the typed
  // error in-band (end-stream frame); unary calls get the Connect error body. Only non-RPC /api
  // paths still return null for the serve proxy.
  const rpc = pathname.match(/^\/api\/(ioi\.v1\.[A-Za-z]+\/[A-Za-z]+)$/);
  if (rpc) {
    const message = `adapter_unmatched_rpc: ${rpc[1]} has no daemon-backed lane in this deployment; it refuses rather than serve fixture or wildcard-mock data`;
    if ((reqCtx.getStore()?.contentType || "").includes("application/connect+json")) {
      return connectStreamError("unimplemented", message);
    }
    return jsonStatus(501, { code: "unimplemented", message });
  }
  return null;
}
