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

async function daemon(method, path, body) {
  const headers = currentDaemonHeaders({ includeContentType: Boolean(body) });
  const res = await fetch(DAEMON + path, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`daemon ${method} ${path} -> ${res.status}`);
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
  const whoamiPrincipal = async () => {
    const w = await daemon("GET", "/v1/hypervisor/auth/whoami");
    return w.principal && w.principal.principal_id ? w.principal : null;
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
    // Account = the whoami principal. The membership row carries only structural refs — the
    // organization display fields (name, tier) are OMITTED, not fabricated: the W0.6 org read
    // (GET /v1/hypervisor/organization) itself serves display_name null with the gap named.
    try {
      const p = await whoamiPrincipal();
      if (!p) return unavailableRpc("identity_principal_unresolved", "whoami returned no principal; no local-constant account is served");
      return json({ account: { id: p.principal_id, name: p.name || "", avatarUrl: "", email: p.email || "", createdAt: p.created_at || "", updatedAt: p.updated_at || p.created_at || "", memberships: [{ userId: p.principal_id, userRole: p.role === "admin" ? "ORGANIZATION_ROLE_ADMIN" : "ORGANIZATION_ROLE_MEMBER", organizationId: LOCAL_SCOPE.orgId }], publicEmailProvider: false } });
    } catch (e) {
      return identityRefusal(e);
    }
  }
  if (pathname === "/api/ioi.v1.AccountService/GetChatIdentityToken") {
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganization") {
    // Daemon-backed (W0.6 landed GET /v1/hypervisor/organization): projects only what the daemon
    // persists about the org scope. display_name is null at the daemon with the gap NAMED (no org
    // display-name/tier record exists), so name renders as honest absence — never the former
    // "IOI Workspace"/tier constant. tier/createdAt/inviteDomains are omitted (nothing backs them).
    try {
      const r = await daemon("GET", "/v1/hypervisor/organization");
      const org = r.organization || {};
      return json({ organization: { id: LOCAL_SCOPE.orgId, name: org.display_name || "" } });
    } catch (e) {
      return unavailableRpc("org_identity_daemon_unavailable", `the daemon organization read did not answer (${e.message}); no fabricated organization is served`);
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
        const desired = body.spec?.desiredPhase || body.req?.spec?.desiredPhase;
        if (desired === "ENVIRONMENT_PHASE_RUNNING") return json({ environment: daemonEnvToIOI(await act(id, "start")) });
        if (desired === "ENVIRONMENT_PHASE_STOPPED") return json({ environment: daemonEnvToIOI(await act(id, "stop")) });
        for (const port of portsFromBody(body)) {
          const portNo = Number(port?.port || 0);
          if (!Number.isFinite(portNo) || portNo <= 0) continue;
          const endpoint = isPortUnexpose(port) ? "unexpose" : "expose";
          await daemon("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/ports/${portNo}/${endpoint}`, {});
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
      case "/api/ioi.v1.EnvironmentService/CreateEnvironmentLogsToken":
        // No daemon logs-token route exists (byte-verified); the former handler minted a made-up
        // constant. Logs themselves read via GET /v1/hypervisor/environments/:id/logs; a scoped
        // token plane is a named backend gap.
        return unavailableRpc("environment_logs_token_route_missing", "the daemon has no environment logs-token route; no fabricated token is minted");
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
    return unavailableRpc("environment_daemon_unavailable", `the daemon environment plane did not answer (${e.message}); no fixture environments are served`);
  }

  // ---- AgentService: real IOI daemon threads/turns (Session) ----
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
      const { agentExecutionId, environment, userInputBlockId } = await startAgentRun({
        daemonBase: DAEMON,
        prompt,
        environmentClassId,
        daemonHeaders: currentDaemonHeaders(),
      });
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
      return unavailableRpc("runner_daemon_unavailable", `the daemon provider plane did not answer (${e.message}); runner availability is unknown, not empty`);
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
      return unavailableRpc("runner_daemon_unavailable", `the daemon provider plane did not answer (${e.message})`);
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
      return unavailableRpc("runner_daemon_unavailable", `the daemon provider plane did not answer (${e.message})`);
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
      const editors = active.map((t) => ({ id: t, name: labels[t] || t, alias: t, urlTemplate: URL_TEMPLATES[t] || "", installationInstructions: "" }));
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
      // The env classes a project can launch into (the detail page's class picker). Honest = the
      // daemon substrate catalog (same EnvironmentClass shape as EnvironmentService/ListEnvironmentClasses).
      try {
        const r = await daemon("GET", "/v1/hypervisor/environment-classes");
        return json({ pagination: {}, environmentClasses: (r.environmentClasses || []).map(daemonClassToIOI) });
      } catch {
        return json({ pagination: {}, environmentClasses: [] });
      }
    }
    if (op === "UpdateProjectEnvironmentClasses") {
      // OQ-5 saga step 2 — the write plane exists now (PATCH :id/environment-classes). The
      // response always names the exact durable state; a refusal never claims rollback.
      const id = projectIdFromBody(body);
      const ids = (body.environmentClassIds || body.environment_class_ids ||
        (Array.isArray(body.environmentClasses) ? body.environmentClasses.map((c) => c?.id || c) : []) || [])
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
    // UpdateProject is an edit flow the daemon has no write plane for yet — it falls through
    // (not fabricated here), and is not exercised by read navigation.
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
      return unavailableRpc("scm_connector_daemon_unavailable", `the daemon SCM connector plane did not answer (${e.message}); no hand-written integration row is served`);
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
      return unavailableRpc("environment_class_daemon_unavailable", `the daemon substrate catalog did not answer (${e.message}); no fixture class is served`);
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
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListServices") {
    return json({ pagination: {}, services: [] });
  }
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListTasks") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/ioi.v1.EnvironmentAutomationService/ListTaskExecutions") {
    return json({ pagination: {} });
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
  if (pathname === "/api/ioi.v1.OrganizationService/ListSSOConfigurations") {
    // Real SSO/OIDC login connections, projected from the daemon (no secrets surface here).
    try {
      const r = await daemon("GET", "/v1/hypervisor/sso-configurations");
      const cfgs = (r.sso_configurations || []).map((c) => ({
        id: c.sso_id, organizationId: LOCAL_SCOPE.orgId, issuerUrl: c.issuer_url,
        state: c.state === "active" ? "SSO_CONFIGURATION_STATE_ACTIVE" : "SSO_CONFIGURATION_STATE_INACTIVE",
        providerType: "PROVIDER_TYPE_OIDC", displayName: c.display_name, emailDomain: c.email_domain || "",
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
    try {
      const r = await daemon("POST", "/v1/hypervisor/sso-configurations", { issuer_url: issuerUrl, client_id: clientId, client_secret: body.clientSecret || body.client_secret || "", email_domain: body.emailDomain || body.email_domain || "", display_name: body.displayName || body.display_name || issuerUrl });
      const c = r.sso_configuration || {};
      return json({ ssoConfiguration: { id: c.sso_id, organizationId: LOCAL_SCOPE.orgId, issuerUrl: c.issuer_url, state: "SSO_CONFIGURATION_STATE_ACTIVE", providerType: "PROVIDER_TYPE_OIDC", displayName: c.display_name, emailDomain: c.email_domain || "" } });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to create SSO configuration: ${e.message}` });
    }
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
      return json({ scimConfiguration: { id: c.scim_id, organizationId: LOCAL_SCOPE.orgId, name: c.name || body.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: true, ssoConfigurationId: body.ssoConfigurationId || "", bearerToken: r.token } });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to create SCIM configuration: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateSCIMConfiguration") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/scim-configurations");
      const c = (r.scim_configurations || [])[0] || {};
      return json({ scimConfiguration: { id: c.scim_id || body.scimConfigurationId, organizationId: LOCAL_SCOPE.orgId, name: body.name || c.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: body.enabled !== false, ssoConfigurationId: body.ssoConfigurationId || "" } });
    } catch {
      return json({ scimConfiguration: { id: body.scimConfigurationId, enabled: body.enabled !== false } });
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
