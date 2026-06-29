// IOI-owned API adapter for the product-ui bundle's IOI Connect-RPC surface.
//
// "Working backwards" from the product-ui bundle: endpoints here are backed by real IOI —
// the hypervisor-daemon (governed objects), an IOI-persisted store (preferences), and the
// EnvironmentProvider (lifecycle). handle() returns a response for endpoints we own and
// null for the rest, so the serve layer transparently proxies anything not-yet-ported to
// the product-ui bundle; if the daemon is unreachable we also return null (graceful fallback).
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
// Per-request context: carries the caller's session cookie so daemon calls forward the principal
// when auth enforcement is on (the daemon's auth_gate reads ioi_session= / Bearer). Off → no-op.
const reqCtx = new AsyncLocalStorage();

const json = (payload) => ({ contentType: "application/json", body: JSON.stringify(payload) });
// Connect-protocol error: non-2xx HTTP + {code,message} so the SPA's client rejects (e.g. a
// rejected GitHub token surfaces as a real connect failure, not a silent success).
const jsonStatus = (status, payload) => ({ contentType: "application/json", body: JSON.stringify(payload), status });

// Local operator identity. Account/Org/User are NOT daemon runtime truth — in a local
// single-operator hypervisor there is exactly one account, one organization (admin role),
// one user. We own these directly (stable local identity, same class as app-local
// preferences) rather than proxying the harvested demo identity. Display name/email match the
// serve layer's IDENTITY_REWRITES so the header/avatar stay consistent across surfaces.
const IDENTITY = {
  userId: "00000000-0000-4000-8000-000000000001",
  orgId: "00000000-0000-4000-8000-0000000000a1",
  accountId: "00000000-0000-4000-8000-0000000000ac",
  groupId: "00000000-0000-4000-8000-0000000000a2",
  orgName: "IOI Workspace",
  name: "John Doe",
  email: "johndoe@ioi.local",
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};

async function daemon(method, path, body) {
  const headers = body ? { "Content-Type": "application/json" } : {};
  const ctx = reqCtx.getStore();
  if (ctx?.cookie) headers.Cookie = ctx.cookie; // forward the caller's session so enforcement resolves the principal
  if (ctx?.forwardedHost) headers["X-Forwarded-Host"] = ctx.forwardedHost; // tell the loopback daemon it was reached via a tunnel
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
          organizationId: IDENTITY.orgId,
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
const runnerFromProvider = (p = {}) => {
  const id = p.provider_ref || p.runnerId || "local-microvm";
  const active = !p.status || p.status === "available";
  const label = p.reason || id;
  return {
    id,
    runnerId: id,
    name: label,
    spec: {
      desiredPhase: "RUNNER_PHASE_ACTIVE",
      configuration: {
        region: p.capabilities?.locality || "local",
        releaseChannel: "RUNNER_RELEASE_CHANNEL_STABLE",
      },
      variant: "RUNNER_VARIANT_STANDARD",
    },
    // status.capabilities gates env-class selectability and the Git-auth connect action. It must
    // include AGENT_EXECUTION plus the local side capabilities this seeded shell expects.
    status: {
      phase: active ? "RUNNER_PHASE_ACTIVE" : "RUNNER_PHASE_INACTIVE",
      message: label,
      version: "ioi-local",
      capabilities: [3, 4, 5],
    },
    kind: "RUNNER_KIND_REMOTE",
  };
};
async function listProjectedRunners() {
  const r = await daemon("GET", "/v1/hypervisor/providers");
  return (r.providers || []).map(runnerFromProvider);
}
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
  // Establish the per-request context (session cookie) so owned handlers' daemon calls carry the
  // caller's identity under enforcement. Off → cookie undefined → no-op.
  const cookie = reqHeaders.cookie || reqHeaders.Cookie || "";
  const forwardedHost = reqHeaders["x-forwarded-host"] || reqHeaders["X-Forwarded-Host"] || "";
  return reqCtx.run({ cookie, forwardedHost }, () => handleImpl(pathname, bodyText));
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
    const seedTime = { createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt };
    const merged = {};
    for (const [k, v] of Object.entries(store)) merged[k] = v.value;
    const preferences = Object.entries(merged).map(([key, value]) => makePreference(key, value, store[key] || seedTime));
    return json({ pagination: {}, preferences });
  }

  // ---- Identity: UserService / AccountService / OrganizationService (local single operator) ----
  if (pathname === "/api/ioi.v1.UserService/GetAuthenticatedUser") {
    // Reflect the authenticated session principal (the logged-in user), falling back to the local
    // operator when auth isn't enforced / no session.
    try {
      const w = await daemon("GET", "/v1/hypervisor/auth/whoami");
      const p = w.principal;
      if (p && p.principal_id) {
        return json({ user: { id: p.principal_id, organizationId: IDENTITY.orgId, name: p.name || IDENTITY.name, avatarUrl: "", createdAt: p.created_at || IDENTITY.createdAt, status: p.status === "active" ? "USER_STATUS_ACTIVE" : "USER_STATUS_SUSPENDED", email: p.email || IDENTITY.email } });
      }
    } catch { /* fall through to operator identity */ }
    return json({ user: { id: IDENTITY.userId, organizationId: IDENTITY.orgId, name: IDENTITY.name, avatarUrl: "", createdAt: IDENTITY.createdAt, status: "USER_STATUS_ACTIVE", email: IDENTITY.email } });
  }
  if (pathname === "/api/ioi.v1.AccountService/GetAccount") {
    return json({ account: { id: IDENTITY.accountId, name: IDENTITY.name, avatarUrl: "", email: IDENTITY.email, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, memberships: [{ userId: IDENTITY.userId, userRole: "ORGANIZATION_ROLE_ADMIN", organizationId: IDENTITY.orgId, organizationName: IDENTITY.orgName, organizationMemberCount: 1, organizationTier: "ORGANIZATION_TIER_CORE" }], publicEmailProvider: false } });
  }
  if (pathname === "/api/ioi.v1.AccountService/GetChatIdentityToken") {
    return json({});
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganization") {
    return json({ organization: { id: IDENTITY.orgId, name: IDENTITY.orgName, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, inviteDomains: {}, tier: "ORGANIZATION_TIER_CORE" } });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetTermsOfService") {
    return json({ termsOfService: { organizationId: IDENTITY.orgId } });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetOrganizationPolicies") {
    return json({ policies: { organizationId: IDENTITY.orgId, membersCreateProjects: true, maximumRunningEnvironmentsPerUser: "10", maximumEnvironmentsPerUser: "50", deleteArchivedEnvironmentsAfter: "1209600s", agentPolicy: { conversationSharingPolicy: "CONVERSATION_SHARING_POLICY_ORGANIZATION" }, securityAgentPolicy: {}, vetoExecPolicy: {}, vetoFilePolicy: {}, archiveEnvironmentsAfter: "259200s" } });
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
        const classes = (r.environmentClasses || []).map((c) => ({
          id: c.id,
          displayName: c.display_name || c.id,
          description: [c.substrate_class, c.minimum_isolation || c.isolation_claim || c.note].filter(Boolean).join(" • "),
          configuration: [{ key: "substrateClass", value: c.substrate_class || "" }],
          runnerId: "local-microvm",
          enabled: c.enabled !== false,
        }));
        return json({ pagination: {}, environmentClasses: classes });
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
        return json({ accessToken: `ioi-env-token-${envIdFromBody(body)}` });
      case "/api/ioi.v1.EnvironmentService/MarkEnvironmentActive":
        return json({});
      case "/api/ioi.v1.EnvironmentService/ArchiveEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "archive")) });
      case "/api/ioi.v1.EnvironmentService/UnarchiveEnvironment":
        return json({ environment: daemonEnvToIOI(await act(envIdFromBody(body), "restore")) });
      default:
        break;
    }
  } catch (e) {
    console.error("[ioi-api-adapter] daemon env call failed, proxying:", e.message);
    return null;
  }

  // ---- AgentService: real IOI daemon threads/turns (Session) ----
  try {
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
        const run = registerAgentRun({ envId });
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
        const userInputBlockId = await sendToAgentRun({ daemonBase: DAEMON, runId: id, prompt, userInputBlockId: clientBlockId });
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
    try {
      return json({ pagination: {}, runners: await listProjectedRunners() });
    } catch {
      return json({ pagination: {}, runners: [] });
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/GetRunner") {
    try {
      const runnerId = body.runnerId || body.runner_id || "local-microvm";
      const runner = (await listProjectedRunners()).find((r) => r.runnerId === runnerId) || runnerFromProvider({ provider_ref: runnerId, reason: runnerId, status: "available" });
      return json({ runner });
    } catch {
      return json({ runner: runnerFromProvider({ provider_ref: body.runnerId || body.runner_id || "local-microvm", reason: "local microVM node", status: "available" }) });
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/CreateRunner") {
    try {
      const runner = (await listProjectedRunners()).find((x) => x.status?.phase === "RUNNER_PHASE_ACTIVE") || runnerFromProvider();
      return json({ runner });
    } catch {
      return json({ runner: runnerFromProvider() });
    }
  }
  if (pathname === "/api/ioi.v1.RunnerService/ParseContextURL") {
    const parsed = parseGitHubContextUrl(body.contextUrl || body.context_url || "");
    if (!parsed) return jsonStatus(400, { code: "invalid_argument", message: "Only GitHub repository URLs are supported by the local Hypervisor Git auth bridge." });
    return json(parsed);
  }
  if (pathname === "/api/ioi.v1.RunnerManagerService/ListAvailableRunnerManagers") {
    // A local deployment exposes ONE runner manager: the local node that hosts environments (the
    // same provider ListRunners projects as a runner). Region "local" — no cloud regions to pick.
    return json({ pagination: {}, runnerManagers: [{ runnerManagerId: "local-runner-manager", name: "IOI Local (microVM)", region: "local" }] });
  }
  if (pathname === "/api/ioi.v1.RunnerService/CreateRunnerLogsToken") {
    // Scoped access token for viewing a runner's logs. The local runner's logs are the daemon's;
    // mint a local token (streaming the logs themselves is a follow-up, like EventService streaming).
    const runnerId = body.runnerId || body.runner_id || "local-microvm";
    return json({ accessToken: `ioi_runnerlogs_${Buffer.from(runnerId).toString("hex").slice(0, 24)}` });
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
      let active = r.active_targets || [];
      // Surface vscode-browser first (the working one); ensure it's present even if the registry shifts.
      if (!active.includes("vscode-browser")) active = ["vscode-browser", ...active];
      active = ["vscode-browser", ...active.filter((t) => t !== "vscode-browser")];
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
          return json({ pagination: {}, projects: records.map((p) => daemonProjectToIOI(p, IDENTITY.orgId)) });
        }
        if (op === "GetProject") {
          const id = projectIdFromBody(body);
          const r = await daemon("GET", `/v1/hypervisor/projects/${encodeURIComponent(id)}`);
          if (!r.ok || !r.project) return jsonStatus(404, { code: "not_found", message: `project ${id} not found` });
          return json({ project: daemonProjectToIOI(r.project, IDENTITY.orgId) });
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
          return json({ project: daemonProjectToIOI(record, IDENTITY.orgId) });
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
        const environmentClasses = (r.environmentClasses || []).map((c) => ({
          id: c.id,
          displayName: c.display_name || c.id,
          description: [c.substrate_class, c.minimum_isolation || c.isolation_claim].filter(Boolean).join(" • "),
          configuration: [{ key: "substrateClass", value: c.substrate_class || "" }],
          runnerId: "local-microvm",
          enabled: c.enabled !== false,
        }));
        return json({ pagination: {}, environmentClasses });
      } catch {
        return json({ pagination: {}, environmentClasses: [] });
      }
    }
    // UpdateProject / UpdateProjectEnvironmentClasses are edit flows the daemon has no write plane
    // for yet — they fall through (not fabricated here), and are not exercised by read navigation.
  }

  // ---- Local-deployment projections: honest local posture for planes the daemon does not yet
  // own (groups / workflows / per-env automation / SCM). These are deferred data planes — empty is
  // the honest local truth (NOT the mock's fabricated rows). Identity-derived surfaces (members,
  // org-members group) reflect the single local operator. ----
  if (pathname === "/api/ioi.v1.ServiceAccountService/ListServiceAccounts") {
    // The org's service accounts (identities environments are created/operated under). A local
    // single-operator deployment has one system-managed account = the Hypervisor automation identity.
    return json({ pagination: {}, serviceAccounts: [{
      id: "00000000-0000-4000-8000-0000000005a0",
      organizationId: IDENTITY.orgId,
      name: "IOI Hypervisor",
      description: "System-managed Hypervisor service account for automated environment operations",
      creator: { id: IDENTITY.userId, principal: "PRINCIPAL_USER" },
      createdAt: IDENTITY.createdAt,
      validUntil: "2099-12-31T23:59:59Z",
      systemManaged: true,
    }] });
  }
  if (pathname === "/api/ioi.v1.UserService/GetDotfilesConfiguration") {
    return json({ dotfilesConfiguration: { repository: "" } });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/ListMembers") {
    // Real multi-user roster — projected from the daemon principals plane (active members only).
    try {
      const r = await daemon("GET", "/v1/hypervisor/principals");
      const members = (r.principals || []).filter((p) => p.status === "active").map((p) => ({
        userId: p.principal_id, role: p.role === "admin" ? "ORGANIZATION_ROLE_ADMIN" : "ORGANIZATION_ROLE_MEMBER",
        memberSince: p.created_at, avatarUrl: "", fullName: p.name, email: p.email, status: "USER_STATUS_ACTIVE", loginProvider: p.source || "local",
      }));
      if (members.length) return json({ pagination: {}, members });
    } catch { /* fall through to the single operator */ }
    return json({ pagination: {}, members: [{ userId: IDENTITY.userId, role: "ORGANIZATION_ROLE_ADMIN", memberSince: IDENTITY.createdAt, avatarUrl: "", fullName: IDENTITY.name, email: IDENTITY.email, status: "USER_STATUS_ACTIVE", loginProvider: "local" }] });
  }
  if (pathname === "/api/ioi.v1.GroupService/GetGroup") {
    return json({ group: { id: IDENTITY.groupId, organizationId: IDENTITY.orgId, name: "org-members", systemManaged: true, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, memberCount: 1 } });
  }
  if (pathname === "/api/ioi.v1.GroupService/ListGroups") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/ioi.v1.GroupService/ListRoleAssignments") {
    return json({ pagination: {}, assignments: [] });
  }
  if (pathname === "/api/ioi.v1.RunnerConfigurationService/ListSCMIntegrations") {
    // Surface a github.com SCM integration so the native Git-authentications surface offers
    // connecting GitHub (PAT). Backed by the daemon SCM connector model.
    return json({ pagination: {}, integrations: [{
      id: "scmint-github", runnerId: "local-microvm", scmId: "github", host: "github.com",
      issuerUrl: "https://github.com", oauthClientId: "", pat: true,
    }] });
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
    return json({ token: { id: r.connector_id || "scm_host_github", runnerId: "local-microvm", host, scmId: "github", userId: IDENTITY.userId, source: "HOST_AUTHENTICATION_TOKEN_SOURCE_PAT", expiresAt: undefined } });
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
    // Self-hosted entitlement posture — one active, non-expiring "sovereign" contract (no SaaS plan,
    // no payment). Replaces the mock cancelled subscription.
    return json({ subscriptions: [{ contractId: "ioi-self-hosted", subscriptionType: "SUBSCRIPTION_TYPE_CORE", status: "SUBSCRIPTION_STATUS_ACTIVE", startsAt: IDENTITY.createdAt, endsAt: "2099-12-31T23:59:59Z" }] });
  }
  if (pathname === "/api/ioi.v1.OrganizationService/GetAnnouncementBanner") {
    return json({ banner: { organizationId: IDENTITY.orgId } });
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
        id: c.sso_id, organizationId: IDENTITY.orgId, issuerUrl: c.issuer_url,
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
      return json({ ssoConfiguration: { id: c.sso_id, organizationId: IDENTITY.orgId, issuerUrl: c.issuer_url, state: "SSO_CONFIGURATION_STATE_ACTIVE", providerType: "PROVIDER_TYPE_OIDC", displayName: c.display_name, emailDomain: c.email_domain || "" } });
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
      const cfgs = (r.scim_configurations || []).map((c) => ({ id: c.scim_id, organizationId: IDENTITY.orgId, name: c.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: c.enabled !== false, ssoConfigurationId: c.sso_configuration_id || "" }));
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
      return json({ scimConfiguration: { id: c.scim_id, organizationId: IDENTITY.orgId, name: c.name || body.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: true, ssoConfigurationId: body.ssoConfigurationId || "", bearerToken: r.token } });
    } catch (e) {
      return jsonStatus(502, { code: "unavailable", message: `failed to create SCIM configuration: ${e.message}` });
    }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/UpdateSCIMConfiguration") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/scim-configurations");
      const c = (r.scim_configurations || [])[0] || {};
      return json({ scimConfiguration: { id: c.scim_id || body.scimConfigurationId, organizationId: IDENTITY.orgId, name: body.name || c.name || "SCIM provisioning", baseUrl: c.base_url || "/scim/v2", enabled: body.enabled !== false, ssoConfigurationId: body.ssoConfigurationId || "" } });
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
  const dvToIOI = (d) => ({ id: d.id, organizationId: IDENTITY.orgId, domain: d.domain, verified: !!d.verified, state: d.verified ? "DOMAIN_VERIFICATION_STATE_VERIFIED" : "DOMAIN_VERIFICATION_STATE_PENDING", recordName: d.record_name || "@", recordType: d.record_type || "TXT", recordValue: d.verification_token, verificationToken: d.verification_token });
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
    try { const r = await daemon("GET", "/v1/hypervisor/org-invite"); return json({ invite: { inviteId: r.invite?.invite_id, organizationId: IDENTITY.orgId } }); }
    catch { return json({}); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/CreateOrganizationInvite" || pathname === "/api/ioi.v1.OrganizationService/ResetOrganizationInvite") {
    try { const r = await daemon("POST", "/v1/hypervisor/org-invite"); return json({ invite: { inviteId: r.invite?.invite_id, organizationId: IDENTITY.orgId } }); }
    catch (e) { return jsonStatus(502, { code: "unavailable", message: e.message }); }
  }
  if (pathname === "/api/ioi.v1.OrganizationService/JoinOrganization") {
    // An already-authenticated principal is already a member in this single-org deployment → ack.
    return json({ member: { userId: IDENTITY.userId, organizationId: IDENTITY.orgId } });
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
        .map((c) => ({ id: c.connector_id, runnerId: "local-microvm", host: c.host || "github.com", scmId: "github", userId: IDENTITY.userId, source: "HOST_AUTHENTICATION_TOKEN_SOURCE_PAT" }));
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
    userId: t.user_id || IDENTITY.userId,
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
      if (wantUsers.length) tokens = tokens.filter((t) => wantUsers.includes(t.user_id || IDENTITY.userId));
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
        user_id: body.userId || body.user_id || IDENTITY.userId,
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

  // Not yet IOI-backed -> proxy to the product-ui bundle. Remaining (see reference-api-
  // integration.md): ProjectService (daemon needs a project-list GET), EventService
  // streaming bridge, approvals/reviews surfacing.
  return null;
}
