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

const json = (payload) => ({ contentType: "application/json", body: JSON.stringify(payload) });

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
  if (pathname === "/api/gitpod.v1.UserService/ListPreferences") {
    const store = loadStore();
    // App-local defaults that keep the harvested shell past the onboarding gate (config, not truth).
    const seedTime = { createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt };
    const merged = { IS_ONA_ONBOARDED: "true" };
    for (const [k, v] of Object.entries(store)) merged[k] = v.value;
    const preferences = Object.entries(merged).map(([key, value]) => makePreference(key, value, store[key] || seedTime));
    return json({ pagination: {}, preferences });
  }

  // ---- Identity: UserService / AccountService / OrganizationService (local single operator) ----
  if (pathname === "/api/gitpod.v1.UserService/GetAuthenticatedUser") {
    return json({ user: { id: IDENTITY.userId, organizationId: IDENTITY.orgId, name: IDENTITY.name, avatarUrl: "", createdAt: IDENTITY.createdAt, status: "USER_STATUS_ACTIVE", email: IDENTITY.email } });
  }
  if (pathname === "/api/gitpod.v1.AccountService/GetAccount") {
    return json({ account: { id: IDENTITY.accountId, name: IDENTITY.name, avatarUrl: "", email: IDENTITY.email, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, memberships: [{ userId: IDENTITY.userId, userRole: "ORGANIZATION_ROLE_ADMIN", organizationId: IDENTITY.orgId, organizationName: IDENTITY.orgName, organizationMemberCount: 1, organizationTier: "ORGANIZATION_TIER_CORE" }], publicEmailProvider: false } });
  }
  if (pathname === "/api/gitpod.v1.AccountService/GetChatIdentityToken") {
    return json({});
  }
  if (pathname === "/api/gitpod.v1.OrganizationService/GetOrganization") {
    return json({ organization: { id: IDENTITY.orgId, name: IDENTITY.orgName, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, inviteDomains: {}, tier: "ORGANIZATION_TIER_CORE" } });
  }
  if (pathname === "/api/gitpod.v1.OrganizationService/GetTermsOfService") {
    return json({ termsOfService: { organizationId: IDENTITY.orgId } });
  }
  if (pathname === "/api/gitpod.v1.OrganizationService/GetOrganizationPolicies") {
    return json({ policies: { organizationId: IDENTITY.orgId, membersCreateProjects: true, maximumRunningEnvironmentsPerUser: "10", maximumEnvironmentsPerUser: "50", deleteArchivedEnvironmentsAfter: "1209600s", agentPolicy: { conversationSharingPolicy: "CONVERSATION_SHARING_POLICY_ORGANIZATION" }, securityAgentPolicy: {}, vetoExecPolicy: {}, vetoFilePolicy: {}, archiveEnvironmentsAfter: "259200s" } });
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
      case "/api/gitpod.v1.EnvironmentService/ListEnvironmentClasses": {
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
        let envRecord = created.environment;
        // The compose flow asks for desiredPhase RUNNING — actually start it so it has a real
        // workspace (the daemon create leaves it stopped). This is what makes the agent + editor work.
        const desired = body.spec?.desiredPhase || body.desiredPhase;
        if (desired === "ENVIRONMENT_PHASE_RUNNING" && envRecord?.id) {
          try { envRecord = await act(envRecord.id, "start"); } catch (e) { console.error("[ioi-api-adapter] env auto-start failed:", e.message); }
        }
        return json({ environment: daemonEnvToGitpod(envRecord) });
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
    // CreateAgentSession is the /ai composer's submit: spin up a real env + run the agent over
    // the harness (create env → start → bound session → mint grant → execute). Returns once the
    // env exists; the harness runs async (tracked in the run registry). The SPA then navigates to
    // /details/:environmentId and polls GetAgentExecution.
    if (pathname === "/api/gitpod.v1.AgentService/CreateAgentSession") {
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
    if (pathname === "/api/gitpod.v1.AgentService/ListAgentExecutions") {
      const wanted = body.filter?.environmentIds || body.filter?.environment_ids || null;
      const runList = listRuns()
        .filter((run) => !wanted || wanted.includes(run.envId))
        .map(runToAgentExecution);
      const threads = await daemon("GET", "/v1/threads");
      const list = Array.isArray(threads) ? threads : threads.threads || [];
      return json({ pagination: {}, agentExecutions: [...runList, ...list.map(threadToAgentExecution)] });
    }
    if (pathname === "/api/gitpod.v1.AgentService/GetAgentExecution") {
      const id = body.agentExecutionId;
      const run = getRun(id);
      if (run) return json({ agentExecution: runToAgentExecution(run) });
      const t = await daemon("GET", `/v1/threads/${encodeURIComponent(id)}`);
      return json({ agentExecution: threadToAgentExecution(t) });
    }
    if (
      pathname === "/api/gitpod.v1.AgentService/CreateAgentExecution" ||
      pathname === "/api/gitpod.v1.AgentService/StartAgent"
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
    if (pathname === "/api/gitpod.v1.AgentService/SendToAgentExecution") {
      const id = body.agentExecutionId;
      const prompt = extractPrompt(body) || textFromBody(body);
      if (getRun(id)) {
        await sendToAgentRun({ daemonBase: DAEMON, runId: id, prompt });
        return json({});
      }
      if (id && prompt) await daemon("POST", `/v1/threads/${encodeURIComponent(id)}/turns`, { text: prompt });
      return json({});
    }
    if (pathname === "/api/gitpod.v1.AgentService/StopAgentExecution") {
      const id = body.agentExecutionId;
      if (id) await daemon("POST", `/v1/threads/${encodeURIComponent(id)}/cancel`);
      return json({});
    }
    if (pathname === "/api/gitpod.v1.AgentService/DeleteAgentExecution") {
      const id = body.agentExecutionId;
      if (id) await daemon("DELETE", `/v1/threads/${encodeURIComponent(id)}`);
      return json({});
    }
    if (pathname === "/api/gitpod.v1.AgentService/CreateAgentExecutionConversationToken") {
      return json({ token: `ioi-agent-conv-${body.agentExecutionId || "anon"}` });
    }
  } catch (e) {
    console.error("[ioi-api-adapter] daemon call failed, proxying:", e.message);
    return null;
  }

  // ---- RunnerService: runners backed by the EnvironmentProvider registry (local authority) ----
  if (pathname === "/api/gitpod.v1.RunnerService/CheckAuthenticationForHost") {
    return json({ type: "Authenticated" });
  }
  if (pathname === "/api/gitpod.v1.RunnerService/ListRunners") {
    // The compose flow filters runners to RUNNER_KIND_REMOTE (environments run on a remote-shaped
    // host). Our local provider IS that host for the served app, so present it as a REMOTE runner —
    // otherwise the env class has no supported runner and shows "Unsupported" (unselectable).
    try {
      const r = await daemon("GET", "/v1/hypervisor/providers");
      const runners = (r.providers || []).map((p) => ({
        runnerId: p.provider_ref,
        name: p.reason || p.provider_ref,
        spec: { desiredPhase: "RUNNER_PHASE_ACTIVE", configuration: { region: p.capabilities?.locality || "local", releaseChannel: "RUNNER_RELEASE_CHANNEL_STABLE" }, variant: "RUNNER_VARIANT_STANDARD" },
        // status.capabilities gates env-class selectability in the composer: it must include
        // AGENT_EXECUTION or the class shows "Unsupported" (RunnerCapability enum, unprefixed names).
        status: { phase: p.status === "available" ? "RUNNER_PHASE_ACTIVE" : "RUNNER_PHASE_INACTIVE", message: p.reason || "", version: "ioi-local", capabilities: [3, 4, 5] },
        kind: "RUNNER_KIND_REMOTE",
      }));
      return json({ pagination: {}, runners });
    } catch {
      return json({ pagination: {}, runners: [] });
    }
  }
  if (pathname === "/api/gitpod.v1.RunnerService/CreateRunner") {
    try {
      const r = await daemon("GET", "/v1/hypervisor/providers");
      const p = (r.providers || []).find((x) => x.status === "available") || (r.providers || [])[0];
      const id = p?.provider_ref || "local-microvm";
      return json({ runner: { id, spec: { configuration: { region: "local" } }, status: { phase: "RUNNER_PHASE_ACTIVE", message: "" }, kind: "RUNNER_KIND_REMOTE" } });
    } catch {
      return json({ runner: { id: "local-microvm", spec: {}, status: { phase: "RUNNER_PHASE_ACTIVE", message: "" }, kind: "RUNNER_KIND_REMOTE" } });
    }
  }

  // ---- EditorService: real daemon editor targets (vscode / insiders / browser) ----
  if (pathname === "/api/gitpod.v1.EditorService/ListEditors") {
    // vscode-browser is the proven end-to-end target: its urlTemplate points at the serve layer's
    // /__ioi/editor/open, which drives the daemon editor chain and redirects to the live editor.
    // Desktop targets carry their native deep-link scheme (best-effort on the host).
    const URL_TEMPLATES = {
      "vscode-browser": "/__ioi/editor/open?environmentId={{.EnvironmentId}}",
      vscode: "vscode://gitpod.gitpod-flex/connect?environmentId={{.EnvironmentId}}",
      "vscode-insiders": "vscode-insiders://gitpod.gitpod-flex/connect?environmentId={{.EnvironmentId}}",
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

  // ---- Local-deployment projections: honest local posture for planes the daemon does not yet
  // own (projects / groups / workflows / per-env automation / SCM). These are deferred data
  // planes — empty is the honest local truth (NOT the mock's fabricated rows). Identity-derived
  // surfaces (members, org-members group) reflect the single local operator. ----
  if (pathname === "/api/gitpod.v1.ProjectService/ListProjects") {
    return json({ pagination: {}, projects: [] });
  }
  if (pathname === "/api/gitpod.v1.OrganizationService/ListMembers") {
    return json({ pagination: {}, members: [{ userId: IDENTITY.userId, role: "ORGANIZATION_ROLE_ADMIN", memberSince: IDENTITY.createdAt, avatarUrl: "", fullName: IDENTITY.name, email: IDENTITY.email, status: "USER_STATUS_ACTIVE", loginProvider: "local" }] });
  }
  if (pathname === "/api/gitpod.v1.GroupService/GetGroup") {
    return json({ group: { id: IDENTITY.groupId, organizationId: IDENTITY.orgId, name: "org-members", systemManaged: true, createdAt: IDENTITY.createdAt, updatedAt: IDENTITY.updatedAt, memberCount: 1 } });
  }
  if (pathname === "/api/gitpod.v1.GroupService/ListGroups") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/gitpod.v1.GroupService/ListRoleAssignments") {
    return json({ pagination: {}, assignments: [] });
  }
  if (pathname === "/api/gitpod.v1.RunnerConfigurationService/ListSCMIntegrations") {
    return json({ pagination: {}, integrations: [] });
  }
  if (pathname === "/api/gitpod.v1.PrebuildService/ListPrebuilds") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/gitpod.v1.WorkflowService/ListWorkflows") {
    return json({ pagination: {}, workflows: [] });
  }
  if (pathname === "/api/gitpod.v1.WorkflowService/ListWorkflowExecutions") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/gitpod.v1.WorkflowService/GetWorkflowExecutionSummary") {
    return json({ totalWorkflowsInOrganization: "0" });
  }
  if (pathname === "/api/gitpod.v1.EnvironmentAutomationService/ListServices") {
    return json({ pagination: {}, services: [] });
  }
  if (pathname === "/api/gitpod.v1.EnvironmentAutomationService/ListTasks") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/gitpod.v1.EnvironmentAutomationService/ListTaskExecutions") {
    return json({ pagination: {} });
  }
  if (pathname === "/api/gitpod.v1.BillingService/GetBillingInfo") {
    // A local hypervisor has no billing plane: report an unmetered local posture (never gates).
    return json({ totalCredits: 0, availableCredits: 0, usedCredits: 0, paymentMethodStatus: "PAYMENT_METHOD_STATUS_VERIFIED", creditStatus: "CREDIT_STATUS_HAS_CREDITS", autoTopupSettings: {}, monthlyCommitmentCents: "0" });
  }
  if (pathname === "/api/gitpod.v1.OrganizationService/GetAnnouncementBanner") {
    return json({ banner: { organizationId: IDENTITY.orgId } });
  }
  if (pathname === "/api/gitpod.v1.IntegrationService/ListIntegrations") {
    // No integrations wired in the local deployment yet (honest empty state).
    return json({ pagination: {}, integrations: [] });
  }
  if (pathname === "/api/gitpod.v1.IntegrationService/ListIntegrationDefinitions") {
    // No integration catalog provisioned in the local deployment yet (honest empty state).
    return json({ pagination: {}, definitions: [] });
  }
  if (pathname === "/api/gitpod.v1.RunnerConfigurationService/ListHostAuthenticationTokens") {
    // Local authority is unconditional (CheckAuthenticationForHost -> Authenticated); no stored
    // host OAuth tokens to enumerate.
    return json({ pagination: {}, tokens: [] });
  }
  if (pathname === "/api/gitpod.v1.AgentService/ListPrompts") {
    return json({ pagination: {} });
  }

  // Not yet IOI-backed -> proxy to the live reference. Remaining (see reference-api-
  // integration.md): ProjectService (daemon needs a project-list GET), EventService
  // streaming bridge, approvals/reviews surfacing.
  return null;
}
