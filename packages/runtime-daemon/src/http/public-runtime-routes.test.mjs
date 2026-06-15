import assert from "node:assert/strict";
import test from "node:test";

import { createPublicRuntimeRequestHandler } from "./public-runtime-routes.mjs";

function responseRecorder() {
  return {
    headers: {},
    statusCode: 200,
    ended: false,
    body: null,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(value = "") {
      this.ended = true;
      this.body = value;
    },
  };
}

function request({ method = "GET", url = "/", body = {} } = {}) {
  return {
    method,
    url,
    headers: {},
    body,
  };
}

function retiredRouteWrapper() {
  throw new Error("retired public runtime route wrapper must not be routed");
}

function routeHarness(overrides = {}) {
  const calls = [];
  const deps = {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: "usage.v.test",
    baseUrlForRequest: () => "http://daemon.test",
    computerUseProviderRegistryReport: () => ({ providers: [] }),
    discoverComputerUseBrowsers: async () => ({ browsers: [] }),
    handleAgentRoute: async () => calls.push("agent"),
    handleModelMountingNativeRoute: async () => calls.push("model-native"),
    handleOpenAiCompatibilityRoute: async () => calls.push("openai"),
    handleRunRoute: async () => calls.push("run"),
    handleThreadRoute: async () => calls.push("thread"),
    isOpenAiCompatibilityRoute: () => false,
    normalizeBooleanOption: (value, fallback) => (value == null ? fallback : value !== "false" && value !== "0"),
    notFound: (message, details) => {
      const error = new Error(message);
      error.details = details;
      throw error;
    },
    optionalString: (value) => {
      const text = typeof value === "string" ? value.trim() : "";
      return text || null;
    },
    readBody: async (req) => req.body ?? {},
    runtimeError: (error) => Object.assign(new Error(error.message), error),
    usageRequestMetadataFromUrl: () => ({ requestMetadata: true }),
    usageTelemetryWithRequestMetadata: (payload, metadata) => ({ payload, metadata }),
    writeError: (response, error) => {
      response.statusCode = error.status ?? 500;
      response.error = error;
      response.end(JSON.stringify({ error: error.code ?? error.message }));
    },
    writeJsonResponse: (response, payload, status = 200) => {
      response.statusCode = status;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(payload));
    },
    writeMcpJsonRpcResponse: (response, payload) => {
      response.statusCode = 200;
      response.end(JSON.stringify(payload));
    },
    ...overrides,
  };
  return {
    calls,
    handleRequest: createPublicRuntimeRequestHandler(deps),
  };
}

test("public runtime routes answer CORS preflight without store access", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ method: "OPTIONS", url: "/v1/doctor" }), response, store: null });

  assert.equal(response.statusCode, 204);
  assert.equal(response.ended, true);
  assert.equal(response.headers["access-control-allow-origin"], "*");
  assert.match(response.headers["x-request-id"], /^req_/);
});

test("public runtime routes dispatch top-level daemon projections", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    contextPolicyCore: {
      projectRuntimeDoctorReport(request) {
        calls.push({ method: "projectRuntimeDoctorReport", request });
        return { report: { ok: true, baseUrl: request.base_url } };
      },
    },
    runtimeDoctorReport: retiredRouteWrapper,
    doctorReport: retiredRouteWrapper,
  };

  await handleRequest({ request: request({ url: "/v1/doctor" }), response, store });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { ok: true, baseUrl: "http://daemon.test" });
  assert.deepEqual(calls, [{
    method: "projectRuntimeDoctorReport",
    request: {
      operation: "runtime_doctor_report_projection",
      operation_kind: "runtime.doctor_report.projection",
      base_url: "http://daemon.test",
      workspace_root: "/workspace",
      state_dir: "/state",
      home_dir: "/home/operator",
      runtime_schema_version: "ioi.agentgres.runtime.v0",
      source: "public_runtime_routes./v1/doctor",
    },
  }]);
});

test("public runtime repository workflow routes use mounted repository surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const repositorySurface = {
    listRepositories(surfaceStore) {
      calls.push({ method: "listRepositories", surfaceStore });
      return { repositories: [] };
    },
    repositoryContext(surfaceStore) {
      calls.push({ method: "repositoryContext", surfaceStore });
      return { context_id: "repo_context" };
    },
    branchPolicy(surfaceStore) {
      calls.push({ method: "branchPolicy", surfaceStore });
      return { policy_id: "branch_policy" };
    },
    githubContext(surfaceStore) {
      calls.push({ method: "githubContext", surfaceStore });
      return { context_id: "github_context" };
    },
    prAttempts(surfaceStore) {
      calls.push({ method: "prAttempts", surfaceStore });
      return { attempts: [] };
    },
    issueContext(surfaceStore) {
      calls.push({ method: "issueContext", surfaceStore });
      return { issue_id: "issue_context" };
    },
    reviewGate(surfaceStore) {
      calls.push({ method: "reviewGate", surfaceStore });
      return { gate_id: "review_gate" };
    },
    githubPrCreatePlan(surfaceStore) {
      calls.push({ method: "githubPrCreatePlan", surfaceStore });
      return { plan_id: "pr_plan" };
    },
  };
  const store = {
    repositorySurface,
    listRepositories: retiredRouteWrapper,
    repositoryContext: retiredRouteWrapper,
    branchPolicy: retiredRouteWrapper,
    githubContext: retiredRouteWrapper,
    prAttempts: retiredRouteWrapper,
    issueContext: retiredRouteWrapper,
    reviewGate: retiredRouteWrapper,
    githubPrCreatePlan: retiredRouteWrapper,
  };
  const routes = [
    ["/v1/repositories", "listRepositories"],
    ["/v1/repository-context", "repositoryContext"],
    ["/v1/branch-policy", "branchPolicy"],
    ["/v1/github-context", "githubContext"],
    ["/v1/pr-attempts", "prAttempts"],
    ["/v1/issue-context", "issueContext"],
    ["/v1/review-gate", "reviewGate"],
    ["/v1/github/pr-create-plan", "githubPrCreatePlan"],
  ];

  for (const [url] of routes) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url }), response, store });
    assert.equal(response.statusCode, 200);
  }

  assert.deepEqual(calls.map((call) => call.method), routes.map(([, method]) => method));
  assert.equal(calls.every((call) => call.surfaceStore === store), true);
});

test("public runtime skill and hook routes use mounted skill hook surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    defaultCwd: "/workspace/canonical",
    skillHookSurface: {
      listSkills(request) {
        calls.push({ method: "listSkills", request });
        return {
          skills: [{ id: "skill.route" }],
          rust_core_boundary: "runtime.skill_hook_registry",
        };
      },
      listHooks(request) {
        calls.push({ method: "listHooks", request });
        return {
          hooks: [{ id: "hook.route" }],
          rust_core_boundary: "runtime.skill_hook_registry",
        };
      },
    },
    listSkills: retiredRouteWrapper,
    listHooks: retiredRouteWrapper,
  };

  const skillsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/skills" }), response: skillsResponse, store });
  assert.equal(skillsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(skillsResponse.body), {
    skills: [{ id: "skill.route" }],
    rust_core_boundary: "runtime.skill_hook_registry",
  });

  const hooksResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/hooks" }), response: hooksResponse, store });
  assert.equal(hooksResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(hooksResponse.body), {
    hooks: [{ id: "hook.route" }],
    rust_core_boundary: "runtime.skill_hook_registry",
  });

  assert.deepEqual(calls, [
    { method: "listSkills", request: { cwd: "/workspace/canonical" } },
    { method: "listHooks", request: { cwd: "/workspace/canonical" } },
  ]);
});

test("public runtime model catalog routes use mounted model projection surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    modelMounting: {
      runtimeModelCatalogList() {
        calls.push({ method: "runtimeModelCatalogList" });
        return {
          object: "list",
          data: [{ id: "model.route" }],
        };
      },
      listModelCapabilities() {
        calls.push({ method: "listModelCapabilities" });
        return {
          capabilities: [{ model: "model.route", features: ["chat"] }],
        };
      },
    },
    listModels: retiredRouteWrapper,
    listModelCapabilities: retiredRouteWrapper,
  };

  const modelsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/models" }), response: modelsResponse, store });
  assert.equal(modelsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(modelsResponse.body), {
    object: "list",
    data: [{ id: "model.route" }],
  });

  const capabilitiesResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/model-capabilities" }),
    response: capabilitiesResponse,
    store,
  });
  assert.equal(capabilitiesResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(capabilitiesResponse.body), {
    capabilities: [{ model: "model.route", features: ["chat"] }],
  });

  assert.deepEqual(calls, [
    { method: "runtimeModelCatalogList" },
    { method: "listModelCapabilities" },
  ]);
});

test("public runtime studio intent route uses Rust daemon-core projection", async () => {
  const calls = [];
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    resolveStudioIntentFrame: retiredRouteWrapper,
    contextPolicyCore: {
      projectStudioIntentFrame(request) {
        calls.push({ method: "projectStudioIntentFrame", request });
        return {
          frame: {
            object: "ioi.studio_intent_frame",
            route_directive: "agent",
            target: request.prompt,
          },
        };
      },
    },
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/studio/intent-frame",
      body: { prompt: "inspect the runtime", execution_mode: "agent", executionMode: "ask" },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [
    {
      method: "projectStudioIntentFrame",
      request: {
        operation: "studio_intent_frame_projection",
        operation_kind: "studio.intent_frame.projection",
        prompt: "inspect the runtime",
        input: undefined,
        query: undefined,
        execution_mode: "agent",
        source: "public_runtime_routes./v1/studio/intent-frame",
      },
    },
  ]);
  assert.deepEqual(JSON.parse(response.body), {
    object: "ioi.studio_intent_frame",
    route_directive: "agent",
    target: "inspect the runtime",
  });
});

test("public runtime account node and tool routes use mounted tool surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    toolSurface: {
      getAccount() {
        calls.push({ method: "getAccount" });
        return { account_id: "acct_route" };
      },
      listRuntimeNodes() {
        calls.push({ method: "listRuntimeNodes" });
        return { nodes: [] };
      },
      listTools(options) {
        calls.push({ method: "listTools", options });
        return { tools: [], pack: options.pack };
      },
    },
    getAccount: retiredRouteWrapper,
    listRuntimeNodes: retiredRouteWrapper,
    listTools: retiredRouteWrapper,
  };

  const accountResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/account" }), response: accountResponse, store });
  assert.deepEqual(JSON.parse(accountResponse.body), { account_id: "acct_route" });

  const nodesResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/runtime/nodes" }), response: nodesResponse, store });
  assert.deepEqual(JSON.parse(nodesResponse.body), { nodes: [] });

  const toolsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/tools?pack=coding" }), response: toolsResponse, store });
  assert.deepEqual(JSON.parse(toolsResponse.body), { tools: [], pack: "coding" });

  assert.deepEqual(calls, [
    { method: "getAccount" },
    { method: "listRuntimeNodes" },
    { method: "listTools", options: { pack: "coding" } },
  ]);
});

test("public runtime routes delegate thread subroutes unchanged", async () => {
  const { calls, handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ url: "/v1/threads/thread_123/events" }), response, store: {} });

  assert.deepEqual(calls, ["thread"]);
  assert.equal(response.ended, false);
});

test("public runtime agent and thread list routes use mounted lifecycle projection surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    lifecycleProjectionSurface: {
      listAgents(surfaceStore) {
        calls.push({ method: "listAgents", surfaceStore });
        return [{ id: "agent_route" }];
      },
      listThreads(surfaceStore) {
        calls.push({ method: "listThreads", surfaceStore });
        return [{ thread_id: "thread_route" }];
      },
    },
  };

  const agentsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/agents" }), response: agentsResponse, store });
  assert.equal(agentsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(agentsResponse.body), [{ id: "agent_route" }]);

  const threadsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/threads" }), response: threadsResponse, store });
  assert.equal(threadsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(threadsResponse.body), [{ thread_id: "thread_route" }]);
  assert.deepEqual(calls.map((call) => call.method), ["listAgents", "listThreads"]);
  assert.equal(calls.every((call) => call.surfaceStore === store), true);
});

test("public runtime run list route uses mounted lifecycle projection surface", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    lifecycleProjectionSurface: {
      listRuns(_store, agent_id) {
        calls.push({ agent_id });
        return [{ id: "run_route", agent_id: agent_id ?? null }];
      },
    },
  };

  await handleRequest({
    request: request({ url: "/v1/runs?agent_id=agent-canonical" }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), [
    { id: "run_route", agent_id: "agent-canonical" },
  ]);
  assert.deepEqual(calls, [{ agent_id: "agent-canonical" }]);

  const unfilteredResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/runs" }),
    response: unfilteredResponse,
    store,
  });

  assert.deepEqual(calls.at(-1), { agent_id: undefined });
  assert.equal(unfilteredResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(unfilteredResponse.body), [
    { id: "run_route", agent_id: null },
  ]);
});

test("public runtime agent create route uses mounted agent lifecycle surface", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    agentRunLifecycleSurface: {
      createAgent(surfaceStore, options) {
        calls.push({ surfaceStore, options });
        const error = new Error("agent creation requires Rust core");
        error.status = 501;
        error.code = "runtime_agent_create_rust_core_required";
        error.details = { rust_core_boundary: "runtime.agent_create", requested_cwd: options.local?.cwd };
        throw error;
      },
    },
    createAgent: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/agents",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 501);
  assert.equal(response.error.code, "runtime_agent_create_rust_core_required");
  assert.deepEqual(calls, [{ surfaceStore: store, options: { local: { cwd: "/workspace/project" } } }]);
});

test("public runtime thread create route uses mounted agent lifecycle surface", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    agentRunLifecycleSurface: {
      async createThread(surfaceStore, body) {
        calls.push({ surfaceStore, body });
        return {
          thread_id: "thread_route",
          status: "active",
        };
      },
    },
    createThread: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), {
    thread_id: "thread_route",
    status: "active",
  });
  assert.deepEqual(calls, [
    {
      surfaceStore: store,
      body: { options: { local: { cwd: "/workspace/project" } } },
    },
  ]);
});

test("public runtime usage and authority evidence routes use mounted lifecycle projection surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    lifecycleProjectionSurface: {
      listUsage(surfaceStore, options) {
        calls.push({ method: "listUsage", surfaceStore, options });
        return {
          schema_version: "runtime.usage.telemetry.v1",
          items: [{ run_id: "run_route" }],
        };
      },
      authorityEvidenceSummary(surfaceStore, options) {
        calls.push({ method: "authorityEvidenceSummary", surfaceStore, options });
        return {
          schema_version: "authority.evidence.summary.v1",
          filters: options,
        };
      },
    },
    runReadSurface: {
      listUsage: retiredRouteWrapper,
      authorityEvidenceSummary: retiredRouteWrapper,
    },
    listUsage: retiredRouteWrapper,
    authorityEvidenceSummary: retiredRouteWrapper,
  };

  const usageResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/usage?group_by=thread&agent_id=agent_route" }),
    response: usageResponse,
    store,
  });

  assert.equal(usageResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(usageResponse.body), {
    payload: {
      schema_version: "runtime.usage.telemetry.v1",
      items: [{ run_id: "run_route" }],
    },
    metadata: { requestMetadata: true },
  });

  const evidenceResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/authority-evidence?thread_id=thread_route" }),
    response: evidenceResponse,
    store,
  });

  assert.equal(evidenceResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(evidenceResponse.body), {
    schema_version: "authority.evidence.summary.v1",
    filters: { thread_id: "thread_route" },
  });
  assert.deepEqual(calls, [
    {
      method: "listUsage",
      surfaceStore: store,
      options: { group_by: "thread", agent_id: "agent_route" },
    },
    {
      method: "authorityEvidenceSummary",
      surfaceStore: store,
      options: { thread_id: "thread_route" },
    },
  ]);
});

test("public runtime top-level memory context routes are retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const store = {
    threadMemorySurface: {
      publicMemoryStatus() {
        assert.fail("retired top-level memory status route must not reach the memory surface");
      },
      publicMemoryProjectionForContext() {
        assert.fail("retired top-level memory records route must not reach the memory surface");
      },
      publicMemoryPolicyForContext() {
        assert.fail("retired top-level memory policy route must not reach the memory surface");
      },
      publicMemoryPathForContext() {
        assert.fail("retired top-level memory path route must not reach the memory surface");
      },
      publicValidateMemory() {
        assert.fail("retired top-level memory validation route must not reach the memory surface");
      },
    },
  };

  for (const route of [
    { method: "GET", url: "/v1/memory?thread_id=thread_route", path: "/v1/memory" },
    { method: "GET", url: "/v1/memory/records?thread_id=thread_route", path: "/v1/memory/records" },
    { method: "GET", url: "/v1/memory/policy?agent_id=agent_route", path: "/v1/memory/policy" },
    { method: "GET", url: "/v1/memory/path?thread_id=thread_route", path: "/v1/memory/path" },
    { method: "POST", url: "/v1/memory/validate", path: "/v1/memory/validate", body: { thread_id: "thread_route" } },
  ]) {
    const response = responseRecorder();
    await handleRequest({
      request: request({ method: route.method, url: route.url, body: route.body }),
      response,
      store,
    });
    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method: route.method, path: route.path });
  }
});

test("public conversation artifact routes use mounted Rust-owned artifact surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    conversationArtifactSurface: {
      listConversationArtifacts(surfaceStore, query) {
        calls.push({ method: "listConversationArtifacts", surfaceStore, query });
        return [{ id: "artifact_route", thread_id: query.thread_id }];
      },
      createConversationArtifact(surfaceStore, threadId, input) {
        calls.push({ method: "createConversationArtifact", surfaceStore, threadId, input });
        return { artifact_id: "artifact_created", thread_id: threadId, input, commit_hash: "commit-created" };
      },
      getConversationArtifact(surfaceStore, artifactId) {
        calls.push({ method: "getConversationArtifact", surfaceStore, artifactId });
        return { id: artifactId, thread_id: "thread_route" };
      },
      listConversationArtifactRevisions(surfaceStore, artifactId) {
        calls.push({ method: "listConversationArtifactRevisions", surfaceStore, artifactId });
        return [{ revision_id: "revision_route", artifact_id: artifactId }];
      },
      performConversationArtifactAction(surfaceStore, artifactId, input) {
        calls.push({ method: "performConversationArtifactAction", surfaceStore, artifactId, input });
        return { artifact_id: artifactId, action_kind: input.action_kind, commit_hash: "commit-action" };
      },
      exportConversationArtifact(surfaceStore, artifactId, input) {
        calls.push({ method: "exportConversationArtifact", surfaceStore, artifactId, input });
        return { artifact_id: artifactId, export_format: input.export_format, commit_hash: "commit-export" };
      },
      promoteConversationArtifact(surfaceStore, artifactId, input) {
        calls.push({ method: "promoteConversationArtifact", surfaceStore, artifactId, input });
        return { artifact_id: artifactId, promotion_target: input.promotion_target, commit_hash: "commit-promote" };
      },
    },
    listConversationArtifacts: retiredRouteWrapper,
    createConversationArtifact: retiredRouteWrapper,
    getConversationArtifact: retiredRouteWrapper,
    listConversationArtifactRevisions: retiredRouteWrapper,
    performConversationArtifactAction: retiredRouteWrapper,
    exportConversationArtifact: retiredRouteWrapper,
    promoteConversationArtifact: retiredRouteWrapper,
  };

  const requests = [
    {
      req: request({ url: "/v1/conversation-artifacts?thread_id=thread_route" }),
      status: 200,
      body: [{ id: "artifact_route", thread_id: "thread_route" }],
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts",
      body: { thread_id: "thread_route", title: "Draft" },
      }),
      status: 201,
      body: { artifact_id: "artifact_created", thread_id: "thread_route", input: { thread_id: "thread_route", title: "Draft" }, commit_hash: "commit-created" },
    },
    {
      req: request({ url: "/v1/conversation-artifacts/artifact_route" }),
      status: 200,
      body: { id: "artifact_route", thread_id: "thread_route" },
    },
    {
      req: request({ url: "/v1/conversation-artifacts/artifact_route/revisions" }),
      status: 200,
      body: [{ revision_id: "revision_route", artifact_id: "artifact_route" }],
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/actions",
      body: { action_kind: "edit" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", action_kind: "edit", commit_hash: "commit-action" },
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/export",
      body: { export_format: "zip" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", export_format: "zip", commit_hash: "commit-export" },
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/promote",
      body: { promotion_target: "canvas" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", promotion_target: "canvas", commit_hash: "commit-promote" },
    },
  ];

  for (const { req, status, body } of requests) {
    const response = responseRecorder();
    await handleRequest({ request: req, response, store });
    assert.equal(response.statusCode, status);
    assert.deepEqual(JSON.parse(response.body), body);
  }

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
  assert.deepEqual(
    calls.map(({ method, query, threadId, artifactId, input }) => ({
      method,
      query,
      threadId,
      artifactId,
      input,
    })),
    [
      {
        method: "listConversationArtifacts",
        query: { thread_id: "thread_route" },
        threadId: undefined,
        artifactId: undefined,
        input: undefined,
      },
      {
        method: "createConversationArtifact",
        query: undefined,
        threadId: "thread_route",
        artifactId: undefined,
        input: { thread_id: "thread_route", title: "Draft" },
      },
      {
        method: "getConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: undefined,
      },
      {
        method: "listConversationArtifactRevisions",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: undefined,
      },
      {
        method: "performConversationArtifactAction",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { action_kind: "edit" },
      },
      {
        method: "exportConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { export_format: "zip" },
      },
      {
        method: "promoteConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { promotion_target: "canvas" },
      },
    ],
  );
});

test("public runtime task and job routes use task job surface directly", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const body = { prompt: "plan the cutover" };
  const surfaceResult = (method, args) => ({
    status: "blocked",
    method,
    args,
  });
  const store = {
    taskJobSurface: {
      createTask(surfaceStore, requestBody) {
        calls.push({ method: "createTask", surfaceStore, args: [requestBody] });
        return surfaceResult("createTask", [requestBody]);
      },
      listTasks(surfaceStore, options) {
        calls.push({ method: "listTasks", surfaceStore, args: [options] });
        return surfaceResult("listTasks", [options]);
      },
      getTask(surfaceStore, taskId) {
        calls.push({ method: "getTask", surfaceStore, args: [taskId] });
        return surfaceResult("getTask", [taskId]);
      },
      cancelTask(surfaceStore, taskId) {
        calls.push({ method: "cancelTask", surfaceStore, args: [taskId] });
        return surfaceResult("cancelTask", [taskId]);
      },
      listJobs(surfaceStore, options) {
        calls.push({ method: "listJobs", surfaceStore, args: [options] });
        return surfaceResult("listJobs", [options]);
      },
      getJob(surfaceStore, jobId) {
        calls.push({ method: "getJob", surfaceStore, args: [jobId] });
        return surfaceResult("getJob", [jobId]);
      },
      cancelJob(surfaceStore, jobId) {
        calls.push({ method: "cancelJob", surfaceStore, args: [jobId] });
        return surfaceResult("cancelJob", [jobId]);
      },
    },
    createTask: retiredRouteWrapper,
    listTasks: retiredRouteWrapper,
    getTask: retiredRouteWrapper,
    cancelTask: retiredRouteWrapper,
    listJobs: retiredRouteWrapper,
    getJob: retiredRouteWrapper,
    cancelJob: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/tasks",
      surfaceMethod: "createTask",
      expectedArgs: [body],
    },
    {
      method: "GET",
      path: "/v1/tasks?agent_id=agent-canonical",
      surfaceMethod: "listTasks",
      expectedArgs: [{ agent_id: "agent-canonical" }],
    },
    {
      method: "GET",
      path: "/v1/tasks/task_1",
      surfaceMethod: "getTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "POST",
      path: "/v1/tasks/task_1/cancel",
      surfaceMethod: "cancelTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "GET",
      path: "/v1/jobs?agent_id=agent-canonical",
      surfaceMethod: "listJobs",
      expectedArgs: [{ agent_id: "agent-canonical" }],
    },
    {
      method: "GET",
      path: "/v1/jobs/job_1",
      surfaceMethod: "getJob",
      expectedArgs: ["job_1"],
    },
    {
      method: "POST",
      path: "/v1/jobs/job_1/cancel",
      surfaceMethod: "cancelJob",
      expectedArgs: ["job_1"],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body,
      }),
      response,
      store,
    });
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.method, testCase.surfaceMethod);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.expectedArgs);
    assert.deepEqual(JSON.parse(response.body), {
      status: "blocked",
      method: testCase.surfaceMethod,
      args: testCase.expectedArgs,
    });
  }
});

test("public runtime context budget route uses context policy surface directly", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const body = { request_id: "public-context-budget-route-test" };
  const store = {
    contextPolicySurface: {
      evaluateContextBudget(surfaceStore, input) {
        calls.push({ surfaceStore, input });
        return {
          status: "rust_core_required",
          input,
          direct_truth_write_allowed: false,
        };
      },
    },
    evaluateContextBudget: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({ method: "POST", url: "/v1/context-budget", body }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].surfaceStore, store);
  assert.deepEqual(calls[0].input, { request: body });
  assert.deepEqual(JSON.parse(response.body), {
    status: "rust_core_required",
    input: { request: body },
    direct_truth_write_allowed: false,
  });
});

test("public runtime top-level MCP route family is retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const failRetiredRoute = () => assert.fail("retired top-level MCP route must not reach an MCP surface");
  const store = {
    mcpCatalogSurface: {
      mcpStatus: failRetiredRoute,
      listMcpServers: failRetiredRoute,
      listMcpTools: failRetiredRoute,
      searchMcpTools: failRetiredRoute,
      getMcpTool: failRetiredRoute,
      listMcpResources: failRetiredRoute,
      listMcpPrompts: failRetiredRoute,
      validateMcp: failRetiredRoute,
    },
    mcpControlSurface: {
      importMcp: failRetiredRoute,
      addMcpServer: failRetiredRoute,
      setMcpServerEnabled: failRetiredRoute,
      removeMcpServer: failRetiredRoute,
      invokeMcpTool: failRetiredRoute,
    },
    mcpServeSurface: {
      mcpServeStatus: failRetiredRoute,
      handleMcpServeJsonRpc: failRetiredRoute,
    },
  };
  const cases = [
    { method: "GET", path: "/v1/mcp?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/servers?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/tools" },
    { method: "GET", path: "/v1/mcp/tools/search?query=diff" },
    { method: "GET", path: "/v1/mcp/tools/mcp.tool" },
    { method: "GET", path: "/v1/mcp/resources" },
    { method: "GET", path: "/v1/mcp/prompts" },
    { method: "POST", path: "/v1/mcp/validate" },
    { method: "POST", path: "/v1/mcp/import?thread_id=thread_route" },
    { method: "POST", path: "/v1/mcp/servers" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/enable" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/disable" },
    { method: "DELETE", path: "/v1/mcp/servers/mcp.docs" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/remove" },
    { method: "POST", path: "/v1/mcp/tools/mcp.tool/invoke" },
    { method: "GET", path: "/v1/mcp/serve?thread_id=thread-retired" },
    { method: "POST", path: "/v1/mcp/serve?thread_id=thread-retired" },
  ];

  for (const { method, path } of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method,
        url: path,
        body: { request_id: "public-mcp-route-test" },
      }),
      response,
      store,
    });

    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method, path: new URL(path, "http://daemon.test").pathname });
  }
});

test("public runtime MCP serve route accepts stable protocol admission envelope", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    mcpServeSurface: {
      handleMcpServeJsonRpc(surfaceStore, threadId, message, options) {
        calls.push({ surfaceStore, threadId, message, options });
        return { jsonrpc: "2.0", id: message.id, result: { ok: true } };
      },
    },
  };
  const admission = {
    authority_grant_refs: ["wallet.network://grant/mcp-serve/git.diff"],
    authority_receipt_refs: ["receipt://wallet.network/mcp-serve/git.diff"],
    custody_ref: "ctee://workspace/thread-route",
    containment_ref: "containment://mcp-serve/thread-route/git.diff",
  };
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve",
      body: {
        schema_version: "ioi.runtime.mcp-serve-client.v1",
        source: "sdk_client",
        ...admission,
        message: {
          jsonrpc: "2.0",
          id: 31,
          method: "tools/call",
          params: { name: "git.diff", arguments: { includeStat: true } },
        },
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls[0].threadId, "thread_route");
  assert.equal(calls[0].message.method, "tools/call");
  assert.deepEqual(calls[0].options.authority_grant_refs, admission.authority_grant_refs);
  assert.deepEqual(calls[0].options.authority_receipt_refs, admission.authority_receipt_refs);
  assert.equal(calls[0].options.custody_ref, admission.custody_ref);
  assert.equal(calls[0].options.containment_ref, admission.containment_ref);
  assert.equal(calls[0].options.thread_id, "thread_route");
  assert.deepEqual(JSON.parse(response.body), { jsonrpc: "2.0", id: 31, result: { ok: true } });
});
