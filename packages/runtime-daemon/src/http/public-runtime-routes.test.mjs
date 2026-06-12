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
    resolveStudioIntentFrame: (input) => ({
      object: "ioi.studio_intent_frame",
      target: input.prompt ?? null,
    }),
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
    runtimeDoctorReport: {
      doctorReport(surfaceStore, { baseUrl }) {
        calls.push({ surfaceStore, baseUrl });
        return { ok: true, baseUrl };
      },
    },
    doctorReport: retiredRouteWrapper,
  };

  await handleRequest({ request: request({ url: "/v1/doctor" }), response, store });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { ok: true, baseUrl: "http://daemon.test" });
  assert.deepEqual(calls, [{ surfaceStore: store, baseUrl: "http://daemon.test" }]);
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

test("public runtime studio intent route uses resolver dependency directly", async () => {
  const calls = [];
  const { handleRequest } = routeHarness({
    resolveStudioIntentFrame(input) {
      calls.push(input);
      return {
        object: "ioi.studio_intent_frame",
        route_directive: "agent",
        target: input.prompt,
      };
    },
  });
  const response = responseRecorder();
  const store = {
    resolveStudioIntentFrame: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/studio/intent-frame",
      body: { prompt: "inspect the runtime" },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [{ prompt: "inspect the runtime" }]);
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

test("public runtime usage and authority evidence routes use mounted run read surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    runReadSurface: {
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

test("public runtime memory projection routes fail closed through thread memory surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const rustCoreRequired = (details = {}) => {
    const error = new Error("thread memory control requires Rust core");
    error.status = 501;
    error.code = "runtime_thread_memory_control_rust_core_required";
    error.details = {
      rust_core_boundary: "runtime.thread_memory_control",
      ...details,
    };
    throw error;
  };
  const store = {
    threadMemorySurface: {
      publicMemoryStatus(surfaceStore, options) {
        calls.push({ method: "publicMemoryStatus", surfaceStore, options });
        rustCoreRequired({ requested_control_kind: "memory_status_projection" });
      },
      publicMemoryProjectionForContext(surfaceStore, options) {
        calls.push({ method: "publicMemoryProjectionForContext", surfaceStore, options });
        rustCoreRequired({ requested_control_kind: "memory_read_projection" });
      },
      publicMemoryPolicyForContext(surfaceStore, options) {
        calls.push({ method: "publicMemoryPolicyForContext", surfaceStore, options });
        rustCoreRequired({ requested_control_kind: "memory_policy_projection" });
      },
      publicMemoryPathForContext(surfaceStore, options) {
        calls.push({ method: "publicMemoryPathForContext", surfaceStore, options });
        rustCoreRequired({ requested_control_kind: "memory_path_projection" });
      },
      publicValidateMemory(surfaceStore, input) {
        calls.push({ method: "publicValidateMemory", surfaceStore, input });
        rustCoreRequired({ requested_control_kind: "memory_validate_projection" });
      },
    },
    memoryProjectionForContext: retiredRouteWrapper,
    memoryStatus: retiredRouteWrapper,
    validateMemory: retiredRouteWrapper,
  };

  for (const path of [
    "/v1/memory?thread_id=thread_route",
    "/v1/memory/records?thread_id=thread_route",
    "/v1/memory/policy?agent_id=agent_route",
    "/v1/memory/path?thread_id=thread_route",
  ]) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url: path }), response, store });
    assert.equal(response.statusCode, 501);
    assert.equal(response.error.code, "runtime_thread_memory_control_rust_core_required");
  }

  const validateResponse = responseRecorder();
  await handleRequest({
    request: request({ method: "POST", url: "/v1/memory/validate", body: { thread_id: "thread_route" } }),
    response: validateResponse,
    store,
  });
  assert.equal(validateResponse.statusCode, 501);
  assert.equal(validateResponse.error.code, "runtime_thread_memory_control_rust_core_required");
  assert.equal(calls.every((call) => call.surfaceStore === store), true);
  assert.deepEqual(
    calls.map(({ method, options, input }) => ({ method, options, input })),
    [
      { method: "publicMemoryStatus", options: { thread_id: "thread_route" }, input: undefined },
      { method: "publicMemoryProjectionForContext", options: { thread_id: "thread_route" }, input: undefined },
      { method: "publicMemoryPolicyForContext", options: { agent_id: "agent_route" }, input: undefined },
      { method: "publicMemoryPathForContext", options: { thread_id: "thread_route" }, input: undefined },
      { method: "publicValidateMemory", options: undefined, input: { thread_id: "thread_route" } },
    ],
  );
});

test("public conversation artifact routes fail closed through mounted artifact surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const rustCoreRequired = (details = {}) => {
    const error = new Error("conversation artifact control requires Rust core");
    error.status = 501;
    error.code = "runtime_conversation_artifact_control_rust_core_required";
    error.details = {
      rust_core_boundary: "runtime.conversation_artifact_control",
      ...details,
    };
    throw error;
  };
  const store = {
    conversationArtifactSurface: {
      listConversationArtifacts(surfaceStore, query) {
        calls.push({ method: "listConversationArtifacts", surfaceStore, query });
        rustCoreRequired({ operation: "conversation_artifact_list" });
      },
      createConversationArtifact(surfaceStore, threadId, input) {
        calls.push({ method: "createConversationArtifact", surfaceStore, threadId, input });
        rustCoreRequired({ operation: "conversation_artifact_create", thread_id: threadId });
      },
      getConversationArtifact(surfaceStore, artifactId) {
        calls.push({ method: "getConversationArtifact", surfaceStore, artifactId });
        rustCoreRequired({ operation: "conversation_artifact_get", artifact_id: artifactId });
      },
      listConversationArtifactRevisions(surfaceStore, artifactId) {
        calls.push({ method: "listConversationArtifactRevisions", surfaceStore, artifactId });
        rustCoreRequired({ operation: "conversation_artifact_revision_list", artifact_id: artifactId });
      },
      performConversationArtifactAction(surfaceStore, artifactId, input) {
        calls.push({ method: "performConversationArtifactAction", surfaceStore, artifactId, input });
        rustCoreRequired({ operation: "conversation_artifact_action", artifact_id: artifactId });
      },
      exportConversationArtifact(surfaceStore, artifactId, input) {
        calls.push({ method: "exportConversationArtifact", surfaceStore, artifactId, input });
        rustCoreRequired({ operation: "conversation_artifact_export", artifact_id: artifactId });
      },
      promoteConversationArtifact(surfaceStore, artifactId, input) {
        calls.push({ method: "promoteConversationArtifact", surfaceStore, artifactId, input });
        rustCoreRequired({ operation: "conversation_artifact_promote", artifact_id: artifactId });
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
    request({ url: "/v1/conversation-artifacts?thread_id=thread_route" }),
    request({
      method: "POST",
      url: "/v1/conversation-artifacts",
      body: { thread_id: "thread_route", title: "Draft" },
    }),
    request({ url: "/v1/conversation-artifacts/artifact_route" }),
    request({ url: "/v1/conversation-artifacts/artifact_route/revisions" }),
    request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/actions",
      body: { kind: "edit" },
    }),
    request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/export",
      body: { format: "zip" },
    }),
    request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/promote",
      body: { target: "canvas" },
    }),
  ];

  for (const req of requests) {
    const response = responseRecorder();
    await handleRequest({ request: req, response, store });
    assert.equal(response.statusCode, 501);
    assert.equal(response.error.code, "runtime_conversation_artifact_control_rust_core_required");
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
        input: { kind: "edit" },
      },
      {
        method: "exportConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { format: "zip" },
      },
      {
        method: "promoteConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { target: "canvas" },
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

test("public runtime MCP routes use mounted MCP surfaces directly", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const body = { request_id: "public-mcp-route-test" };
  const result = (surface, method, args) => ({ surface, method, args });
  const store = {
    mcpCatalogSurface: {
      mcpStatus(surfaceStore, options) {
        calls.push({ surface: "mcpCatalogSurface", method: "mcpStatus", surfaceStore, args: [options] });
        return result("mcpCatalogSurface", "mcpStatus", [options]);
      },
      listMcpServers(surfaceStore, options) {
        calls.push({ surface: "mcpCatalogSurface", method: "listMcpServers", surfaceStore, args: [options] });
        return result("mcpCatalogSurface", "listMcpServers", [options]);
      },
      searchMcpTools(surfaceStore, options) {
        calls.push({ surface: "mcpCatalogSurface", method: "searchMcpTools", surfaceStore, args: [options] });
        return result("mcpCatalogSurface", "searchMcpTools", [options]);
      },
      getMcpTool(surfaceStore, toolId, options) {
        calls.push({ surface: "mcpCatalogSurface", method: "getMcpTool", surfaceStore, args: [toolId, options] });
        return result("mcpCatalogSurface", "getMcpTool", [toolId, options]);
      },
      validateMcp(surfaceStore, requestBody) {
        calls.push({ surface: "mcpCatalogSurface", method: "validateMcp", surfaceStore, args: [requestBody] });
        return result("mcpCatalogSurface", "validateMcp", [requestBody]);
      },
    },
    mcpControlSurface: {
      importMcp(surfaceStore, input) {
        calls.push({ surface: "mcpControlSurface", method: "importMcp", surfaceStore, args: [input] });
        return result("mcpControlSurface", "importMcp", [input]);
      },
      addMcpServer(surfaceStore, input) {
        calls.push({ surface: "mcpControlSurface", method: "addMcpServer", surfaceStore, args: [input] });
        return result("mcpControlSurface", "addMcpServer", [input]);
      },
      setMcpServerEnabled(surfaceStore, serverId, enabled, input) {
        calls.push({
          surface: "mcpControlSurface",
          method: "setMcpServerEnabled",
          surfaceStore,
          args: [serverId, enabled, input],
        });
        return result("mcpControlSurface", "setMcpServerEnabled", [serverId, enabled, input]);
      },
      removeMcpServer(surfaceStore, serverId, input) {
        calls.push({ surface: "mcpControlSurface", method: "removeMcpServer", surfaceStore, args: [serverId, input] });
        return result("mcpControlSurface", "removeMcpServer", [serverId, input]);
      },
      invokeMcpTool(surfaceStore, input) {
        calls.push({ surface: "mcpControlSurface", method: "invokeMcpTool", surfaceStore, args: [input] });
        return result("mcpControlSurface", "invokeMcpTool", [input]);
      },
    },
    mcpServeSurface: {
      mcpServeStatus(surfaceStore, options) {
        calls.push({ surface: "mcpServeSurface", method: "mcpServeStatus", surfaceStore, args: [options] });
        return result("mcpServeSurface", "mcpServeStatus", [options]);
      },
      handleMcpServeJsonRpc(surfaceStore, threadId, message, options) {
        calls.push({
          surface: "mcpServeSurface",
          method: "handleMcpServeJsonRpc",
          surfaceStore,
          args: [threadId, message, options],
        });
        return result("mcpServeSurface", "handleMcpServeJsonRpc", [threadId, message, options]);
      },
    },
    mcpStatus: retiredRouteWrapper,
    listMcpServers: retiredRouteWrapper,
    searchMcpTools: retiredRouteWrapper,
    getMcpTool: retiredRouteWrapper,
    validateMcp: retiredRouteWrapper,
    importMcp: retiredRouteWrapper,
    addMcpServer: retiredRouteWrapper,
    setMcpServerEnabled: retiredRouteWrapper,
    removeMcpServer: retiredRouteWrapper,
    invokeMcpTool: retiredRouteWrapper,
    mcpServeStatus: retiredRouteWrapper,
    handleMcpServeJsonRpc: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "GET",
      path: "/v1/mcp?thread_id=thread_route",
      expectedMethod: "mcpStatus",
      expectedArgs: [{ thread_id: "thread_route" }],
    },
    {
      method: "GET",
      path: "/v1/mcp/servers?thread_id=thread_route",
      expectedMethod: "listMcpServers",
      expectedArgs: [{ thread_id: "thread_route" }],
    },
    {
      method: "GET",
      path: "/v1/mcp/tools/search?query=diff",
      expectedMethod: "searchMcpTools",
      expectedArgs: [{ query: "diff" }],
    },
    {
      method: "GET",
      path: "/v1/mcp/tools/mcp.tool",
      expectedMethod: "getMcpTool",
      expectedArgs: ["mcp.tool", {}],
    },
    {
      method: "POST",
      path: "/v1/mcp/validate",
      expectedMethod: "validateMcp",
      expectedArgs: [body],
    },
    {
      method: "POST",
      path: "/v1/mcp/import?thread_id=thread_route",
      expectedMethod: "importMcp",
      expectedArgs: [{ thread_id: "thread_route", ...body }],
    },
    {
      method: "POST",
      path: "/v1/mcp/servers",
      expectedMethod: "addMcpServer",
      expectedArgs: [body],
      expectedStatus: 201,
    },
    {
      method: "POST",
      path: "/v1/mcp/servers/mcp.docs/enable",
      expectedMethod: "setMcpServerEnabled",
      expectedArgs: ["mcp.docs", true, body],
    },
    {
      method: "POST",
      path: "/v1/mcp/servers/mcp.docs/remove",
      expectedMethod: "removeMcpServer",
      expectedArgs: ["mcp.docs", body],
    },
    {
      method: "POST",
      path: "/v1/mcp/tools/mcp.tool/invoke",
      expectedMethod: "invokeMcpTool",
      expectedArgs: [{ ...body, tool_id: "mcp.tool" }],
    },
    {
      method: "GET",
      path: "/v1/mcp/serve?thread_id=thread_route",
      expectedMethod: "mcpServeStatus",
      expectedArgs: [{ thread_id: "thread_route" }],
    },
    {
      method: "POST",
      path: "/v1/mcp/serve?thread_id=thread_route",
      expectedMethod: "handleMcpServeJsonRpc",
      expectedArgs: ["thread_route", body, { thread_id: "thread_route" }],
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
    assert.equal(response.statusCode, testCase.expectedStatus ?? 200);
    assert.equal(call.method, testCase.expectedMethod);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.expectedArgs);
    assert.deepEqual(JSON.parse(response.body), {
      surface: call.surface,
      method: testCase.expectedMethod,
      args: testCase.expectedArgs,
    });
  }
});

test("public runtime routes preserve MCP serve thread requirement", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({ method: "POST", url: "/v1/mcp/serve", body: { jsonrpc: "2.0" } }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.error.code, "mcp_thread_required");
  assert.deepEqual(response.error.details, { route: "/v1/mcp/serve" });
});

test("public runtime MCP serve route ignores retired threadId query alias", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    async handleMcpServeJsonRpc() {
      assert.fail("retired threadId query alias must not reach MCP serve handler");
    },
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/mcp/serve?threadId=thread-retired",
      body: { jsonrpc: "2.0", id: 1, method: "initialize" },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.error.code, "mcp_thread_required");
  assert.deepEqual(response.error.details, { route: "/v1/mcp/serve" });
});
