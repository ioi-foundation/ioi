import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRouteHandlers } from "./runtime-route-handlers.mjs";

function responseRecorder() {
  return {
    headers: {},
    statusCode: 200,
    body: "",
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(value = "") {
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
  throw new Error("retired route wrapper must not be routed");
}

function routeHandlers(overrides = {}) {
  return createRuntimeRouteHandlers({
    baseUrlForRequest: () => "http://daemon.test",
    notFound(message, details) {
      const error = new Error(message);
      error.status = 404;
      error.code = "not_found";
      error.details = details;
      throw error;
    },
    readBody: async (req) => req.body ?? {},
    runtimeEventCursorFromRequest: () => ({}),
    usageRequestMetadataFromUrl: () => ({}),
    usageTelemetryWithRequestMetadata: (payload) => payload,
    writeJsonResponse(response, payload, status = 200) {
      response.statusCode = status;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(payload));
    },
    writeMcpJsonRpcResponse(response, payload) {
      response.statusCode = 200;
      response.end(JSON.stringify(payload));
    },
    writeSse(response, payload) {
      response.statusCode = 200;
      response.end(JSON.stringify(payload));
    },
    ...overrides,
  });
}

test("native authority evidence compatibility routes are retired", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const store = {
    modelMounting: {
      snapshot: retiredRouteWrapper,
      authoritySnapshot: retiredRouteWrapper,
      listModelCapabilities: retiredRouteWrapper,
    },
    projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
      calls.push({ projectionKind, facts });
      return {
        schema_version: "authority.evidence.summary.v1",
        filters: facts,
      };
    },
    authorityEvidenceSummary: retiredRouteWrapper,
  };
  const paths = [
    "/api/v1/authority-evidence",
    "/api/v1/authority-evidence-summaries",
    "/api/v1/workflow-capability-preflight-evidence",
    "/api/v1/workflow-capability-preflight",
  ];

  for (const path of paths) {
    const response = responseRecorder();
    await assert.rejects(
      handleModelMountingNativeRoute({
        request: request({ url: `${path}?thread_id=thread_route` }),
        response,
        store,
        url: new URL(`${path}?thread_id=thread_route`, "http://daemon.test"),
        segments: path.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details?.path === path,
    );
  }

  assert.deepEqual(calls, []);
});

test("native chat, responses, and embeddings invocation aliases are retired with native rerank tokenizer utilities", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const store = {
    modelMounting: {
      invokeModel(payload) {
        calls.push(payload);
        return {};
      },
      tokenizeModel(payload) {
        calls.push(payload);
        return {};
      },
      fitModelContext(payload) {
        calls.push(payload);
        return {};
      },
    },
  };
  const paths = [
    "/api/v1/chat",
    "/api/v1/responses",
    "/api/v1/embeddings",
    "/api/v1/rerank",
    "/api/v1/tokenize",
    "/api/v1/context/fit",
  ];

  for (const path of paths) {
    const response = responseRecorder();
    await assert.rejects(
      handleModelMountingNativeRoute({
        request: request({ method: "POST", url: path, body: { input: "retired alias" } }),
        response,
        store,
        url: new URL(path, "http://daemon.test"),
        segments: path.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details?.path === path,
    );
  }

  assert.deepEqual(calls, []);
});

test("agent, thread, and run detail routes return store-owned lifecycle projection API output", async () => {
  const { handleAgentRoute, handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const store = {
    projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
      calls.push({ projectionKind, facts });
      return Array.isArray(projectionForRoute(projectionKind))
        ? projectionForRoute(projectionKind).map((record) => ({ ...record, ...facts }))
        : { ...projectionForRoute(projectionKind), ...facts };
    },
    usageForRun: retiredRouteWrapper,
    eventsForRun: retiredRouteWrapper,
    usageForThread: retiredRouteWrapper,
    listTurns: retiredRouteWrapper,
    getTurn: retiredRouteWrapper,
    eventsForThread: retiredRouteWrapper,
  };

  const routeRequests = [
    {
      handler: handleAgentRoute,
      request: request({ url: "/v1/agents/agent_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/agents/agent_route", "http://daemon.test"),
      segments: ["v1", "agents", "agent_route"],
    },
    {
      handler: handleAgentRoute,
      request: request({ url: "/v1/agents/agent_route/runs" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/agents/agent_route/runs", "http://daemon.test"),
      segments: ["v1", "agents", "agent_route", "runs"],
    },
    {
      handler: handleThreadRoute,
      request: request({ url: "/v1/threads/thread_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/threads/thread_route", "http://daemon.test"),
      segments: ["v1", "threads", "thread_route"],
      retired: true,
    },
  ];
  for (const { path, retired } of [
    { path: "/v1/threads/thread_route/usage", retired: true },
    { path: "/v1/threads/thread_route/turns" },
    { path: "/v1/threads/thread_route/turns/turn_1" },
    { path: "/v1/threads/thread_route/events", retired: true },
    { path: "/v1/threads/thread_route/events/stream", retired: true },
  ]) {
    routeRequests.push({
      handler: handleThreadRoute,
      request: request({ url: path }),
      response: responseRecorder(),
      store,
      url: new URL(path, "http://daemon.test"),
      segments: path.split("/").filter(Boolean),
      retired,
    });
  }
  routeRequests.push({
    handler: handleRunRoute,
      request: request({ url: "/v1/runs/run_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/runs/run_route", "http://daemon.test"),
      segments: ["v1", "runs", "run_route"],
  });
  // Read-only run projections + cancel/events + replay are all Rust-owned (410).
  for (const { path, retired } of [
    { path: "/v1/runs/run_route/usage", retired: true },
    { path: "/v1/runs/run_route/wait", retired: true },
    { path: "/v1/runs/run_route/conversation", retired: true },
    { path: "/v1/runs/run_route/events", retired: true },
    { path: "/v1/runs/run_route/replay", retired: true },
    { path: "/v1/runs/run_route/trace", retired: true },
    { path: "/v1/runs/run_route/inspect", retired: true },
    { path: "/v1/runs/run_route/computer-use/trace", retired: true },
    { path: "/v1/runs/run_route/computer-use/trajectory", retired: true },
    { path: "/v1/runs/run_route/scorecard", retired: true },
    { path: "/v1/runs/run_route/artifacts", retired: true },
    { path: "/v1/runs/run_route/artifacts/artifact_1", retired: true },
  ]) {
    routeRequests.push({
      handler: handleRunRoute,
      request: request({ url: path }),
      response: responseRecorder(),
      store,
      url: new URL(path, "http://daemon.test"),
      segments: path.split("/").filter(Boolean),
      retired,
    });
  }

  for (const routeRequest of routeRequests) {
    await routeRequest.handler(routeRequest);
    assert.equal(routeRequest.response.statusCode, routeRequest.retired ? 410 : 200);
  }

  // Retired thread + run lifecycle routes are served by the Rust daemon, so they never
  // hit the store. Only the bare run get remains JS-served.
  assert.deepEqual(calls, [
    { projectionKind: "agent", facts: { agent_id: "agent_route" } },
    { projectionKind: "agent_runs", facts: { agent_id: "agent_route" } },
    { projectionKind: "thread_turns", facts: { thread_id: "thread_route" } },
    { projectionKind: "thread_turn", facts: { thread_id: "thread_route", turn_id: "turn_1" } },
    { projectionKind: "run", facts: { run_id: "run_route" } },
  ]);
});

function projectionForRoute(projectionKind) {
  if (["thread_turns", "thread_events", "run_events", "run_replay", "run_conversation", "run_computer_use_trajectory", "run_artifacts", "agent_runs"].includes(projectionKind)) {
    return [{ projection: projectionKind }];
  }
  return { projection: projectionKind };
}

test("agent lifecycle mutation routes use direct Rust lifecycle APIs", async () => {
  const calls = [];
  const rustCoreRequired = (code, details = {}) => {
    const error = new Error("agent lifecycle requires Rust core");
    error.status = 501;
    error.code = code;
    error.details = details;
    throw error;
  };
  const { handleAgentRoute } = routeHandlers({
    updateLifecycleAgent(surfaceStore, agentId, status, operationKind, deps) {
      calls.push({ method: "updateAgent", surfaceStore, agentId, status, operationKind, deps });
      rustCoreRequired("runtime_agent_status_control_rust_core_required", {
        agent_id: agentId,
        requested_status: status,
        requested_operation_kind: operationKind,
      });
    },
    deleteLifecycleAgent(surfaceStore, agentId, deps) {
      calls.push({ method: "deleteAgent", surfaceStore, agentId, deps });
      rustCoreRequired("runtime_agent_delete_rust_core_required", { agent_id: agentId });
    },
    createLifecycleRun(surfaceStore, agentId, input, deps) {
      calls.push({ method: "createRun", surfaceStore, agentId, input, deps });
      rustCoreRequired("runtime_run_create_rust_core_required", { agent_id: agentId });
    },
  });
  const contextPolicyCore = { direct: true };
  const store = {
    updateAgent: retiredRouteWrapper,
    deleteAgent: retiredRouteWrapper,
    createRun: retiredRouteWrapper,
    getAgent: retiredRouteWrapper,
  };

  const requests = [
    request({ method: "DELETE", url: "/v1/agents/agent_route" }),
    request({ method: "POST", url: "/v1/agents/agent_route/archive" }),
    request({ method: "POST", url: "/v1/agents/agent_route/unarchive" }),
    request({ method: "POST", url: "/v1/agents/agent_route/resume" }),
    request({ method: "POST", url: "/v1/agents/agent_route/close" }),
    request({ method: "POST", url: "/v1/agents/agent_route/reload" }),
  ];

  for (const req of requests) {
    await assert.rejects(
      () => handleAgentRoute({
        request: req,
        response: responseRecorder(),
        store,
        contextPolicyCore,
        url: new URL(req.url, "http://daemon.test"),
        segments: new URL(req.url, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "runtime_agent_status_control_rust_core_required" ||
        error.code === "runtime_agent_delete_rust_core_required",
    );
  }

  // Agent run-create (POST /runs) is Rust-owned (410), not a rust_core_required throw.
  const runsResponse = responseRecorder();
  await handleAgentRoute({
    request: request({ method: "POST", url: "/v1/agents/agent_route/runs", body: { prompt: "ship it" } }),
    response: runsResponse,
    store,
    contextPolicyCore,
    url: new URL("/v1/agents/agent_route/runs", "http://daemon.test"),
    segments: ["v1", "agents", "agent_route", "runs"],
  });
  assert.equal(runsResponse.statusCode, 410);
  assert.equal(
    JSON.parse(runsResponse.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.equal(
    calls.some((call) => call.method === "createRun"),
    false,
    "Rust-owned agent run-create must not invoke the JS createLifecycleRun",
  );

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
  assert.equal(calls.every((call) => call.deps.lifecycleAdmissionRunner === contextPolicyCore ||
    call.deps.statusStateUpdateRunner === contextPolicyCore ||
    call.deps.deleteStateUpdateRunner === contextPolicyCore), true);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
  assert.deepEqual(
    calls.map(({ method, agentId, status, operationKind, input }) => ({
      method,
      agentId,
      status,
      operationKind,
      input,
    })),
    [
      { method: "deleteAgent", agentId: "agent_route", status: undefined, operationKind: undefined, input: undefined },
      { method: "updateAgent", agentId: "agent_route", status: "archived", operationKind: "agent.archive", input: undefined },
      { method: "updateAgent", agentId: "agent_route", status: "active", operationKind: "agent.unarchive", input: undefined },
      { method: "updateAgent", agentId: "agent_route", status: "active", operationKind: "agent.resume", input: undefined },
      { method: "updateAgent", agentId: "agent_route", status: "closed", operationKind: "agent.close", input: undefined },
      { method: "updateAgent", agentId: "agent_route", status: null, operationKind: "agent.reload", input: undefined },
    ],
  );
});

test("agent and thread memory read routes use store-owned thread memory APIs", async () => {
  const { handleAgentRoute, handleThreadRoute } = routeHandlers();
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
  const threadMemorySurface = {
    publicMemoryPolicyForAgent: retiredRouteWrapper,
    publicMemoryPathForAgent: retiredRouteWrapper,
    publicListMemoryForAgent: retiredRouteWrapper,
    publicMemoryPolicyForThread: retiredRouteWrapper,
    publicMemoryPathForThread: retiredRouteWrapper,
    publicListMemoryForThread: retiredRouteWrapper,
  };
  const store = {
    threadMemorySurface,
    publicMemoryPolicyForAgent(agentId, options) {
      calls.push({ method: "publicMemoryPolicyForAgent", agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_policy_projection", agent_id: agentId });
    },
    publicMemoryPathForAgent(agentId, options) {
      calls.push({ method: "publicMemoryPathForAgent", agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_path_projection", agent_id: agentId });
    },
    publicListMemoryForAgent(agentId, options) {
      calls.push({ method: "publicListMemoryForAgent", agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_read_projection", agent_id: agentId });
    },
    publicMemoryPolicyForThread(threadId, options) {
      calls.push({ method: "publicMemoryPolicyForThread", threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_policy_projection", thread_id: threadId });
    },
    publicMemoryPathForThread(threadId, options) {
      calls.push({ method: "publicMemoryPathForThread", threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_path_projection", thread_id: threadId });
    },
    publicListMemoryForThread(threadId, options) {
      calls.push({ method: "publicListMemoryForThread", threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_read_projection", thread_id: threadId });
    },
    listMemoryForAgent: retiredRouteWrapper,
    memoryPolicyForAgent: retiredRouteWrapper,
    memoryPathForAgent: retiredRouteWrapper,
    listMemoryForThread: retiredRouteWrapper,
    memoryPolicyForThread: retiredRouteWrapper,
    memoryPathForThread: retiredRouteWrapper,
  };

  for (const path of [
    "/v1/agents/agent_route/memory/policy?thread_id=thread_custom",
    "/v1/agents/agent_route/memory/path?thread_id=thread_custom",
    "/v1/agents/agent_route/memory?query=deploy",
  ]) {
    await assert.rejects(
      () => handleAgentRoute({
        request: request({ url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      { code: "runtime_thread_memory_control_rust_core_required" },
    );
  }
  for (const path of [
    "/v1/threads/thread_route/memory/policy?redaction=summary",
    "/v1/threads/thread_route/memory/path",
    "/v1/threads/thread_route/memory?query=deploy",
  ]) {
    await assert.rejects(
      () => handleThreadRoute({
        request: request({ url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      { code: "runtime_thread_memory_control_rust_core_required" },
    );
  }

  assert.deepEqual(
    calls.map(({ method, agentId, threadId, options }) => ({ method, agentId, threadId, options })),
    [
      {
        method: "publicMemoryPolicyForAgent",
        agentId: "agent_route",
        threadId: undefined,
        options: { thread_id: "thread_custom" },
      },
      {
        method: "publicMemoryPathForAgent",
        agentId: "agent_route",
        threadId: undefined,
        options: { thread_id: "thread_custom" },
      },
      {
        method: "publicListMemoryForAgent",
        agentId: "agent_route",
        threadId: undefined,
        options: { query: "deploy" },
      },
      {
        method: "publicMemoryPolicyForThread",
        agentId: undefined,
        threadId: "thread_route",
        options: { redaction: "summary" },
      },
      {
        method: "publicMemoryPathForThread",
        agentId: undefined,
        threadId: "thread_route",
        options: {},
      },
      {
        method: "publicListMemoryForThread",
        agentId: undefined,
        threadId: "thread_route",
        options: { query: "deploy" },
      },
    ],
  );
});

test("agent and thread memory mutation routes use store-owned thread memory APIs", async () => {
  const { handleAgentRoute, handleThreadRoute } = routeHandlers();
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
  const threadMemorySurface = {
    setMemoryPolicyForAgent: retiredRouteWrapper,
    updateMemoryForAgentId: retiredRouteWrapper,
    deleteMemoryForAgentId: retiredRouteWrapper,
    rememberForAgentId: retiredRouteWrapper,
    recordThreadMemoryStatus: retiredRouteWrapper,
    validateThreadMemory: retiredRouteWrapper,
    setMemoryPolicyForThread: retiredRouteWrapper,
    updateMemoryForThread: retiredRouteWrapper,
    deleteMemoryForThread: retiredRouteWrapper,
    rememberForThread: retiredRouteWrapper,
  };
  const store = {
    threadMemorySurface,
    setMemoryPolicyForAgent(agentId, input) {
      calls.push({ method: "setMemoryPolicyForAgent", agentId, input });
      rustCoreRequired({ requested_control_kind: "memory_policy", agent_id: agentId });
    },
    updateMemoryForAgentId(agentId, memoryId, input) {
      calls.push({ method: "updateMemoryForAgentId", agentId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_edit", agent_id: agentId, memory_id: memoryId });
    },
    deleteMemoryForAgentId(agentId, memoryId, input) {
      calls.push({ method: "deleteMemoryForAgentId", agentId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_delete", agent_id: agentId, memory_id: memoryId });
    },
    rememberForAgentId(agentId, input) {
      calls.push({ method: "rememberForAgentId", agentId, input });
      rustCoreRequired({ requested_control_kind: "memory_write", agent_id: agentId });
    },
    recordThreadMemoryStatus(threadId, input) {
      calls.push({ method: "recordThreadMemoryStatus", threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_status", thread_id: threadId });
    },
    validateThreadMemory(threadId, input) {
      calls.push({ method: "validateThreadMemory", threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_validate", thread_id: threadId });
    },
    setMemoryPolicyForThread(threadId, input) {
      calls.push({ method: "setMemoryPolicyForThread", threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_policy", thread_id: threadId });
    },
    updateMemoryForThread(threadId, memoryId, input) {
      calls.push({ method: "updateMemoryForThread", threadId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_edit", thread_id: threadId, memory_id: memoryId });
    },
    deleteMemoryForThread(threadId, memoryId, input) {
      calls.push({ method: "deleteMemoryForThread", threadId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_delete", thread_id: threadId, memory_id: memoryId });
    },
    rememberForThread(threadId, input) {
      calls.push({ method: "rememberForThread", threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_write", thread_id: threadId });
    },
  };

  const agentRoutes = [
    { method: "PUT", path: "/v1/agents/agent_route/memory/policy", body: { read_only: true } },
    { method: "PATCH", path: "/v1/agents/agent_route/memory/memory_1", body: { text: "edited" } },
    { method: "DELETE", path: "/v1/agents/agent_route/memory/memory_1", body: { reason: "stale" } },
    { method: "POST", path: "/v1/agents/agent_route/memory", body: { text: "remember" } },
  ];
  for (const route of agentRoutes) {
    const url = new URL(route.path, "http://daemon.test");
    await assert.rejects(
      () => handleAgentRoute({
        request: request({ method: route.method, url: route.path, body: route.body }),
        response: responseRecorder(),
        store,
        url,
        segments: url.pathname.split("/").filter(Boolean),
      }),
      { code: "runtime_thread_memory_control_rust_core_required" },
    );
  }

  // memory/status + memory/validate are migrated to the Rust daemon (admit memory
  // control events onto the unified log); the JS routes are retired here.
  for (const path of [
    "/v1/threads/thread_route/memory/status",
    "/v1/threads/thread_route/memory/validate",
  ]) {
    const url = new URL(path, "http://daemon.test");
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({ method: "POST", url: path, body: {} }),
      response,
      store,
      url,
      segments: url.pathname.split("/").filter(Boolean),
    });
    assert.equal(response.statusCode, 410);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }

  const threadRoutes = [
    { method: "PATCH", path: "/v1/threads/thread_route/memory/policy", body: { read_only: false } },
    { method: "PUT", path: "/v1/threads/thread_route/memory/memory_1", body: { text: "edited" } },
    { method: "DELETE", path: "/v1/threads/thread_route/memory/memory_1", body: { reason: "stale" } },
    { method: "POST", path: "/v1/threads/thread_route/memory", body: { text: "remember" } },
  ];
  for (const route of threadRoutes) {
    const url = new URL(route.path, "http://daemon.test");
    await assert.rejects(
      () => handleThreadRoute({
        request: request({ method: route.method, url: route.path, body: route.body }),
        response: responseRecorder(),
        store,
        url,
        segments: url.pathname.split("/").filter(Boolean),
      }),
      { code: "runtime_thread_memory_control_rust_core_required" },
    );
  }

  assert.deepEqual(
    calls.map(({ method, agentId, threadId, memoryId, input }) => ({ method, agentId, threadId, memoryId, input })),
    [
      { method: "setMemoryPolicyForAgent", agentId: "agent_route", threadId: undefined, memoryId: undefined, input: { read_only: true } },
      { method: "updateMemoryForAgentId", agentId: "agent_route", threadId: undefined, memoryId: "memory_1", input: { text: "edited" } },
      { method: "deleteMemoryForAgentId", agentId: "agent_route", threadId: undefined, memoryId: "memory_1", input: { reason: "stale" } },
      { method: "rememberForAgentId", agentId: "agent_route", threadId: undefined, memoryId: undefined, input: { text: "remember" } },
      { method: "setMemoryPolicyForThread", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { read_only: false } },
      { method: "updateMemoryForThread", agentId: undefined, threadId: "thread_route", memoryId: "memory_1", input: { text: "edited" } },
      { method: "deleteMemoryForThread", agentId: undefined, threadId: "thread_route", memoryId: "memory_1", input: { reason: "stale" } },
      { method: "rememberForThread", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { text: "remember" } },
    ],
  );
});

test("thread conversation artifact routes use store-owned artifact API", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const store = {
    listConversationArtifacts(query) {
      calls.push({ method: "listConversationArtifacts", query });
      return [{ id: "artifact_route", thread_id: query.thread_id }];
    },
    createConversationArtifact(threadId, input) {
      calls.push({ method: "createConversationArtifact", threadId, input });
      return { artifact_id: "artifact_created", thread_id: threadId, input, commit_hash: "commit-created" };
    },
  };

  // GET /artifacts (list projection) + POST /artifacts (create) are migrated to the
  // Rust daemon and retired here. There is no thread-scoped artifact-by-id route.
  for (const method of ["GET", "POST"]) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({ method, url: "/v1/threads/thread_route/artifacts", body: { title: "Draft" } }),
      response,
      store,
      url: new URL("/v1/threads/thread_route/artifacts", "http://daemon.test"),
      segments: ["v1", "threads", "thread_route", "artifacts"],
    });
    assert.equal(response.statusCode, 410);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }

  assert.deepEqual(
    calls.map(({ method, query, threadId, input }) => ({ method, query, threadId, input })),
    [],
  );
});

test("thread route sends governed admission controls through store-owned APIs", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "route-admission-test" };
  const apiResult = (api, args) => ({
    status: "admitted",
    api,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    governedImprovementApi: {
      admitGovernedImprovementProposal: retiredRouteWrapper,
    },
    externalCapabilityAuthorityApi: {
      authorizeExternalCapabilityExit: retiredRouteWrapper,
    },
    workerServicePackageApi: {
      admitWorkerServicePackageInvocation: retiredRouteWrapper,
    },
    cteePrivateWorkspaceApi: {
      executeCteePrivateWorkspaceAction: retiredRouteWrapper,
    },
    l1SettlementApi: {
      admitL1SettlementAttempt: retiredRouteWrapper,
    },
    admitGovernedImprovementProposal(threadId, requestBody) {
      calls.push({ api: "admitGovernedImprovementProposal", args: [threadId, requestBody] });
      return apiResult("admitGovernedImprovementProposal", [threadId, requestBody]);
    },
    authorizeExternalCapabilityExit(threadId, requestBody) {
      calls.push({ api: "authorizeExternalCapabilityExit", args: [threadId, requestBody] });
      return apiResult("authorizeExternalCapabilityExit", [threadId, requestBody]);
    },
    admitWorkerServicePackageInvocation(threadId, requestBody) {
      calls.push({ api: "admitWorkerServicePackageInvocation", args: [threadId, requestBody] });
      return apiResult("admitWorkerServicePackageInvocation", [threadId, requestBody]);
    },
    executeCteePrivateWorkspaceAction(threadId, requestBody) {
      calls.push({ api: "executeCteePrivateWorkspaceAction", args: [threadId, requestBody] });
      return apiResult("executeCteePrivateWorkspaceAction", [threadId, requestBody]);
    },
    admitL1SettlementAttempt(threadId, requestBody) {
      calls.push({ api: "admitL1SettlementAttempt", args: [threadId, requestBody] });
      return apiResult("admitL1SettlementAttempt", [threadId, requestBody]);
    },
  };
  const cases = [
    {
      path: "/v1/threads/thread_route/governed-improvement-proposals",
      segments: ["v1", "threads", "thread_route", "governed-improvement-proposals"],
      api: "admitGovernedImprovementProposal",
    },
    {
      path: "/v1/threads/thread_route/external-capability-exits",
      segments: ["v1", "threads", "thread_route", "external-capability-exits"],
      api: "authorizeExternalCapabilityExit",
    },
    {
      path: "/v1/threads/thread_route/worker-service-package-invocations",
      segments: ["v1", "threads", "thread_route", "worker-service-package-invocations"],
      api: "admitWorkerServicePackageInvocation",
    },
    {
      path: "/v1/threads/thread_route/ctee-private-workspace-actions",
      segments: ["v1", "threads", "thread_route", "ctee-private-workspace-actions"],
      api: "executeCteePrivateWorkspaceAction",
    },
    {
      path: "/v1/threads/thread_route/l1-settlement-attempts",
      segments: ["v1", "threads", "thread_route", "l1-settlement-attempts"],
      api: "admitL1SettlementAttempt",
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: "POST",
        url: testCase.path,
        body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    const call = calls.pop();
    assert.equal(response.statusCode, 201);
    assert.equal(call.api, testCase.api);
    assert.deepEqual(call.args, ["thread_route", body]);
    assert.deepEqual(JSON.parse(response.body), {
      status: "admitted",
      api: testCase.api,
      args: ["thread_route", body],
      direct_truth_write_allowed: false,
    });
  }
});

test("thread route sends workflow, diagnostics, and snapshot controls through store-owned APIs", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "route-control-test" };
  const apiResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    workflowEditApi: {
      proposeWorkflowEdit: retiredRouteWrapper,
      applyWorkflowEditProposal: retiredRouteWrapper,
    },
    diagnosticsRepairApi: {
      executeDiagnosticsRepairDecision: retiredRouteWrapper,
    },
    workspaceSnapshotApi: {
      listWorkspaceSnapshots: retiredRouteWrapper,
      previewWorkspaceSnapshotRestore: retiredRouteWrapper,
      applyWorkspaceSnapshotRestore: retiredRouteWrapper,
    },
    proposeWorkflowEdit(threadId, requestBody) {
      calls.push({ operation: "proposeWorkflowEdit", args: [threadId, requestBody] });
      return apiResult("proposeWorkflowEdit", [threadId, requestBody]);
    },
    applyWorkflowEditProposal(threadId, proposalId, requestBody) {
      calls.push({ operation: "applyWorkflowEditProposal", args: [threadId, proposalId, requestBody] });
      return apiResult("applyWorkflowEditProposal", [threadId, proposalId, requestBody]);
    },
    executeDiagnosticsRepairDecision(threadId, decisionRef, requestBody) {
      calls.push({ operation: "executeDiagnosticsRepairDecision", args: [threadId, decisionRef, requestBody] });
      return apiResult("executeDiagnosticsRepairDecision", [threadId, decisionRef, requestBody]);
    },
    listWorkspaceSnapshots(threadId) {
      calls.push({ operation: "listWorkspaceSnapshots", args: [threadId] });
      return apiResult("listWorkspaceSnapshots", [threadId]);
    },
    previewWorkspaceSnapshotRestore(threadId, snapshotId, requestBody) {
      calls.push({ operation: "previewWorkspaceSnapshotRestore", args: [threadId, snapshotId, requestBody] });
      return apiResult("previewWorkspaceSnapshotRestore", [threadId, snapshotId, requestBody]);
    },
    applyWorkspaceSnapshotRestore(threadId, snapshotId, requestBody) {
      calls.push({ operation: "applyWorkspaceSnapshotRestore", args: [threadId, snapshotId, requestBody] });
      return apiResult("applyWorkspaceSnapshotRestore", [threadId, snapshotId, requestBody]);
    },
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/threads/thread_route/workflow-edit-proposals",
      segments: ["v1", "threads", "thread_route", "workflow-edit-proposals"],
      operation: "proposeWorkflowEdit",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/workflow-edit-proposals/proposal_route/apply",
      segments: ["v1", "threads", "thread_route", "workflow-edit-proposals", "proposal_route", "apply"],
      operation: "applyWorkflowEditProposal",
      args: ["thread_route", "proposal_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/diagnostics/repair-decisions/decision_route/execute",
      segments: ["v1", "threads", "thread_route", "diagnostics", "repair-decisions", "decision_route", "execute"],
      operation: "executeDiagnosticsRepairDecision",
      args: ["thread_route", "decision_route", body],
      // Migrated to the Rust daemon (synthesizes + admits the repair event onto the log).
      retired: true,
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/snapshots",
      segments: ["v1", "threads", "thread_route", "snapshots"],
      operation: "listWorkspaceSnapshots",
      args: ["thread_route"],
      // Migrated to the Rust daemon (read-only projection over captured snapshots).
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/snapshots/snapshot_route/restore-preview",
      segments: ["v1", "threads", "thread_route", "snapshots", "snapshot_route", "restore-preview"],
      operation: "previewWorkspaceSnapshotRestore",
      args: ["thread_route", "snapshot_route", body],
      // Migrated to the Rust daemon (restore preview over the captured snapshot).
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/snapshots/snapshot_route/restore-apply",
      segments: ["v1", "threads", "thread_route", "snapshots", "snapshot_route", "restore-apply"],
      operation: "applyWorkspaceSnapshotRestore",
      args: ["thread_route", "snapshot_route", body],
      // Migrated to the Rust daemon (real-FS restore apply over the captured snapshot).
      retired: true,
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body: testCase.body ?? body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    if (testCase.retired) {
      // Migrated routes are retired in the JS daemon (served by the Rust daemon).
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      assert.equal(calls.length, 0, "retired route must not invoke the JS store");
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread route sends approvals through store-owned approval API", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "approval-route-test" };
  const apiResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    approvalApi: {
      listThreadApprovals: retiredRouteWrapper,
      requestThreadApproval: retiredRouteWrapper,
      decideThreadApproval: retiredRouteWrapper,
      revokeThreadApproval: retiredRouteWrapper,
    },
    listThreadApprovals(threadId, requestQuery) {
      calls.push({ operation: "listThreadApprovals", args: [threadId, requestQuery] });
      return apiResult("listThreadApprovals", [threadId, requestQuery]);
    },
    requestThreadApproval(threadId, requestBody) {
      calls.push({ operation: "requestThreadApproval", args: [threadId, requestBody] });
      return apiResult("requestThreadApproval", [threadId, requestBody]);
    },
    decideThreadApproval(threadId, approvalId, requestBody) {
      calls.push({
        operation: "decideThreadApproval",
        args: [threadId, approvalId, requestBody],
      });
      return apiResult("decideThreadApproval", [threadId, approvalId, requestBody]);
    },
    revokeThreadApproval(threadId, approvalId, requestBody) {
      calls.push({
        operation: "revokeThreadApproval",
        args: [threadId, approvalId, requestBody],
      });
      return apiResult("revokeThreadApproval", [threadId, approvalId, requestBody]);
    },
  };
  const cases = [
    {
      method: "GET",
      path: "/v1/threads/thread_route/approvals?include_resolved=true",
      segments: ["v1", "threads", "thread_route", "approvals"],
      operation: "listThreadApprovals",
      args: ["thread_route", { include_resolved: "true" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals",
      segments: ["v1", "threads", "thread_route", "approvals"],
      operation: "requestThreadApproval",
      args: ["thread_route", body],
      // Migrated to the Rust daemon (authorizes + folds the approval onto the agent/run).
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/decision",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "decision"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", body],
      // Migrated to the Rust daemon (authorizes the wallet-signed grant).
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/approve",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "approve"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "approve" }],
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/reject",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "reject"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "reject" }],
      retired: true,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/revoke",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "revoke"],
      operation: "revokeThreadApproval",
      args: ["thread_route", "approval_route", body],
      retired: true,
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body: testCase.body ?? body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    if (testCase.retired) {
      // Migrated routes are retired in the JS daemon (served by the Rust daemon).
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      assert.equal(calls.length, 0, "retired route must not invoke the JS store");
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread and run routes use store-owned context policy API methods", async () => {
  const { handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "context-policy-route-test" };
  const apiResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    contextPolicySurface: {
      evaluateContextBudget: retiredRouteWrapper,
      evaluateCompactionPolicy: retiredRouteWrapper,
      compactThread: retiredRouteWrapper,
    },
    evaluateContextBudget(input) {
      calls.push({ operation: "evaluateContextBudget", args: [input] });
      return apiResult("evaluateContextBudget", [input]);
    },
    evaluateCompactionPolicy(input) {
      calls.push({ operation: "evaluateCompactionPolicy", args: [input] });
      return apiResult("evaluateCompactionPolicy", [input]);
    },
    compactThread(threadId, requestBody) {
      calls.push({ operation: "compactThread", args: [threadId, requestBody] });
      return apiResult("compactThread", [threadId, requestBody]);
    },
  };
  const cases = [
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/context-budget",
      segments: ["v1", "threads", "thread_route", "context-budget"],
      operation: "evaluateContextBudget",
      args: [{ threadId: "thread_route", request: body }],
      // Thread-scoped context-budget is migrated to the Rust daemon (admits a
      // decision event onto the unified log). Run-scoped context-budget stays here.
      retired: true,
    },
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/compaction-policy",
      segments: ["v1", "threads", "thread_route", "compaction-policy"],
      operation: "evaluateCompactionPolicy",
      args: [{ threadId: "thread_route", request: body }],
      // Migrated to the Rust daemon (admits the decision event onto the unified log).
      retired: true,
    },
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/compact",
      segments: ["v1", "threads", "thread_route", "compact"],
      operation: "compactThread",
      args: ["thread_route", body],
      // Migrated to the Rust daemon (admits the context.compacted event onto the log).
      retired: true,
    },
    {
      handler: handleRunRoute,
      path: "/v1/runs/run_route/context-budget",
      segments: ["v1", "runs", "run_route", "context-budget"],
      operation: "evaluateContextBudget",
      args: [{ runId: "run_route", request: body }],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await testCase.handler({
      request: request({
        method: "POST",
        url: testCase.path,
        body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    if (testCase.retired) {
      // Migrated routes are retired in the JS daemon (served by the Rust daemon).
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      assert.equal(calls.length, 0, "retired route must not invoke the JS store");
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread auxiliary and run cancel routes use store-owned auxiliary API directly", async () => {
  const { handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "thread-auxiliary-route-test" };
  const apiResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    forkThread(threadId, requestBody) {
      calls.push({ operation: "forkThread", args: [threadId, requestBody] });
      return apiResult("forkThread", [threadId, requestBody]);
    },
    inspectManagedSessionsForThread(threadId, requestBody) {
      calls.push({ operation: "inspectManagedSessionsForThread", args: [threadId, requestBody] });
      return apiResult("inspectManagedSessionsForThread", [threadId, requestBody]);
    },
    inspectWorkspaceChangeReviewsForThread(threadId, requestBody) {
      calls.push({ operation: "inspectWorkspaceChangeReviewsForThread", args: [threadId, requestBody] });
      return apiResult("inspectWorkspaceChangeReviewsForThread", [threadId, requestBody]);
    },
    controlWorkspaceChangeForThread(threadId, requestBody) {
      calls.push({ operation: "controlWorkspaceChangeForThread", args: [threadId, requestBody] });
      return apiResult("controlWorkspaceChangeForThread", [threadId, requestBody]);
    },
    controlManagedSessionForThread(threadId, requestBody) {
      calls.push({ operation: "controlManagedSessionForThread", args: [threadId, requestBody] });
      return apiResult("controlManagedSessionForThread", [threadId, requestBody]);
    },
    cancelRun(runId) {
      calls.push({ operation: "cancelRun", args: [runId] });
      return apiResult("cancelRun", [runId]);
    },
  };
  const cases = [
    {
      handler: handleThreadRoute,
      method: "POST",
      path: "/v1/threads/thread_route/fork",
      operation: "forkThread",
      args: ["thread_route", body],
    },
    {
      handler: handleThreadRoute,
      method: "GET",
      path: "/v1/threads/thread_route/managed-sessions?projection=summary",
      operation: "inspectManagedSessionsForThread",
      args: ["thread_route", { projection: "summary" }],
      // Migrated to the Rust daemon (read-only projection).
      retired: true,
    },
    {
      handler: handleThreadRoute,
      method: "GET",
      path: "/v1/threads/thread_route/workspace-change-reviews?scope=active",
      operation: "inspectWorkspaceChangeReviewsForThread",
      args: ["thread_route", { scope: "active" }],
      retired: true,
    },
    {
      handler: handleThreadRoute,
      method: "POST",
      path: "/v1/threads/thread_route/workspace-change-reviews/control",
      operation: "controlWorkspaceChangeForThread",
      args: ["thread_route", body],
      // Migrated to the Rust daemon (kernel control over the real-git-detected reviews).
      retired: true,
    },
    {
      handler: handleThreadRoute,
      method: "POST",
      path: "/v1/threads/thread_route/managed-sessions/control",
      operation: "controlManagedSessionForThread",
      args: ["thread_route", body],
      // Migrated to the Rust daemon (kernel control over the bridge-produced
      // managed_session events).
      retired: true,
    },
    {
      handler: handleRunRoute,
      method: "POST",
      path: "/v1/runs/run_route/cancel",
      operation: "cancelRun",
      args: ["run_route"],
      // Migrated to the Rust daemon (handle_run_cancel via plan_run_cancel_state_update).
      retired: true,
    },
  ];

  for (const testCase of cases) {
    const url = new URL(testCase.path, "http://daemon.test");
    const response = responseRecorder();
    await testCase.handler({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body,
      }),
      response,
      store,
      url,
      segments: url.pathname.split("/").filter(Boolean),
    });
    if (testCase.retired) {
      // Migrated routes are retired in the JS daemon (served by the Rust daemon).
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      assert.equal(calls.length, 0, "retired route must not invoke the JS store");
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("run route sends coding-tool budget recovery through store-owned API", async () => {
  const { handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "coding-tool-budget-recovery-route-test" };
  const store = {
    retiredBudgetRecoverySurface: {
      codingToolBudgetRecoveryForRun: retiredRouteWrapper,
    },
    codingToolBudgetRecoveryForRun(runId, requestBody) {
      calls.push({ args: [runId, requestBody] });
      return {
        status: "rust_core_required",
        args: [runId, requestBody],
        direct_truth_write_allowed: false,
      };
    },
  };
  const response = responseRecorder();

  await handleRunRoute({
    request: request({
      method: "POST",
      url: "/v1/runs/run_route/coding-tool-budget-recovery",
      body,
    }),
    response,
    store,
    url: new URL("/v1/runs/run_route/coding-tool-budget-recovery", "http://daemon.test"),
    segments: ["v1", "runs", "run_route", "coding-tool-budget-recovery"],
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, ["run_route", body]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "rust_core_required",
    args: ["run_route", body],
    direct_truth_write_allowed: false,
  });
});

test("thread route sends MCP controls through store-owned MCP APIs", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "thread-mcp-route-test" };
  const serveBody = {
    schema_version: "ioi.runtime.mcp-serve-client.v1",
    source: "sdk_client",
    allowed_tools: ["workspace.status"],
    authority_grant_refs: ["wallet.network://grant/mcp-serve/thread_route/workspace.status"],
    authority_receipt_refs: ["receipt://wallet.network/mcp-serve/thread_route/workspace.status"],
    custody_ref: "ctee://workspace/thread_route",
    containment_ref: "containment://mcp-serve/thread_route/workspace.status",
    message: { jsonrpc: "2.0", id: "thread-route-serve", method: "tools/list" },
  };
  const { message: serveMessage, ...serveContext } = serveBody;
  const apiResult = (method, args) => ({
    status: "rust_core_required",
    api: "store",
    method,
    args,
  });
  const store = {
    mcpControlSurface: retiredRouteWrapper,
    mcpCatalogSurface: retiredRouteWrapper,
    mcpServeSurface: retiredRouteWrapper,
    mcpControlApi: {
      importThreadMcp: retiredRouteWrapper,
      addThreadMcpServer: retiredRouteWrapper,
      removeThreadMcpServer: retiredRouteWrapper,
      setThreadMcpServerEnabled: retiredRouteWrapper,
      invokeThreadMcpTool: retiredRouteWrapper,
      recordThreadMcpStatus: retiredRouteWrapper,
      validateThreadMcp: retiredRouteWrapper,
    },
    mcpCatalogApi: {
      searchThreadMcpTools: retiredRouteWrapper,
      getThreadMcpTool: retiredRouteWrapper,
    },
    mcpServeApi: {
      mcpServeStatus: retiredRouteWrapper,
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
    importThreadMcp(threadId, requestBody) {
      calls.push({ method: "importThreadMcp", thisArg: this, args: [threadId, requestBody] });
      return apiResult("importThreadMcp", [threadId, requestBody]);
    },
    addThreadMcpServer(threadId, requestBody) {
      calls.push({ method: "addThreadMcpServer", thisArg: this, args: [threadId, requestBody] });
      return apiResult("addThreadMcpServer", [threadId, requestBody]);
    },
    removeThreadMcpServer(threadId, serverId, requestBody) {
      calls.push({ method: "removeThreadMcpServer", thisArg: this, args: [threadId, serverId, requestBody] });
      return apiResult("removeThreadMcpServer", [threadId, serverId, requestBody]);
    },
    setThreadMcpServerEnabled(threadId, serverId, enabled, requestBody) {
      calls.push({ method: "setThreadMcpServerEnabled", thisArg: this, args: [threadId, serverId, enabled, requestBody] });
      return apiResult("setThreadMcpServerEnabled", [threadId, serverId, enabled, requestBody]);
    },
    searchThreadMcpTools(threadId, requestBody) {
      calls.push({ method: "searchThreadMcpTools", thisArg: this, args: [threadId, requestBody] });
      return apiResult("searchThreadMcpTools", [threadId, requestBody]);
    },
    getThreadMcpTool(threadId, toolId, requestBody) {
      calls.push({ method: "getThreadMcpTool", thisArg: this, args: [threadId, toolId, requestBody] });
      return apiResult("getThreadMcpTool", [threadId, toolId, requestBody]);
    },
    invokeThreadMcpTool(threadId, toolId, requestBody) {
      calls.push({ method: "invokeThreadMcpTool", thisArg: this, args: [threadId, toolId, requestBody] });
      return apiResult("invokeThreadMcpTool", [threadId, toolId, requestBody]);
    },
    mcpServeStatus(threadId) {
      calls.push({ method: "mcpServeStatus", thisArg: this, args: [threadId] });
      return apiResult("mcpServeStatus", [threadId]);
    },
    handleMcpServeJsonRpc(threadId, message, requestBody) {
      calls.push({ method: "handleMcpServeJsonRpc", thisArg: this, args: [threadId, message, requestBody] });
      return apiResult("handleMcpServeJsonRpc", [threadId, message, requestBody]);
    },
    recordThreadMcpStatus(threadId, requestBody) {
      calls.push({ method: "recordThreadMcpStatus", thisArg: this, args: [threadId, requestBody] });
      return apiResult("recordThreadMcpStatus", [threadId, requestBody]);
    },
    validateThreadMcp(threadId, requestBody) {
      calls.push({ method: "validateThreadMcp", thisArg: this, args: [threadId, requestBody] });
      return apiResult("validateThreadMcp", [threadId, requestBody]);
    },
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/import",
      segments: ["v1", "threads", "thread_route", "mcp", "import"],
      apiMethod: "importThreadMcp",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers",
      segments: ["v1", "threads", "thread_route", "mcp", "servers"],
      apiMethod: "addThreadMcpServer",
      args: ["thread_route", body],
      expectedStatus: 201,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers/mcp.docs/remove",
      segments: ["v1", "threads", "thread_route", "mcp", "servers", "mcp.docs", "remove"],
      apiMethod: "removeThreadMcpServer",
      args: ["thread_route", "mcp.docs", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers/mcp.docs/enable",
      segments: ["v1", "threads", "thread_route", "mcp", "servers", "mcp.docs", "enable"],
      apiMethod: "setThreadMcpServerEnabled",
      args: ["thread_route", "mcp.docs", true, body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/tools/search?query=diff",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "search"],
      apiMethod: "searchThreadMcpTools",
      args: ["thread_route", { query: "diff", source: "sdk_client" }],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/tools/mcp.tool",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "mcp.tool"],
      apiMethod: "getThreadMcpTool",
      args: ["thread_route", "mcp.tool", { source: "sdk_client" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/tools/mcp.tool/invoke",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "mcp.tool", "invoke"],
      apiMethod: "invokeThreadMcpTool",
      args: ["thread_route", "mcp.tool", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/invoke",
      segments: ["v1", "threads", "thread_route", "mcp", "invoke"],
      apiMethod: "invokeThreadMcpTool",
      args: ["thread_route", null, body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/serve",
      segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      apiMethod: "mcpServeStatus",
      args: ["thread_route"],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/serve",
      segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      body: serveBody,
      apiMethod: "handleMcpServeJsonRpc",
      args: ["thread_route", serveMessage, { ...serveContext, thread_id: "thread_route" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/status",
      segments: ["v1", "threads", "thread_route", "mcp", "status"],
      apiMethod: "recordThreadMcpStatus",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/validate",
      segments: ["v1", "threads", "thread_route", "mcp", "validate"],
      apiMethod: "validateThreadMcp",
      args: ["thread_route", body],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body: testCase.body ?? body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    // import / servers / tools-search / status / validate are migrated to the Rust
    // daemon (retired here); serve / tools-fetch / invoke (live transport) are preserved.
    const s = testCase.segments;
    const retired =
      !s[4] ||
      s[4] === "import" ||
      s[4] === "servers" ||
      s[4] === "status" ||
      s[4] === "validate" ||
      (s[4] === "tools" && s[5] === "search");
    if (retired) {
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, testCase.expectedStatus ?? 200);
    assert.equal(call.method, testCase.apiMethod);
    assert.equal(call.thisArg, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      api: "store",
      method: testCase.apiMethod,
      args: testCase.args,
    });
  }
});

test("thread route MCP serve rejects query or raw JSON-RPC compatibility transport", async () => {
  const { handleThreadRoute } = routeHandlers();
  const store = {
    mcpServeStatus: retiredRouteWrapper,
    handleMcpServeJsonRpc: retiredRouteWrapper,
    mcpServeApi: {
      mcpServeStatus: retiredRouteWrapper,
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
  };

  await assert.rejects(
    () =>
      handleThreadRoute({
        request: request({ method: "GET", url: "/v1/threads/thread_route/mcp/serve?server_id=mcp.docs" }),
        response: responseRecorder(),
        store,
        url: new URL("/v1/threads/thread_route/mcp/serve?server_id=mcp.docs", "http://daemon.test"),
        segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      }),
    (error) =>
      error.code === "runtime_mcp_serve_query_context_retired" &&
      error.details?.retired_query_fields?.includes("server_id"),
  );

  await assert.rejects(
    () =>
      handleThreadRoute({
        request: request({
          method: "POST",
          url: "/v1/threads/thread_route/mcp/serve",
          body: { jsonrpc: "2.0", id: "raw", method: "tools/list" },
        }),
        response: responseRecorder(),
        store,
        url: new URL("/v1/threads/thread_route/mcp/serve", "http://daemon.test"),
        segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      }),
    (error) => error.code === "runtime_mcp_serve_protocol_envelope_required",
  );
});

test("thread route invokes coding tools through mounted invocation surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    turn_id: "turn_route",
    workflow_node_id: "node.route",
    input: { include_stat: true },
  };
  const store = {
    codingToolInvocationSurface: {
      invokeThreadTool(surfaceStore, threadId, toolId, requestBody) {
        calls.push({ surfaceStore, threadId, toolId, requestBody });
        return {
          status: "completed",
          thread_id: threadId,
          tool_id: toolId,
          request: requestBody,
        };
      },
    },
    invokeThreadTool() {
      throw new Error("retired invokeThreadTool wrapper must not be routed");
    },
    invokeThreadToolAsync() {
      throw new Error("retired invokeThreadToolAsync wrapper must not be routed");
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/tools/git.diff/invoke",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/tools/git.diff/invoke", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "tools", "git.diff", "invoke"],
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [{
    surfaceStore: store,
    threadId: "thread_route",
    toolId: "git.diff",
    requestBody: body,
  }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "completed",
    thread_id: "thread_route",
    tool_id: "git.diff",
    request: body,
  });
});

test("thread route sends turn controls through store-owned turn APIs", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const store = {
    threadTurnApi: {
      resumeThread: retiredRouteWrapper,
      createTurn: retiredRouteWrapper,
      interruptTurn: retiredRouteWrapper,
      steerTurn: retiredRouteWrapper,
    },
    resumeThread(threadId, requestBody) {
      calls.push({ method: "resumeThread", threadId, requestBody });
      return { status: "active", thread_id: threadId, request: requestBody };
    },
    createTurn(threadId, requestBody) {
      calls.push({ method: "createTurn", threadId, requestBody });
      return { status: "created", thread_id: threadId, turn_id: "turn_route", request: requestBody };
    },
    interruptTurn(threadId, turnId, requestBody) {
      calls.push({ method: "interruptTurn", threadId, turnId, requestBody });
      return { status: "blocked", thread_id: threadId, turn_id: turnId, request: requestBody };
    },
    steerTurn(threadId, turnId, requestBody) {
      calls.push({ method: "steerTurn", threadId, turnId, requestBody });
      return { status: "blocked", thread_id: threadId, turn_id: turnId, request: requestBody };
    },
  };
  const cases = [
    {
      method: "resumeThread",
      path: "/v1/threads/thread_route/resume",
      segments: ["v1", "threads", "thread_route", "resume"],
      body: { reason: "continue" },
      expected: { method: "resumeThread", threadId: "thread_route", requestBody: { reason: "continue" } },
    },
    {
      method: "createTurn",
      path: "/v1/threads/thread_route/turns",
      segments: ["v1", "threads", "thread_route", "turns"],
      body: { prompt: "next" },
      retired: true,
    },
    {
      method: "interruptTurn",
      path: "/v1/threads/thread_route/turns/turn_route/interrupt",
      segments: ["v1", "threads", "thread_route", "turns", "turn_route", "interrupt"],
      body: { reason: "stop" },
      retired: true,
    },
    {
      method: "steerTurn",
      path: "/v1/threads/thread_route/turns/turn_route/steer",
      segments: ["v1", "threads", "thread_route", "turns", "turn_route", "steer"],
      body: { guidance: "focus" },
      retired: true,
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: "POST",
        url: testCase.path,
        body: testCase.body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });

    if (testCase.retired) {
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      continue;
    }
    assert.equal(response.statusCode, 200);
    assert.equal(JSON.parse(response.body).status, testCase.method === "resumeThread" ? "active" : "blocked");
  }

  assert.deepEqual(
    calls,
    cases.filter((testCase) => !testCase.retired).map((testCase) => testCase.expected),
  );
});

test("thread route sends runtime controls through store-owned thread control API methods", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const store = {
    threadControlSurface: {
      updateThreadMode: retiredRouteWrapper,
      updateThreadModel: retiredRouteWrapper,
      updateThreadThinking: retiredRouteWrapper,
    },
    updateThreadMode(threadId, requestBody) {
      calls.push({ method: "updateThreadMode", threadId, requestBody });
      return {
        status: "blocked",
        thread_id: threadId,
        requested_control_kind: "mode",
      };
    },
    updateThreadModel(threadId, requestBody) {
      calls.push({ method: "updateThreadModel", threadId, requestBody });
      return {
        status: "blocked",
        thread_id: threadId,
        requested_control_kind: "model",
      };
    },
    updateThreadThinking(threadId, requestBody) {
      calls.push({ method: "updateThreadThinking", threadId, requestBody });
      return {
        status: "blocked",
        thread_id: threadId,
        requested_control_kind: "thinking",
      };
    },
  };
  const cases = [
    {
      action: "mode",
      body: { mode: "review" },
      method: "updateThreadMode",
      requestedControlKind: "mode",
    },
    {
      action: "model",
      body: { model: { id: "auto" } },
      method: "updateThreadModel",
      requestedControlKind: "model",
    },
    {
      action: "thinking",
      body: { thinking: "off" },
      method: "updateThreadThinking",
      requestedControlKind: "thinking",
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: "POST",
        url: `/v1/threads/thread_route/${testCase.action}`,
        body: testCase.body,
      }),
      response,
      store,
      url: new URL(`/v1/threads/thread_route/${testCase.action}`, "http://daemon.test"),
      segments: ["v1", "threads", "thread_route", testCase.action],
    });

    // Retired: thread mode/model/thinking controls are served by the Rust daemon.
    assert.equal(response.statusCode, 410);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
  assert.equal(calls.length, 0, "the JS thread control API must not be invoked");
});

test("thread route sends workspace-trust acknowledgement through thread control API", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = { reason: "operator acknowledged" };
  const store = {
    threadControlSurface: {
      acknowledgeWorkspaceTrustWarning: retiredRouteWrapper,
    },
    acknowledgeWorkspaceTrustWarning(threadId, warningId, requestBody) {
      calls.push({ threadId, warningId, requestBody });
      return {
        status: "blocked",
        thread_id: threadId,
        warning_id: warningId,
        requested_control_kind: "workspace_trust_acknowledgement",
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/workspace-trust/warning_1/acknowledge",
      body,
    }),
    response,
    store,
    url: new URL(
      "/v1/threads/thread_route/workspace-trust/warning_1/acknowledge",
      "http://daemon.test",
    ),
    segments: ["v1", "threads", "thread_route", "workspace-trust", "warning_1", "acknowledge"],
  });

  // Migrated to the Rust daemon (plans + admits the workspace.trust_acknowledged event;
  // the warning is raised by the Rust mode route on review/yolo).
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.equal(calls.length, 0, "retired route must not invoke the JS store");
});

test("thread route sends subagent controls through store-owned subagent API", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { prompt: "coordinate the migration" };
  const apiResult = (method, args) => ({
    status: "blocked",
    method,
    args,
  });
  const store = {
    listSubagents(threadId, options) {
      calls.push({ method: "listSubagents", args: [threadId, options] });
      return apiResult("listSubagents", [threadId, options]);
    },
    spawnSubagent(threadId, requestBody) {
      calls.push({ method: "spawnSubagent", args: [threadId, requestBody] });
      return apiResult("spawnSubagent", [threadId, requestBody]);
    },
    propagateSubagentCancellation(threadId, requestBody) {
      calls.push({ method: "propagateSubagentCancellation", args: [threadId, requestBody] });
      return apiResult("propagateSubagentCancellation", [threadId, requestBody]);
    },
    waitSubagent(threadId, subagentId, requestBody) {
      calls.push({ method: "waitSubagent", args: [threadId, subagentId, requestBody] });
      return apiResult("waitSubagent", [threadId, subagentId, requestBody]);
    },
    sendSubagentInput(threadId, subagentId, requestBody) {
      calls.push({ method: "sendSubagentInput", args: [threadId, subagentId, requestBody] });
      return apiResult("sendSubagentInput", [threadId, subagentId, requestBody]);
    },
    cancelSubagent(threadId, subagentId, requestBody) {
      calls.push({ method: "cancelSubagent", args: [threadId, subagentId, requestBody] });
      return apiResult("cancelSubagent", [threadId, subagentId, requestBody]);
    },
    resumeSubagent(threadId, subagentId, requestBody) {
      calls.push({ method: "resumeSubagent", args: [threadId, subagentId, requestBody] });
      return apiResult("resumeSubagent", [threadId, subagentId, requestBody]);
    },
    assignSubagent(threadId, subagentId, requestBody) {
      calls.push({ method: "assignSubagent", args: [threadId, subagentId, requestBody] });
      return apiResult("assignSubagent", [threadId, subagentId, requestBody]);
    },
    getSubagentResult(threadId, subagentId) {
      calls.push({ method: "getSubagentResult", args: [threadId, subagentId] });
      return apiResult("getSubagentResult", [threadId, subagentId]);
    },
    subagentSurface: retiredRouteWrapper,
    subagentApi: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "GET",
      path: "/v1/threads/thread_route/subagents?role=reviewer",
      segments: ["v1", "threads", "thread_route", "subagents"],
      apiMethod: "listSubagents",
      expectedArgs: ["thread_route", { role: "reviewer" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents",
      segments: ["v1", "threads", "thread_route", "subagents"],
      apiMethod: "spawnSubagent",
      expectedArgs: ["thread_route", body],
      expectedStatus: 201,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/cancel",
      segments: ["v1", "threads", "thread_route", "subagents", "cancel"],
      apiMethod: "propagateSubagentCancellation",
      expectedArgs: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/wait",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "wait"],
      apiMethod: "waitSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/input",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "input"],
      apiMethod: "sendSubagentInput",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/cancel",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "cancel"],
      apiMethod: "cancelSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/resume",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "resume"],
      apiMethod: "resumeSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/assign",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "assign"],
      apiMethod: "assignSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/subagents/subagent_1/result",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "result"],
      apiMethod: "getSubagentResult",
      expectedArgs: ["thread_route", "subagent_1"],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleThreadRoute({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body,
      }),
      response,
      store,
      url: new URL(testCase.path, "http://daemon.test"),
      segments: testCase.segments,
    });
    // spawn (POST) + list (GET) + result + tail (wait/input/resume/assign/cancel on /:id)
    // + propagate-cancel (/subagents/cancel) are all migrated to the Rust daemon (retired here).
    const s = testCase.segments;
    const retired =
      !s[4] ||
      (s[4] === "cancel" && !s[5]) ||
      ["result", "wait", "input", "resume", "assign", "cancel"].includes(s[5]);
    if (retired) {
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, testCase.expectedStatus ?? 200);
    assert.equal(call.method, testCase.apiMethod);
    assert.deepEqual(call.args, testCase.expectedArgs);
    assert.deepEqual(JSON.parse(response.body), {
      status: "blocked",
      method: testCase.apiMethod,
      args: testCase.expectedArgs,
    });
  }
});

test("model mounting native route does not expose retired estimate-load endpoint", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const store = {
    modelMounting: {
      authorize(...args) {
        calls.push(["authorize", ...args]);
      },
      loadModel(...args) {
        calls.push(["loadModel", ...args]);
        return { status: "legacy_estimate" };
      },
    },
  };

  await assert.rejects(
    () => handleModelMountingNativeRoute({
      request: request({
        method: "POST",
        url: "/api/v1/models/estimate-load",
        body: { model_id: "model://legacy-estimate" },
      }),
      response,
      store,
      url: new URL("/api/v1/models/estimate-load", "http://daemon.test"),
      segments: ["api", "v1", "models", "estimate-load"],
    }),
    (error) =>
      error.code === "not_found" &&
      error.details.path === "/api/v1/models/estimate-load",
  );

  assert.deepEqual(calls, []);
});

test("model mounting native route does not expose retired stable read aliases", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const failRetiredAlias = (name) => (...args) => {
    calls.push([name, ...args]);
    throw new Error(`retired stable read alias ${name} must not be reached`);
  };
  const store = {
    modelMounting: {
      catalogSearch: failRetiredAlias("catalogSearch"),
      listArtifacts: failRetiredAlias("listArtifacts"),
      listModelCapabilities: failRetiredAlias("listModelCapabilities"),
      listProviders: failRetiredAlias("listProviders"),
      listRoutes: failRetiredAlias("listRoutes"),
      getModel: failRetiredAlias("getModel"),
      projection: failRetiredAlias("projection"),
      snapshot: failRetiredAlias("snapshot"),
    },
  };
  const cases = [
    "/api/v1/models",
    "/api/v1/models/events",
    "/api/v1/model-capabilities",
    "/api/v1/models/catalog/search?query=qwen",
    "/api/v1/models/artifacts",
    "/api/v1/models/model.route",
    "/api/v1/models/routes",
    "/api/v1/providers",
    "/api/v1/routes",
    "/api/v1/projections/model-mounting",
  ];

  for (const path of cases) {
    await assert.rejects(
      () => handleModelMountingNativeRoute({
        request: request({ url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details.path === new URL(path, "http://daemon.test").pathname,
    );
  }

  assert.deepEqual(calls, []);
});

test("model mounting native route does not expose retired receipt read aliases", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const failRetiredAlias = (name) => (...args) => {
    calls.push([name, ...args]);
    throw new Error(`retired receipt alias ${name} must not be reached`);
  };
  const store = {
    modelMounting: {
      listReceipts: failRetiredAlias("listReceipts"),
      getReceipt: failRetiredAlias("getReceipt"),
      receiptReplay: failRetiredAlias("receiptReplay"),
    },
  };
  const cases = [
    "/api/v1/receipts",
    "/api/v1/receipts/receipt.route",
    "/api/v1/receipts/receipt.route/replay",
  ];

  for (const path of cases) {
    await assert.rejects(
      () => handleModelMountingNativeRoute({
        request: request({ url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details.path === new URL(path, "http://daemon.test").pathname,
    );
  }

  assert.deepEqual(calls, []);
});

test("model mounting native route does not expose retired operational read, server-control, backend-control, runtime-control, route-control, lifecycle-control, or storage-control aliases", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const failRetiredAlias = (name) => (...args) => {
    calls.push([name, ...args]);
    throw new Error(`retired operational alias ${name} must not be reached`);
  };
  const store = {
    modelMounting: {
      authoritySnapshot: failRetiredAlias("authoritySnapshot"),
      backendHealth: failRetiredAlias("backendHealth"),
      backendLogs: failRetiredAlias("backendLogs"),
      cancelDownload: failRetiredAlias("cancelDownload"),
      catalogImportUrl: failRetiredAlias("catalogImportUrl"),
      cleanupModelStorage: failRetiredAlias("cleanupModelStorage"),
      deleteModelArtifact: failRetiredAlias("deleteModelArtifact"),
      downloadModel: failRetiredAlias("downloadModel"),
      downloadStatus: failRetiredAlias("downloadStatus"),
      importModel: failRetiredAlias("importModel"),
      listBackends: failRetiredAlias("listBackends"),
      listInstances: failRetiredAlias("listInstances"),
      listRuntimeEngines: failRetiredAlias("listRuntimeEngines"),
      loadModel: failRetiredAlias("loadModel"),
      mountEndpoint: failRetiredAlias("mountEndpoint"),
      removeRuntimeEngineOverride: failRetiredAlias("removeRuntimeEngineOverride"),
      runtimeEngine: failRetiredAlias("runtimeEngine"),
      runtimeSurvey: failRetiredAlias("runtimeSurvey"),
      selectRuntimeEngine: failRetiredAlias("selectRuntimeEngine"),
      serverEvents: failRetiredAlias("serverEvents"),
      serverLogs: failRetiredAlias("serverLogs"),
      serverRestart: failRetiredAlias("serverRestart"),
      serverStart: failRetiredAlias("serverStart"),
      serverStatus: failRetiredAlias("serverStatus"),
      serverStop: failRetiredAlias("serverStop"),
      startBackend: failRetiredAlias("startBackend"),
      stopBackend: failRetiredAlias("stopBackend"),
      testRoute: failRetiredAlias("testRoute"),
      unloadModel: failRetiredAlias("unloadModel"),
      unmountEndpoint: failRetiredAlias("unmountEndpoint"),
      updateRuntimeEngine: failRetiredAlias("updateRuntimeEngine"),
      upsertRoute: failRetiredAlias("upsertRoute"),
      executeWorkflowNode: failRetiredAlias("executeWorkflowNode"),
      validateReceiptGate: failRetiredAlias("validateReceiptGate"),
    },
  };
  const cases = [
    "/api/v1/server/status",
    "/api/v1/server/logs",
    "/api/v1/server/events",
    ["POST", "/api/v1/server/start"],
    ["POST", "/api/v1/server/stop"],
    ["POST", "/api/v1/server/restart"],
    "/api/v1/models/server",
    ["POST", "/api/v1/models/server/start"],
    ["POST", "/api/v1/models/server/stop"],
    "/api/v1/backends",
    ["POST", "/api/v1/backends/backend.route/health"],
    ["POST", "/api/v1/backends/backend.route/start"],
    ["POST", "/api/v1/backends/backend.route/stop"],
    "/api/v1/backends/backend.route/logs",
    "/api/v1/models/backends",
    "/api/v1/runtime/engines",
    "/api/v1/runtime/engines/engine.route",
    ["POST", "/api/v1/runtime/engines/engine.route/select"],
    ["PATCH", "/api/v1/runtime/engines/engine.route"],
    ["DELETE", "/api/v1/runtime/engines/engine.route"],
    ["POST", "/api/v1/runtime/survey"],
    ["POST", "/api/v1/runtime/select"],
    ["POST", "/api/v1/routes"],
    ["POST", "/api/v1/routes/route.route/test"],
    ["POST", "/api/v1/workflows/nodes/execute"],
    ["POST", "/api/v1/workflows/receipt-gate"],
    ["POST", "/api/v1/models/import"],
    ["POST", "/api/v1/models/mount"],
    ["POST", "/api/v1/models/unmount"],
    ["POST", "/api/v1/models/load"],
    ["POST", "/api/v1/models/unload"],
    ["POST", "/api/v1/models/mounts"],
    ["POST", "/api/v1/models/mounts/endpoint.route/load"],
    ["POST", "/api/v1/models/mounts/endpoint.route/unload"],
    ["DELETE", "/api/v1/models/mounts/endpoint.route"],
    ["POST", "/api/v1/models/instances/instance.route/unload"],
    ["POST", "/api/v1/models/catalog/import-url"],
    ["POST", "/api/v1/models/download"],
    "/api/v1/models/download/status/download.route",
    ["POST", "/api/v1/models/download/download.route/cancel"],
    ["POST", "/api/v1/models/download/cancel/download.route"],
    ["POST", "/api/v1/models/storage/cleanup"],
    ["DELETE", "/api/v1/models/artifact.route"],
    "/api/v1/models/runtime-engines",
    "/api/v1/models/instances",
    "/api/v1/models/loaded",
    "/api/v1/authority",
  ];

  for (const entry of cases) {
    const [method, path] = Array.isArray(entry) ? entry : ["GET", entry];
    await assert.rejects(
      () => handleModelMountingNativeRoute({
        request: request({ method, url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details.path === new URL(path, "http://daemon.test").pathname,
    );
  }

  assert.deepEqual(calls, []);
});

test("model mounting native route does not expose retired provider vault token or catalog control aliases", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const failRetiredAlias = (name) => (...args) => {
    calls.push([name, ...args]);
    throw new Error(`retired provider/vault/token alias ${name} must not be reached`);
  };
  const store = {
    modelMounting: {
      bindVaultRef: failRetiredAlias("bindVaultRef"),
      completeCatalogProviderOAuth: failRetiredAlias("completeCatalogProviderOAuth"),
      configureCatalogProvider: failRetiredAlias("configureCatalogProvider"),
      countModelTokens: failRetiredAlias("countModelTokens"),
      createToken: failRetiredAlias("createToken"),
      exchangeCatalogProviderOAuth: failRetiredAlias("exchangeCatalogProviderOAuth"),
      getCatalogProviderConfig: failRetiredAlias("getCatalogProviderConfig"),
      latestProviderHealth: failRetiredAlias("latestProviderHealth"),
      latestVaultHealth: failRetiredAlias("latestVaultHealth"),
      listProviderLoaded: failRetiredAlias("listProviderLoaded"),
      listProviderModels: failRetiredAlias("listProviderModels"),
      listTokens: failRetiredAlias("listTokens"),
      listVaultRefs: failRetiredAlias("listVaultRefs"),
      providerHealth: failRetiredAlias("providerHealth"),
      refreshCatalogProviderOAuth: failRetiredAlias("refreshCatalogProviderOAuth"),
      removeVaultRef: failRetiredAlias("removeVaultRef"),
      revokeCatalogProviderOAuth: failRetiredAlias("revokeCatalogProviderOAuth"),
      revokeToken: failRetiredAlias("revokeToken"),
      startCatalogProviderOAuth: failRetiredAlias("startCatalogProviderOAuth"),
      startProvider: failRetiredAlias("startProvider"),
      stopProvider: failRetiredAlias("stopProvider"),
      upsertProvider: failRetiredAlias("upsertProvider"),
      vaultHealth: failRetiredAlias("vaultHealth"),
      vaultRefMetadata: failRetiredAlias("vaultRefMetadata"),
      vaultStatus: failRetiredAlias("vaultStatus"),
    },
  };
  const cases = [
    "/api/v1/models/catalog/providers/catalog.route",
    ["PATCH", "/api/v1/models/catalog/providers/catalog.route"],
    ["POST", "/api/v1/models/catalog/providers/catalog.route/oauth/start"],
    ["POST", "/api/v1/models/catalog/providers/catalog.route/oauth/callback"],
    ["POST", "/api/v1/models/catalog/providers/catalog.route/oauth/exchange"],
    ["POST", "/api/v1/models/catalog/providers/catalog.route/oauth/refresh"],
    ["POST", "/api/v1/models/catalog/providers/catalog.route/oauth/revoke"],
    "/api/v1/vault/refs",
    ["POST", "/api/v1/vault/refs"],
    ["DELETE", "/api/v1/vault/refs"],
    ["POST", "/api/v1/vault/refs/meta"],
    "/api/v1/vault/status",
    ["POST", "/api/v1/vault/health"],
    "/api/v1/vault/health/latest",
    "/api/v1/providers",
    ["POST", "/api/v1/providers"],
    ["PATCH", "/api/v1/providers/provider.route"],
    "/api/v1/providers/provider.route/health/latest",
    ["POST", "/api/v1/providers/provider.route/health"],
    "/api/v1/providers/provider.route/models",
    "/api/v1/providers/provider.route/loaded",
    ["POST", "/api/v1/providers/provider.route/start"],
    ["POST", "/api/v1/providers/provider.route/stop"],
    "/api/v1/tokens",
    ["POST", "/api/v1/tokens"],
    ["DELETE", "/api/v1/tokens/token.route"],
    ["POST", "/api/v1/tokens/count"],
  ];

  for (const entry of cases) {
    const [method, path] = Array.isArray(entry) ? entry : ["GET", entry];
    await assert.rejects(
      () => handleModelMountingNativeRoute({
        request: request({ method, url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: new URL(path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "not_found" &&
        error.details.path === new URL(path, "http://daemon.test").pathname,
    );
  }

  assert.deepEqual(calls, []);
});

test("model mounting native route does not expose retired MCP aliases", async () => {
  const { handleModelMountingNativeRoute } = routeHandlers();
  const calls = [];
  const failRetiredAlias = (name) => (...args) => {
    calls.push([name, ...args]);
    throw new Error(`retired MCP alias ${name} must not be reached`);
  };
  const store = {
    modelMounting: {
      authorize: failRetiredAlias("authorize"),
      listMcpServers: failRetiredAlias("listMcpServers"),
      importMcpJson: failRetiredAlias("importMcpJson"),
      invokeMcpTool: failRetiredAlias("invokeMcpTool"),
    },
  };
  const cases = [
    { method: "GET", path: "/api/v1/mcp" },
    { method: "POST", path: "/api/v1/mcp/import" },
    { method: "POST", path: "/api/v1/mcp/invoke" },
  ];

  for (const testCase of cases) {
    await assert.rejects(
      () => handleModelMountingNativeRoute({
        request: request({
          method: testCase.method,
          url: testCase.path,
          body: { request_id: "retired-mcp-alias" },
        }),
        response: responseRecorder(),
        store,
        url: new URL(testCase.path, "http://daemon.test"),
        segments: new URL(testCase.path, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) => error.code === "not_found" && error.details.path === testCase.path,
    );
  }

  assert.deepEqual(calls, []);
});

test("thread route does not expose governed improvement apply shortcut", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();

  await assert.rejects(
    () => handleThreadRoute({
      request: request({
        method: "POST",
        url: "/v1/threads/thread_route/governed-improvement-proposals/proposal_1/apply",
      }),
      response,
      store: {},
      url: new URL(
        "/v1/threads/thread_route/governed-improvement-proposals/proposal_1/apply",
        "http://daemon.test",
      ),
      segments: [
        "v1",
        "threads",
        "thread_route",
        "governed-improvement-proposals",
        "proposal_1",
        "apply",
      ],
    }),
    (error) =>
      error.code === "not_found" &&
      error.details.action === "governed-improvement-proposals",
  );
});

test("thread route does not expose L1 settlement apply shortcut", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();

  await assert.rejects(
    () => handleThreadRoute({
      request: request({
        method: "POST",
        url: "/v1/threads/thread_route/l1-settlement-attempts/settlement_1/apply",
      }),
      response,
      store: {},
      url: new URL(
        "/v1/threads/thread_route/l1-settlement-attempts/settlement_1/apply",
        "http://daemon.test",
      ),
      segments: [
        "v1",
        "threads",
        "thread_route",
        "l1-settlement-attempts",
        "settlement_1",
        "apply",
      ],
    }),
    (error) =>
      error.code === "not_found" &&
      error.details.action === "l1-settlement-attempts",
  );
});

test("thread route does not expose cTEE private workspace apply shortcut", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();

  await assert.rejects(
    () => handleThreadRoute({
      request: request({
        method: "POST",
        url: "/v1/threads/thread_route/ctee-private-workspace-actions/invocation_1/apply",
      }),
      response,
      store: {},
      url: new URL(
        "/v1/threads/thread_route/ctee-private-workspace-actions/invocation_1/apply",
        "http://daemon.test",
      ),
      segments: [
        "v1",
        "threads",
        "thread_route",
        "ctee-private-workspace-actions",
        "invocation_1",
        "apply",
      ],
    }),
    (error) =>
      error.code === "not_found" &&
      error.details.action === "ctee-private-workspace-actions",
  );
});

test("thread route does not expose worker/service package apply shortcut", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();

  await assert.rejects(
    () => handleThreadRoute({
      request: request({
        method: "POST",
        url: "/v1/threads/thread_route/worker-service-package-invocations/invocation_1/apply",
      }),
      response,
      store: {},
      url: new URL(
        "/v1/threads/thread_route/worker-service-package-invocations/invocation_1/apply",
        "http://daemon.test",
      ),
      segments: [
        "v1",
        "threads",
        "thread_route",
        "worker-service-package-invocations",
        "invocation_1",
        "apply",
      ],
    }),
    (error) =>
      error.code === "not_found" &&
      error.details.action === "worker-service-package-invocations",
  );
});
