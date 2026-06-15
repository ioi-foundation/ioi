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

function routeHandlers() {
  return createRuntimeRouteHandlers({
    baseUrlForRequest: () => "http://daemon.test",
    nativeEmbeddingResponse: () => ({}),
    nativeInvocationResponse: () => ({}),
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
    lifecycleProjectionSurface: {
      authorityEvidenceSummary(surfaceStore, options) {
        calls.push({ surfaceStore, options });
        return {
          schema_version: "authority.evidence.summary.v1",
          filters: options,
        };
      },
    },
    runReadSurface: {
      authorityEvidenceSummary: retiredRouteWrapper,
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

test("agent, thread, and run detail routes return lifecycle projection surface output", async () => {
  const { handleAgentRoute, handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const lifecycleProjectionSurface = {
    getAgent(_store, agentId) {
      calls.push({ method: "getAgent", id: agentId });
      return { projection: "agent", agentId };
    },
    getThread(_store, threadId) {
      calls.push({ method: "getThread", id: threadId });
      return { projection: "thread", threadId };
    },
    getThreadUsage(_store, threadId) {
      calls.push({ method: "getThreadUsage", id: threadId });
      return { projection: "thread_usage", threadId };
    },
    listThreadTurns(_store, threadId) {
      calls.push({ method: "listThreadTurns", id: threadId });
      return [{ projection: "thread_turns", threadId }];
    },
    getThreadTurn(_store, threadId, turnId) {
      calls.push({ method: "getThreadTurn", id: threadId, turnId });
      return { projection: "thread_turn", threadId, turnId };
    },
    listThreadEvents(_store, threadId) {
      calls.push({ method: "listThreadEvents", id: threadId });
      return [{ projection: "thread_events", threadId }];
    },
    getRun(_store, runId) {
      calls.push({ method: "getRun", id: runId });
      return { projection: "run", runId };
    },
    waitRun(_store, runId) {
      calls.push({ method: "waitRun", id: runId });
      return { projection: "run_wait", runId };
    },
    getRunConversation(_store, runId) {
      calls.push({ method: "getRunConversation", id: runId });
      return [{ projection: "run_conversation", runId }];
    },
    getRunUsage(_store, runId) {
      calls.push({ method: "getRunUsage", id: runId });
      return { projection: "run_usage", runId };
    },
    listRunEvents(_store, runId) {
      calls.push({ method: "listRunEvents", id: runId });
      return [{ projection: "run_events", runId }];
    },
    replayRun(_store, runId) {
      calls.push({ method: "replayRun", id: runId });
      return [{ projection: "run_replay", runId }];
    },
    getRunTrace(_store, runId) {
      calls.push({ method: "getRunTrace", id: runId });
      return { projection: "run_trace", runId };
    },
    getRunComputerUseTrace(_store, runId) {
      calls.push({ method: "getRunComputerUseTrace", id: runId });
      return { projection: "run_computer_use_trace", runId };
    },
    getRunComputerUseTrajectory(_store, runId) {
      calls.push({ method: "getRunComputerUseTrajectory", id: runId });
      return [{ projection: "run_computer_use_trajectory", runId }];
    },
    getRunScorecard(_store, runId) {
      calls.push({ method: "getRunScorecard", id: runId });
      return { projection: "run_scorecard", runId };
    },
    listRunArtifacts(_store, runId) {
      calls.push({ method: "listRunArtifacts", id: runId });
      return [{ projection: "run_artifacts", runId }];
    },
    getRunArtifact(_store, runId, artifactRef) {
      calls.push({ method: "getRunArtifact", id: runId, artifactRef });
      return { projection: "run_artifact", runId, artifactRef };
    },
    listRuns(_store, agentId) {
      calls.push({ method: "listRuns", id: agentId });
      return [{ projection: "agent_runs", agentId }];
    },
  };
  const store = {
    lifecycleProjectionSurface,
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
    },
  ];
  for (const path of [
    "/v1/threads/thread_route/usage",
    "/v1/threads/thread_route/turns",
    "/v1/threads/thread_route/turns/turn_1",
    "/v1/threads/thread_route/events",
    "/v1/threads/thread_route/events/stream",
  ]) {
    routeRequests.push({
      handler: handleThreadRoute,
      request: request({ url: path }),
      response: responseRecorder(),
      store,
      url: new URL(path, "http://daemon.test"),
      segments: path.split("/").filter(Boolean),
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
  for (const path of [
    "/v1/runs/run_route/usage",
    "/v1/runs/run_route/wait",
    "/v1/runs/run_route/conversation",
    "/v1/runs/run_route/events",
    "/v1/runs/run_route/replay",
    "/v1/runs/run_route/trace",
    "/v1/runs/run_route/inspect",
    "/v1/runs/run_route/computer-use/trace",
    "/v1/runs/run_route/computer-use/trajectory",
    "/v1/runs/run_route/scorecard",
    "/v1/runs/run_route/artifacts",
    "/v1/runs/run_route/artifacts/artifact_1",
  ]) {
    routeRequests.push({
      handler: handleRunRoute,
      request: request({ url: path }),
      response: responseRecorder(),
      store,
      url: new URL(path, "http://daemon.test"),
      segments: path.split("/").filter(Boolean),
    });
  }

  for (const routeRequest of routeRequests) {
    await routeRequest.handler(routeRequest);
    assert.equal(routeRequest.response.statusCode, 200);
  }

  assert.deepEqual(calls, [
    { method: "getAgent", id: "agent_route" },
    { method: "listRuns", id: "agent_route" },
    { method: "getThread", id: "thread_route" },
    { method: "getThreadUsage", id: "thread_route" },
    { method: "listThreadTurns", id: "thread_route" },
    { method: "getThreadTurn", id: "thread_route", turnId: "turn_1" },
    { method: "listThreadEvents", id: "thread_route" },
    { method: "listThreadEvents", id: "thread_route" },
    { method: "getRun", id: "run_route" },
    { method: "getRunUsage", id: "run_route" },
    { method: "waitRun", id: "run_route" },
    { method: "getRunConversation", id: "run_route" },
    { method: "listRunEvents", id: "run_route" },
    { method: "replayRun", id: "run_route" },
    { method: "getRunTrace", id: "run_route" },
    { method: "getRunTrace", id: "run_route" },
    { method: "getRunComputerUseTrace", id: "run_route" },
    { method: "getRunComputerUseTrajectory", id: "run_route" },
    { method: "getRunScorecard", id: "run_route" },
    { method: "listRunArtifacts", id: "run_route" },
    { method: "getRunArtifact", id: "run_route", artifactRef: "artifact_1" },
  ]);
});

test("agent lifecycle mutation routes use mounted agent lifecycle surface", async () => {
  const { handleAgentRoute } = routeHandlers();
  const calls = [];
  const rustCoreRequired = (code, details = {}) => {
    const error = new Error("agent lifecycle requires Rust core");
    error.status = 501;
    error.code = code;
    error.details = details;
    throw error;
  };
  const store = {
    agentRunLifecycleSurface: {
      updateAgent(surfaceStore, agentId, status, operationKind) {
        calls.push({ method: "updateAgent", surfaceStore, agentId, status, operationKind });
        rustCoreRequired("runtime_agent_status_control_rust_core_required", {
          agent_id: agentId,
          requested_status: status,
          requested_operation_kind: operationKind,
        });
      },
      deleteAgent(surfaceStore, agentId) {
        calls.push({ method: "deleteAgent", surfaceStore, agentId });
        rustCoreRequired("runtime_agent_delete_rust_core_required", { agent_id: agentId });
      },
      createRun(surfaceStore, agentId, input) {
        calls.push({ method: "createRun", surfaceStore, agentId, input });
        rustCoreRequired("runtime_run_create_rust_core_required", { agent_id: agentId });
      },
    },
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
    request({ method: "POST", url: "/v1/agents/agent_route/runs", body: { prompt: "ship it" } }),
  ];

  for (const req of requests) {
    await assert.rejects(
      () => handleAgentRoute({
        request: req,
        response: responseRecorder(),
        store,
        url: new URL(req.url, "http://daemon.test"),
        segments: new URL(req.url, "http://daemon.test").pathname.split("/").filter(Boolean),
      }),
      (error) =>
        error.code === "runtime_agent_status_control_rust_core_required" ||
        error.code === "runtime_agent_delete_rust_core_required" ||
        error.code === "runtime_run_create_rust_core_required",
    );
  }

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
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
      { method: "createRun", agentId: "agent_route", status: undefined, operationKind: undefined, input: { prompt: "ship it" } },
    ],
  );
});

test("agent and thread memory read routes use mounted thread memory surface", async () => {
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
    publicMemoryPolicyForAgent(surfaceStore, agentId, options) {
      calls.push({ method: "publicMemoryPolicyForAgent", surfaceStore, agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_policy_projection", agent_id: agentId });
    },
    publicMemoryPathForAgent(surfaceStore, agentId, options) {
      calls.push({ method: "publicMemoryPathForAgent", surfaceStore, agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_path_projection", agent_id: agentId });
    },
    publicListMemoryForAgent(surfaceStore, agentId, options) {
      calls.push({ method: "publicListMemoryForAgent", surfaceStore, agentId, options });
      rustCoreRequired({ requested_control_kind: "memory_read_projection", agent_id: agentId });
    },
    publicMemoryPolicyForThread(surfaceStore, threadId, options) {
      calls.push({ method: "publicMemoryPolicyForThread", surfaceStore, threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_policy_projection", thread_id: threadId });
    },
    publicMemoryPathForThread(surfaceStore, threadId, options) {
      calls.push({ method: "publicMemoryPathForThread", surfaceStore, threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_path_projection", thread_id: threadId });
    },
    publicListMemoryForThread(surfaceStore, threadId, options) {
      calls.push({ method: "publicListMemoryForThread", surfaceStore, threadId, options });
      rustCoreRequired({ requested_control_kind: "memory_read_projection", thread_id: threadId });
    },
  };
  const store = {
    threadMemorySurface,
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

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
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

test("agent and thread memory mutation routes use mounted thread memory surface", async () => {
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
    setMemoryPolicyForAgent(surfaceStore, agentId, input) {
      calls.push({ method: "setMemoryPolicyForAgent", surfaceStore, agentId, input });
      rustCoreRequired({ requested_control_kind: "memory_policy", agent_id: agentId });
    },
    updateMemoryForAgentId(surfaceStore, agentId, memoryId, input) {
      calls.push({ method: "updateMemoryForAgentId", surfaceStore, agentId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_edit", agent_id: agentId, memory_id: memoryId });
    },
    deleteMemoryForAgentId(surfaceStore, agentId, memoryId, input) {
      calls.push({ method: "deleteMemoryForAgentId", surfaceStore, agentId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_delete", agent_id: agentId, memory_id: memoryId });
    },
    rememberForAgentId(surfaceStore, agentId, input) {
      calls.push({ method: "rememberForAgentId", surfaceStore, agentId, input });
      rustCoreRequired({ requested_control_kind: "memory_write", agent_id: agentId });
    },
    recordThreadMemoryStatus(surfaceStore, threadId, input) {
      calls.push({ method: "recordThreadMemoryStatus", surfaceStore, threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_status", thread_id: threadId });
    },
    validateThreadMemory(surfaceStore, threadId, input) {
      calls.push({ method: "validateThreadMemory", surfaceStore, threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_validate", thread_id: threadId });
    },
    setMemoryPolicyForThread(surfaceStore, threadId, input) {
      calls.push({ method: "setMemoryPolicyForThread", surfaceStore, threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_policy", thread_id: threadId });
    },
    updateMemoryForThread(surfaceStore, threadId, memoryId, input) {
      calls.push({ method: "updateMemoryForThread", surfaceStore, threadId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_edit", thread_id: threadId, memory_id: memoryId });
    },
    deleteMemoryForThread(surfaceStore, threadId, memoryId, input) {
      calls.push({ method: "deleteMemoryForThread", surfaceStore, threadId, memoryId, input });
      rustCoreRequired({ requested_control_kind: "memory_delete", thread_id: threadId, memory_id: memoryId });
    },
    rememberForThread(surfaceStore, threadId, input) {
      calls.push({ method: "rememberForThread", surfaceStore, threadId, input });
      rustCoreRequired({ requested_control_kind: "memory_write", thread_id: threadId });
    },
  };
  const store = {
    threadMemorySurface,
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

  const threadRoutes = [
    { method: "POST", path: "/v1/threads/thread_route/memory/status", body: { source: "status" } },
    { method: "POST", path: "/v1/threads/thread_route/memory/validate", body: { source: "validate" } },
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

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
  assert.deepEqual(
    calls.map(({ method, agentId, threadId, memoryId, input }) => ({ method, agentId, threadId, memoryId, input })),
    [
      { method: "setMemoryPolicyForAgent", agentId: "agent_route", threadId: undefined, memoryId: undefined, input: { read_only: true } },
      { method: "updateMemoryForAgentId", agentId: "agent_route", threadId: undefined, memoryId: "memory_1", input: { text: "edited" } },
      { method: "deleteMemoryForAgentId", agentId: "agent_route", threadId: undefined, memoryId: "memory_1", input: { reason: "stale" } },
      { method: "rememberForAgentId", agentId: "agent_route", threadId: undefined, memoryId: undefined, input: { text: "remember" } },
      { method: "recordThreadMemoryStatus", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { source: "status" } },
      { method: "validateThreadMemory", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { source: "validate" } },
      { method: "setMemoryPolicyForThread", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { read_only: false } },
      { method: "updateMemoryForThread", agentId: undefined, threadId: "thread_route", memoryId: "memory_1", input: { text: "edited" } },
      { method: "deleteMemoryForThread", agentId: undefined, threadId: "thread_route", memoryId: "memory_1", input: { reason: "stale" } },
      { method: "rememberForThread", agentId: undefined, threadId: "thread_route", memoryId: undefined, input: { text: "remember" } },
    ],
  );
});

test("thread conversation artifact routes use mounted artifact surface", async () => {
  const { handleThreadRoute } = routeHandlers();
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
    },
    listConversationArtifacts: retiredRouteWrapper,
    createConversationArtifact: retiredRouteWrapper,
  };

  const listResponse = responseRecorder();
  await handleThreadRoute({
    request: request({ url: "/v1/threads/thread_route/artifacts" }),
    response: listResponse,
    store,
    url: new URL("/v1/threads/thread_route/artifacts", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "artifacts"],
  });
  assert.equal(listResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(listResponse.body), [
    { id: "artifact_route", thread_id: "thread_route" },
  ]);
  const createResponse = responseRecorder();
  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/artifacts",
      body: { title: "Draft" },
    }),
    response: createResponse,
    store,
    url: new URL("/v1/threads/thread_route/artifacts", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "artifacts"],
  });
  assert.equal(createResponse.statusCode, 201);
  assert.deepEqual(JSON.parse(createResponse.body), {
    artifact_id: "artifact_created",
    thread_id: "thread_route",
    input: { title: "Draft" },
    commit_hash: "commit-created",
  });

  assert.equal(calls.every((call) => call.surfaceStore === store), true);
  assert.deepEqual(
    calls.map(({ method, query, threadId, input }) => ({ method, query, threadId, input })),
    [
      {
        method: "listConversationArtifacts",
        query: { thread_id: "thread_route" },
        threadId: undefined,
        input: undefined,
      },
      {
        method: "createConversationArtifact",
        query: undefined,
        threadId: "thread_route",
        input: { title: "Draft" },
      },
    ],
  );
});

test("thread route sends admission controls through mounted admission surfaces", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "route-admission-test" };
  const surfaceResult = (surface, args) => ({
    status: "admitted",
    surface,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    governedImprovementSurface: {
      admitGovernedImprovementProposal(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "governedImprovementSurface", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("governedImprovementSurface", [threadId, requestBody]);
      },
    },
    externalCapabilityAuthoritySurface: {
      authorizeExternalCapabilityExit(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "externalCapabilityAuthoritySurface", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("externalCapabilityAuthoritySurface", [threadId, requestBody]);
      },
    },
    workerServicePackageSurface: {
      admitWorkerServicePackageInvocation(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "workerServicePackageSurface", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("workerServicePackageSurface", [threadId, requestBody]);
      },
    },
    cteePrivateWorkspaceSurface: {
      executeCteePrivateWorkspaceAction(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "cteePrivateWorkspaceSurface", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("cteePrivateWorkspaceSurface", [threadId, requestBody]);
      },
    },
    l1SettlementSurface: {
      admitL1SettlementAttempt(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "l1SettlementSurface", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("l1SettlementSurface", [threadId, requestBody]);
      },
    },
    admitGovernedImprovementProposal: retiredRouteWrapper,
    authorizeExternalCapabilityExit: retiredRouteWrapper,
    admitWorkerServicePackageInvocation: retiredRouteWrapper,
    executeCteePrivateWorkspaceAction: retiredRouteWrapper,
    admitL1SettlementAttempt: retiredRouteWrapper,
  };
  const cases = [
    {
      path: "/v1/threads/thread_route/governed-improvement-proposals",
      segments: ["v1", "threads", "thread_route", "governed-improvement-proposals"],
      surface: "governedImprovementSurface",
    },
    {
      path: "/v1/threads/thread_route/external-capability-exits",
      segments: ["v1", "threads", "thread_route", "external-capability-exits"],
      surface: "externalCapabilityAuthoritySurface",
    },
    {
      path: "/v1/threads/thread_route/worker-service-package-invocations",
      segments: ["v1", "threads", "thread_route", "worker-service-package-invocations"],
      surface: "workerServicePackageSurface",
    },
    {
      path: "/v1/threads/thread_route/ctee-private-workspace-actions",
      segments: ["v1", "threads", "thread_route", "ctee-private-workspace-actions"],
      surface: "cteePrivateWorkspaceSurface",
    },
    {
      path: "/v1/threads/thread_route/l1-settlement-attempts",
      segments: ["v1", "threads", "thread_route", "l1-settlement-attempts"],
      surface: "l1SettlementSurface",
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
    assert.equal(call.surface, testCase.surface);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, ["thread_route", body]);
    assert.deepEqual(JSON.parse(response.body), {
      status: "admitted",
      surface: testCase.surface,
      args: ["thread_route", body],
      direct_truth_write_allowed: false,
    });
  }
});

test("thread route sends workflow, diagnostics, and snapshot controls through mounted surfaces", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "route-control-test" };
  const surfaceResult = (surface, args) => ({
    status: "rust_core_required",
    surface,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    workflowEditSurface: {
      proposeWorkflowEdit(surfaceStore, threadId, requestBody) {
        calls.push({
          surface: "workflowEditSurface",
          surfaceStore,
          args: [threadId, requestBody],
        });
        return surfaceResult("workflowEditSurface", [threadId, requestBody]);
      },
      applyWorkflowEditProposal(surfaceStore, threadId, proposalId, requestBody) {
        calls.push({
          surface: "workflowEditSurface",
          surfaceStore,
          args: [threadId, proposalId, requestBody],
        });
        return surfaceResult("workflowEditSurface", [threadId, proposalId, requestBody]);
      },
    },
    diagnosticsRepairSurface: {
      executeDiagnosticsRepairDecision(surfaceStore, threadId, decisionRef, requestBody) {
        calls.push({
          surface: "diagnosticsRepairSurface",
          surfaceStore,
          args: [threadId, decisionRef, requestBody],
        });
        return surfaceResult("diagnosticsRepairSurface", [threadId, decisionRef, requestBody]);
      },
    },
    workspaceSnapshotSurface: {
      listWorkspaceSnapshots(surfaceStore, threadId) {
        calls.push({
          surface: "workspaceSnapshotSurface",
          surfaceStore,
          args: [threadId],
        });
        return surfaceResult("workspaceSnapshotSurface", [threadId]);
      },
      previewWorkspaceSnapshotRestore(surfaceStore, threadId, snapshotId, requestBody) {
        calls.push({
          surface: "workspaceSnapshotSurface",
          surfaceStore,
          args: [threadId, snapshotId, requestBody],
        });
        return surfaceResult("workspaceSnapshotSurface", [threadId, snapshotId, requestBody]);
      },
      applyWorkspaceSnapshotRestore(surfaceStore, threadId, snapshotId, requestBody) {
        calls.push({
          surface: "workspaceSnapshotSurface",
          surfaceStore,
          args: [threadId, snapshotId, requestBody],
        });
        return surfaceResult("workspaceSnapshotSurface", [threadId, snapshotId, requestBody]);
      },
    },
    applyWorkflowEditProposal: retiredRouteWrapper,
    proposeWorkflowEdit: retiredRouteWrapper,
    executeDiagnosticsRepairDecision: retiredRouteWrapper,
    listWorkspaceSnapshots: retiredRouteWrapper,
    previewWorkspaceSnapshotRestore: retiredRouteWrapper,
    applyWorkspaceSnapshotRestore: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/threads/thread_route/workflow-edit-proposals",
      segments: ["v1", "threads", "thread_route", "workflow-edit-proposals"],
      surface: "workflowEditSurface",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/workflow-edit-proposals/proposal_route/apply",
      segments: ["v1", "threads", "thread_route", "workflow-edit-proposals", "proposal_route", "apply"],
      surface: "workflowEditSurface",
      args: ["thread_route", "proposal_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/diagnostics/repair-decisions/decision_route/execute",
      segments: ["v1", "threads", "thread_route", "diagnostics", "repair-decisions", "decision_route", "execute"],
      surface: "diagnosticsRepairSurface",
      args: ["thread_route", "decision_route", body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/snapshots",
      segments: ["v1", "threads", "thread_route", "snapshots"],
      surface: "workspaceSnapshotSurface",
      args: ["thread_route"],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/snapshots/snapshot_route/restore-preview",
      segments: ["v1", "threads", "thread_route", "snapshots", "snapshot_route", "restore-preview"],
      surface: "workspaceSnapshotSurface",
      args: ["thread_route", "snapshot_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/snapshots/snapshot_route/restore-apply",
      segments: ["v1", "threads", "thread_route", "snapshots", "snapshot_route", "restore-apply"],
      surface: "workspaceSnapshotSurface",
      args: ["thread_route", "snapshot_route", body],
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
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.surface, testCase.surface);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      surface: testCase.surface,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread route sends approvals through mounted approval surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "approval-route-test" };
  const surfaceResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    approvalSurface: {
      listThreadApprovals(surfaceStore, threadId, requestQuery) {
        calls.push({ operation: "listThreadApprovals", surfaceStore, args: [threadId, requestQuery] });
        return surfaceResult("listThreadApprovals", [threadId, requestQuery]);
      },
      requestThreadApproval(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "requestThreadApproval", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("requestThreadApproval", [threadId, requestBody]);
      },
      decideThreadApproval(surfaceStore, threadId, approvalId, requestBody) {
        calls.push({
          operation: "decideThreadApproval",
          surfaceStore,
          args: [threadId, approvalId, requestBody],
        });
        return surfaceResult("decideThreadApproval", [threadId, approvalId, requestBody]);
      },
      revokeThreadApproval(surfaceStore, threadId, approvalId, requestBody) {
        calls.push({
          operation: "revokeThreadApproval",
          surfaceStore,
          args: [threadId, approvalId, requestBody],
        });
        return surfaceResult("revokeThreadApproval", [threadId, approvalId, requestBody]);
      },
    },
    requestThreadApproval: retiredRouteWrapper,
    listThreadApprovals: retiredRouteWrapper,
    decideThreadApproval: retiredRouteWrapper,
    revokeThreadApproval: retiredRouteWrapper,
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
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/decision",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "decision"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/approve",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "approve"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "approve" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/reject",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "reject"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "reject" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/approvals/approval_route/revoke",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "revoke"],
      operation: "revokeThreadApproval",
      args: ["thread_route", "approval_route", body],
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
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread and run routes send context policy controls through mounted context policy surface", async () => {
  const { handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "context-policy-route-test" };
  const surfaceResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    contextPolicySurface: {
      evaluateContextBudget(surfaceStore, input) {
        calls.push({ operation: "evaluateContextBudget", surfaceStore, args: [input] });
        return surfaceResult("evaluateContextBudget", [input]);
      },
      evaluateCompactionPolicy(surfaceStore, input) {
        calls.push({ operation: "evaluateCompactionPolicy", surfaceStore, args: [input] });
        return surfaceResult("evaluateCompactionPolicy", [input]);
      },
      compactThread(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "compactThread", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("compactThread", [threadId, requestBody]);
      },
    },
    evaluateContextBudget: retiredRouteWrapper,
    evaluateCompactionPolicy: retiredRouteWrapper,
    compactThread: retiredRouteWrapper,
  };
  const cases = [
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/context-budget",
      segments: ["v1", "threads", "thread_route", "context-budget"],
      operation: "evaluateContextBudget",
      args: [{ threadId: "thread_route", request: body }],
    },
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/compaction-policy",
      segments: ["v1", "threads", "thread_route", "compaction-policy"],
      operation: "evaluateCompactionPolicy",
      args: [{ threadId: "thread_route", request: body }],
    },
    {
      handler: handleThreadRoute,
      path: "/v1/threads/thread_route/compact",
      segments: ["v1", "threads", "thread_route", "compact"],
      operation: "compactThread",
      args: ["thread_route", body],
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
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("thread auxiliary and run cancel routes use mounted auxiliary surface", async () => {
  const { handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "thread-auxiliary-route-test" };
  const surfaceResult = (operation, args) => ({
    status: "rust_core_required",
    operation,
    args,
    direct_truth_write_allowed: false,
  });
  const store = {
    threadAuxiliarySurface: {
      forkThread(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "forkThread", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("forkThread", [threadId, requestBody]);
      },
      inspectManagedSessionsForThread(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "inspectManagedSessionsForThread", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("inspectManagedSessionsForThread", [threadId, requestBody]);
      },
      inspectWorkspaceChangeReviewsForThread(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "inspectWorkspaceChangeReviewsForThread", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("inspectWorkspaceChangeReviewsForThread", [threadId, requestBody]);
      },
      controlManagedSessionForThread(surfaceStore, threadId, requestBody) {
        calls.push({ operation: "controlManagedSessionForThread", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("controlManagedSessionForThread", [threadId, requestBody]);
      },
      cancelRun(surfaceStore, runId) {
        calls.push({ operation: "cancelRun", surfaceStore, args: [runId] });
        return surfaceResult("cancelRun", [runId]);
      },
    },
    forkThread: retiredRouteWrapper,
    inspectManagedSessionsForThread: retiredRouteWrapper,
    inspectWorkspaceChangeReviewsForThread: retiredRouteWrapper,
    controlManagedSessionForThread: retiredRouteWrapper,
    cancelRun: retiredRouteWrapper,
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
    },
    {
      handler: handleThreadRoute,
      method: "GET",
      path: "/v1/threads/thread_route/workspace-change-reviews?scope=active",
      operation: "inspectWorkspaceChangeReviewsForThread",
      args: ["thread_route", { scope: "active" }],
    },
    {
      handler: handleThreadRoute,
      method: "POST",
      path: "/v1/threads/thread_route/managed-sessions/control",
      operation: "controlManagedSessionForThread",
      args: ["thread_route", body],
    },
    {
      handler: handleRunRoute,
      method: "POST",
      path: "/v1/runs/run_route/cancel",
      operation: "cancelRun",
      args: ["run_route"],
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
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.operation, testCase.operation);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      operation: testCase.operation,
      args: testCase.args,
      direct_truth_write_allowed: false,
    });
  }
});

test("run route sends coding-tool budget recovery through mounted surface", async () => {
  const { handleRunRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "coding-tool-budget-recovery-route-test" };
  const store = {
    codingToolBudgetRecoverySurface: {
      codingToolBudgetRecoveryForRun(surfaceStore, runId, requestBody) {
        calls.push({ surfaceStore, args: [runId, requestBody] });
        return {
          status: "rust_core_required",
          args: [runId, requestBody],
          direct_truth_write_allowed: false,
        };
      },
    },
    codingToolBudgetRecoveryForRun: retiredRouteWrapper,
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
  assert.equal(calls[0].surfaceStore, store);
  assert.deepEqual(calls[0].args, ["run_route", body]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "rust_core_required",
    args: ["run_route", body],
    direct_truth_write_allowed: false,
  });
});

test("thread route sends MCP controls through mounted MCP surfaces", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { request_id: "thread-mcp-route-test" };
  const surfaceResult = (surface, method, args) => ({
    status: "rust_core_required",
    surface,
    method,
    args,
  });
  const store = {
    mcpControlSurface: {
      importThreadMcp(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "mcpControlSurface", method: "importThreadMcp", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("mcpControlSurface", "importThreadMcp", [threadId, requestBody]);
      },
      addThreadMcpServer(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "mcpControlSurface", method: "addThreadMcpServer", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("mcpControlSurface", "addThreadMcpServer", [threadId, requestBody]);
      },
      removeThreadMcpServer(surfaceStore, threadId, serverId, requestBody) {
        calls.push({
          surface: "mcpControlSurface",
          method: "removeThreadMcpServer",
          surfaceStore,
          args: [threadId, serverId, requestBody],
        });
        return surfaceResult("mcpControlSurface", "removeThreadMcpServer", [threadId, serverId, requestBody]);
      },
      setThreadMcpServerEnabled(surfaceStore, threadId, serverId, enabled, requestBody) {
        calls.push({
          surface: "mcpControlSurface",
          method: "setThreadMcpServerEnabled",
          surfaceStore,
          args: [threadId, serverId, enabled, requestBody],
        });
        return surfaceResult("mcpControlSurface", "setThreadMcpServerEnabled", [threadId, serverId, enabled, requestBody]);
      },
      invokeThreadMcpTool(surfaceStore, threadId, toolId, requestBody) {
        calls.push({
          surface: "mcpControlSurface",
          method: "invokeThreadMcpTool",
          surfaceStore,
          args: [threadId, toolId, requestBody],
        });
        return surfaceResult("mcpControlSurface", "invokeThreadMcpTool", [threadId, toolId, requestBody]);
      },
      recordThreadMcpStatus(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "mcpControlSurface", method: "recordThreadMcpStatus", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("mcpControlSurface", "recordThreadMcpStatus", [threadId, requestBody]);
      },
      validateThreadMcp(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "mcpControlSurface", method: "validateThreadMcp", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("mcpControlSurface", "validateThreadMcp", [threadId, requestBody]);
      },
    },
    mcpCatalogSurface: {
      searchThreadMcpTools(surfaceStore, threadId, requestBody) {
        calls.push({ surface: "mcpCatalogSurface", method: "searchThreadMcpTools", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("mcpCatalogSurface", "searchThreadMcpTools", [threadId, requestBody]);
      },
      getThreadMcpTool(surfaceStore, threadId, toolId, requestBody) {
        calls.push({
          surface: "mcpCatalogSurface",
          method: "getThreadMcpTool",
          surfaceStore,
          args: [threadId, toolId, requestBody],
        });
        return surfaceResult("mcpCatalogSurface", "getThreadMcpTool", [threadId, toolId, requestBody]);
      },
    },
    mcpServeSurface: {
      mcpServeStatus(surfaceStore, requestBody) {
        calls.push({ surface: "mcpServeSurface", method: "mcpServeStatus", surfaceStore, args: [requestBody] });
        return surfaceResult("mcpServeSurface", "mcpServeStatus", [requestBody]);
      },
      handleMcpServeJsonRpc(surfaceStore, threadId, message, requestBody) {
        calls.push({
          surface: "mcpServeSurface",
          method: "handleMcpServeJsonRpc",
          surfaceStore,
          args: [threadId, message, requestBody],
        });
        return surfaceResult("mcpServeSurface", "handleMcpServeJsonRpc", [threadId, message, requestBody]);
      },
    },
    importThreadMcp: retiredRouteWrapper,
    addThreadMcpServer: retiredRouteWrapper,
    removeThreadMcpServer: retiredRouteWrapper,
    setThreadMcpServerEnabled: retiredRouteWrapper,
    searchThreadMcpTools: retiredRouteWrapper,
    getThreadMcpTool: retiredRouteWrapper,
    invokeThreadMcpTool: retiredRouteWrapper,
    mcpServeStatus: retiredRouteWrapper,
    handleMcpServeJsonRpc: retiredRouteWrapper,
    recordThreadMcpStatus: retiredRouteWrapper,
    validateThreadMcp: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/import",
      segments: ["v1", "threads", "thread_route", "mcp", "import"],
      surfaceMethod: "importThreadMcp",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers",
      segments: ["v1", "threads", "thread_route", "mcp", "servers"],
      surfaceMethod: "addThreadMcpServer",
      args: ["thread_route", body],
      expectedStatus: 201,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers/mcp.docs/remove",
      segments: ["v1", "threads", "thread_route", "mcp", "servers", "mcp.docs", "remove"],
      surfaceMethod: "removeThreadMcpServer",
      args: ["thread_route", "mcp.docs", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/servers/mcp.docs/enable",
      segments: ["v1", "threads", "thread_route", "mcp", "servers", "mcp.docs", "enable"],
      surfaceMethod: "setThreadMcpServerEnabled",
      args: ["thread_route", "mcp.docs", true, body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/tools/search?query=diff",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "search"],
      surfaceMethod: "searchThreadMcpTools",
      args: ["thread_route", { query: "diff", source: "sdk_client" }],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/tools/mcp.tool",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "mcp.tool"],
      surfaceMethod: "getThreadMcpTool",
      args: ["thread_route", "mcp.tool", { source: "sdk_client" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/tools/mcp.tool/invoke",
      segments: ["v1", "threads", "thread_route", "mcp", "tools", "mcp.tool", "invoke"],
      surfaceMethod: "invokeThreadMcpTool",
      args: ["thread_route", "mcp.tool", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/invoke",
      segments: ["v1", "threads", "thread_route", "mcp", "invoke"],
      surfaceMethod: "invokeThreadMcpTool",
      args: ["thread_route", null, body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/mcp/serve?transport=sse",
      segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      surfaceMethod: "mcpServeStatus",
      args: [{ transport: "sse", thread_id: "thread_route" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/serve",
      segments: ["v1", "threads", "thread_route", "mcp", "serve"],
      surfaceMethod: "handleMcpServeJsonRpc",
      args: ["thread_route", body, { thread_id: "thread_route" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/status",
      segments: ["v1", "threads", "thread_route", "mcp", "status"],
      surfaceMethod: "recordThreadMcpStatus",
      args: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/mcp/validate",
      segments: ["v1", "threads", "thread_route", "mcp", "validate"],
      surfaceMethod: "validateThreadMcp",
      args: ["thread_route", body],
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
    const call = calls.pop();
    assert.equal(response.statusCode, testCase.expectedStatus ?? 200);
    assert.equal(call.method, testCase.surfaceMethod);
    assert.equal(call.surfaceStore, store);
    assert.deepEqual(call.args, testCase.args);
    assert.deepEqual(JSON.parse(response.body), {
      status: "rust_core_required",
      surface: call.surface,
      method: testCase.surfaceMethod,
      args: testCase.args,
    });
  }
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

test("thread route sends turn controls through mounted turn surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const store = {
    threadTurnSurface: {
      resumeThread(surfaceStore, threadId, requestBody) {
        calls.push({ method: "resumeThread", surfaceStore, threadId, requestBody });
        return { status: "active", thread_id: threadId, request: requestBody };
      },
      createTurn(surfaceStore, threadId, requestBody) {
        calls.push({ method: "createTurn", surfaceStore, threadId, requestBody });
        return { status: "created", thread_id: threadId, turn_id: "turn_route", request: requestBody };
      },
      interruptTurn(surfaceStore, threadId, turnId, requestBody) {
        calls.push({ method: "interruptTurn", surfaceStore, threadId, turnId, requestBody });
        return { status: "blocked", thread_id: threadId, turn_id: turnId, request: requestBody };
      },
      steerTurn(surfaceStore, threadId, turnId, requestBody) {
        calls.push({ method: "steerTurn", surfaceStore, threadId, turnId, requestBody });
        return { status: "blocked", thread_id: threadId, turn_id: turnId, request: requestBody };
      },
    },
    resumeThread() {
      throw new Error("retired resumeThread wrapper must not be routed");
    },
    createTurn() {
      throw new Error("retired createTurn wrapper must not be routed");
    },
    interruptTurn() {
      throw new Error("retired interruptTurn wrapper must not be routed");
    },
    steerTurn() {
      throw new Error("retired steerTurn wrapper must not be routed");
    },
  };
  const cases = [
    {
      method: "resumeThread",
      path: "/v1/threads/thread_route/resume",
      segments: ["v1", "threads", "thread_route", "resume"],
      body: { reason: "continue" },
      expected: { method: "resumeThread", surfaceStore: store, threadId: "thread_route", requestBody: { reason: "continue" } },
    },
    {
      method: "createTurn",
      path: "/v1/threads/thread_route/turns",
      segments: ["v1", "threads", "thread_route", "turns"],
      body: { prompt: "next" },
      expected: { method: "createTurn", surfaceStore: store, threadId: "thread_route", requestBody: { prompt: "next" } },
    },
    {
      method: "interruptTurn",
      path: "/v1/threads/thread_route/turns/turn_route/interrupt",
      segments: ["v1", "threads", "thread_route", "turns", "turn_route", "interrupt"],
      body: { reason: "stop" },
      expected: {
        method: "interruptTurn",
        surfaceStore: store,
        threadId: "thread_route",
        turnId: "turn_route",
        requestBody: { reason: "stop" },
      },
    },
    {
      method: "steerTurn",
      path: "/v1/threads/thread_route/turns/turn_route/steer",
      segments: ["v1", "threads", "thread_route", "turns", "turn_route", "steer"],
      body: { guidance: "focus" },
      expected: {
        method: "steerTurn",
        surfaceStore: store,
        threadId: "thread_route",
        turnId: "turn_route",
        requestBody: { guidance: "focus" },
      },
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

    assert.equal(response.statusCode, 200);
    assert.equal(JSON.parse(response.body).status, testCase.method === "createTurn" ? "created" : testCase.method === "resumeThread" ? "active" : "blocked");
  }

  assert.deepEqual(calls, cases.map((testCase) => testCase.expected));
});

test("thread route sends runtime controls through thread control surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = { mode: "review" };
  const store = {
    threadControlSurface: {
      updateThreadMode(surfaceStore, threadId, requestBody) {
        calls.push({ surfaceStore, threadId, requestBody });
        return {
          status: "blocked",
          thread_id: threadId,
          requested_control_kind: "mode",
        };
      },
    },
    updateThreadMode() {
      throw new Error("retired updateThreadMode wrapper must not be routed");
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/mode",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/mode", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "mode"],
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].surfaceStore, store);
  assert.equal(calls[0].threadId, "thread_route");
  assert.deepEqual(calls[0].requestBody, body);
  assert.deepEqual(JSON.parse(response.body), {
    status: "blocked",
    thread_id: "thread_route",
    requested_control_kind: "mode",
  });
});

test("thread route sends workspace-trust acknowledgement through thread control surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = { reason: "operator acknowledged" };
  const store = {
    threadControlSurface: {
      acknowledgeWorkspaceTrustWarning(surfaceStore, threadId, warningId, requestBody) {
        calls.push({ surfaceStore, threadId, warningId, requestBody });
        return {
          status: "blocked",
          thread_id: threadId,
          warning_id: warningId,
          requested_control_kind: "workspace_trust_acknowledgement",
        };
      },
    },
    acknowledgeWorkspaceTrustWarning() {
      throw new Error("retired acknowledgeWorkspaceTrustWarning wrapper must not be routed");
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

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].surfaceStore, store);
  assert.equal(calls[0].threadId, "thread_route");
  assert.equal(calls[0].warningId, "warning_1");
  assert.deepEqual(calls[0].requestBody, body);
  assert.deepEqual(JSON.parse(response.body), {
    status: "blocked",
    thread_id: "thread_route",
    warning_id: "warning_1",
    requested_control_kind: "workspace_trust_acknowledgement",
  });
});

test("thread route sends subagent controls through subagent surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const calls = [];
  const body = { prompt: "coordinate the migration" };
  const surfaceResult = (method, args) => ({
    status: "blocked",
    method,
    args,
  });
  const store = {
    subagentSurface: {
      listSubagents(surfaceStore, threadId, options) {
        calls.push({ method: "listSubagents", surfaceStore, args: [threadId, options] });
        return surfaceResult("listSubagents", [threadId, options]);
      },
      spawnSubagent(surfaceStore, threadId, requestBody) {
        calls.push({ method: "spawnSubagent", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("spawnSubagent", [threadId, requestBody]);
      },
      propagateSubagentCancellation(surfaceStore, threadId, requestBody) {
        calls.push({ method: "propagateSubagentCancellation", surfaceStore, args: [threadId, requestBody] });
        return surfaceResult("propagateSubagentCancellation", [threadId, requestBody]);
      },
      waitSubagent(surfaceStore, threadId, subagentId, requestBody) {
        calls.push({ method: "waitSubagent", surfaceStore, args: [threadId, subagentId, requestBody] });
        return surfaceResult("waitSubagent", [threadId, subagentId, requestBody]);
      },
      sendSubagentInput(surfaceStore, threadId, subagentId, requestBody) {
        calls.push({ method: "sendSubagentInput", surfaceStore, args: [threadId, subagentId, requestBody] });
        return surfaceResult("sendSubagentInput", [threadId, subagentId, requestBody]);
      },
      cancelSubagent(surfaceStore, threadId, subagentId, requestBody) {
        calls.push({ method: "cancelSubagent", surfaceStore, args: [threadId, subagentId, requestBody] });
        return surfaceResult("cancelSubagent", [threadId, subagentId, requestBody]);
      },
      resumeSubagent(surfaceStore, threadId, subagentId, requestBody) {
        calls.push({ method: "resumeSubagent", surfaceStore, args: [threadId, subagentId, requestBody] });
        return surfaceResult("resumeSubagent", [threadId, subagentId, requestBody]);
      },
      assignSubagent(surfaceStore, threadId, subagentId, requestBody) {
        calls.push({ method: "assignSubagent", surfaceStore, args: [threadId, subagentId, requestBody] });
        return surfaceResult("assignSubagent", [threadId, subagentId, requestBody]);
      },
      getSubagentResult(surfaceStore, threadId, subagentId) {
        calls.push({ method: "getSubagentResult", surfaceStore, args: [threadId, subagentId] });
        return surfaceResult("getSubagentResult", [threadId, subagentId]);
      },
    },
    listSubagents: retiredRouteWrapper,
    spawnSubagent: retiredRouteWrapper,
    propagateSubagentCancellation: retiredRouteWrapper,
    waitSubagent: retiredRouteWrapper,
    sendSubagentInput: retiredRouteWrapper,
    cancelSubagent: retiredRouteWrapper,
    resumeSubagent: retiredRouteWrapper,
    assignSubagent: retiredRouteWrapper,
    getSubagentResult: retiredRouteWrapper,
  };
  const cases = [
    {
      method: "GET",
      path: "/v1/threads/thread_route/subagents?role=reviewer",
      segments: ["v1", "threads", "thread_route", "subagents"],
      surfaceMethod: "listSubagents",
      expectedArgs: ["thread_route", { role: "reviewer" }],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents",
      segments: ["v1", "threads", "thread_route", "subagents"],
      surfaceMethod: "spawnSubagent",
      expectedArgs: ["thread_route", body],
      expectedStatus: 201,
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/cancel",
      segments: ["v1", "threads", "thread_route", "subagents", "cancel"],
      surfaceMethod: "propagateSubagentCancellation",
      expectedArgs: ["thread_route", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/wait",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "wait"],
      surfaceMethod: "waitSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/input",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "input"],
      surfaceMethod: "sendSubagentInput",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/cancel",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "cancel"],
      surfaceMethod: "cancelSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/resume",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "resume"],
      surfaceMethod: "resumeSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "POST",
      path: "/v1/threads/thread_route/subagents/subagent_1/assign",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "assign"],
      surfaceMethod: "assignSubagent",
      expectedArgs: ["thread_route", "subagent_1", body],
    },
    {
      method: "GET",
      path: "/v1/threads/thread_route/subagents/subagent_1/result",
      segments: ["v1", "threads", "thread_route", "subagents", "subagent_1", "result"],
      surfaceMethod: "getSubagentResult",
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
    const call = calls.pop();
    assert.equal(response.statusCode, testCase.expectedStatus ?? 200);
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
