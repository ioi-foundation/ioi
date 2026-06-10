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
  const store = {
    doctorReport: ({ baseUrl }) => ({ ok: true, baseUrl }),
  };

  await handleRequest({ request: request({ url: "/v1/doctor" }), response, store });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { ok: true, baseUrl: "http://daemon.test" });
});

test("public runtime routes delegate thread subroutes unchanged", async () => {
  const { calls, handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ url: "/v1/threads/thread_123/events" }), response, store: {} });

  assert.deepEqual(calls, ["thread"]);
  assert.equal(response.ended, false);
});

test("public runtime run list route ignores retired agentId query alias", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    listRuns(agentId) {
      calls.push({ agentId });
      return [{ id: agentId ?? "all-runs" }];
    },
  };

  await handleRequest({
    request: request({ url: "/v1/runs?agentId=agent-retired&agent_id=agent-canonical" }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [{ agentId: "agent-canonical" }]);
  assert.deepEqual(JSON.parse(response.body), [{ id: "agent-canonical" }]);

  const retiredOnlyResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/runs?agentId=agent-retired" }),
    response: retiredOnlyResponse,
    store,
  });

  assert.deepEqual(calls.at(-1), { agentId: undefined });
  assert.deepEqual(JSON.parse(retiredOnlyResponse.body), [{ id: "all-runs" }]);
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
