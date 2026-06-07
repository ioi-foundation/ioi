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
