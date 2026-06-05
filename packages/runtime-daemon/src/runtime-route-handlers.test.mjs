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
    resolveRunArtifact: () => null,
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

test("thread route admits governed improvement proposals through store facade", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    proposal: {
      schema_version: "ioi.governed_runtime_improvement.v1",
      proposal_id: "proposal://runtime-improvement/route",
    },
  };
  const store = {
    admitGovernedImprovementProposal(threadId, requestBody) {
      calls.push({ threadId, requestBody });
      return {
        status: "admitted",
        proposal_id: requestBody.proposal.proposal_id,
        mutation_executed: false,
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/governed-improvement-proposals",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/governed-improvement-proposals", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "governed-improvement-proposals"],
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(calls, [{ threadId: "thread_route", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "admitted",
    proposal_id: "proposal://runtime-improvement/route",
    mutation_executed: false,
  });
});

test("thread route admits worker/service package invocations through store facade", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    invocation: {
      schema_version: "ioi.worker_service_package_invocation.v1",
      package_kind: "worker_package",
      package_ref: "worker://runtime-auditor",
      manifest_ref: "worker://runtime-auditor@1",
    },
  };
  const store = {
    admitWorkerServicePackageInvocation(threadId, requestBody) {
      calls.push({ threadId, requestBody });
      return {
        status: "admitted",
        package_ref: requestBody.invocation.package_ref,
        invocation_admitted: true,
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/worker-service-package-invocations",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/worker-service-package-invocations", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "worker-service-package-invocations"],
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(calls, [{ threadId: "thread_route", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "admitted",
    package_ref: "worker://runtime-auditor",
    invocation_admitted: true,
  });
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
