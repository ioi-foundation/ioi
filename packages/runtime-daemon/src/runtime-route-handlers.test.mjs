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

test("thread route authorizes external capability exits through store facade", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    request: {
      schema_version: "ioi.external_capability_exit_authority.v1",
      exit_ref: "exit://aiip/slack-post-message",
      capability_ref: "capability://connector/slack.postMessage",
    },
  };
  const store = {
    authorizeExternalCapabilityExit(threadId, requestBody) {
      calls.push({ threadId, requestBody });
      return {
        status: "authorized",
        exit_ref: requestBody.request.exit_ref,
        exit_authorized: true,
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/external-capability-exits",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/external-capability-exits", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "external-capability-exits"],
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(calls, [{ threadId: "thread_route", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "authorized",
    exit_ref: "exit://aiip/slack-post-message",
    exit_authorized: true,
  });
});

test("thread route executes cTEE private workspace actions through store facade", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    action: {
      invocation: {
        schema_version: "ioi.step_module_invocation.v1",
        invocation_id: "invocation://ctee/route",
      },
      node_trust: {
        runtime_node_ref: "node://rented-untrusted",
        trusted_for_plaintext: false,
      },
    },
  };
  const store = {
    executeCteePrivateWorkspaceAction(threadId, requestBody) {
      calls.push({ threadId, requestBody });
      return {
        status: "admitted",
        invocation_id: requestBody.action.invocation.invocation_id,
        action_executed: true,
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/ctee-private-workspace-actions",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/ctee-private-workspace-actions", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "ctee-private-workspace-actions"],
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(calls, [{ threadId: "thread_route", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "admitted",
    invocation_id: "invocation://ctee/route",
    action_executed: true,
  });
});

test("thread route admits L1 settlement attempts through store facade", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    attempt: {
      schema_version: "ioi.l1_settlement_admission.v1",
      settlement_ref: "l1://settlement/route",
      domain_ref: "domain://marketplace/services",
      state_root_ref: "state-root://agentgres/marketplace/after",
      trigger_refs: ["l1-trigger://service-contract/payment"],
      receipt_refs: ["receipt://local-settlement/payment"],
    },
  };
  const store = {
    admitL1SettlementAttempt(threadId, requestBody) {
      calls.push({ threadId, requestBody });
      return {
        status: "admitted",
        settlement_ref: requestBody.attempt.settlement_ref,
        settlement_admitted: true,
      };
    },
  };

  await handleThreadRoute({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/l1-settlement-attempts",
      body,
    }),
    response,
    store,
    url: new URL("/v1/threads/thread_route/l1-settlement-attempts", "http://daemon.test"),
    segments: ["v1", "threads", "thread_route", "l1-settlement-attempts"],
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(calls, [{ threadId: "thread_route", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "admitted",
    settlement_ref: "l1://settlement/route",
    settlement_admitted: true,
  });
});

test("thread route invokes coding tools through canonical store surface", async () => {
  const { handleThreadRoute } = routeHandlers();
  const response = responseRecorder();
  const calls = [];
  const body = {
    turn_id: "turn_route",
    workflow_node_id: "node.route",
    input: { include_stat: true },
  };
  const store = {
    invokeThreadTool(threadId, toolId, requestBody) {
      calls.push({ threadId, toolId, requestBody });
      return {
        status: "completed",
        thread_id: threadId,
        tool_id: toolId,
        request: requestBody,
      };
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
  assert.deepEqual(calls, [{ threadId: "thread_route", toolId: "git.diff", requestBody: body }]);
  assert.deepEqual(JSON.parse(response.body), {
    status: "completed",
    thread_id: "thread_route",
    tool_id: "git.diff",
    request: body,
  });
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
