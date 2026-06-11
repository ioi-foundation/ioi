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

test("agent, thread, and run detail routes use lifecycle projection surface", async () => {
  const { handleAgentRoute, handleThreadRoute, handleRunRoute } = routeHandlers();
  const calls = [];
  const lifecycleProjectionSurface = {
    getAgent(_store, agentId) {
      calls.push({ method: "getAgent", id: agentId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "agent", agent_id: agentId };
      throw error;
    },
    getThread(_store, threadId) {
      calls.push({ method: "getThread", id: threadId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "thread", thread_id: threadId };
      throw error;
    },
    getRun(_store, runId) {
      calls.push({ method: "getRun", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run", run_id: runId };
      throw error;
    },
    waitRun(_store, runId) {
      calls.push({ method: "waitRun", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_wait", run_id: runId };
      throw error;
    },
    getRunConversation(_store, runId) {
      calls.push({ method: "getRunConversation", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_conversation", run_id: runId };
      throw error;
    },
    getRunTrace(_store, runId) {
      calls.push({ method: "getRunTrace", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_trace", run_id: runId };
      throw error;
    },
    getRunComputerUseTrace(_store, runId) {
      calls.push({ method: "getRunComputerUseTrace", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_computer_use_trace", run_id: runId };
      throw error;
    },
    getRunComputerUseTrajectory(_store, runId) {
      calls.push({ method: "getRunComputerUseTrajectory", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_computer_use_trajectory", run_id: runId };
      throw error;
    },
    getRunScorecard(_store, runId) {
      calls.push({ method: "getRunScorecard", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_scorecard", run_id: runId };
      throw error;
    },
    listRunArtifacts(_store, runId) {
      calls.push({ method: "listRunArtifacts", id: runId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_artifacts", run_id: runId };
      throw error;
    },
    getRunArtifact(_store, runId, artifactRef) {
      calls.push({ method: "getRunArtifact", id: runId, artifactRef });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "run_artifact", run_id: runId, artifact_ref: artifactRef };
      throw error;
    },
    listRuns(_store, agentId) {
      calls.push({ method: "listRuns", id: agentId });
      const error = new Error("runtime lifecycle projection requires Rust core");
      error.status = 501;
      error.code = "runtime_lifecycle_projection_rust_core_required";
      error.details = { projection_kind: "agent_runs", agent_id: agentId };
      throw error;
    },
  };
  const store = { lifecycleProjectionSurface };

  await assert.rejects(
    () => handleAgentRoute({
      request: request({ url: "/v1/agents/agent_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/agents/agent_route", "http://daemon.test"),
      segments: ["v1", "agents", "agent_route"],
    }),
    { code: "runtime_lifecycle_projection_rust_core_required" },
  );
  await assert.rejects(
    () => handleAgentRoute({
      request: request({ url: "/v1/agents/agent_route/runs" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/agents/agent_route/runs", "http://daemon.test"),
      segments: ["v1", "agents", "agent_route", "runs"],
    }),
    { code: "runtime_lifecycle_projection_rust_core_required" },
  );
  await assert.rejects(
    () => handleThreadRoute({
      request: request({ url: "/v1/threads/thread_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/threads/thread_route", "http://daemon.test"),
      segments: ["v1", "threads", "thread_route"],
    }),
    { code: "runtime_lifecycle_projection_rust_core_required" },
  );
  await assert.rejects(
    () => handleRunRoute({
      request: request({ url: "/v1/runs/run_route" }),
      response: responseRecorder(),
      store,
      url: new URL("/v1/runs/run_route", "http://daemon.test"),
      segments: ["v1", "runs", "run_route"],
    }),
    { code: "runtime_lifecycle_projection_rust_core_required" },
  );
  for (const path of [
    "/v1/runs/run_route/wait",
    "/v1/runs/run_route/conversation",
    "/v1/runs/run_route/trace",
    "/v1/runs/run_route/inspect",
    "/v1/runs/run_route/computer-use/trace",
    "/v1/runs/run_route/computer-use/trajectory",
    "/v1/runs/run_route/scorecard",
    "/v1/runs/run_route/artifacts",
    "/v1/runs/run_route/artifacts/artifact_1",
  ]) {
    await assert.rejects(
      () => handleRunRoute({
        request: request({ url: path }),
        response: responseRecorder(),
        store,
        url: new URL(path, "http://daemon.test"),
        segments: path.split("/").filter(Boolean),
      }),
      { code: "runtime_lifecycle_projection_rust_core_required" },
    );
  }

  assert.deepEqual(calls, [
    { method: "getAgent", id: "agent_route" },
    { method: "listRuns", id: "agent_route" },
    { method: "getThread", id: "thread_route" },
    { method: "getRun", id: "run_route" },
    { method: "waitRun", id: "run_route" },
    { method: "getRunConversation", id: "run_route" },
    { method: "getRunTrace", id: "run_route" },
    { method: "getRunTrace", id: "run_route" },
    { method: "getRunComputerUseTrace", id: "run_route" },
    { method: "getRunComputerUseTrajectory", id: "run_route" },
    { method: "getRunScorecard", id: "run_route" },
    { method: "listRunArtifacts", id: "run_route" },
    { method: "getRunArtifact", id: "run_route", artifactRef: "artifact_1" },
  ]);
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
    decideThreadApproval: retiredRouteWrapper,
    revokeThreadApproval: retiredRouteWrapper,
  };
  const cases = [
    {
      path: "/v1/threads/thread_route/approvals",
      segments: ["v1", "threads", "thread_route", "approvals"],
      operation: "requestThreadApproval",
      args: ["thread_route", body],
    },
    {
      path: "/v1/threads/thread_route/approvals/approval_route/decision",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "decision"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", body],
    },
    {
      path: "/v1/threads/thread_route/approvals/approval_route/approve",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "approve"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "approve" }],
    },
    {
      path: "/v1/threads/thread_route/approvals/approval_route/reject",
      segments: ["v1", "threads", "thread_route", "approvals", "approval_route", "reject"],
      operation: "decideThreadApproval",
      args: ["thread_route", "approval_route", { ...body, decision: "reject" }],
    },
    {
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
