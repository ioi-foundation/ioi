import {
  createRun as createLifecycleRun,
} from "./runtime-agent-run-lifecycle.mjs";
import {
  deleteAgent as deleteLifecycleAgent,
  updateAgent as updateLifecycleAgent,
} from "./threads/thread-store.mjs";

export function createRuntimeRouteHandlers(deps) {
  const {
    approvalModeForThreadMode = null,
    buildRun = null,
    createLifecycleRun: createLifecycleRunDep = createLifecycleRun,
    deleteLifecycleAgent: deleteLifecycleAgentDep = deleteLifecycleAgent,
    ensureProviderAvailable = null,
    nativeInvocationResponse,
    notFound,
    readBody,
    runtimeError = null,
    threadModeForRunMode = null,
    updateLifecycleAgent: updateLifecycleAgentDep = updateLifecycleAgent,
    writeJsonResponse,
    writeMcpJsonRpcResponse,
    writeSse,
  } = deps;
  const lifecycleRuntimeError = typeof runtimeError === "function" ? runtimeError : undefined;
  function requiredRouteContextPolicyCore(contextPolicyCore, rustCoreBoundary) {
    if (contextPolicyCore) {
      return contextPolicyCore;
    }
    const error = {
      status: 501,
      code: "runtime_route_context_policy_core_required",
      message: "Runtime lifecycle routes require the explicit Rust daemon-core policy boundary.",
      details: {
        rust_core_boundary: rustCoreBoundary,
        retired_store_fallback: "context_policy_core_store_mount",
      },
    };
    throw lifecycleRuntimeError ? lifecycleRuntimeError(error) : Object.assign(new Error(error.message), error);
  }

  async function handleModelMountingNativeRoute({ request, response, store, url, segments }) {
    const mounts = store.modelMounting;
    const authorization = request.headers.authorization;
    if (request.method === "POST" && url.pathname === "/api/v1/rerank") {
      const invocation = await mounts.invokeModel({
        authorization,
        requiredScope: "model.rerank:*",
        kind: "rerank",
        body: await readBody(request),
      });
      writeJsonResponse(response, nativeInvocationResponse(invocation));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/tokenize") {
      writeJsonResponse(
        response,
        mounts.tokenizeModel({
          authorization,
          requiredScope: "model.tokenize:*",
          body: await readBody(request),
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/context/fit") {
      writeJsonResponse(
        response,
        mounts.fitModelContext({
          authorization,
          requiredScope: "model.context:*",
          body: await readBody(request),
        }),
      );
      return;
    }
    throw notFound("Model mounting route not found.", {
      method: request.method,
      path: url.pathname,
    });
  }

  async function handleAgentRoute({ request, response, store, url, segments, contextPolicyCore }) {
    const agentId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getAgent(store, agentId));
      return;
    }
    if (request.method === "DELETE" && !action) {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_delete");
      writeJsonResponse(response, deleteLifecycleAgentDep(store, agentId, {
        deleteStateUpdateRunner: routeContextPolicyCore,
        runtimeError: lifecycleRuntimeError,
      }), 204);
      return;
    }
    if (request.method === "POST" && action === "archive") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_status_control");
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "archived", "agent.archive", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: routeContextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "unarchive") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_status_control");
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "active", "agent.unarchive", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: routeContextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "resume") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_status_control");
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "active", "agent.resume", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: routeContextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "close") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_status_control");
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "closed", "agent.close", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: routeContextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "reload") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.agent_status_control");
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, null, "agent.reload", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: routeContextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "runs") {
      const routeContextPolicyCore = requiredRouteContextPolicyCore(contextPolicyCore, "runtime.run_create");
      writeJsonResponse(response, createLifecycleRunDep(store, agentId, await readBody(request), {
        approvalModeForThreadMode,
        buildRun,
        ensureProviderAvailable,
        lifecycleAdmissionRunner: routeContextPolicyCore,
        runtimeError: lifecycleRuntimeError,
        threadModeForRunMode,
      }));
      return;
    }
    if (request.method === "GET" && action === "runs") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listRuns(store, agentId));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPolicyForAgent(store, agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.setMemoryPolicyForAgent(store, agentId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPathForAgent(store, agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.updateMemoryForAgentId(store, agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.deleteMemoryForAgentId(store, agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.publicListMemoryForAgent(store, agentId, Object.fromEntries(new URL(request.url ?? "/", "http://127.0.0.1").searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.rememberForAgentId(store, agentId, await readBody(request)));
      return;
    }
    throw notFound("Agent route not found.", { agentId, action, method: request.method });
  }

  async function handleThreadRoute({ request, response, store, url, segments }) {
    const threadId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getThread(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getThreadUsage(store, threadId));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateContextBudget(store, { threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.conversationArtifactSurface.listConversationArtifacts(store, { thread_id: threadId }));
      return;
    }
    if (request.method === "POST" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(
        response,
        store.conversationArtifactSurface.createConversationArtifact(store, threadId, await readBody(request)),
        201,
      );
      return;
    }
    if (request.method === "POST" && action === "compaction-policy" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateCompactionPolicy(store, { threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "resume") {
      writeJsonResponse(response, await store.threadTurnSurface.resumeThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "fork") {
      writeJsonResponse(response, await store.threadAuxiliarySurface.forkThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "compact") {
      writeJsonResponse(response, store.contextPolicySurface.compactThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mode" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadMode(store, threadId, await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      action === "workspace-trust" &&
      segments[4] &&
      segments[5] === "acknowledge" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        store.threadControlSurface.acknowledgeWorkspaceTrustWarning(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "model" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadModel(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "thinking" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadThinking(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "managed-sessions" && !segments[4]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.inspectManagedSessionsForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && action === "workspace-change-reviews" && !segments[4]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.inspectWorkspaceChangeReviewsForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "managed-sessions" && segments[4] === "control" && !segments[5]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.controlManagedSessionForThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.subagentSurface.listSubagents(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.subagentSurface.spawnSubagent(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] === "cancel" && !segments[5]) {
      writeJsonResponse(response, store.subagentSurface.propagateSubagentCancellation(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "wait" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.waitSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "input" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.sendSubagentInput(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "cancel" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.cancelSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "resume" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.resumeSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "assign" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.assignSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && segments[4] && segments[5] === "result" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.getSubagentResult(store, threadId, decodeURIComponent(segments[4])));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "import" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.importThreadMcp(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "servers" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.addThreadMcpServer(store, threadId, await readBody(request)), 201);
      return;
    }
    if (
      (request.method === "DELETE" || request.method === "POST") &&
      action === "mcp" &&
      segments[4] === "servers" &&
      segments[5] &&
      (request.method === "DELETE" ? !segments[6] : segments[6] === "remove" && !segments[7])
    ) {
      writeJsonResponse(
        response,
        store.mcpControlSurface.removeThreadMcpServer(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (
      request.method === "POST" &&
      action === "mcp" &&
      segments[4] === "servers" &&
      segments[5] &&
      (segments[6] === "enable" || segments[6] === "disable") &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        store.mcpControlSurface.setThreadMcpServerEnabled(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          segments[6] === "enable",
          await readBody(request),
        ),
      );
      return;
    }
    if (
      request.method === "GET" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] === "search" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        await store.mcpCatalogSurface.searchThreadMcpTools(store, threadId, {
          ...Object.fromEntries(url.searchParams.entries()),
          source: "sdk_client",
        }),
      );
      return;
    }
    if (
      request.method === "GET" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        await store.mcpCatalogSurface.getThreadMcpTool(store, threadId, decodeURIComponent(segments[5]), {
          ...Object.fromEntries(url.searchParams.entries()),
          source: "sdk_client",
        }),
      );
      return;
    }
    if (
      request.method === "POST" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] &&
      segments[6] === "invoke" &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        await store.mcpControlSurface.invokeThreadMcpTool(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "invoke" && !segments[5]) {
      writeJsonResponse(response, await store.mcpControlSurface.invokeThreadMcpTool(store, threadId, null, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      assertNoMcpServeQueryContext(url);
      writeJsonResponse(response, store.mcpServeSurface.mcpServeStatus(store, {
        thread_id: threadId,
      }));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      assertNoMcpServeQueryContext(url);
      const { message, context } = mcpServeProtocolParts(await readBody(request));
      writeMcpJsonRpcResponse(
        response,
        await store.mcpServeSurface.handleMcpServeJsonRpc(store, threadId, message, {
          ...context,
          thread_id: threadId,
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && (!segments[4] || segments[4] === "status") && !segments[5]) {
      writeJsonResponse(response, await store.mcpControlSurface.recordThreadMcpStatus(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.validateThreadMcp(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "status" && !segments[5]) {
      writeJsonResponse(response, store.threadMemorySurface.recordThreadMemoryStatus(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.threadMemorySurface.validateThreadMemory(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, await store.threadTurnSurface.createTurn(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "interrupt" && !segments[6]) {
      writeJsonResponse(response, await store.threadTurnSurface.interruptTurn(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "steer" && !segments[6]) {
      writeJsonResponse(response, store.threadTurnSurface.steerTurn(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.approvalSurface.listThreadApprovals(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.approvalSurface.requestThreadApproval(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "decision" && !segments[6]) {
      writeJsonResponse(
        response,
        store.approvalSurface.decideThreadApproval(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && ["approve", "reject"].includes(segments[5]) && !segments[6]) {
      const body = await readBody(request);
      writeJsonResponse(
        response,
        store.approvalSurface.decideThreadApproval(store, threadId, decodeURIComponent(segments[4]), {
          ...body,
          decision: segments[5],
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "revoke" && !segments[6]) {
      writeJsonResponse(
        response,
        store.approvalSurface.revokeThreadApproval(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "workflow-edit-proposals" && !segments[4]) {
      writeJsonResponse(response, store.workflowEditSurface.proposeWorkflowEdit(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "governed-improvement-proposals" && !segments[4]) {
      writeJsonResponse(response, store.governedImprovementSurface.admitGovernedImprovementProposal(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "external-capability-exits" && !segments[4]) {
      writeJsonResponse(response, store.externalCapabilityAuthoritySurface.authorizeExternalCapabilityExit(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "worker-service-package-invocations" && !segments[4]) {
      writeJsonResponse(response, store.workerServicePackageSurface.admitWorkerServicePackageInvocation(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "ctee-private-workspace-actions" && !segments[4]) {
      writeJsonResponse(response, store.cteePrivateWorkspaceSurface.executeCteePrivateWorkspaceAction(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "l1-settlement-attempts" && !segments[4]) {
      writeJsonResponse(response, store.l1SettlementSurface.admitL1SettlementAttempt(store, threadId, await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      action === "workflow-edit-proposals" &&
      segments[4] &&
      segments[5] === "apply" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        store.workflowEditSurface.applyWorkflowEditProposal(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "tools" && segments[4] && segments[5] === "invoke" && !segments[6]) {
      writeJsonResponse(response, await store.codingToolInvocationSurface.invokeThreadTool(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      action === "diagnostics" &&
      segments[4] === "repair-decisions" &&
      segments[5] &&
      segments[6] === "execute" &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        store.diagnosticsRepairSurface.executeDiagnosticsRepairDecision(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "GET" && action === "snapshots" && !segments[4]) {
      writeJsonResponse(response, store.workspaceSnapshotSurface.listWorkspaceSnapshots(store, threadId));
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-preview" && !segments[6]) {
      writeJsonResponse(
        response,
        store.workspaceSnapshotSurface.previewWorkspaceSnapshotRestore(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-apply" && !segments[6]) {
      writeJsonResponse(
        response,
        store.workspaceSnapshotSurface.applyWorkspaceSnapshotRestore(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "GET" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listThreadTurns(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "turns" && segments[4] && !segments[5]) {
      writeJsonResponse(
        response,
        store.lifecycleProjectionSurface.getThreadTurn(store, threadId, decodeURIComponent(segments[4])),
      );
      return;
    }
    if (request.method === "GET" && action === "events" && (!segments[4] || segments[4] === "stream")) {
      writeSse(response, store.lifecycleProjectionSurface.listThreadEvents(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPolicyForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.setMemoryPolicyForThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPathForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.updateMemoryForThread(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.deleteMemoryForThread(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.publicListMemoryForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.rememberForThread(store, threadId, await readBody(request)));
      return;
    }
    throw notFound("Thread route not found.", { threadId, action, method: request.method });
  }

  async function handleRunRoute({ request, response, store, url, segments }) {
    const runId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunUsage(store, runId));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateContextBudget(store, { runId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "coding-tool-budget-recovery" && !segments[4]) {
      writeJsonResponse(
        response,
        store.codingToolBudgetRecoverySurface.codingToolBudgetRecoveryForRun(store, runId, await readBody(request)),
      );
      return;
    }
    if (request.method === "POST" && action === "cancel") {
      writeJsonResponse(response, store.threadAuxiliarySurface.cancelRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "wait") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.waitRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "conversation") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunConversation(store, runId));
      return;
    }
    if (request.method === "GET" && action === "events") {
      writeSse(
        response,
        store.lifecycleProjectionSurface.listRunEvents(store, runId),
      );
      return;
    }
    if (request.method === "GET" && action === "replay") {
      writeSse(
        response,
        store.lifecycleProjectionSurface.replayRun(store, runId),
      );
      return;
    }
    if (request.method === "GET" && (action === "trace" || action === "inspect")) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunTrace(store, runId));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trace" && !segments[5]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunComputerUseTrace(store, runId));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trajectory" && !segments[5]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunComputerUseTrajectory(store, runId));
      return;
    }
    if (request.method === "GET" && action === "scorecard") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunScorecard(store, runId));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listRunArtifacts(store, runId));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && segments[4]) {
      const artifactRef = decodeURIComponent(segments[4]);
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunArtifact(store, runId, artifactRef));
      return;
    }
    throw notFound("Run route not found.", { runId, action, method: request.method });
  }

  return {
    handleAgentRoute,
    handleModelMountingNativeRoute,
    handleRunRoute,
    handleThreadRoute,
  };
}

function assertNoMcpServeQueryContext(url) {
  if (url.searchParams.size === 0) return;
  const error = new Error("MCP serve query-string context is retired; send the stable protocol admission body.");
  error.status = 400;
  error.code = "runtime_mcp_serve_query_context_retired";
  error.details = {
    retired_query_fields: [...url.searchParams.keys()],
    canonical_transport: "ioi.runtime.mcp-serve-client.v1 body",
  };
  throw error;
}

function mcpServeProtocolParts(body) {
  const record = body && typeof body === "object" && !Array.isArray(body) ? body : null;
  if (record && Object.hasOwn(record, "message")) {
    const { message, ...context } = record;
    return { message, context };
  }
  const error = new Error("MCP serve requires the stable protocol admission envelope.");
  error.status = 400;
  error.code = "runtime_mcp_serve_protocol_envelope_required";
  error.details = {
    schema_version: "ioi.runtime.mcp-serve-client.v1",
    required_fields: ["schema_version", "message"],
  };
  throw error;
}
