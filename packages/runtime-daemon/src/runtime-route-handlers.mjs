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
    throw notFound("Model mounting route not found.", {
      method: request.method,
      path: url.pathname,
    });
  }

  async function handleAgentRoute({ request, response, store, url, segments, contextPolicyCore }) {
    const agentId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("agent", { agent_id: agentId }));
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
      writeJsonResponse(response, await createLifecycleRunDep(store, agentId, await readBody(request), {
        approvalModeForThreadMode,
        buildRun,
        ensureProviderAvailable,
        lifecycleAdmissionRunner: routeContextPolicyCore,
        repositoryWorkflowProjector: routeContextPolicyCore,
        runtimeError: lifecycleRuntimeError,
        threadModeForRunMode,
      }));
      return;
    }
    if (request.method === "GET" && action === "runs") {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("agent_runs", { agent_id: agentId }));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.publicMemoryPolicyForAgent(agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.setMemoryPolicyForAgent(agentId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.publicMemoryPathForAgent(agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.updateMemoryForAgentId(agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.deleteMemoryForAgentId(agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.publicListMemoryForAgent(agentId, Object.fromEntries(new URL(request.url ?? "/", "http://127.0.0.1").searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.rememberForAgentId(agentId, await readBody(request)));
      return;
    }
    throw notFound("Agent route not found.", { agentId, action, method: request.method });
  }

  async function handleThreadRoute({ request, response, store, url, segments }) {
    const threadId = decodeURIComponent(segments[2]);
    const action = segments[3];
    // Unified-Rust-daemon migration: these thread lifecycle sub-routes are owned by the
    // Rust hypervisor-daemon (127.0.0.1:8765). They are retired here; non-migrated thread
    // sub-routes (usage, context-budget, artifacts, memory, approvals, workspace-trust,
    // managed-sessions, tools, diagnostics, snapshots, subagents tail, mcp serve/fetch, ...)
    // are preserved.
    if (
      (request.method === "GET" && !action) ||
      (action === "turns" &&
        ((request.method === "POST" && !segments[4]) ||
          segments[5] === "interrupt" ||
          segments[5] === "steer")) ||
      action === "mode" ||
      action === "model" ||
      action === "thinking" ||
      action === "events" ||
      // compaction-policy + (thread-scoped) context-budget + compact: owned by the
      // Rust daemon, which admits the decision/compaction event onto the unified
      // persisted log. The run-scoped context-budget (handleRunRoute) stays preserved.
      (action === "compaction-policy" && !segments[4]) ||
      (action === "context-budget" && !segments[4]) ||
      (action === "compact" && !segments[4]) ||
      // diagnostics repair-decision execute: the Rust daemon synthesizes + admits the
      // diagnostics.repair_decision.execute event onto the unified persisted log.
      (action === "diagnostics" &&
        segments[4] === "repair-decisions" &&
        segments[5] &&
        segments[6] === "execute") ||
      // approvals create (POST /approvals): the Rust daemon authorizes + folds the
      // approval onto the agent/run. GET (list) + decide/approve/reject/revoke stay preserved.
      (request.method === "POST" && action === "approvals" && !segments[4]) ||
      // memory status/validate: the Rust daemon projects the memory snapshot + admits the
      // memory.status/memory.validate event onto the unified log. Other memory routes preserved.
      (request.method === "POST" &&
        action === "memory" &&
        (segments[4] === "status" || segments[4] === "validate") &&
        !segments[5]) ||
      // usage (thread-scoped GET): the Rust daemon projects run usage via the kernel
      // runtime-lifecycle projection. Run-scoped GET /runs/:id/usage stays preserved.
      (request.method === "GET" && action === "usage" && !segments[4]) ||
      // managed-sessions + workspace-change-reviews (GET projections): the Rust daemon
      // projects them. The POST .../control routes stay preserved (gated).
      (request.method === "GET" && action === "managed-sessions" && !segments[4]) ||
      (request.method === "GET" && action === "workspace-change-reviews" && !segments[4]) ||
      // subagents: spawn (POST) + list (GET) + result + tail (wait/input/resume/assign/cancel
      // on /:id) + propagate-cancel (POST /subagents/cancel) are all migrated.
      (action === "subagents" &&
        (!segments[4] ||
          (segments[4] === "cancel" && !segments[5]) ||
          ["result", "wait", "input", "resume", "assign", "cancel"].includes(segments[5]))) ||
      // mcp: import, servers (add/remove/enable/disable), tools/search, status (POST /mcp
      // or /mcp/status), and validate are migrated; serve (JSON-RPC), invoke, and
      // tools/:id (fetch / :id/invoke) need live MCP transport and stay preserved.
      (action === "mcp" &&
        (!segments[4] ||
          segments[4] === "import" ||
          segments[4] === "servers" ||
          segments[4] === "status" ||
          segments[4] === "validate" ||
          (segments[4] === "tools" && segments[5] === "search")))
    ) {
      writeJsonResponse(
        response,
        {
          error: {
            code: "runtime_lifecycle_retired_served_by_rust_daemon",
            message:
              "This thread lifecycle route is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
            retryable: false,
            details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
          },
        },
        410,
      );
      return;
    }
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("thread", { thread_id: threadId }));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("thread_usage", { thread_id: threadId }));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.evaluateContextBudget({ threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.listConversationArtifacts({ thread_id: threadId }));
      return;
    }
    if (request.method === "POST" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(
        response,
        store.createConversationArtifact(threadId, await readBody(request)),
        201,
      );
      return;
    }
    if (request.method === "POST" && action === "compaction-policy" && !segments[4]) {
      writeJsonResponse(
        response,
        store.evaluateCompactionPolicy({ threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "resume") {
      writeJsonResponse(response, await store.resumeThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "fork") {
      writeJsonResponse(response, await store.forkThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "compact") {
      writeJsonResponse(response, store.compactThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mode" && !segments[4]) {
      writeJsonResponse(response, store.updateThreadMode(threadId, await readBody(request)));
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
        store.acknowledgeWorkspaceTrustWarning(
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "model" && !segments[4]) {
      writeJsonResponse(response, store.updateThreadModel(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "thinking" && !segments[4]) {
      writeJsonResponse(response, store.updateThreadThinking(threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "managed-sessions" && !segments[4]) {
      writeJsonResponse(response, await store.inspectManagedSessionsForThread(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && action === "workspace-change-reviews" && !segments[4]) {
      writeJsonResponse(response, await store.inspectWorkspaceChangeReviewsForThread(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "workspace-change-reviews" && segments[4] === "control" && !segments[5]) {
      writeJsonResponse(response, await store.controlWorkspaceChangeForThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "managed-sessions" && segments[4] === "control" && !segments[5]) {
      writeJsonResponse(response, await store.controlManagedSessionForThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.listSubagents(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.spawnSubagent(threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] === "cancel" && !segments[5]) {
      writeJsonResponse(response, store.propagateSubagentCancellation(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "wait" && !segments[6]) {
      writeJsonResponse(response, store.waitSubagent(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "input" && !segments[6]) {
      writeJsonResponse(response, store.sendSubagentInput(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "cancel" && !segments[6]) {
      writeJsonResponse(response, store.cancelSubagent(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "resume" && !segments[6]) {
      writeJsonResponse(response, store.resumeSubagent(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "assign" && !segments[6]) {
      writeJsonResponse(response, store.assignSubagent(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && segments[4] && segments[5] === "result" && !segments[6]) {
      writeJsonResponse(response, store.getSubagentResult(threadId, decodeURIComponent(segments[4])));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "import" && !segments[5]) {
      writeJsonResponse(response, store.importThreadMcp(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "servers" && !segments[5]) {
      writeJsonResponse(response, store.addThreadMcpServer(threadId, await readBody(request)), 201);
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
        store.removeThreadMcpServer(
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
        store.setThreadMcpServerEnabled(
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
        await store.searchThreadMcpTools(threadId, {
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
        await store.getThreadMcpTool(threadId, decodeURIComponent(segments[5]), {
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
        await store.invokeThreadMcpTool(
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "invoke" && !segments[5]) {
      writeJsonResponse(response, await store.invokeThreadMcpTool(threadId, null, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      assertNoMcpServeQueryContext(url);
      writeJsonResponse(response, store.mcpServeStatus(threadId));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      assertNoMcpServeQueryContext(url);
      const { message, context } = mcpServeProtocolParts(await readBody(request));
      writeMcpJsonRpcResponse(
        response,
        await store.handleMcpServeJsonRpc(threadId, message, {
          ...context,
          thread_id: threadId,
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && (!segments[4] || segments[4] === "status") && !segments[5]) {
      writeJsonResponse(response, await store.recordThreadMcpStatus(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.validateThreadMcp(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "status" && !segments[5]) {
      writeJsonResponse(response, store.recordThreadMemoryStatus(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.validateThreadMemory(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, await store.createTurn(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "interrupt" && !segments[6]) {
      writeJsonResponse(response, await store.interruptTurn(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "steer" && !segments[6]) {
      writeJsonResponse(response, await store.steerTurn(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.listThreadApprovals(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.requestThreadApproval(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "decision" && !segments[6]) {
      writeJsonResponse(
        response,
        store.decideThreadApproval(
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
        store.decideThreadApproval(threadId, decodeURIComponent(segments[4]), {
          ...body,
          decision: segments[5],
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "revoke" && !segments[6]) {
      writeJsonResponse(
        response,
        store.revokeThreadApproval(
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "workflow-edit-proposals" && !segments[4]) {
      writeJsonResponse(response, store.proposeWorkflowEdit(threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "governed-improvement-proposals" && !segments[4]) {
      writeJsonResponse(response, store.admitGovernedImprovementProposal(threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "external-capability-exits" && !segments[4]) {
      writeJsonResponse(response, store.authorizeExternalCapabilityExit(threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "worker-service-package-invocations" && !segments[4]) {
      writeJsonResponse(response, store.admitWorkerServicePackageInvocation(threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "ctee-private-workspace-actions" && !segments[4]) {
      writeJsonResponse(response, store.executeCteePrivateWorkspaceAction(threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "l1-settlement-attempts" && !segments[4]) {
      writeJsonResponse(response, store.admitL1SettlementAttempt(threadId, await readBody(request)), 201);
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
        store.applyWorkflowEditProposal(threadId, decodeURIComponent(segments[4]), await readBody(request)),
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
        store.executeDiagnosticsRepairDecision(threadId, decodeURIComponent(segments[5]), await readBody(request)),
      );
      return;
    }
    if (request.method === "GET" && action === "snapshots" && !segments[4]) {
      writeJsonResponse(response, store.listWorkspaceSnapshots(threadId));
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-preview" && !segments[6]) {
      writeJsonResponse(
        response,
        store.previewWorkspaceSnapshotRestore(threadId, decodeURIComponent(segments[4]), await readBody(request)),
      );
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-apply" && !segments[6]) {
      writeJsonResponse(
        response,
        store.applyWorkspaceSnapshotRestore(threadId, decodeURIComponent(segments[4]), await readBody(request)),
      );
      return;
    }
    if (request.method === "GET" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("thread_turns", { thread_id: threadId }));
      return;
    }
    if (request.method === "GET" && action === "turns" && segments[4] && !segments[5]) {
      writeJsonResponse(
        response,
        store.projectRuntimeLifecycleProjection("thread_turn", {
          thread_id: threadId,
          turn_id: decodeURIComponent(segments[4]),
        }),
      );
      return;
    }
    if (request.method === "GET" && action === "events" && (!segments[4] || segments[4] === "stream")) {
      writeSse(response, store.projectRuntimeLifecycleProjection("thread_events", { thread_id: threadId }));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.publicMemoryPolicyForThread(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.setMemoryPolicyForThread(threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.publicMemoryPathForThread(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.updateMemoryForThread(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.deleteMemoryForThread(threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.publicListMemoryForThread(threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.rememberForThread(threadId, await readBody(request)));
      return;
    }
    throw notFound("Thread route not found.", { threadId, action, method: request.method });
  }

  async function handleRunRoute({ request, response, store, url, segments }) {
    const runId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_usage", { run_id: runId }));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.evaluateContextBudget({ runId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "coding-tool-budget-recovery" && !segments[4]) {
      writeJsonResponse(
        response,
        store.codingToolBudgetRecoveryForRun(runId, await readBody(request)),
      );
      return;
    }
    if (request.method === "POST" && action === "cancel") {
      writeJsonResponse(response, store.cancelRun(runId));
      return;
    }
    if (request.method === "GET" && action === "wait") {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_wait", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "conversation") {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_conversation", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "events") {
      writeSse(
        response,
        store.projectRuntimeLifecycleProjection("run_events", { run_id: runId }),
      );
      return;
    }
    if (request.method === "GET" && action === "replay") {
      writeSse(
        response,
        store.projectRuntimeLifecycleProjection("run_replay", { run_id: runId }),
      );
      return;
    }
    if (request.method === "GET" && (action === "trace" || action === "inspect")) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_trace", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trace" && !segments[5]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_computer_use_trace", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trajectory" && !segments[5]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_computer_use_trajectory", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "scorecard") {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_scorecard", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_artifacts", { run_id: runId }));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && segments[4]) {
      const artifactRef = decodeURIComponent(segments[4]);
      writeJsonResponse(response, store.projectRuntimeLifecycleProjection("run_artifact", {
        run_id: runId,
        artifact_ref: artifactRef,
      }));
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
