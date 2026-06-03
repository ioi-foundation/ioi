import {
  emptyWorkspaceChangeReviewSnapshot,
  normalizeWorkspaceChangeReviewInspection,
} from "../workspace-change-inspection.mjs";
import { runtimeError } from "../runtime-http-utils.mjs";

export async function inspectWorkspaceChangeReviewsForThread(store, threadId, request = {}, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    isRuntimeBackedAgent,
    runtimeSessionIdForAgent,
  } = deps;
  const agent = store.agentForThread(threadId);
  const sessionId = runtimeSessionIdForAgent(agent);
  if (!isRuntimeBackedAgent(agent)) {
    return {
      ...emptyWorkspaceChangeReviewSnapshot(threadId, sessionId),
      runtime_profile: agent.runtimeProfile ?? "fixture",
      runtimeProfile: agent.runtimeProfile ?? "fixture",
      status: "not_runtime_backed",
    };
  }
  store.assertRuntimeBridgeAvailable({
    runtimeProfile: agent.runtimeProfile,
    operation: "inspect_thread",
  });
  try {
    const bridgeResult = await store.runtimeBridge.inspectThread({
      sessionId,
      threadId,
      workspaceRoot: agent.cwd,
      projection: "workspace_change_reviews",
      requestedAt: new Date().toISOString(),
      ...request,
    });
    return normalizeWorkspaceChangeReviewInspection({
      bridgeResult,
      agent,
      threadId,
      sessionId,
    });
  } catch (error) {
    if (RuntimeApiBridgeUnavailableError && error instanceof RuntimeApiBridgeUnavailableError) {
      throw store.runtimeBridgeUnavailable({
        runtimeProfile: agent.runtimeProfile,
        operation: "inspect_thread",
        details: error.details,
      });
    }
    throw error;
  }
}

export async function controlWorkspaceChangeForThread(store, threadId, request = {}, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    doctorHash,
    isRuntimeBackedAgent,
    optionalString,
    runtimeSessionIdForAgent,
    safeId,
  } = deps;
  const agent = store.agentForThread(threadId);
  if (!isRuntimeBackedAgent(agent)) {
    throw store.runtimeBridgeUnavailable({
      runtimeProfile: agent.runtimeProfile,
      operation: "control_thread",
      details: { reason: "workspace_change_control_requires_runtime_service" },
    });
  }
  const toolId = optionalString(request.toolId ?? request.tool_id);
  const input = request.input && typeof request.input === "object" ? request.input : request;
  const changeId = optionalString(
    input.changeId ?? input.change_id ?? input.workspaceChangeId ?? input.workspace_change_id,
  );
  if (!changeId) {
    throw runtimeError({
      status: 400,
      code: "workspace_change_control_contract",
      message: "Workspace change control requires changeId.",
      details: { threadId, operation: "control_thread", toolId },
    });
  }
  const action = toolId === "workspace_change__reject"
    ? "workspace_change_reject"
    : toolId === "workspace_change__rollback"
      ? "workspace_change_rollback"
      : "workspace_change_accept";
  store.assertRuntimeBridgeAvailable({
    runtimeProfile: agent.runtimeProfile,
    operation: "control_thread",
  });
  const sessionId = runtimeSessionIdForAgent(agent);
  const createdAt = optionalString(request.createdAt ?? request.created_at) ?? new Date().toISOString();
  try {
    const bridgeResult = await store.runtimeBridge.controlThread({
      sessionId,
      threadId,
      workspaceRoot: agent.cwd,
      action,
      reason:
        optionalString(input.reason ?? request.reason ?? request.message) ??
        `operator requested ${action.replace(/_/g, " ")}`,
      requestHash:
        optionalString(request.requestHash ?? request.request_hash) ??
        doctorHash(`${threadId}:${changeId}:${action}:${createdAt}`).slice(0, 16),
      changeId,
      createdAt,
    });
    const inspection = normalizeWorkspaceChangeReviewInspection({
      bridgeResult: bridgeResult?.inspection ?? bridgeResult,
      agent,
      threadId,
      sessionId,
    });
    const status = action === "workspace_change_reject"
      ? "rejected"
      : action === "workspace_change_rollback"
        ? "rolled_back"
        : "completed";
    const receiptRef = `receipt_workspace_change_${safeId(action)}_${doctorHash(`${threadId}:${changeId}:${createdAt}`).slice(0, 12)}`;
    return {
      schema_version: "ioi.runtime.workspace-change-control.daemon.v1",
      schemaVersion: "ioi.runtime.workspace-change-control.daemon.v1",
      thread_id: threadId,
      threadId,
      session_id: sessionId,
      sessionId,
      tool_id: toolId,
      toolId,
      action,
      change_id: changeId,
      changeId,
      source: "daemon",
      status,
      receipt_refs: [receiptRef],
      receiptRefs: [receiptRef],
      bridge_result: bridgeResult,
      bridgeResult,
      inspection,
      result: {
        action,
        changeId,
        status,
        inspection,
        receiptRefs: [receiptRef],
        receipt_refs: [receiptRef],
      },
    };
  } catch (error) {
    if (RuntimeApiBridgeUnavailableError && error instanceof RuntimeApiBridgeUnavailableError) {
      throw store.runtimeBridgeUnavailable({
        runtimeProfile: agent.runtimeProfile,
        operation: "control_thread",
        details: error.details,
      });
    }
    throw error;
  }
}
