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
      status: "not_runtime_backed",
    };
  }
  const retiredAliases = retiredWorkspaceChangeInspectionAliases(request);
  if (retiredAliases.length > 0) {
    throw runtimeError({
      status: 400,
      code: "workspace_change_inspection_request_aliases_retired",
      message: "Workspace change inspection request uses retired aliases.",
      details: { thread_id: threadId, retired_aliases: retiredAliases },
    });
  }
  store.assertRuntimeBridgeAvailable({
    runtimeProfile: agent.runtimeProfile,
    operation: "inspect_thread",
  });
  try {
    const bridgeResult = await store.runtimeBridge.inspectThread({
      session_id: sessionId,
      thread_id: threadId,
      workspace_root: agent.cwd,
      projection: "workspace_change_reviews",
      requested_at: new Date().toISOString(),
    });
    return normalizeWorkspaceChangeReviewInspection({
      bridge_result: bridgeResult,
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
  const retiredAliases = retiredWorkspaceChangeControlAliases(request);
  if (retiredAliases.length > 0) {
    throw runtimeError({
      status: 400,
      code: "workspace_change_control_request_aliases_retired",
      message: "Workspace change control request uses retired aliases.",
      details: { thread_id: threadId, retired_aliases: retiredAliases },
    });
  }
  const toolId = optionalString(request.tool_id);
  const input = request.input && typeof request.input === "object" ? request.input : request;
  const changeId = optionalString(input.change_id);
  if (!changeId) {
    throw runtimeError({
      status: 400,
      code: "workspace_change_control_contract",
      message: "Workspace change control requires changeId.",
      details: { thread_id: threadId, operation: "control_thread", tool_id: toolId },
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
  const createdAt = optionalString(request.created_at) ?? new Date().toISOString();
  try {
    const bridgeResult = await store.runtimeBridge.controlThread({
      session_id: sessionId,
      thread_id: threadId,
      workspace_root: agent.cwd,
      action,
      reason:
        optionalString(input.reason ?? request.reason ?? request.message) ??
        `operator requested ${action.replace(/_/g, " ")}`,
      request_hash:
        optionalString(request.request_hash) ??
        doctorHash(`${threadId}:${changeId}:${action}:${createdAt}`).slice(0, 16),
      change_id: changeId,
      created_at: createdAt,
    });
    const inspection = normalizeWorkspaceChangeReviewInspection({
      bridge_result: bridgeResult?.inspection ?? bridgeResult,
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
      thread_id: threadId,
      session_id: sessionId,
      tool_id: toolId,
      action,
      change_id: changeId,
      source: "daemon",
      status,
      receipt_refs: [receiptRef],
      bridge_result: bridgeResult,
      inspection,
      result: {
        action,
        change_id: changeId,
        status,
        inspection,
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

function retiredWorkspaceChangeInspectionAliases(request = {}) {
  return [
    ["sessionId", request],
    ["threadId", request],
    ["workspaceRoot", request],
    ["requestedAt", request],
  ]
    .filter(([key, container]) => Object.hasOwn(container, key))
    .map(([key]) => key);
}

function retiredWorkspaceChangeControlAliases(request = {}) {
  const input = request.input && typeof request.input === "object" ? request.input : {};
  return [
    ["toolId", request],
    ["createdAt", request],
    ["requestHash", request],
    ["changeId", request],
    ["workspaceChangeId", request],
    ["changeId", input],
    ["workspaceChangeId", input],
    ["workspace_change_id", input],
  ]
    .filter(([key, container]) => Object.hasOwn(container, key))
    .map(([key]) => key);
}
