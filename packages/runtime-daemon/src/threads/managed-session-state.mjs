import {
  emptyManagedSessionSnapshot,
  managedSessionControlAction,
  normalizeManagedSessionInspection,
} from "../managed-session-inspection.mjs";
import { runtimeError } from "../runtime-http-utils.mjs";

export async function inspectManagedSessionsForThread(store, threadId, request = {}, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    isRuntimeBackedAgent,
    runtimeSessionIdForAgent,
  } = deps;
  const agent = store.agentForThread(threadId);
  const sessionId = runtimeSessionIdForAgent(agent);
  if (!isRuntimeBackedAgent(agent)) {
    return {
      schema_version: "ioi.runtime.managed-session.daemon.v1",
      thread_id: threadId,
      session_id: sessionId,
      runtime_profile: agent.runtime_profile ?? "fixture",
      source: "daemon",
      status: "not_runtime_backed",
      managed_sessions: emptyManagedSessionSnapshot(threadId),
    };
  }
  const retiredAliases = retiredManagedSessionInspectionAliases(request);
  if (retiredAliases.length > 0) {
    throw runtimeError({
      status: 400,
      code: "managed_session_inspection_request_aliases_retired",
      message: "Managed session inspection request uses retired aliases.",
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
      projection: "managed_sessions",
      managed_sessions_only: true,
      requested_at: new Date().toISOString(),
    });
    return normalizeManagedSessionInspection({
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

function retiredManagedSessionInspectionAliases(request = {}) {
  return [
    "sessionId",
    "threadId",
    "workspaceRoot",
    "managedSessionsOnly",
    "requestedAt",
  ].filter((key) => Object.hasOwn(request, key));
}

export async function controlManagedSessionForThread(store, threadId, request = {}, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    doctorHash,
    isRuntimeBackedAgent,
    optionalString,
    runtimeSessionIdForAgent,
  } = deps;
  const agent = store.agentForThread(threadId);
  if (!isRuntimeBackedAgent(agent)) {
    throw store.runtimeBridgeUnavailable({
      runtimeProfile: agent.runtimeProfile,
      operation: "control_thread",
      details: { reason: "managed_session_control_requires_runtime_service" },
    });
  }
  const retiredAliases = retiredManagedSessionControlAliases(request);
  if (retiredAliases.length > 0) {
    throw runtimeError({
      status: 400,
      code: "managed_session_control_request_aliases_retired",
      message: "Managed session control request uses retired aliases.",
      details: { thread_id: threadId, retired_aliases: retiredAliases },
    });
  }
  const action = managedSessionControlAction(request.action ?? request.control ?? request.state);
  const managedSessionId = optionalString(request.managed_session_id);
  if (!managedSessionId) {
    throw runtimeError({
      status: 400,
      code: "managed_session_control_contract",
      message: "Managed session control requires managed_session_id.",
      details: { thread_id: threadId, operation: "control_thread" },
    });
  }
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
        optionalString(request.reason ?? request.message) ??
        `operator requested ${action.replace(/_/g, " ")}`,
      request_hash:
        optionalString(request.request_hash) ??
        doctorHash(`${threadId}:${managedSessionId}:${action}:${createdAt}`).slice(0, 16),
      managed_session_id: managedSessionId,
      created_at: createdAt,
    });
    return {
      schema_version: "ioi.runtime.managed-session-control.daemon.v1",
      thread_id: threadId,
      session_id: sessionId,
      action,
      managed_session_id: managedSessionId,
      source: "daemon",
      bridge_result: bridgeResult,
      inspection: normalizeManagedSessionInspection({
        bridgeResult: bridgeResult?.inspection ?? bridgeResult,
        agent,
        threadId,
        sessionId,
      }),
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

function retiredManagedSessionControlAliases(request = {}) {
  return [
    "managedSessionId",
    "sessionCardId",
    "session_card_id",
    "createdAt",
    "requestHash",
  ].filter((key) => Object.hasOwn(request, key));
}
