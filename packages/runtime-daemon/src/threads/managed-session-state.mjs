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
      threadId,
      session_id: sessionId,
      sessionId,
      runtime_profile: agent.runtimeProfile ?? "fixture",
      source: "daemon",
      status: "not_runtime_backed",
      managed_sessions: emptyManagedSessionSnapshot(threadId),
      managedSessions: emptyManagedSessionSnapshot(threadId),
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
      projection: "managed_sessions",
      managedSessionsOnly: true,
      requestedAt: new Date().toISOString(),
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
  const action = managedSessionControlAction(request.action ?? request.control ?? request.state);
  const managedSessionId = optionalString(
    request.managedSessionId ?? request.managed_session_id ?? request.sessionCardId ?? request.session_card_id,
  );
  if (!managedSessionId) {
    throw runtimeError({
      status: 400,
      code: "managed_session_control_contract",
      message: "Managed session control requires managedSessionId.",
      details: { threadId, operation: "control_thread" },
    });
  }
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
        optionalString(request.reason ?? request.message) ??
        `operator requested ${action.replace(/_/g, " ")}`,
      requestHash:
        optionalString(request.requestHash ?? request.request_hash) ??
        doctorHash(`${threadId}:${managedSessionId}:${action}:${createdAt}`).slice(0, 16),
      managedSessionId,
      createdAt,
    });
    return {
      schema_version: "ioi.runtime.managed-session-control.daemon.v1",
      thread_id: threadId,
      threadId,
      session_id: sessionId,
      sessionId,
      action,
      managed_session_id: managedSessionId,
      managedSessionId,
      source: "daemon",
      bridge_result: bridgeResult,
      bridgeResult,
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
