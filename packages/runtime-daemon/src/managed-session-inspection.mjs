import { runtimeError } from "./runtime-http-utils.mjs";

export function emptyManagedSessionSnapshot(threadId) {
  return {
    schema_version: "ioi.runtime.managed-session.v1",
    thread_id: threadId,
    sessions: [],
    product_lane: [],
    replay: {
      available: false,
      replayable: false,
    },
  };
}

export function normalizeManagedSessionInspection({
  bridgeResult,
  agent,
  threadId,
  sessionId,
}) {
  const managedSessions =
    bridgeResult?.managed_sessions ??
    emptyManagedSessionSnapshot(threadId);
  return {
    schema_version: "ioi.runtime.managed-session.daemon.v1",
    bridge_id: bridgeResult?.bridge_id ?? agent.runtime_bridge_id ?? null,
    source: bridgeResult?.source ?? "runtime_service",
    status: bridgeResult?.status ?? agent.status ?? "active",
    thread_id: bridgeResult?.thread_id ?? threadId,
    session_id: bridgeResult?.session_id ?? sessionId,
    workspace_root: bridgeResult?.workspace_root ?? agent.cwd,
    managed_sessions: managedSessions,
  };
}

export function managedSessionControlAction(value) {
  const normalized = optionalString(value)?.toLowerCase().replace(/[\s-]+/g, "_") ?? "observe_session";
  if (["observe", "observe_session", "managed_session_observe"].includes(normalized)) {
    return "observe_session";
  }
  if (["take_over", "take_over_session", "managed_session_take_over"].includes(normalized)) {
    return "take_over_session";
  }
  if (["return", "return_agent", "return_agent_session", "managed_session_return_agent"].includes(normalized)) {
    return "return_agent";
  }
  throw runtimeError({
    status: 400,
    code: "managed_session_control_contract",
    message:
      "Unsupported managed session control action; expected observe, take_over, or return_agent.",
    details: { action: value },
  });
}

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}
