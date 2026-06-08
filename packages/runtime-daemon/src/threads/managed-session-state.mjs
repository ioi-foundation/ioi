import {
  emptyManagedSessionSnapshot,
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
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_managed_session_control_rust_core_required",
    message: "Managed session control requires direct Rust daemon-core admission and projection.",
    details: {
      rust_core_boundary: "runtime.managed_session_control",
      operation: "managed_session_control",
      operation_kind: "managed_session_control",
      thread_id: threadId,
      evidence_refs: [
        "managed_session_control_js_facade_retired",
        "managed_session_control_bridge_dispatch_retired",
        "managed_session_control_result_envelope_js_retired",
        "rust_daemon_core_managed_session_control_required",
        "agentgres_managed_session_truth_required",
      ],
    },
  });
}
