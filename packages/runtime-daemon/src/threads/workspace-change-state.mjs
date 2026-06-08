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
  void store;
  void request;
  void deps;
  throw runtimeError({
    status: 501,
    code: "runtime_workspace_change_control_rust_core_required",
    message: "Workspace change control requires direct Rust daemon-core admission and projection.",
    details: {
      rust_core_boundary: "runtime.workspace_change_control",
      operation: "workspace_change_control",
      operation_kind: "workspace_change_control",
      thread_id: threadId,
      evidence_refs: [
        "workspace_change_control_js_facade_retired",
        "workspace_change_control_bridge_dispatch_retired",
        "workspace_change_control_receipt_synthesis_js_retired",
        "rust_daemon_core_workspace_change_control_required",
        "agentgres_workspace_change_truth_required",
      ],
    },
  });
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
