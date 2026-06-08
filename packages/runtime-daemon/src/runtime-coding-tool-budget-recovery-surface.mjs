import { optionalString } from "./runtime-value-helpers.mjs";

function defaultRuntimeError(payload = {}) {
  const error = new Error(payload.message || "Runtime error");
  Object.assign(error, payload);
  return error;
}

export function createRuntimeCodingToolBudgetRecoverySurface(deps = {}) {
  const { runtimeError = defaultRuntimeError } = deps;

  function throwCodingToolBudgetRecoveryRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_coding_tool_budget_recovery_rust_core_required",
      message: "Runtime coding-tool budget recovery requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function latestCodingToolBudgetBlockedEventForRun(store, runId, sourceEventId = null) {
    throwCodingToolBudgetRecoveryRustCoreRequired("coding_tool_budget_blocked_event_projection", "workflow.run.coding_tool_budget_blocked.project", {
      run_id: runId,
      source_event_id: optionalString(sourceEventId) ?? null,
      evidence_refs: [
        "coding_tool_budget_blocked_event_js_projection_retired",
        "rust_daemon_core_coding_tool_budget_recovery_projection_required",
        "agentgres_coding_tool_budget_recovery_projection_truth_required",
      ],
    });
  }

  function codingToolBudgetRecoveryForRun(store, runId, request = {}) {
    throwCodingToolBudgetRecoveryRustCoreRequired("coding_tool_budget_recovery_control", "workflow.run.coding_tool_budget_recovery", {
      run_id: runId,
      thread_id: optionalString(request.thread_id) ?? null,
      action: optionalString(request.action ?? request.recovery_action) ?? "request_approval",
      approval_id: optionalString(request.approval_id) ?? null,
      source_event_id: optionalString(request.source_event_id) ?? null,
      evidence_refs: [
        "coding_tool_budget_recovery_js_facade_retired",
        "rust_daemon_core_budget_recovery_admission_required",
        "agentgres_budget_recovery_state_truth_required",
      ],
    });
  }

  return {
    latestCodingToolBudgetBlockedEventForRun,
    codingToolBudgetRecoveryForRun,
  };
}
