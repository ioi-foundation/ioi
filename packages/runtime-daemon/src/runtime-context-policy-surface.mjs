import {
  contextBudgetUsageTelemetryFromRequest,
  evaluateContextBudgetPolicy,
} from "./threads/context-budget-policy.mjs";
import { optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeContextPolicySurface({
  contextBudgetUsageTelemetryFromRequest: contextBudgetUsageTelemetryFromRequestDep = contextBudgetUsageTelemetryFromRequest,
  evaluateContextBudgetPolicy: evaluateContextBudgetPolicyDep = evaluateContextBudgetPolicy,
  optionalString: optionalStringDep = optionalString,
  runtimeError,
} = {}) {
  function throwContextPolicyRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_context_policy_rust_core_required",
      message: "Runtime context policy control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.context_policy",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  return {
    compactThread(store, threadId, request = {}) {
      throwContextPolicyRustCoreRequired("context_compaction", "thread.compact", {
        thread_id: threadId,
        evidence_refs: [
          "context_compaction_js_facade_retired",
          "rust_daemon_core_context_compaction_required",
          "agentgres_context_compaction_state_truth_required",
        ],
      });
    },

    evaluateContextBudget(store, { threadId = null, runId = null, request = {} } = {}) {
      const requestedRunId = optionalStringDep(request.run_id) ?? runId;
      const requestedThreadId = optionalStringDep(request.thread_id) ?? threadId;
      if (requestedThreadId || requestedRunId) {
        throwContextPolicyRustCoreRequired("context_budget_evaluation", "context_budget.evaluate", {
          thread_id: requestedThreadId,
          run_id: requestedRunId,
          evidence_refs: [
            "context_budget_evaluation_js_event_facade_retired",
            "rust_daemon_core_context_budget_event_required",
            "agentgres_context_budget_event_truth_required",
          ],
        });
      }

      const canonicalRequest = { ...request };
      for (const retiredField of [
        "eventKind",
        "runId",
        "threadId",
        "turnId",
        "workflowGraphId",
        "workflowNodeId",
      ]) {
        delete canonicalRequest[retiredField];
      }
      const usageTelemetry =
        contextBudgetUsageTelemetryFromRequestDep(canonicalRequest) ??
        store.listUsage({ group_by: "thread" });

      return evaluateContextBudgetPolicyDep({
        usageTelemetry,
        request: {
          ...canonicalRequest,
          scope: optionalStringDep(canonicalRequest.scope) ?? "workflow",
          thread_id: null,
          turn_id: null,
          run_id: null,
        },
      });
    },

    evaluateCompactionPolicy(store, { threadId, request = {} } = {}) {
      const requestedThreadId = optionalStringDep(request.thread_id) ?? threadId;
      if (!requestedThreadId) {
        throw runtimeError({
          status: 400,
          code: "runtime_compaction_policy_thread_required",
          message: "Compaction policy evaluation requires a thread id.",
        });
      }
      throwContextPolicyRustCoreRequired("compaction_policy_evaluation", "compaction_policy.evaluate", {
        thread_id: requestedThreadId,
        evidence_refs: [
          "compaction_policy_evaluation_js_event_facade_retired",
          "rust_daemon_core_compaction_policy_event_required",
          "agentgres_compaction_policy_event_truth_required",
        ],
      });
    },
  };
}
