import {
  optionalString,
} from "./runtime-value-helpers.mjs";

export function createRuntimeCodingToolGovernanceSurface(deps = {}) {
  const {
    codingToolBudgetBlockPlanner = deps.contextPolicyCore ?? null,
    runtimeError = ({ status = 500, code = "runtime_error", message = code, details = {} } = {}) => {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
  } = deps;

  function throwGovernanceRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_coding_tool_governance_rust_core_required",
      message: "Runtime coding-tool governance control requires direct Rust daemon-core authority admission and persistence.",
      details: {
        rust_core_boundary: "runtime.coding_tool_governance",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function blockCodingToolForBudget(store, {
    threadId,
    turnId,
    toolId,
    toolCallId,
    workspaceRoot,
    receiptId,
    inputSummary,
    request = {},
    workflowGraphId,
    workflowNodeId,
    requestRollbackRefs = [],
    budgetPolicy,
    artifactRefs = [],
    codingToolIdempotencyKey,
  }) {
    if (!codingToolBudgetBlockPlanner?.planCodingToolBudgetBlock) {
      throwGovernanceRustCoreRequired("coding_tool_budget_block", "policy.blocked", {
        thread_id: threadId,
        turn_id: turnId || null,
        tool_id: optionalString(toolId) ?? null,
        tool_call_id: optionalString(toolCallId) ?? null,
        workflow_graph_id: optionalString(workflowGraphId) ?? null,
        workflow_node_id: optionalString(workflowNodeId) ?? null,
        coding_tool_idempotency_key: optionalString(codingToolIdempotencyKey) ?? null,
        context_budget_status: optionalString(budgetPolicy?.status) ?? null,
        source: optionalString(request.source) ?? null,
        evidence_refs: [
          "coding_tool_budget_block_js_facade_retired",
          "rust_daemon_core_coding_tool_budget_block_required",
          "agentgres_coding_tool_budget_block_truth_required",
        ],
      });
    }
    return codingToolBudgetBlockPlanner.planCodingToolBudgetBlock({
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: optionalString(toolId) ?? null,
      tool_call_id: optionalString(toolCallId) ?? null,
      workspace_root: optionalString(workspaceRoot) ?? null,
      workflow_graph_id: optionalString(workflowGraphId) ?? null,
      workflow_node_id: optionalString(workflowNodeId) ?? null,
      source: optionalString(request.source) ?? null,
      idempotency_key: optionalString(codingToolIdempotencyKey) ?? null,
      receipt_id: optionalString(receiptId) ?? null,
      input_summary: objectRecord(inputSummary) ?? {},
      budget_policy: canonicalBudgetPolicy(budgetPolicy),
      rollback_refs: normalizeArray(requestRollbackRefs),
      receipt_refs: normalizeArray(budgetPolicy?.receipt_refs),
      policy_decision_refs: normalizeArray(budgetPolicy?.policy_decision_refs),
      artifact_refs: normalizeArray(artifactRefs),
    });
  }

  return {
    blockCodingToolForBudget,
  };
}

const RETIRED_BUDGET_POLICY_FIELDS = [
  "receiptRefs",
  "policyDecisionRefs",
  "usageTelemetry",
];

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function canonicalBudgetPolicy(value) {
  const policy = { ...(objectRecord(value) ?? {}) };
  for (const field of RETIRED_BUDGET_POLICY_FIELDS) {
    delete policy[field];
  }
  return policy;
}
