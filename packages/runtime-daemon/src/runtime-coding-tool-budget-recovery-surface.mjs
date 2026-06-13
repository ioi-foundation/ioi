import { WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION } from "./runtime-contract-constants.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";

const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS = [
  "coding_tool_budget_recovery_state_update_rust_owned",
  "rust_daemon_core_budget_recovery_state_update",
  "rust_agentgres_runtime_run_state_commit",
];

const CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS = [
  "coding_tool_budget_recovery_control_rust_owned",
  "rust_daemon_core_budget_recovery_control",
  "rust_agentgres_runtime_run_state_commit",
];

function defaultRuntimeError(payload = {}) {
  const error = new Error(payload.message || "Runtime error");
  Object.assign(error, payload);
  return error;
}

export function createRuntimeCodingToolBudgetRecoverySurface(deps = {}) {
  const {
    runtimeError = defaultRuntimeError,
    codingToolBudgetRecoveryRunner = deps.contextPolicyRunner ?? null,
  } = deps;

  function stringRefs(values) {
    return normalizeArray(values).map((value) => String(value)).filter(Boolean);
  }

  function positiveInteger(value) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : null;
  }

  function normalizedBudgetRecoveryAction(request = {}) {
    const action = optionalString(request.action ?? request.recovery_action) ?? "request_approval";
    return action.toLowerCase().replace(/-/g, "_");
  }

  function budgetRecoveryRunner(
    store,
    method,
    details = {},
    evidenceRefs = CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
  ) {
    const runner = store?.contextPolicyRunner ?? codingToolBudgetRecoveryRunner;
    if (
      typeof runner?.[method] === "function" &&
      typeof store?.getRun === "function" &&
      typeof store?.writeRun === "function"
    ) {
      return runner;
    }
    throwCodingToolBudgetRecoveryRustCoreRequired(
      "coding_tool_budget_recovery_control",
      "workflow.run.coding_tool_budget_recovery",
      {
        ...details,
        evidence_refs: details.evidence_refs ?? evidenceRefs,
      },
    );
  }

  function throwBudgetRecoveryStateUpdateInputRequired(details = {}) {
    throw runtimeError({
      status: 400,
      code: "runtime_coding_tool_budget_recovery_state_update_input_required",
      message:
        "Coding-tool budget recovery retry completion requires canonical approval_id, event_id, seq, and created_at inputs.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function throwBudgetRecoveryStateUpdateIncomplete(details = {}) {
    throw runtimeError({
      status: 502,
      code: "runtime_coding_tool_budget_recovery_state_update_incomplete",
      message:
        "Rust coding-tool budget recovery planning did not return a complete run projection.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function throwBudgetRecoveryControlInputRequired(details = {}) {
    throw runtimeError({
      status: 400,
      code: "runtime_coding_tool_budget_recovery_control_input_required",
      message:
        "Coding-tool budget recovery control requires canonical approval_id, event_id, seq, and created_at inputs.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function throwBudgetRecoveryControlIncomplete(details = {}) {
    throw runtimeError({
      status: 502,
      code: "runtime_coding_tool_budget_recovery_control_incomplete",
      message:
        "Rust coding-tool budget recovery control planning did not return a complete run projection.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function throwCodingToolBudgetRecoveryRustCoreRequired(operation, operationKind, details = {}) {
    const { runner: _providedRunner, ...detailPayload } = details;
    throw runtimeError({
      status: 501,
      code: "runtime_coding_tool_budget_recovery_rust_core_required",
      message: "Runtime coding-tool budget recovery requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.coding_tool_budget_recovery",
        operation,
        operation_kind: operationKind,
        ...detailPayload,
      },
    });
  }

  function codingToolBudgetRecoveryForRun(store, runId, request = {}) {
    const action = normalizedBudgetRecoveryAction(request);
    const details = {
      run_id: runId,
      thread_id: optionalString(request.thread_id) ?? null,
      action,
      approval_id: optionalString(request.approval_id) ?? null,
      source_event_id: optionalString(request.source_event_id) ?? null,
      source: optionalString(request.source) ?? null,
    };
    if (action !== "retry_approved") {
      return codingToolBudgetRecoveryControlForRun(store, runId, request, action, details);
    }

    const runner = budgetRecoveryRunner(
      store,
      "planCodingToolBudgetRecoveryStateUpdate",
      details,
      CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS,
    );
    const approvalId = details.approval_id;
    const eventId = optionalString(request.event_id) ?? null;
    const seq = positiveInteger(request.seq);
    const createdAt = optionalString(request.created_at) ?? null;
    if (!approvalId || !eventId || !seq || !createdAt) {
      throwBudgetRecoveryStateUpdateInputRequired({
        ...details,
        event_id: eventId,
        seq: seq ?? null,
        created_at: createdAt,
      });
    }

    const run = store.getRun(runId);
    if (!objectRecord(run)) {
      throw runtimeError({
        status: 404,
        code: "runtime_coding_tool_budget_recovery_run_not_found",
        message: "Coding-tool budget recovery requires an admitted run record.",
        details: {
          rust_core_boundary: "runtime.coding_tool_budget_recovery",
          run_id: runId,
          evidence_refs: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS,
        },
      });
    }

    const planned = runner.planCodingToolBudgetRecoveryStateUpdate({
      thread_id: details.thread_id,
      run_id: runId,
      run,
      event_id: eventId,
      seq,
      created_at: createdAt,
      approval_id: approvalId,
      source: optionalString(request.source) ?? "runtime_auto",
      receipt_refs: stringRefs(request.receipt_refs),
      policy_decision_refs: stringRefs(request.policy_decision_refs),
    });
    const plannedRun = objectRecord(planned?.run);
    const plannedOperationKind = optionalString(planned?.operation_kind);
    const operatorControl = objectRecord(planned?.operator_control);
    if (
      optionalString(planned?.status) !== "planned" ||
      plannedOperationKind !== "workflow.run.retry_completed" ||
      !plannedRun ||
      optionalString(plannedRun.id) !== runId ||
      !operatorControl ||
      optionalString(operatorControl.control) !== "coding_tool_budget_recovery" ||
      optionalString(operatorControl.action) !== "retry_approved" ||
      optionalString(operatorControl.approval_id) !== approvalId ||
      optionalString(operatorControl.event_id) !== eventId
    ) {
      throwBudgetRecoveryStateUpdateIncomplete({
        ...details,
        event_id: eventId,
        expected_operation_kind: "workflow.run.retry_completed",
        actual_operation_kind: plannedOperationKind ?? null,
        actual_status: optionalString(planned?.status) ?? null,
      });
    }

    const commit = store.writeRun(plannedRun, plannedOperationKind);
    const receiptRefs = [
      ...stringRefs(operatorControl.receipt_refs),
      ...stringRefs(commit?.receipt_refs),
    ];
    const policyDecisionRefs = [
      ...stringRefs(operatorControl.policy_decision_refs),
      ...stringRefs(commit?.policy_decision_refs),
    ];
    return {
      schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      object: "ioi.workflow_coding_tool_budget_recovery",
      status: "completed",
      action,
      recovery_action: action,
      run_id: runId,
      thread_id: details.thread_id,
      approval_id: approvalId,
      source_event_id: details.source_event_id,
      event_id: eventId,
      seq,
      operation_kind: plannedOperationKind,
      operator_control: operatorControl,
      run: plannedRun,
      commit,
      receipt_refs: [...new Set(receiptRefs)],
      policy_decision_refs: [...new Set(policyDecisionRefs)],
      evidence_refs: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_EVIDENCE_REFS,
    };
  }

  function codingToolBudgetRecoveryControlForRun(store, runId, request, action, details) {
    const runner = budgetRecoveryRunner(store, "planCodingToolBudgetRecoveryControl", {
      ...details,
      evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
    });
    if (!["request_approval", "approve_override"].includes(action)) {
      runner.planCodingToolBudgetRecoveryControl({
        operation: "coding_tool_budget_recovery_control",
        operation_kind: "workflow.run.coding_tool_budget_recovery",
        run_id: runId,
        thread_id: details.thread_id,
        action,
        approval_id: details.approval_id,
        source_event_id: details.source_event_id,
        source: details.source,
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
      });
      throwBudgetRecoveryControlIncomplete({
        ...details,
        expected_actions: ["request_approval", "approve_override"],
        actual_action: action,
      });
    }
    const approvalId = details.approval_id;
    const eventId = optionalString(request.event_id) ?? null;
    const seq = positiveInteger(request.seq);
    const createdAt = optionalString(request.created_at) ?? null;
    if (!approvalId || !eventId || !seq || !createdAt) {
      throwBudgetRecoveryControlInputRequired({
        ...details,
        event_id: eventId,
        seq: seq ?? null,
        created_at: createdAt,
      });
    }

    const run = store.getRun(runId);
    if (!objectRecord(run)) {
      throw runtimeError({
        status: 404,
        code: "runtime_coding_tool_budget_recovery_run_not_found",
        message: "Coding-tool budget recovery requires an admitted run record.",
        details: {
          rust_core_boundary: "runtime.coding_tool_budget_recovery",
          run_id: runId,
          evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
        },
      });
    }

    const planned = runner.planCodingToolBudgetRecoveryControl({
      operation: "coding_tool_budget_recovery_control",
      operation_kind: "workflow.run.coding_tool_budget_recovery",
      run_id: runId,
      thread_id: details.thread_id,
      action,
      approval_id: approvalId,
      source_event_id: details.source_event_id,
      source: details.source ?? "runtime_auto",
      run,
      event_id: eventId,
      seq,
      created_at: createdAt,
      reason: optionalString(request.reason) ?? null,
      receipt_refs: stringRefs(request.receipt_refs),
      policy_decision_refs: stringRefs(request.policy_decision_refs),
      authority_grant_refs: stringRefs(request.authority_grant_refs),
      authority_receipt_refs: stringRefs(request.authority_receipt_refs),
      authority_context: objectRecord(request.authority_context) ?? {},
      evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
    });
    const plannedRun = objectRecord(planned?.run);
    const plannedOperationKind = optionalString(planned?.operation_kind);
    const operatorControl = objectRecord(planned?.operator_control);
    const walletGrantRefs = stringRefs(
      operatorControl?.wallet_network_grant_refs ?? planned?.wallet_network_grant_refs,
    );
    const authorityReceiptRefs = stringRefs(
      operatorControl?.authority_receipt_refs ?? planned?.authority_receipt_refs,
    );
    const authorityHash = optionalString(operatorControl?.authority_hash ?? planned?.authority_hash);
    if (
      optionalString(planned?.status) !== "planned" ||
      plannedOperationKind !== `workflow.run.coding_tool_budget_recovery.${action}` ||
      !plannedRun ||
      optionalString(plannedRun.id) !== runId ||
      !operatorControl ||
      optionalString(operatorControl.control) !== "coding_tool_budget_recovery" ||
      optionalString(operatorControl.action) !== action ||
      optionalString(operatorControl.approval_id) !== approvalId ||
      optionalString(operatorControl.event_id) !== eventId ||
      (action === "approve_override" &&
        (!authorityHash || walletGrantRefs.length === 0 || authorityReceiptRefs.length === 0))
    ) {
      throwBudgetRecoveryControlIncomplete({
        ...details,
        event_id: eventId,
        expected_operation_kind: `workflow.run.coding_tool_budget_recovery.${action}`,
        actual_operation_kind: plannedOperationKind ?? null,
        actual_status: optionalString(planned?.status) ?? null,
      });
    }

    const commit = store.writeRun(plannedRun, plannedOperationKind);
    const receiptRefs = [
      ...stringRefs(planned?.receipt_refs),
      ...stringRefs(operatorControl.receipt_refs),
      ...stringRefs(commit?.receipt_refs),
    ];
    const policyDecisionRefs = [
      ...stringRefs(planned?.policy_decision_refs),
      ...stringRefs(operatorControl.policy_decision_refs),
      ...stringRefs(commit?.policy_decision_refs),
    ];
    return {
      schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      object: "ioi.workflow_coding_tool_budget_recovery",
      status: optionalString(operatorControl.status) ?? "planned",
      action,
      recovery_action: action,
      run_id: runId,
      thread_id: details.thread_id,
      approval_id: approvalId,
      source_event_id: details.source_event_id,
      event_id: eventId,
      seq,
      operation_kind: plannedOperationKind,
      operator_control: operatorControl,
      run: plannedRun,
      commit,
      receipt_refs: [...new Set(receiptRefs)],
      policy_decision_refs: [...new Set(policyDecisionRefs)],
      wallet_network_grant_refs: walletGrantRefs,
      authority_receipt_refs: authorityReceiptRefs,
      authority_hash: authorityHash ?? null,
      evidence_refs: CODING_TOOL_BUDGET_RECOVERY_CONTROL_EVIDENCE_REFS,
    };
  }

  return {
    codingToolBudgetRecoveryForRun,
  };
}
