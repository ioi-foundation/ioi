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

const CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_EVIDENCE_REFS = [
  "coding_tool_budget_recovery_js_facade_retired",
  "rust_daemon_core_budget_recovery_admission_required",
  "agentgres_budget_recovery_state_truth_required",
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

  function budgetRecoveryRunner(store, details = {}) {
    const runner = store?.contextPolicyRunner ?? codingToolBudgetRecoveryRunner;
    if (
      typeof runner?.planCodingToolBudgetRecoveryStateUpdate === "function" &&
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
        evidence_refs: CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_EVIDENCE_REFS,
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

  function throwCodingToolBudgetRecoveryRustCoreRequired(operation, operationKind, details = {}) {
    const { runner: providedRunner, ...detailPayload } = details;
    const runner = providedRunner ?? codingToolBudgetRecoveryRunner;
    if (runner?.planCodingToolBudgetRecoveryAdmissionRequired) {
      const record = runner.planCodingToolBudgetRecoveryAdmissionRequired({
        operation,
        operation_kind: operationKind,
        run_id: detailPayload.run_id,
        thread_id: detailPayload.thread_id,
        action: detailPayload.action,
        approval_id: detailPayload.approval_id,
        source_event_id: detailPayload.source_event_id,
        source: detailPayload.source,
        evidence_refs: detailPayload.evidence_refs,
      });
      const planned = record?.record ?? record;
      throw runtimeError({
        status: Number(planned?.status_code ?? record?.status_code ?? 501),
        code: optionalString(planned?.code ?? record?.code) ??
          "runtime_coding_tool_budget_recovery_rust_core_required",
        message:
          optionalString(planned?.message ?? record?.message) ??
          "Runtime coding-tool budget recovery requires direct Rust daemon-core admission and persistence.",
        details: planned?.details ?? record?.details ?? {
          rust_core_boundary: "runtime.coding_tool_budget_recovery",
          operation,
          operation_kind: operationKind,
          ...detailPayload,
        },
      });
    }
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
    };
    if (action !== "retry_approved") {
      throwCodingToolBudgetRecoveryRustCoreRequired(
        "coding_tool_budget_recovery_control",
        "workflow.run.coding_tool_budget_recovery",
        {
          ...details,
          runner: store?.contextPolicyRunner ?? codingToolBudgetRecoveryRunner,
          evidence_refs: CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_EVIDENCE_REFS,
        },
      );
    }

    const runner = budgetRecoveryRunner(store, details);
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

  return {
    codingToolBudgetRecoveryForRun,
  };
}
