import { runtimeError } from "./runtime-http-utils.mjs";
import {
  RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
} from "./subagent-manager.mjs";

const retiredSubagentRecordOutputAliasKeys = new Set([
  "schemaVersion",
  "subagentId",
  "agentId",
  "childThreadId",
  "runId",
  "parentThreadId",
  "parentAgentId",
  "parentTurnId",
  "toolPack",
  "modelRouteId",
  "workflowGraphId",
  "workflowNodeId",
  "sessionBootId",
  "lifecycleStatus",
  "restartStatus",
  "restartCount",
  "forkContext",
  "contextMode",
  "maxConcurrency",
  "budgetUsageTelemetry",
  "budgetStatus",
  "budgetPolicyDecision",
  "blockReason",
  "outputContract",
  "outputContractStatus",
  "outputContractValidation",
  "mergePolicy",
  "cancellationInheritance",
  "contextPressureAction",
  "contextPressure",
  "pressure",
  "pressureStatus",
  "alertId",
  "sourceEventId",
  "sourceReceiptRefs",
  "sourcePolicyDecisionRefs",
  "createdAt",
  "updatedAt",
  "eventId",
  "receiptRefs",
  "policyDecisionRefs",
  "evidenceRefs",
  "waitEventId",
  "waitedAt",
  "inputId",
  "inputCount",
  "inputHistory",
  "inputEventId",
  "lastInput",
  "lastInputAt",
  "previousRunIds",
  "resumeId",
  "resumeHistory",
  "resumeEventId",
  "resumedAt",
  "cancellationReason",
  "cancellationInherited",
  "propagatedFromThreadId",
  "cancellationClearedAt",
  "cancellationHistory",
  "assignmentId",
  "assignmentCount",
  "assignmentHistory",
  "assignEventId",
  "assignedAt",
  "targetAgentId",
  "cancelEventId",
  "canceledAt",
]);

const runtimeSubagentControlFacadeRetirementEvidenceRefs = [
  "runtime_subagent_control_js_facade_retired",
  "runtime_subagent_spawn_js_facade_retired",
  "runtime_subagent_wait_js_facade_retired",
  "runtime_subagent_input_js_facade_retired",
  "runtime_subagent_resume_js_facade_retired",
  "runtime_subagent_assign_js_facade_retired",
  "runtime_subagent_cancel_js_facade_retired",
  "runtime_subagent_cancel_propagation_js_facade_retired",
  "runtime_subagent_control_event_js_facade_retired",
  "runtime_subagent_list_js_facade_retired",
  "runtime_subagent_get_js_facade_retired",
  "runtime_subagent_result_js_facade_retired",
  "rust_daemon_core_runtime_subagent_control_required",
  "agentgres_runtime_subagent_truth_required",
];

function withoutRetiredSubagentRecordOutputAliases(record = {}) {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => !retiredSubagentRecordOutputAliasKeys.has(key)),
  );
}

export function createRuntimeSubagentSurface({
  runtimeError: runtimeErrorDep = runtimeError,
  schemaVersion = RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
} = {}) {
  function throwRuntimeSubagentRustCoreRequired({
    operation,
    operationKind,
    threadId,
    subagentId = null,
    details = {},
  }) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_subagent_control_rust_core_required",
      message:
        "Runtime subagent lifecycle and projection facades require direct Rust daemon-core admission, persistence, and projection.",
      details: {
        rust_core_boundary: "runtime.subagent_control",
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        ...(subagentId ? { subagent_id: subagentId } : {}),
        evidence_refs: [
          ...runtimeSubagentControlFacadeRetirementEvidenceRefs,
          `${operation}_js_facade_retired`,
        ],
        ...details,
      },
    });
  }

  return {
    listSubagents(store, threadId, options = {}) {
      void store;
      void options;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_list",
        operationKind: "subagent.list",
        threadId,
      });
    },
    getSubagent(store, threadId, subagentId) {
      void store;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_get",
        operationKind: "subagent.get",
        threadId,
        subagentId,
      });
    },
    spawnSubagent(store, threadId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_spawn",
        operationKind: "subagent.spawn",
        threadId,
      });
    },
    waitSubagent(store, threadId, subagentId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_wait",
        operationKind: "subagent.wait",
        threadId,
        subagentId,
      });
    },
    getSubagentResult(store, threadId, subagentId) {
      void store;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_result",
        operationKind: "subagent.result",
        threadId,
        subagentId,
      });
    },
    sendSubagentInput(store, threadId, subagentId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_input",
        operationKind: "subagent.input",
        threadId,
        subagentId,
      });
    },
    resumeSubagent(store, threadId, subagentId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_resume",
        operationKind: "subagent.resume",
        threadId,
        subagentId,
      });
    },
    assignSubagent(store, threadId, subagentId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_assign",
        operationKind: "subagent.assign",
        threadId,
        subagentId,
      });
    },
    cancelSubagent(store, threadId, subagentId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_cancel",
        operationKind: "subagent.cancel",
        threadId,
        subagentId,
      });
    },
    propagateSubagentCancellation(store, threadId, request = {}) {
      void store;
      void request;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_cancel_propagation",
        operationKind: "subagent.cancel.propagate",
        threadId,
      });
    },
    subagentProjection(record = {}) {
      const projection = withoutRetiredSubagentRecordOutputAliases(record);
      return {
        ...projection,
        schema_version: projection.schema_version ?? schemaVersion,
        object: projection.object ?? "ioi.runtime_subagent",
        output_contract_status:
          projection.output_contract_status ??
          projection.output_contract_validation?.status ??
          null,
      };
    },
    appendThreadSubagentControlEvent(store, {
      threadId,
      parentAgent,
      record,
      request,
      operation,
      status,
    }) {
      void store;
      void parentAgent;
      void record;
      void request;
      void status;
      throwRuntimeSubagentRustCoreRequired({
        operation: "runtime_subagent_control_event",
        operationKind: `subagent.${operation}`,
        threadId,
        subagentId: record?.subagent_id ?? null,
      });
    },
  };
}
