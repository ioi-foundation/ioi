import { notFound, runtimeError } from "./runtime-http-utils.mjs";
import { optionalString } from "./runtime-value-helpers.mjs";
import {
  RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  subagentContractOutputForRun,
  subagentIsActive,
  subagentResultForRun,
  validateSubagentOutputContract,
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
  "rust_daemon_core_runtime_subagent_control_required",
  "agentgres_runtime_subagent_truth_required",
];

function withoutRetiredSubagentRecordOutputAliases(record = {}) {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => !retiredSubagentRecordOutputAliasKeys.has(key)),
  );
}

export function createRuntimeSubagentSurface({
  notFound: notFoundDep = notFound,
  optionalString: optionalStringDep = optionalString,
  runtimeError: runtimeErrorDep = runtimeError,
  schemaVersion = RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  subagentContractOutputForRun: subagentContractOutputForRunDep = subagentContractOutputForRun,
  subagentIsActive: subagentIsActiveDep = subagentIsActive,
  subagentResultForRun: subagentResultForRunDep = subagentResultForRun,
  validateSubagentOutputContract: validateSubagentOutputContractDep = validateSubagentOutputContract,
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
        "Runtime subagent lifecycle mutations require direct Rust daemon-core admission and persistence.",
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
      const parentAgent = store.agentForThread(threadId);
      const role = optionalStringDep(options.role);
      const subagents = [...store.subagents.values()]
        .filter((record) => record.parent_thread_id === threadId)
        .filter((record) => !role || record.role === role)
        .sort((left, right) =>
          String(left.created_at ?? "").localeCompare(
            String(right.created_at ?? ""),
          ),
        )
        .map((record) => this.subagentProjection(record));
      return {
        schema_version: schemaVersion,
        object: "ioi.runtime_subagent_list",
        thread_id: threadId,
        parent_agent_id: parentAgent.id,
        status: "ready",
        count: subagents.length,
        active_count: subagents.filter((record) => subagentIsActiveDep(record)).length,
        subagents,
      };
    },
    getSubagent(store, threadId, subagentId) {
      const record = store.subagents.get(subagentId);
      if (!record || record.parent_thread_id !== threadId) {
        throw notFoundDep(`Subagent not found: ${subagentId}`, {
          thread_id: threadId,
          subagent_id: subagentId,
        });
      }
      return record;
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
      const record = store.getSubagent(threadId, subagentId);
      const run = store.getRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      return {
        ...subagentResultForRunDep({ record, run, output, outputContractStatus }),
        subagent: this.subagentProjection({
          ...record,
          output_contract_status: outputContractStatus.status,
        }),
      };
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
